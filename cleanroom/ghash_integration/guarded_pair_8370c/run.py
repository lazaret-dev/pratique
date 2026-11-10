#!/usr/bin/env python3
"""Two immutable ELFs, five fixed rounds, unchanged original GHASH selectors.

Administrative orchestration only. No MSR access or production-source display.
"""
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
ADMIN = HERE.parents[2]
CONFIG = json.loads((HERE / 'config.json').read_text())
VERSIONS = ['baseline', 'candidate']
SELECTORS = {
    'gate': 'crypto::timing::ghash_multiplication_is_constant_time',
    'swap': 'crypto::timing::ghash_batch_hot_key_swap_controls',
}
CANCELLED = False
CASE_SECONDS = 55


def output():
    return Path(os.environ['PRATIQUE_PAIR_OUTPUT'])


def workspace():
    return Path(os.environ['GITHUB_WORKSPACE']).resolve()


def source(version):
    assert version in VERSIONS
    return workspace() / ('source-' + version)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def save(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(record, indent=2, allow_nan=False) + '\n')
    temporary.replace(path)


def load(path):
    return json.loads(path.read_text())


def stamp():
    return datetime.now(timezone.utc).isoformat()


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], timeout=15)


def inventory(root):
    paths = git(root, 'ls-files', '-z').decode().split('\0')
    selected = [p for p in paths if p.endswith('.rs') or Path(p).name in ['Cargo.toml', 'Cargo.lock']]
    return {p: sha(root / p) for p in sorted(selected)}


def planned():
    cases = []
    for iteration in range(1, 6):
        versions = VERSIONS if iteration % 2 else list(reversed(VERSIONS))
        for version in versions:
            for kind, selector in SELECTORS.items():
                cases.append({'slot': len(cases)+1, 'iteration': iteration,
                              'version': version, 'kind': kind, 'selector': selector,
                              'execution': 'not_attempted'})
    return cases


def verify():
    assert CONFIG['rounds'] == 5 and CONFIG['maximum_cpu_assignments'] == 40
    assert CONFIG['baseline_commit'] == 'a29c72ffbf7bfcade5b99f04f1414f77ac31a8cf'
    for version in VERSIONS:
        expected = CONFIG[version + '_commit']
        assert re.fullmatch('[0-9a-f]{40}', expected) and expected != '0'*40
    assert CONFIG['candidate_commit'] != CONFIG['baseline_commit']
    assert os.environ['RUSTUP_TOOLCHAIN'] == '1.87.0'
    assert os.environ['RUSTFLAGS'] == CONFIG['rustflags']
    assert os.environ['PRATIQUE_TIMING_SECS'] == CONFIG['timing_seconds'] == '3'
    assert all(n not in os.environ for n in ['PRATIQUE_TIMING_REPS', 'PRATIQUE_TIMING_TICK_NS',
                                              'PRATIQUE_TIMING_TICKS'])
    assert os.environ.get('CARGO_TARGET_DIR') is None
    assert os.environ.get('CARGO_ENCODED_RUSTFLAGS') is None
    host = load(output() / 'host/selection.json')
    assert host['matched_8370C'] is True
    assert re.search(r'\bXeon\b.*\b8370C\b', host['model_name'])
    assert git(ADMIN, 'rev-parse', 'HEAD').decode().strip() == os.environ['GITHUB_SHA']
    assert not git(ADMIN, 'status', '--porcelain', '--untracked-files=all')
    assert os.environ['GITHUB_REF'] == 'refs/heads/' + CONFIG['workflow_branch']
    assert host['workflow_head'] == os.environ['GITHUB_SHA']
    assert host['workflow_sha'] == os.environ['GITHUB_SHA']
    assert host['baseline_commit'] == CONFIG['baseline_commit']
    assert host['candidate_commit'] == CONFIG['candidate_commit']
    assert host['workflow_ref'] == ('lazaret-dev/pratique/.github/workflows/'
                                    'pr10-ghash-8370c-class-controls.yml@refs/heads/'
                                    + CONFIG['workflow_branch'])
    compiler = (output() / 'rustc-vV.txt').read_text()
    assert 'release: 1.87.0\n' in compiler and 'host: x86_64-unknown-linux-gnu\n' in compiler
    bindings = {'schema': 'two-source-bindings-v1', 'config_sha256': sha(HERE / 'config.json'),
                'workflow_head': os.environ['GITHUB_SHA'], 'flags': CONFIG['rustflags'],
                'timing_seconds': CONFIG['timing_seconds'], 'versions': {}}
    for version in VERSIONS:
        root = source(version)
        assert git(root, 'rev-parse', 'HEAD').decode().strip() == CONFIG[version + '_commit']
        assert not git(root, 'status', '--porcelain', '--untracked-files=all')
        assert sha(root / 'src/crypto/timing.rs') == CONFIG['timing_sha256']
        parser = root / 'cleanroom/ghash_integration/class_controls_8370c/run.py'
        assert sha(parser) == CONFIG['parser_sha256']
        bindings['versions'][version] = {'source_commit': CONFIG[version + '_commit'],
                                         'inputs': inventory(root)}
    path = output() / 'source-bindings.json'
    if path.exists():
        assert load(path) == bindings, 'Inputs or configuration changed after first binding.'
    else:
        save(path, bindings)
    return bindings


def bind_binary(version):
    bindings = verify()
    root = output() / version
    events = [json.loads(s) for s in (root / 'build-events.jsonl').read_text().splitlines()]
    binaries = {e['executable'] for e in events if e.get('reason') == 'compiler-artifact'
                and e.get('profile', {}).get('test') and e.get('executable')
                and e.get('target', {}).get('name') == 'pratique'
                and 'lib' in e.get('target', {}).get('kind', [])}
    assert len(binaries) == 1
    binary = Path(binaries.pop()).resolve()
    assert binary.is_relative_to(source(version) / 'target')
    with binary.open('rb') as stream:
        assert stream.read(4) == b'\x7fELF'
    record = {'path': str(binary), 'bytes': binary.stat().st_size, 'sha256': sha(binary),
              'source_commit': bindings['versions'][version]['source_commit']}
    save(root / 'binary.json', record)
    import capture_linked
    capture_linked.capture(binary, root)
    assert sha(binary) == record['sha256']
    verify()


def execute_case(case, binary, directory, timeout=CASE_SECONDS):
    global CANCELLED
    arguments = case.get('test_arguments', ['--exact', '--ignored', '--nocapture', '--test-threads=1'])
    record = {**case, 'argv': [str(binary), case['selector'], *arguments],
              'timeout_seconds': timeout, 'started_at': stamp(), 'execution': 'started'}
    directory.mkdir(parents=True, exist_ok=True)
    save(directory / 'case.json', record)
    start, process = time.monotonic(), None
    try:
        if CANCELLED:
            raise KeyboardInterrupt
        with (directory / 'stdout-stderr.log').open('wb') as log:
            process = subprocess.Popen(record['argv'], stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            record['process_group_id'] = process.pid
            try:
                record['exit_code'] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                record['exit_code'] = 'timeout'
    except BaseException as error:
        record['exit_code'] = 'collector_error'
        record['error'] = repr(error)
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            CANCELLED = True
            record['interrupted'] = True
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError as error:
                record['cleanup_incomplete'] = repr(error)
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            # Kill the owned group even when its leader has exited after TERM;
            # a remaining descendant must not overlap a later timing slot.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError as error:
                record['cleanup_incomplete'] = repr(error)
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired as error:
                record['cleanup_incomplete'] = repr(error)
        record.update(execution='finished', ended_at=stamp(), elapsed_seconds=time.monotonic()-start)
        if (directory / 'stdout-stderr.log').exists():
            record['stdout_stderr_sha256'] = sha(directory / 'stdout-stderr.log')
        save(directory / 'case.json', record)
    return record


def auxiliary(phase):
    assert phase in ['correctness', 'profile']
    verify()
    records = []
    for version in VERSIONS:
        if CANCELLED:
            break
        info = load(output() / version / 'binary.json')
        binary = Path(info['path'])
        assert sha(binary) == info['sha256']
        case = {'version': version, 'kind': phase,
                'source_commit': CONFIG[version + '_commit'], 'binary_sha256': info['sha256'],
                'selector': 'crypto::' if phase == 'correctness' else 'crypto::integration_profile::release_profile',
                'test_arguments': (['--nocapture', '--test-threads=1'] if phase == 'correctness' else
                                   ['--exact', '--ignored', '--nocapture', '--test-threads=1'])}
        directory = output() / ('auxiliary-' + phase + '-' + version)
        record = execute_case(case, binary, directory, timeout=60)
        text = (directory / 'stdout-stderr.log').read_text(errors='replace')
        footer = re.findall(r'^test result: ok\. (\d+) passed; 0 failed; (\d+) ignored;', text, re.M)
        record['binary_sha256_after'] = sha(binary)
        record['passed'] = (record.get('exit_code') == 0 and len(footer) == 1
                            and int(footer[0][0]) > 0 and record['binary_sha256_after'] == info['sha256']
                            and (phase != 'profile' or footer == [('1', '0')]))
        record['footer_counts'] = footer
        save(directory / 'case.json', record)
        records.append(record)
        save(output() / ('auxiliary-' + phase + '.json'), records)
        if record.get('interrupted') or record.get('cleanup_incomplete'):
            break
    verify()
    return 0 if len(records) == 2 and all(r['passed'] for r in records) else 1


def run_all(executor=execute_case):
    verify()
    binaries = {v: load(output() / v / 'binary.json') for v in VERSIONS}
    cases = planned()
    save(output() / 'twenty-slots.json', cases)
    for i, case in enumerate(cases):
        if CANCELLED:
            break
        version = case['version']
        binary = Path(binaries[version]['path'])
        assert sha(binary) == binaries[version]['sha256']
        case.update(source_commit=CONFIG[version + '_commit'], binary_sha256=binaries[version]['sha256'])
        directory = output() / ('%02d-%s-%s-%d' %
                                (case['slot'], version, case['kind'], case['iteration']))
        cases[i] = executor(case, binary, directory)
        save(output() / 'twenty-slots.json', cases)
        print(json.dumps({k: cases[i].get(k) for k in
                          ['slot', 'version', 'kind', 'iteration', 'exit_code']}), flush=True)
        if CANCELLED or cases[i].get('interrupted') or cases[i].get('cleanup_incomplete'):
            for later in cases[i+1:]:
                later['reason'] = 'Cancelled or unsafe child cleanup; no replacement or retry.'
            break
    save(output() / 'twenty-slots.json', cases)
    identities = {v: {'before': info['sha256'], 'after': sha(Path(info['path']))}
                  for v, info in binaries.items()}
    save(output() / 'binary-window-identities.json', identities)
    verify()
    return 130 if CANCELLED else 0


def parser_module():
    path = source('baseline') / 'cleanroom/ghash_integration/class_controls_8370c/run.py'
    assert sha(path) == CONFIG['parser_sha256']
    spec = importlib.util.spec_from_file_location('unchanged_A3_parser', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def summarize_inner():
    parser = parser_module()
    cases = load(output() / 'twenty-slots.json') if (output() / 'twenty-slots.json').exists() else planned()
    results = []
    binding_errors = []
    for i, recorded in enumerate(cases):
        expected = planned()[i]
        fields = ['slot', 'iteration', 'version', 'kind', 'selector']
        case = {**recorded, **{k: expected[k] for k in fields}}
        errors = []
        if any(recorded.get(k) != expected[k] for k in fields):
            errors.append('Recorded slot identity differs from the fixed plan.')
        directory = output() / ('%02d-%s-%s-%d' %
                                (case['slot'], case['version'], case['kind'], case['iteration']))
        log = directory / 'stdout-stderr.log'
        text = log.read_text(errors='replace') if log.exists() else ''
        parsed = (parser.parse_original(text, case.get('exit_code')) if case['kind'] == 'gate'
                  else parser.parse_controls(text, case.get('exit_code'), 'swap'))
        if case.get('execution') != 'finished' or case.get('interrupted') or case.get('cleanup_incomplete'):
            errors.append('Slot did not finish safely.')
        if not (directory / 'case.json').exists() or load(directory / 'case.json') != recorded:
            errors.append('Slot record differs from its case.json.')
        if (not log.exists() or not case.get('stdout_stderr_sha256')
                or sha(log) != case['stdout_stderr_sha256']):
            errors.append('Missing or mismatched required stdout/stderr SHA.')
        info = load(output() / case['version'] / 'binary.json')
        argv = [info['path'], expected['selector'], '--exact', '--ignored', '--nocapture', '--test-threads=1']
        if case.get('argv') != argv or case.get('timeout_seconds') != CASE_SECONDS:
            errors.append('Slot arguments or timeout differ from the fixed plan.')
        if (case.get('source_commit') != CONFIG[case['version'] + '_commit']
                or case.get('binary_sha256') != info['sha256']):
            errors.append('Slot source or ELF identity differs from its binding.')
        parsed['complete_before_binding'] = parsed['complete']
        parsed['complete'] = bool(parsed['complete'] and not errors)
        results.append({'case': case, 'parsed': parsed, 'binding_errors': errors})
        binding_errors.extend({'slot': expected['slot'], 'error': error} for error in errors)
    identity_path = output() / 'binary-window-identities.json'
    identities = load(identity_path) if identity_path.exists() else {}
    identities_valid = set(identities) == set(VERSIONS) and all(
        x['before'] == x['after'] for x in identities.values())
    for version in VERSIONS:
        info_path = output() / version / 'binary.json'
        if not info_path.exists() or version not in identities:
            identities_valid = False
            continue
        info = load(info_path)
        retained = output() / version / 'linked-evidence/compiled-test.elf'
        identities_valid = bool(identities_valid and retained.exists()
            and sha(retained) == info['sha256'] == identities[version]['before']
            and sha(Path(info['path'])) == identities[version]['after']
            and info['source_commit'] == CONFIG[version + '_commit'])
    planned_cases = planned()
    slot_identity_valid = len(cases) == len(planned_cases) and all(
        all(case.get(k) == expected[k] for k in ['slot', 'iteration', 'version', 'kind', 'selector'])
        for case, expected in zip(cases, planned_cases))
    for case in cases:
        if case.get('execution') == 'finished':
            info_path = output() / case['version'] / 'binary.json'
            slot_identity_valid = bool(slot_identity_valid and info_path.exists()
                and case.get('source_commit') == CONFIG[case['version'] + '_commit']
                and case.get('binary_sha256') == load(info_path)['sha256'])
    auxiliary_status = {}
    for phase in ['correctness', 'profile']:
        path = output() / ('auxiliary-' + phase + '.json')
        records = load(path) if path.exists() else []
        valid = len(records) == 2 and [r['version'] for r in records] == VERSIONS
        passed = valid
        for record in records:
            info_path = output() / record['version'] / 'binary.json'
            directory = output() / ('auxiliary-' + phase + '-' + record['version'])
            log = directory / 'stdout-stderr.log'
            footer = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',
                                log.read_text(errors='replace') if log.exists() else '', re.M)
            args = (['--nocapture', '--test-threads=1'] if phase == 'correctness' else
                    ['--exact', '--ignored', '--nocapture', '--test-threads=1'])
            selector = 'crypto::' if phase == 'correctness' else 'crypto::integration_profile::release_profile'
            info = load(info_path) if info_path.exists() else {}
            complete = (len(footer) == 1 and record.get('exit_code') in [0, 101]
                        and record.get('execution') == 'finished' and not record.get('interrupted')
                        and not record.get('cleanup_incomplete') and log.exists()
                        and record.get('stdout_stderr_sha256') == sha(log)
                        and (directory / 'case.json').exists() and load(directory / 'case.json') == record
                        and record.get('argv') == [info.get('path'), selector, *args]
                        and record.get('timeout_seconds') == 60)
            authoritative_pass = bool(complete and record['exit_code'] == 0 and footer[0][0] == 'ok'
                                      and int(footer[0][1]) > 0 and footer[0][2] == '0'
                                      and (phase != 'profile' or footer[0][1:] == ('1', '0', '0')))
            valid = bool(valid and complete and info_path.exists()
                         and record.get('passed') is authoritative_pass
                         and record.get('source_commit') == CONFIG[record['version'] + '_commit']
                         and record.get('binary_sha256') == record.get('binary_sha256_after')
                         == info.get('sha256'))
            passed = bool(passed and authoritative_pass)
        auxiliary_status[phase] = {'collection_complete': valid, 'passed_and_bound': valid and passed,
                                   'records': records}
    try:
        verify()
        sources_valid = True
    except Exception as error:
        sources_valid = False
        save(output() / 'summary-binding-error.json', {'error': repr(error)})
    result = {'schema': 'paired-five-round-results-v1', 'config': CONFIG, 'cases': results,
              'source_binding_valid': sources_valid, 'binary_window_identities': identities,
              'slot_identity_valid': slot_identity_valid,
              'binding_errors': binding_errors,
              'auxiliary_status': auxiliary_status,
              'timing_collection_complete': len(results) == 20 and all(r['parsed']['complete'] for r in results)
                                            and identities_valid and sources_valid and slot_identity_valid,
              'causal_or_security_closure': False,
              'actual_linked_work_review': 'Pending read-only review of both retained native ELFs.'}
    result['collection_complete'] = (result['timing_collection_complete']
                                    and all(x['collection_complete'] for x in auxiliary_status.values()))
    for version in VERSIONS:
        rows = [r for r in results if r['case']['version'] == version]
        result[version] = {
            'gate_confirmed_rows': {str(r['case']['iteration']): (r['parsed']['confirmed_rows'] if r['parsed']['complete'] else None)
                                    for r in rows if r['case']['kind'] == 'gate'},
            'swap_judges': {str(r['case']['iteration']): (r['parsed']['judges'] if r['parsed']['complete'] else None)
                            for r in rows if r['case']['kind'] == 'swap'},
        }
        derived = parser.derive_swap_effects(rows)
        save(output() / version / 'derived-swap-effects.json', derived)
        with (output() / version / 'control-per-call.csv').open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=['iteration', 'row', 'seed', 'reps', 'keep',
                                                       'difference_ns', 'standard_error_ns', 'judge_confirmed'])
            writer.writeheader()
            for item in rows:
                if item['case']['kind'] != 'swap' or not item['parsed']['complete']:
                    continue
                judges = {j['name']: j['confirmed'] for j in item['parsed']['judges']}
                for report in item['parsed']['reports']:
                    for p in report.get('per_call', []):
                        writer.writerow({'iteration': item['case']['iteration'], 'row': report['name'],
                                         'seed': report['seed'], 'reps': report['reps'], 'keep': p['keep'],
                                         'difference_ns': p['difference_ns']['display'],
                                         'standard_error_ns': p['standard_error_ns']['display'],
                                         'judge_confirmed': judges.get(report['name'])})
    save(output() / 'results.json', result)
    manifest = {p.relative_to(output()).as_posix(): {'bytes': p.stat().st_size, 'sha256': sha(p)}
                for p in sorted(output().rglob('*')) if p.is_file() and p.name != 'SHA256SUMS.json'}
    save(output() / 'SHA256SUMS.json', manifest)
    return 0 if result['collection_complete'] else 1


def summarize():
    # Partial/malformed metadata must still yield an honest result and manifest.
    # Raw logs and any linked evidence remain available for independent review.
    try:
        return summarize_inner()
    except Exception as error:
        save(output() / 'results.json', {'schema': 'paired-five-round-results-v1',
                                        'config': CONFIG, 'collection_complete': False,
                                        'causal_or_security_closure': False,
                                        'binding_errors': [{'error': repr(error)}]})
        manifest = {}
        for path in sorted(output().rglob('*')):
            if path.is_file() and path.name != 'SHA256SUMS.json':
                try:
                    manifest[path.relative_to(output()).as_posix()] = {'bytes': path.stat().st_size,
                                                                      'sha256': sha(path)}
                except OSError as file_error:
                    manifest[path.relative_to(output()).as_posix()] = {'error': repr(file_error)}
        save(output() / 'SHA256SUMS.json', manifest)
        return 1


def interrupt(signum, frame):
    global CANCELLED
    CANCELLED = True
    raise KeyboardInterrupt


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    action = sys.argv[1]
    if action == 'verify':
        verify()
    elif action == 'bind-binary':
        bind_binary(sys.argv[2])
    elif action == 'run':
        raise SystemExit(run_all())
    elif action in ['aux-correctness', 'aux-profile']:
        raise SystemExit(auxiliary(action.removeprefix('aux-')))
    elif action == 'summarize':
        raise SystemExit(summarize())
    else:
        raise SystemExit('Unknown fixed action')
