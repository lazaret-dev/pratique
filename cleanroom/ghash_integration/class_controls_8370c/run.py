#!/usr/bin/env python3
"""Fixed six-call exploratory GHASH job; no production or statistical changes."""
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = '4848bea7c7e39b34ed1c74435823197dfd945cc4'
PATCH_SHA = '96159ef4faec2bc3889d69b23fc41817f376394b16f5bf928501d07ee9f105b2'
TIMING_SHA = '27eb52a9346b994a9c4fdfb59c7a74eef3eea16f57203fb145514a5e79956ffd'
FLAGS = '--cfg pratique_portable -C target-feature=-aes,-pclmulqdq'
GATE = 'crypto::timing::ghash_multiplication_is_constant_time'
CONTROL = 'crypto::timing::ghash_batch_class_controls'
SECONDS = 55
LABELS = ['uncropped', 'p99.9', 'p99.0', 'p95.0', 'p90.0', 'p75.0', 'p50.0']
KEEPS = [1.0, 0.95, 0.75, 0.5]
NAMES = [
    'ghash [Portable] data blocks: 0 vs random (fixed H)',
    'ghash [Portable] data blocks: all ones vs random (fixed H)',
    'ghash [Portable] hash key H: 0 vs random',
    'ghash [Portable] hash key H: all ones vs random',
    'ghash [Portable] batch 1024 data: 0 vs random',
    'ghash [Portable] batch 1024 prepared H: 0 vs random',
    'ghash [Portable] batch 2049 data: 0 vs random',
    'ghash [Portable] batch 2049 prepared H: 0 vs random',
]
CONTROL_NAMES = [
    'repro: batch 1024 data: 0 vs random',
    'repro: batch 1024 prepared H: 0 vs random',
    'control: batch 1024 data: all ones vs random',
    'control: batch 1024 data: fixed pattern vs random',
    'control: batch 1024 prepared H: fixed nonzero vs random',
    'control: scalar 1024 data: 0 vs random',
    'control: scalar 1024 H: 0 vs random',
]
NUMBER = r'[+-]?(?:\d+(?:\.\d+)?|inf|NaN)'


def stamp():
    return datetime.now(timezone.utc).isoformat()


def out():
    return Path(os.environ['PRATIQUE_CLASS_OUTPUT'])


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def read(path):
    return json.loads(path.read_text())


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args])


def token(value):
    n = float(value)
    return {'display': value, 'value': n if math.isfinite(n) else None,
            'nonfinite': not math.isfinite(n)}


def footer(text):
    fs = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text, re.M)
    if len(fs) != 1:
        return None
    status, p, f, ignored = fs[0]
    if int(p) + int(f) != 1 or ignored != '0' or (status == 'ok') != (f == '0'):
        return None
    return {'status': status, 'passed': int(p), 'failed': int(f)}


def header(line, names):
    for name in names:
        m = re.search(re.escape(name) + r'\s+n=\s*(\d+)(?:\s+x(\d+))?\s+median\s+(\d+) ns\s+\|t\| uncropped\s+(' + NUMBER + r')\s+max\s+(' + NUMBER + ')', line)
        if m:
            return {'name': name, 'samples': int(m[1]), 'reps': int(m[2] or 1),
                    'median_ns': int(m[3]), 'printed_abs_uncropped_t': token(m[4]),
                    'printed_max_abs_t': token(m[5]), 'display': line}
    return None


def parse_original(text, exit_code):
    """Authoritative final summary, never a post-hoc test of rounded t values."""
    rows = {n: [] for n in NAMES}
    for line in text.splitlines():
        r = header(line, NAMES)
        if r:
            rows[r['name']].append(r)
    marker = 'timing depends on the input:\n'
    summary = text.rsplit(marker, 1)[1] if marker in text else ''
    lines = re.findall(r'^  (ghash[^\n]+)$', summary, re.M)
    confirmed, unknown = [], []
    for line in lines:
        matches = [n for n in NAMES if line.startswith(n + ': ')]
        if len(matches) == 1:
            confirmed.append(matches[0])
        else:
            unknown.append(line)
    repeats = [n for n, rs in rows.items() if len(rs) == 2]
    announced = [n for n in NAMES if re.search(r'above 4\.5; measuring ' + re.escape(json.dumps(n)) + r' again with fresh inputs', text)]
    f = footer(text)
    complete = (all(1 <= len(rs) <= 2 for rs in rows.values())
        and set(repeats) == set(announced) and not unknown
        and len(confirmed) == len(set(confirmed)) and set(confirmed) <= set(repeats)
        and ((exit_code == 0 and f == {'status': 'ok', 'passed': 1, 'failed': 0}
              and not confirmed and marker not in text)
             or (exit_code == 101 and f == {'status': 'FAILED', 'passed': 0, 'failed': 1}
                 and bool(confirmed) and text.count(marker) == 1)))
    return {'complete': complete, 'child_exit': exit_code, 'footer': f, 'rows': rows,
            'fresh_rechecks': repeats, 'fresh_rechecks_announced': announced,
            'confirmed_rows': confirmed, 'final_summary_lines': lines, 'unknown_summary_lines': unknown,
            'authority': 'Unchanged final Rust summary; rounded output cannot reconstruct the exact judge.'}


def parse_controls(text, exit_code):
    reports, judges, errors = [], [], []
    current = None
    for line in text.splitlines():
        r = header(line, CONTROL_NAMES)
        if r:
            reports.append(r)
            current = r
        elif line.strip().startswith('signed t:'):
            pairs = re.findall(r'(uncropped|p\d+\.\d+):(' + NUMBER + ')', line)
            if current is None or 'signed_t' in current or [p[0] for p in pairs] != LABELS:
                errors.append('invalid or duplicate signed-t line')
            else:
                current['signed_t'] = [{'label': label, **token(value)} for label, value in pairs]
        elif line.strip().startswith('per call:'):
            pairs = re.findall(r'keep (1|0\.95|0\.75|0\.5): (' + NUMBER + r') \+- (' + NUMBER + ') ns', line)
            if current is None or 'per_call' in current or [float(p[0]) for p in pairs] != KEEPS:
                errors.append('invalid or duplicate per-call line')
            else:
                current['per_call'] = [{'keep': float(p), 'difference_ns': token(d), 'standard_error_ns': token(se)} for p, d, se in pairs]
        elif line.strip().startswith('unchanged judge:'):
            value = line.strip().removeprefix('unchanged judge: ')
            if value == 'not confirmed':
                confirmed = False
            elif (current is not None and value.startswith('CONFIRMED (' + current['name'] + ': ')
                  and value.endswith(')')):
                confirmed = True
            else:
                errors.append('invalid judge line')
                continue
            judges.append({'name': current['name'] if current else None,
                           'confirmed': confirmed, 'display': value, 'after_report': len(reports)})
    expected = [n for n in CONTROL_NAMES for _ in range(2)]
    counts = {n: 0 for n in CONTROL_NAMES}
    for r in reports:
        r['seed'] = counts[r['name']] if counts[r['name']] < 2 else None
        counts[r['name']] += 1
        r['seed_basis'] = 'Fixed raw-patch call order, not an additional runtime observation.'
    complete = (exit_code == 0 and footer(text) == {'status': 'ok', 'passed': 1, 'failed': 0}
        and [r['name'] for r in reports] == expected
        and all('signed_t' in r and 'per_call' in r for r in reports)
        and [j['name'] for j in judges] == CONTROL_NAMES
        and [j['after_report'] for j in judges] == list(range(2, 15, 2)) and not errors)
    return {'complete': complete, 'child_exit': exit_code, 'footer': footer(text),
            'reports': reports, 'judges': judges, 'errors': errors,
            'signed_difference_direction': 'class 1 minus class 0; random minus the specified fixed class',
            'precision': 'Seven t views at one decimal; four mean/SE views at three decimals. No raw samples.',
            'health_controls': 'Not measured by the exact attached patch; no positive/negative health set is added.',
            'authority': 'Each unchanged judge line is authoritative; test exit0 does not mean unconfirmed.'}


def verify():
    """Bind exact reviewed source A separately from the default-branch workflow head."""
    assert os.environ['RUSTUP_TOOLCHAIN'] == '1.87.0'
    assert os.environ['RUSTFLAGS'] == FLAGS
    assert os.environ['PRATIQUE_TIMING_SECS'] == '3'
    assert all(n not in os.environ for n in ['PRATIQUE_TIMING_REPS', 'PRATIQUE_TIMING_TICK_NS', 'PRATIQUE_TIMING_TICKS', 'CARGO_ENCODED_RUSTFLAGS'])
    expected = os.environ['PRATIQUE_EXPECTED_SOURCE_COMMIT']
    assert re.fullmatch('[0-9a-f]{40}', expected)
    assert git('rev-parse', 'HEAD').decode().strip() == expected
    assert not git('status', '--porcelain', '--untracked-files=no').strip()
    assert sha(HERE / 'raw-user.patch') == PATCH_SHA
    assert sha(ROOT / 'src/crypto/timing.rs') == TIMING_SHA
    changed = git('diff', '--name-only', BASE, 'HEAD').decode().splitlines()
    assert 'src/crypto/timing.rs' in changed
    prefix = str(HERE.relative_to(ROOT)) + '/'
    assert all(p == 'src/crypto/timing.rs' or p.startswith(prefix) for p in changed), changed
    # Every pre-existing path other than the additive timing test is byte/mode-identical.
    def tree(ref):
        return {entry.split(b'\t', 1)[1].decode(): entry.split(b'\t', 1)[0]
                for entry in git('ls-tree', '-r', '-z', ref).split(b'\0') if entry}
    current = tree('HEAD')
    for name, meta in tree(BASE).items():
        if name != 'src/crypto/timing.rs':
            assert current.get(name) == meta, name
    inventory = {}
    for path in git('ls-files', 'src', 'Cargo.toml', 'Cargo.lock', str(HERE.relative_to(ROOT))).decode().splitlines():
        inventory[path] = sha(ROOT / path)
    record = {'schema': 'raw-class-controls-source-v1', 'checked_at': stamp(),
              'base_production_commit': BASE, 'diagnostic_source_commit': expected,
              'workflow_head': os.environ.get('GITHUB_SHA'),
              'workflow_ref': os.environ.get('GITHUB_WORKFLOW_REF'),
              'workflow_sha': os.environ.get('GITHUB_WORKFLOW_SHA'),
              'run_id': os.environ.get('GITHUB_RUN_ID'), 'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
              'patch_sha256': PATCH_SHA, 'patched_timing_sha256': TIMING_SHA,
              'changed_paths_from_base': changed, 'file_sha256': inventory,
              'toolchain': '1.87.0', 'RUSTFLAGS': FLAGS, 'PRATIQUE_TIMING_SECS': '3'}
    save(out() / 'source-binding.json', record)


def bind_binary():
    verify()
    paths = []
    for line in (out() / 'build-events.jsonl').read_text().splitlines():
        v = json.loads(line)
        if (v.get('reason') == 'compiler-artifact' and v.get('target', {}).get('name') == 'pratique'
                and v.get('profile', {}).get('test') is True and v.get('executable')):
            paths.append(str(Path(v['executable']).resolve()))
    assert len(set(paths)) == 1, paths
    binary = Path(paths[0])
    assert binary.is_file() and binary.resolve().is_relative_to((ROOT / 'target').resolve())
    save(out() / 'binary.json', {'path': str(binary), 'sha256': sha(binary),
         'bytes': binary.stat().st_size, 'source_commit': os.environ['PRATIQUE_EXPECTED_SOURCE_COMMIT'],
         'build_argv': ['cargo', 'test', '--release', '--all-features', '--lib', '--no-run', '--message-format=json'],
         'bound_at': stamp()})


def planned():
    return [{'slot': 2 * (i - 1) + (1 if kind == 'gate' else 2), 'iteration': i, 'kind': kind,
             'selector': GATE if kind == 'gate' else CONTROL, 'execution': 'not_attempted'}
            for i in range(1, 4) for kind in ['gate', 'control']]


def execute_case(record, binary, directory, timeout=SECONDS):
    argv = [str(binary), record['selector'], '--exact', '--ignored', '--nocapture', '--test-threads=1']
    directory.mkdir(parents=True, exist_ok=True)
    record = {**record, 'argv': argv, 'timeout_seconds': timeout, 'started_at': stamp(), 'execution': 'started'}
    save(directory / 'case.json', record)
    start = time.monotonic()
    process = None
    try:
        with (directory / 'stdout-stderr.log').open('w') as log:
            process = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            record['process_group_id'] = process.pid
            try:
                record['exit_code'] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                record['exit_code'] = 'timeout'
    except BaseException as e:
        record['exit_code'] = 'collector_error'
        record['error'] = repr(e)
        if isinstance(e, (KeyboardInterrupt, SystemExit)):
            record['interrupted'] = True
    finally:
        if process:
            for sig in [signal.SIGTERM, signal.SIGKILL]:
                try:
                    os.killpg(process.pid, sig)
                except ProcessLookupError:
                    pass
                except OSError as e:
                    record['cleanup_incomplete'] = True
                    record['cleanup_error'] = repr(e)
                if sig == signal.SIGTERM:
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                record['cleanup_incomplete'] = True
        record.update(execution='finished', ended_at=stamp(), elapsed_seconds=time.monotonic() - start)
        if (directory / 'stdout-stderr.log').exists():
            record['stdout_stderr_sha256'] = sha(directory / 'stdout-stderr.log')
        save(directory / 'case.json', record)
    return record


def run_all(executor=execute_case):
    verify()
    host = read(out() / 'host/selection.json')
    assert host.get('matched_8370C') is True, 'No native work on another model.'
    info = read(out() / 'binary.json')
    binary = Path(info['path'])
    assert sha(binary) == info['sha256']
    slots = planned()
    save(out() / 'six-slots.json', slots)
    for i, record in enumerate(slots):
        record['binary_sha256_before_window'] = info['sha256']
        record['source_commit'] = info.get('source_commit')
        directory = out() / ('%02d-%s-%d' % (record['slot'], record['kind'], record['iteration']))
        slots[i] = executor(record, binary, directory)
        save(out() / 'six-slots.json', slots)
        print(json.dumps({'slot': record['slot'], 'kind': record['kind'], 'exit_code': slots[i].get('exit_code')}, allow_nan=False), flush=True)
        if slots[i].get('cleanup_incomplete') or slots[i].get('interrupted'):
            for later in slots[i + 1:]:
                later['reason'] = 'prior process cleanup unsafe or job interrupted'
            save(out() / 'six-slots.json', slots)
            break
    final = {'before_sha256': info['sha256'], 'after_sha256': sha(binary)}
    final['identity_unchanged'] = final['before_sha256'] == final['after_sha256']
    save(out() / 'binary-window-identity.json', final)


def summarize():
    results = []
    slots_path = out() / 'six-slots.json'
    slots = read(slots_path) if slots_path.exists() else planned()
    fields = ['slot', 'iteration', 'kind', 'selector']
    slot_schema_valid = (isinstance(slots, list) and all(isinstance(r, dict) for r in slots)
        and [[r.get(k) for k in fields] for r in slots] == [[r[k] for k in fields] for r in planned()])
    binary_identity = read(out() / 'binary-window-identity.json') if (out() / 'binary-window-identity.json').exists() else None
    for r in slots:
        directory = out() / ('%02d-%s-%d' % (r['slot'], r['kind'], r['iteration']))
        path = directory / 'stdout-stderr.log'
        text = path.read_text() if path.exists() else ''
        parsed = parse_original(text, r.get('exit_code')) if r['kind'] == 'gate' else parse_controls(text, r.get('exit_code'))
        parsed['complete'] = bool(parsed['complete'] and r.get('execution') == 'finished' and not r.get('cleanup_incomplete'))
        results.append({'case': r, 'parsed': parsed})
    result = {'schema': 'exact-raw-class-controls-six-v1', 'cases': results,
              'collection_complete': bool(slot_schema_valid and len(results) == 6 and all(r['parsed']['complete'] for r in results)
                                         and binary_identity and binary_identity.get('identity_unchanged') is True),
              'slot_schema_valid': slot_schema_valid,
              'binary_window_identity': binary_identity,
              'original_confirmed_rows_by_iteration': {str(r['case']['iteration']): r['parsed']['confirmed_rows'] for r in results if r['case']['kind'] == 'gate'},
              'control_confirmed_rows_by_iteration': {str(r['case']['iteration']): [j['name'] for j in r['parsed']['judges'] if j['confirmed']] for r in results if r['case']['kind'] == 'control'},
              'authority_limit': 'Same patched binary, different selectors/row names/probe contexts. No sealed pre-patch binary or sampler trace.',
              'control_health': None, 'causal_or_security_closure': False,
              'source_binding': read(out() / 'source-binding.json') if (out() / 'source-binding.json').exists() else None,
              'binary': read(out() / 'binary.json') if (out() / 'binary.json').exists() else None}
    save(out() / 'results.json', result)
    with (out() / 'control-per-call.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['iteration', 'row', 'seed', 'reps', 'keep', 'difference_ns_display', 'standard_error_ns_display', 'unchanged_judge_confirmed'])
        writer.writeheader()
        for item in results:
            if item['case']['kind'] != 'control':
                continue
            judges = {j['name']: j['confirmed'] for j in item['parsed']['judges']}
            for r in item['parsed']['reports']:
                for p in r.get('per_call', []):
                    writer.writerow({'iteration': item['case']['iteration'], 'row': r['name'], 'seed': r['seed'], 'reps': r['reps'],
                        'keep': p['keep'], 'difference_ns_display': p['difference_ns']['display'], 'standard_error_ns_display': p['standard_error_ns']['display'],
                        'unchanged_judge_confirmed': judges.get(r['name'])})
    with (out() / 'control-signed-t.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['iteration', 'row', 'seed', 'reps', 'statistic', 'signed_t_display'])
        writer.writeheader()
        for item in results:
            if item['case']['kind'] == 'control':
                for r in item['parsed']['reports']:
                    for t in r.get('signed_t', []):
                        writer.writerow({'iteration': item['case']['iteration'], 'row': r['name'], 'seed': r['seed'], 'reps': r['reps'], 'statistic': t['label'], 'signed_t_display': t['display']})
    files = {str(p.relative_to(out())): {'bytes': p.stat().st_size, 'sha256': sha(p)} for p in sorted(out().rglob('*')) if p.is_file() and p.name != 'SHA256SUMS.json'}
    save(out() / 'SHA256SUMS.json', files)
    return 0 if result['collection_complete'] else 1


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    action = sys.argv[1]
    if action == 'verify':
        verify()
    elif action == 'bind-binary':
        bind_binary()
    elif action == 'run':
        run_all()
    elif action == 'summarize':
        raise SystemExit(summarize())
    else:
        raise SystemExit('Unknown fixed action')
