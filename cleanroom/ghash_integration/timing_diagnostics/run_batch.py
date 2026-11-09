#!/usr/bin/env python3
"""Three predeclared default hosts; controls only after same-core sealed failure."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

import analyze
import replay

HERE = Path(__file__).resolve().parent
TEMP = Path(os.environ.get('RUNNER_TEMP', '/private/tmp'))
OUT, INPUT, COMPANION = TEMP / 'batch-output', TEMP / 'batch-sealed', TEMP / 'batch-companion'
REPLICA = int(os.environ.get('PRATIQUE_BATCH_REPLICA', '1'))
assert REPLICA in [1, 2, 3]
replay.COMPANION = COMPANION
NAMES = {'DATA': 'ghash [Portable] batch 1024 data: 0 vs random',
         'KEY': 'ghash [Portable] batch 1024 prepared H: 0 vs random'}


def confirmed_rows(text):
    # Only the unchanged final judge's confirmed-failure summary is a trigger.
    # A first-pass LEAK/max-t line or a 2049/H128 failure is never sufficient.
    marker = 'timing depends on the input:\n'
    summary = text.rsplit(marker, 1)[1] if marker in text else ''
    lines = re.findall(r'^  (ghash[^\n]+)$', summary, re.M)
    return {'confirmed_1024_rows': {kind: any(line.startswith(name + ': ') for line in lines)
                                   for kind, name in NAMES.items()},
            'all_confirmed_failure_lines': lines}


def prepare():
    OUT.mkdir(parents=True, exist_ok=True)
    replay.extract_selected(TEMP / 'phase1.zip', INPUT,
        ['lifecycle_e2dd/unmodified-normal-test-binary', 'lifecycle_e2dd/unmodified-build-record.json'], replay.ARCHIVE_SHA)
    digest = os.environ['PRATIQUE_BATCH_COMPANION_DIGEST'].removeprefix('sha256:')
    replay.extract_selected(TEMP / 'batch-companion.zip', COMPANION,
        ['batch-companion-manifest.json', 'batch-controls-test-binary', 'memory-env-probe', 'native/fixture-storage-unit.log'], digest)
    manifest = json.loads((COMPANION / 'batch-companion-manifest.json').read_text())
    assert manifest['production_source_commit'] == 'e2dd9a91b3d2af6495faa6319fb5384c374dd82f'
    assert manifest['diagnostic_commit'] == os.environ['GITHUB_SHA']
    for filename, expected in manifest['source_files'].items(): assert replay.sha(HERE / filename) == expected, filename
    binary = INPUT / 'lifecycle_e2dd/unmodified-normal-test-binary'
    expected = json.loads((INPUT / 'lifecycle_e2dd/unmodified-build-record.json').read_text())['normal_sha256']
    assert replay.sha(binary) == expected; binary.chmod(0o755)
    for filename, expected in manifest['files'].items():
        assert replay.sha(COMPANION / filename) == expected; (COMPANION / filename).chmod(0o755)
    for key in ['PRATIQUE_TIMING_REPS', 'PRATIQUE_TIMING_TICK_NS', 'PRATIQUE_TIMING_TICKS']:
        assert key not in os.environ, f'unexpected clock override: {key}'
    assert not os.environ.get('GLIBC_TUNABLES'), 'default dispatch only'
    affinity = sorted(os.sched_getaffinity(0)); assert affinity
    cpu = affinity[0]
    topology = {}
    for logical in affinity:
        root = Path(f'/sys/devices/system/cpu/cpu{logical}/topology')
        topology[str(logical)] = {name: replay.optional(root / name) for name in ['core_id', 'physical_package_id']}
    settings = {'scope': 'Exactly three predeclared default VMs, one pinned core, one sealed preflight and one sealed post-window. No replacements, masks, retries, or threshold changes.',
        'replica': REPLICA, 'affinity': affinity, 'selected_cpu': cpu, 'reported_topology': topology,
        'hypervisor_can_hide_physical_topology': True, 'seeds': [0, 1], 'seconds_per_row_seed': 3,
        'sealed_e2dd_binary_sha256': replay.sha(binary), 'sealed_archive_sha256': replay.ARCHIVE_SHA,
        'companion_archive_sha256': digest, 'companion': manifest,
        'lscpu': replay.command(['lscpu']), 'uname': replay.command(['uname', '-a']),
        'glibc': replay.command(['ldd', '--version']), 'proc_cpuinfo': replay.optional(Path('/proc/cpuinfo')),
        'ASLR': replay.optional(Path('/proc/sys/kernel/randomize_va_space')),
        'runner': {k: os.environ.get(k) for k in ['ImageOS', 'ImageVersion', 'RUNNER_ARCH', 'GITHUB_RUN_ID', 'GITHUB_SHA']},
        'frequency': replay.frequency(), 'environment_shape': replay.env_shape(os.environ),
        'same_core_default_probe': replay.probe(os.environ.copy(), cpu),
        'limits': 'A quiet companion literal is an observer/layout limitation, never an exclusion. Prior stores/cache/register history are not fenced. All previous security failures remain.'}
    lib = Path(settings['same_core_default_probe']['memory']['memcpy']['library']).resolve()
    settings['libc_file'] = {'path': str(lib), 'sha256': replay.sha(lib), 'ELF_notes': replay.command(['readelf', '-n', str(lib)])}
    replay.save(OUT / 'settings.json', settings)
    replay.save(OUT / 'fixture-storage-proof.json', {'log': (COMPANION / 'native/fixture-storage-unit.log').read_text()})
    print(json.dumps({'prepared': True, 'selected_cpu': cpu, 'active512': settings['same_core_default_probe']['active_AVX512F']}), flush=True)


def settings(): return json.loads((OUT / 'settings.json').read_text())


def run_case(folder, kind):
    folder.mkdir(parents=True, exist_ok=True)
    cpu = settings()['selected_cpu']; env = os.environ.copy(); env['PRATIQUE_TIMING_SECS'] = '3'
    if kind == 'normal':
        binary = INPUT / 'lifecycle_e2dd/unmodified-normal-test-binary'
        test = 'crypto::timing::ghash_multiplication_is_constant_time'
    else:
        binary = COMPANION / 'batch-controls-test-binary'
        test = 'crypto::timing::pr10_batch_' + ('data' if kind == 'DATA' else 'key') + '_controls'
        env['PRATIQUE_DIAGNOSTIC_DIR'] = str(folder); env['PRATIQUE_BATCH_SECS'] = '3'
    command = ['taskset', '-c', str(cpu), str(binary), '--exact', test, '--ignored', '--nocapture', '--test-threads=1']
    case = {'kind': kind, 'cpu': cpu, 'argv': command, 'binary_sha256': replay.sha(binary),
            'default_probe': replay.probe(env, cpu), 'environment_shape': replay.env_shape(env),
            'frequency_before': replay.frequency(), 'execution_state': 'starting'}
    replay.save(folder / 'case.json', case)
    print(json.dumps({'begin': str(folder.relative_to(OUT)), 'cpu': cpu, 'kind': kind}), flush=True)
    started = time.monotonic()
    with (folder / 'run.log').open('w') as log:
        process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        time.sleep(.05)
        case['early_process_maps'] = replay.optional(Path(f'/proc/{process.pid}/maps'))
        case['execution_state'] = 'running'; replay.save(folder / 'case.json', case)
        try: case['exit_code'] = process.wait(timeout=170)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(); case['exit_code'] = 'timeout'
    case['elapsed_seconds'] = time.monotonic() - started
    case['execution_state'] = 'finished'; case['frequency_after'] = replay.frequency()
    if kind == 'normal':
        case.update(confirmed_rows((folder / 'run.log').read_text()))
        case['authoritative_normal_gate'] = True
    else:
        path = folder / 'batch-control-results.txt'
        fields = dict(line.split('=', 1) for line in path.read_text().splitlines()) if path.exists() else {}
        case['control_status'] = fields
        case['positive_controls_all_healthy'] = bool(fields) and all(fields.get(k) == 'true'
            for k in ['sensitivity', 'early_exit', 'positive_matched_healthy'])
        case['negative_identical_equal_passed'] = fields.get('negative_identical_equal_confirmed_failure') == 'false'
        case['literal_co_reproduced'] = fields.get('literal_confirmed_failure') == 'true'
        case['collection_success_is_not_timing_readiness'] = True
    replay.save(folder / 'case.json', case)
    print(json.dumps({'end': str(folder.relative_to(OUT)), 'exit_code': case['exit_code'],
                      'literal_co_reproduced': case.get('literal_co_reproduced'),
                      'positive_controls_all_healthy': case.get('positive_controls_all_healthy')}), flush=True)
    return case


def preflight():
    case = run_case(OUT / 'sealed-preflight', 'normal')
    triggers = {kind: case['exit_code'] == 101 and failed
                for kind, failed in case['confirmed_1024_rows'].items()}
    replay.save(OUT / 'triggers.json', {'corresponding_preflight_failures': triggers,
        'rule': 'Only a confirmed corresponding sealed 1024 row failure on this same live pinned core triggers its triplet. H128/2049-only failures remain outside scope.',
        'all_confirmed_failure_lines': case['all_confirmed_failure_lines']})


def controls(kind):
    triggers = json.loads((OUT / 'triggers.json').read_text())['corresponding_preflight_failures']
    if triggers[kind]: run_case(OUT / (kind + '-controls'), kind)
    else:
        replay.save(OUT / (kind + '-skipped.json'), {'kind': kind, 'reason': 'Corresponding sealed1024 preflight did not confirm failure; inconclusive nonreproducer retained, no replacement.'})
        print(json.dumps({'skipped': kind, 'reason': 'no corresponding confirmed same-core sealed preflight failure'}), flush=True)


def postflight():
    # Exactly one post-window gate. It cannot retrospectively trigger controls.
    run_case(OUT / 'sealed-post-window', 'normal')


def report():
    rows, errors, cases = {}, {}, {}
    for path in sorted(OUT.rglob('*.csv')):
        try: rows[str(path.relative_to(OUT))] = analyze.analyze(path)
        except Exception as error: errors[str(path.relative_to(OUT))] = repr(error)
    replay.save(OUT / 'sample-analysis.json', rows)
    for path in sorted(OUT.rglob('case.json')):
        try: cases[str(path.parent.relative_to(OUT))] = json.loads(path.read_text())
        except Exception as error: errors[str(path.relative_to(OUT))] = repr(error)
    trigger_path = OUT / 'triggers.json'
    triggers = json.loads(trigger_path.read_text())['corresponding_preflight_failures'] if trigger_path.exists() else {}
    expected_groups = sum(triggers.values()); expected_cases = 2 + expected_groups
    complete = len(triggers) == 2 and len(cases) == expected_cases and len(rows) == 10 * expected_groups and not errors and all(
        c.get('execution_state') == 'finished' and (c['kind'] == 'normal' and c.get('exit_code') in [0, 101] or c['kind'] != 'normal' and c.get('exit_code') == 0)
        for c in cases.values())
    interpretation = {}
    post_case = cases.get('sealed-post-window', {})
    post = post_case.get('confirmed_1024_rows', {})
    authoritative_post_complete = (post_case.get('execution_state') == 'finished'
        and post_case.get('exit_code') == 101 and post_case.get('authoritative_normal_gate') is True)
    for kind in NAMES:
        case = cases.get(kind + '-controls', {})
        expected_paths = {f'{kind}-controls/{name}-seed{seed}.csv'
            for name in ['literal', 'identical_history', 'equal_variable', 'negative_identical_equal', 'positive_matched']
            for seed in [0, 1]}
        analyzed_paths = {path for path in rows if path.startswith(kind + '-controls/')}
        group_collection_complete = (case.get('execution_state') == 'finished' and case.get('exit_code') == 0
            and analyzed_paths == expected_paths and not any(path.startswith(kind + '-controls/') for path in errors))
        interpretation[kind] = {'preflight_triggered': triggers.get(kind), 'post_window_confirmed_same_row': post.get(kind),
            'group_collection_complete': group_collection_complete,
            'authoritative_postflight_complete': authoritative_post_complete,
            'literal_co_reproduced': case.get('literal_co_reproduced'),
            'matched_positive_healthy': case.get('positive_controls_all_healthy'),
            'identical_negative_passed': case.get('negative_identical_equal_passed'),
            'observer_layout_limitation': bool(triggers.get(kind) and not case.get('literal_co_reproduced')),
            'counterfactual_comparison_prerequisites_met': bool(triggers.get(kind) and authoritative_post_complete
                and post.get(kind) and group_collection_complete and case.get('literal_co_reproduced')
                and case.get('positive_controls_all_healthy') and case.get('negative_identical_equal_passed'))}
    replay.save(OUT / 'outcomes.json', {'replica': REPLICA, 'cases': cases, 'raw_rows': len(rows), 'analysis_errors': errors,
        'collection_complete': complete, 'expected_cases': expected_cases, 'expected_raw_rows': 10 * expected_groups,
        'interpretation_prerequisites': interpretation,
        'normal_gate_failures': [name for name, c in cases.items() if c['kind'] == 'normal' and c.get('exit_code') != 0],
        'warning': 'Collection success and comparison prerequisites are not timing readiness or causal closure. Every host/prior failure is retained. Quiet literal or nonreproducing live regime is inconclusive; no replacement or threshold waiver.'})
    print(json.dumps({'cases': len(cases), 'raw_rows': len(rows), 'collection_complete': complete, 'interpretation_prerequisites': interpretation}), flush=True)
    if not complete: raise SystemExit('Incomplete collection; all partial data preserved for upload.')


def check_parser():
    for kind, name in NAMES.items():
        assert not confirmed_rows(name + ' max 99 LEAK')['confirmed_1024_rows'][kind]
        text = 'timing depends on the input:\n  ' + name + ': t = +6.0 and +7.0 on repeat\n'
        result = confirmed_rows(text)['confirmed_1024_rows']
        assert result[kind] and sum(result.values()) == 1
    assert not any(confirmed_rows('timing depends on the input:\n  ghash [Portable] batch 2049 data: 0 vs random: fail\n')['confirmed_1024_rows'].values())
    print('confirmed1024-only trigger parser: pass')


if __name__ == '__main__':
    action = sys.argv[1]
    if action in ['DATA', 'KEY']: controls(action)
    else: {'prepare': prepare, 'preflight': preflight, 'postflight': postflight, 'report': report, 'check-parser': check_parser}[action]()
