#!/usr/bin/env python3
"""Predeclared bounded default H-stage replicas; preserve every outcome."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import analyze
import replay

HERE = Path(__file__).resolve().parent
TEMP = Path(os.environ.get('RUNNER_TEMP', '/private/tmp'))
OUT = TEMP / 'h-output'
INPUT = TEMP / 'h-sealed-input'
COMPANION = TEMP / 'h-companion'
ORDER = ['original326', 'lifecycle_e2dd', 'restored_d359']
REPLICA = int(os.environ.get('PRATIQUE_H_REPLICA', '1'))
assert REPLICA in [1, 2, 3]
replay.COMPANION = COMPANION


def prepare():
    OUT.mkdir(parents=True, exist_ok=True)
    names = [f'{variant}/{name}' for variant in ORDER
             for name in ['unmodified-normal-test-binary', 'unmodified-build-record.json']]
    replay.extract_selected(TEMP / 'phase1.zip', INPUT, names, replay.ARCHIVE_SHA)
    digest = os.environ['PRATIQUE_H_COMPANION_DIGEST'].removeprefix('sha256:')
    replay.extract_selected(TEMP / 'h-companion.zip', COMPANION,
        ['h-companion-manifest.json', 'h-controls-test-binary', 'memory-env-probe', 'native/fixture-cleanup-unit.log'], digest)
    manifest = json.loads((COMPANION / 'h-companion-manifest.json').read_text())
    assert manifest['production_source_commit'] == 'e2dd9a91b3d2af6495faa6319fb5384c374dd82f'
    assert manifest['diagnostic_commit'] == os.environ['GITHUB_SHA']
    for filename, expected in manifest['source_files'].items():
        assert replay.sha(HERE / filename) == expected, filename
    sealed = {}
    for variant in ORDER:
        binary = INPUT / variant / 'unmodified-normal-test-binary'
        expected = json.loads((INPUT / variant / 'unmodified-build-record.json').read_text())['normal_sha256']
        assert replay.sha(binary) == expected
        binary.chmod(0o755)
        sealed[variant] = expected
    for filename, expected in manifest['files'].items():
        assert replay.sha(COMPANION / filename) == expected
        (COMPANION / filename).chmod(0o755)
    for key in ['PRATIQUE_TIMING_REPS', 'PRATIQUE_TIMING_TICK_NS', 'PRATIQUE_TIMING_TICKS']:
        assert key not in os.environ, f'unexpected timing override: {key}'
    assert not os.environ.get('GLIBC_TUNABLES'), 'no diagnostic dispatch mode in this bounded run'
    affinity = sorted(os.sched_getaffinity(0))
    assert affinity
    cpu = affinity[0]
    topology = {}
    for logical in affinity:
        root = Path(f'/sys/devices/system/cpu/cpu{logical}/topology')
        topology[str(logical)] = {name: replay.optional(root / name) for name in ['core_id', 'physical_package_id']}
    settings = {'scope': 'Exactly three predeclared fresh VMs with identical default protocol, one pinned CPU each; no mask/feature matrix or failure-selected rerun.',
        'replica': REPLICA, 'all_hosts_and_regimes_retained': True,
        'affinity': affinity, 'selected_cpu': cpu, 'reported_topology': topology,
        'hypervisor_can_hide_physical_topology': True, 'startup_order': ORDER, 'pinned_order': list(reversed(ORDER)),
        'seeds': [0, 1], 'seconds_per_H_row_seed': 3, 'sealed_ELFs': sealed, 'companion': manifest,
        'sealed_archive_sha256': replay.ARCHIVE_SHA, 'companion_archive_sha256': digest,
        'lscpu': replay.command(['lscpu']), 'uname': replay.command(['uname', '-a']),
        'glibc': replay.command(['ldd', '--version']), 'proc_cpuinfo': replay.optional(Path('/proc/cpuinfo')),
        'ASLR': replay.optional(Path('/proc/sys/kernel/randomize_va_space')),
        'runner': {key: os.environ.get(key) for key in ['ImageOS', 'ImageVersion', 'RUNNER_ARCH', 'GITHUB_RUN_ID', 'GITHUB_SHA']},
        'frequency': replay.frequency(), 'environment_shape': replay.env_shape(os.environ),
        'same_core_default_probe': replay.probe(os.environ.copy(), cpu),
        'limits': 'Stage boundaries do not fence prior stores or establish pure instruction latency. Row medians cannot be subtracted as a causal decomposition.'}
    lib = Path(settings['same_core_default_probe']['memory']['memcpy']['library']).resolve()
    settings['libc_file'] = {'path': str(lib), 'sha256': replay.sha(lib), 'notes': replay.command(['readelf', '-n', str(lib)])}
    settings['sealed_dependencies'] = replay.command(['ldd', str(INPUT / 'lifecycle_e2dd/unmodified-normal-test-binary')])
    settings['companion_dependencies'] = replay.command(['ldd', str(COMPANION / 'h-controls-test-binary')])
    replay.save(OUT / 'settings.json', settings)
    replay.save(OUT / 'fixture-cleanup-proof.json', {'log': (COMPANION / 'native/fixture-cleanup-unit.log').read_text()})
    print(json.dumps({'prepared': True, 'selected_cpu': cpu, 'active_AVX512F': settings['same_core_default_probe']['active_AVX512F'], 'sealed_normal_ELFs': len(sealed)}), flush=True)


def run_case(folder, variant=None, cpu=None):
    folder.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env['PRATIQUE_TIMING_SECS'] = '3'
    if variant:
        binary = INPUT / variant / 'unmodified-normal-test-binary'
        test = 'crypto::timing::ghash_multiplication_is_constant_time'
        timeout = 180
    else:
        binary = COMPANION / 'h-controls-test-binary'
        test = 'crypto::timing::pr10_h_preparation_controls'
        env['PRATIQUE_DIAGNOSTIC_DIR'] = str(folder)
        env['PRATIQUE_H_DIAGNOSTIC_SECS'] = '3'
        timeout = 240
    command = [str(binary), '--exact', test, '--ignored', '--nocapture', '--test-threads=1']
    if cpu is not None:
        command = ['taskset', '-c', str(cpu)] + command
    case = {'kind': 'sealed_normal_gate' if variant else 'H_companion_collection', 'variant': variant,
            'cpu': cpu, 'argv': command, 'binary_sha256': replay.sha(binary),
            'default_probe': replay.probe(env, cpu), 'environment_shape': replay.env_shape(env),
            'frequency_before': replay.frequency(), 'execution_state': 'starting'}
    replay.save(folder / 'case.json', case)
    print(json.dumps({'begin': str(folder.relative_to(OUT)), 'kind': case['kind'], 'cpu': cpu}), flush=True)
    started = time.monotonic()
    with (folder / 'run.log').open('w') as log:
        process = subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT)
        time.sleep(.05)
        case['early_process_maps'] = replay.optional(Path(f'/proc/{process.pid}/maps'))
        case['execution_state'] = 'running'
        replay.save(folder / 'case.json', case)
        try:
            case['exit_code'] = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            case['exit_code'] = 'timeout'
    case['elapsed_seconds'] = time.monotonic() - started
    case['execution_state'] = 'finished'
    case['frequency_after'] = replay.frequency()
    if not variant:
        status = folder / 'h-control-results.txt'
        fields = dict(line.split('=', 1) for line in status.read_text().splitlines()) if status.exists() else {}
        case['H_controls'] = fields
        required = ['sensitivity', 'early_exit', 'matched_cost_positive_healthy']
        case['positive_controls_all_healthy'] = bool(fields) and all(fields.get(name) == 'true' for name in required)
        case['identical_operation_negative_passed'] = fields.get('identical_operation_negative_passed') == 'true'
        case['collection_success_is_not_timing_success'] = True
    replay.save(folder / 'case.json', case)
    print(json.dumps({'end': str(folder.relative_to(OUT)), 'exit_code': case['exit_code'],
                      'positive_controls_all_healthy': case.get('positive_controls_all_healthy')}), flush=True)


def startup():
    for variant in ORDER:
        run_case(OUT / 'startup' / variant, variant)


def pinned():
    cpu = json.loads((OUT / 'settings.json').read_text())['selected_cpu']
    for variant in reversed(ORDER):
        run_case(OUT / 'pinned' / variant, variant, cpu)


def controls():
    cpu = json.loads((OUT / 'settings.json').read_text())['selected_cpu']
    run_case(OUT / 'H-controls', cpu=cpu)


def report():
    # This same repository-owned analyzer was frozen before the run. No code
    # downloaded in either archive is imported or used as an analysis script.
    rows, errors = {}, {}
    for path in sorted(OUT.rglob('*.csv')):
        try:
            rows[str(path.relative_to(OUT))] = analyze.analyze(path)
        except Exception as error:
            errors[str(path.relative_to(OUT))] = repr(error)
    replay.save(OUT / 'sample-analysis.json', rows)
    cases = {}
    for path in sorted(OUT.rglob('case.json')):
        try:
            cases[str(path.parent.relative_to(OUT))] = json.loads(path.read_text())
        except Exception as error:
            errors[str(path.relative_to(OUT))] = repr(error)
    complete = len(cases) == 7 and len(rows) == 18 and not errors and all(
        case.get('execution_state') == 'finished' and (case['kind'] == 'sealed_normal_gate' or case.get('exit_code') == 0)
        for case in cases.values())
    replay.save(OUT / 'outcomes.json', {'replica': REPLICA, 'cases': cases, 'raw_H_rows': len(rows), 'analysis_errors': errors,
        'collection_complete': complete, 'expected_cases': 7, 'expected_raw_H_rows': 18,
        'normal_gate_failures': [name for name, case in cases.items() if case['kind'] == 'sealed_normal_gate' and case.get('exit_code') != 0],
        'warning': 'Collection success is not timing readiness. Every host/outcome and prior failure remains evidence. All legacy hosts leave target regime unfulfilled/HOLD. Stage results cannot waive production gates or establish instruction-latency causality.'})
    print(json.dumps({'saved_cases': len(cases), 'raw_H_rows': len(rows),
                     'normal_gate_outcomes': {name: case.get('exit_code') for name, case in cases.items() if case['kind'] == 'sealed_normal_gate'}}), flush=True)
    if not complete:
        raise SystemExit('Collection incomplete; partial outcomes and analysis errors retained for unconditional upload.')


if __name__ == '__main__':
    {'prepare': prepare, 'startup': startup, 'pinned': pinned, 'controls': controls, 'report': report}[sys.argv[1]]()
