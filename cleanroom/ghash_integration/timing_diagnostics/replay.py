#!/usr/bin/env python3
"""Predeclared fixed-ELF environment/placement experiment. No gate is waived."""
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import zipfile

HERE = Path(__file__).resolve().parent
TEMP = Path(os.environ.get('RUNNER_TEMP', '/private/tmp'))
OUT = TEMP / 'replay-output'
INPUT = TEMP / 'replay-input'
COMPANION = TEMP / 'history-companion'
REPLICA = int(os.environ.get('PRATIQUE_REPLICA', '1'))
ARCHIVE_SHA = '08f96335668f5f4ab67b2fad10f5c9b275bd1558d9d976f3e99f8dabece6ab40'
VARIANTS = ['original326', 'lifecycle_e2dd', 'restored_d359']
MASK = 'glibc.cpu.hwcaps=-AVX512F,-AVX512VL'
ORDER = {1: VARIANTS, 2: list(reversed(VARIANTS)), 3: ['lifecycle_e2dd', 'original326', 'restored_d359']}[REPLICA]


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''): h.update(block)
    return h.hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n')


def command(args, env=None):
    r = subprocess.run(args, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return {'exit_code': r.returncode, 'output': r.stdout}


def optional(path):
    try: return path.read_text().strip()
    except OSError as e: return {'unavailable': str(e)}


def frequency():
    result = {}
    for cpu in os.sched_getaffinity(0):
        root = Path(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq')
        result[str(cpu)] = {name: optional(root / name) for name in ['scaling_cur_freq', 'cpuinfo_cur_freq', 'cpuinfo_max_freq', 'scaling_governor']}
    return result


def probe(env, cpu=None):
    args = [str(COMPANION / 'memory-env-probe')]
    if cpu is not None: args = ['taskset', '-c', str(cpu)] + args
    r = command(args, env=env)
    assert r['exit_code'] == 0, r
    return json.loads(r['output'])


def env_shape(env):
    return {'ordered_names': list(env), 'total_string_bytes': sum(len(k.encode()) + len(v.encode()) + 2 for k, v in env.items()),
            'GLIBC_TUNABLES': env.get('GLIBC_TUNABLES'), 'mode_pad_bytes': len(env.get('PRATIQUE_MODE_PAD', ''))}


def extract_selected(archive, dest, names, expected):
    assert sha(archive) == expected, 'archive digest mismatch'
    with zipfile.ZipFile(archive) as z:
        for name in names:
            path = dest / name
            assert path.resolve().is_relative_to(dest.resolve())
            path.parent.mkdir(parents=True, exist_ok=True)
            with z.open(name) as src, path.open('wb') as dst:
                for block in iter(lambda: src.read(1 << 20), b''): dst.write(block)


def prepare():
    OUT.mkdir(parents=True, exist_ok=True)
    names = []
    for variant in VARIANTS:
        for stage in ['unmodified', 'diagnostic']:
            names += [f'{variant}/{stage}-normal-test-binary', f'{variant}/{stage}-build-record.json']
    extract_selected(TEMP / 'phase1.zip', INPUT, names, ARCHIVE_SHA)
    digest = os.environ['PRATIQUE_COMPANION_DIGEST'].removeprefix('sha256:')
    extract_selected(TEMP / 'history.zip', COMPANION, ['companion-manifest.json', 'memory-env-probe', 'history-test-binary', 'storage-proof-unit.log'], digest)
    manifest = json.loads((COMPANION / 'companion-manifest.json').read_text())
    sealed = {}
    for variant in VARIANTS:
        for stage in ['unmodified', 'diagnostic']:
            path = INPUT / variant / f'{stage}-normal-test-binary'
            expected = json.loads((INPUT / variant / f'{stage}-build-record.json').read_text())['normal_sha256']
            assert sha(path) == expected
            path.chmod(0o755)
            sealed[f'{variant}/{stage}'] = expected
    for name, expected in manifest['files'].items():
        assert sha(COMPANION / name) == expected
        (COMPANION / name).chmod(0o755)
    assert manifest['production_source_commit'] == 'e2dd9a91b3d2af6495faa6319fb5384c374dd82f'
    topology, representatives = {}, {}
    readable_topology = True
    affinity = sorted(os.sched_getaffinity(0))
    for cpu in affinity:
        root = Path(f'/sys/devices/system/cpu/cpu{cpu}/topology')
        core, socket = optional(root / 'core_id'), optional(root / 'physical_package_id')
        readable_topology &= isinstance(core, str) and isinstance(socket, str)
        topology[str(cpu)] = {'reported_core': core, 'reported_socket': socket}
        representatives.setdefault(str((socket, core)), cpu)
    cores = list(representatives.values())[:2]
    uncertain = not readable_topology or len(cores) < 2
    if uncertain: cores = affinity[:2]
    assert len(cores) == 2, 'two logical CPUs required; unsupported host retained as setup failure'
    settings = {'replica': REPLICA, 'affinity': affinity, 'reported_topology': topology, 'selected_cores': cores,
                'topology_uncertain': uncertain, 'hypervisor_can_hide_physical_topology': True,
                'variant_order': ORDER, 'offsets': {1: [0, 48], 2: [16, 32], 3: [32, 16]}[REPLICA],
                'seeds': [0, 1], 'sealed_binaries': sealed, 'companion': manifest,
                'original_archive_sha256': ARCHIVE_SHA, 'companion_archive_sha256': digest,
                'timing_seconds_per_row': 3, 'mask_counterfactual_only': MASK,
                'runner': {k: os.environ.get(k) for k in ['ImageOS', 'ImageVersion', 'RUNNER_OS', 'RUNNER_ARCH', 'GITHUB_RUN_ID', 'GITHUB_SHA', 'GITHUB_JOB']},
                'environment_shape': env_shape(os.environ), 'frequency': frequency(),
                'lscpu': command(['lscpu']), 'uname': command(['uname', '-a']), 'glibc': command(['ldd', '--version']),
                'proc_cpuinfo': optional(Path('/proc/cpuinfo')), 'ASLR': optional(Path('/proc/sys/kernel/randomize_va_space'))}
    for key in ['PRATIQUE_TIMING_REPS', 'PRATIQUE_TIMING_TICK_NS', 'PRATIQUE_TIMING_TICKS']:
        assert key not in os.environ, f'unexpected timing override {key}'
    settings['default_probe'] = probe(os.environ.copy())
    lib = Path(settings['default_probe']['memory']['memcpy']['library']).resolve()
    settings['libc_file'] = {'path': str(lib), 'sha256': sha(lib), 'ELF_notes': command(['readelf', '-n', str(lib)])}
    settings['dependencies'] = command(['ldd', str(INPUT / 'lifecycle_e2dd/unmodified-normal-test-binary')])
    save(OUT / 'settings.json', settings)
    save(OUT / 'storage-proof-unit.json', {'output': (COMPANION / 'storage-proof-unit.log').read_text()})
    print(json.dumps({'prepared': REPLICA, 'cores': cores, 'sealed_ELFs': len(sealed), 'AVX512_active': settings['default_probe']['active_AVX512F']}), flush=True)


def settings(): return json.loads((OUT / 'settings.json').read_text())


def run_case(folder, kind, variant, env, cpu=None):
    folder.mkdir(parents=True, exist_ok=True)
    if kind == 'normal':
        binary = INPUT / variant / 'unmodified-normal-test-binary'
        test = 'crypto::timing::ghash_multiplication_is_constant_time'
    elif kind == 'old_controls':
        binary = INPUT / variant / 'diagnostic-normal-test-binary'
        test = 'crypto::timing::pr10_ghash_timing_diagnostics'
    else:
        binary = COMPANION / 'history-test-binary'
        test = 'crypto::timing::pr10_actual_buffer_history_controls'
    child_env = dict(env)
    child_env['PRATIQUE_TIMING_SECS'] = '3'
    child_env['PRATIQUE_DIAGNOSTIC_SECS'] = '3'
    if kind != 'normal': child_env['PRATIQUE_DIAGNOSTIC_DIR'] = str(folder)
    args = [str(binary), '--exact', test, '--ignored', '--nocapture', '--test-threads=1']
    if cpu is not None: args = ['taskset', '-c', str(cpu)] + args
    record = {'kind': kind, 'variant': variant, 'cpu': cpu, 'argv': args, 'binary_sha256': sha(binary),
              'env_shape': env_shape(child_env), 'frequency_before': frequency(), 'probe': probe(child_env, cpu)}
    record['execution_state'] = 'starting'
    save(folder / 'case.json', record)
    print(json.dumps({'begin': str(folder.relative_to(OUT)), 'kind': kind, 'variant': variant, 'cpu': cpu}), flush=True)
    start = time.monotonic()
    with (folder / 'run.log').open('w') as log:
        process = subprocess.Popen(args, env=child_env, stdout=log, stderr=subprocess.STDOUT)
        time.sleep(.05)
        maps = optional(Path(f'/proc/{process.pid}/maps'))
        record['process_maps_early'] = maps
        record['process_task_ids_early'] = sorted(p.name for p in Path(f'/proc/{process.pid}/task').iterdir()) if Path(f'/proc/{process.pid}/task').exists() else []
        record['execution_state'] = 'running'
        save(folder / 'case.json', record)
        try:
            record['exit_code'] = process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            record['exit_code'] = 'timeout'
    record['elapsed_seconds'] = time.monotonic() - start
    record['execution_state'] = 'finished'
    record['frequency_after'] = frequency()
    if kind != 'normal':
        path = folder / ('positive-control-results.txt' if kind == 'old_controls' else 'history-positive-control-results.txt')
        controls = dict(line.split('=', 1) for line in path.read_text().splitlines()) if path.exists() else {}
        record['positive_controls'] = controls
        record['positive_controls_all_pass'] = bool(controls) and all(v == 'true' for v in controls.values())
    save(folder / 'case.json', record)
    print(json.dumps({'end': str(folder.relative_to(OUT)), 'exit_code': record['exit_code'], 'positive_controls_all_pass': record.get('positive_controls_all_pass')}), flush=True)
    return record


def startup():
    for variant in ORDER:
        run_case(OUT / 'startup' / variant, 'normal', variant, os.environ.copy())


def core(index):
    s = settings()
    cpu, offset = s['selected_cores'][index], s['offsets'][index]
    env = os.environ.copy()
    env['PRATIQUE_DIAGNOSTIC_SEED'] = str(index)
    env['PRATIQUE_HISTORY_OFFSET'] = f'{offset:02}'
    order = ORDER if index == 0 else list(reversed(ORDER))
    results = []
    for variant in order:
        results.append(run_case(OUT / f'core-{index}' / 'native' / variant / 'normal', 'normal', variant, env, cpu))
    expanded = index == 0 or any(r['exit_code'] != 0 for r in results)
    if expanded:
        for variant in order:
            run_case(OUT / f'core-{index}' / 'native' / variant / 'control', 'old_controls', variant, env, cpu)
    run_case(OUT / f'core-{index}' / 'native' / 'history', 'history', 'lifecycle_e2dd', env, cpu)
    save(OUT / f'core-{index}' / 'scope.json', {'old_controls_ran': expanded, 'rule': 'mandatory on primary core; predeclared expansion on secondary if any normal gate fails'})


def dispatch():
    s = settings()
    base = os.environ.copy()
    cpu = s['selected_cores'][0]
    default = probe(base, cpu)
    if base.get('GLIBC_TUNABLES') or 'PRATIQUE_MODE_PAD' in base or default['active_AVX512F'] != 1:
        save(OUT / 'dispatch' / 'scope.json', {'skipped': True, 'reason': 'active AVX512 unavailable, inherited tunable, or padding collision', 'default_probe': default})
        return
    envs = {}
    for mode in ['sham__', 'mask__']:
        env = base.copy()
        values = {'GLIBC_TUNABLES': '' if mode == 'sham__' else MASK,
                  'PRATIQUE_MODE_PAD': 'P' * len(MASK) if mode == 'sham__' else ''}
        keys = list(values) if REPLICA != 2 else list(reversed(values))
        for key in keys: env[key] = values[key]
        env['PRATIQUE_DIAGNOSTIC_SEED'] = '0'
        env['PRATIQUE_HISTORY_OFFSET'] = f'{s["offsets"][0]:02}'
        envs[mode] = env
    probes = {mode: probe(env, cpu) for mode, env in envs.items()}
    sham_matches = probes['sham__']['memory'] == default['memory']
    mask_verified = probes['mask__']['active_AVX512F'] == 0 and probes['mask__']['active_AVX512VL'] == 0
    changes = {name: probes['mask__']['memory'][name]['offset_hex'] != probes['sham__']['memory'][name]['offset_hex'] for name in ['memcpy', 'memmove', 'memset']}
    shapes = {mode: env_shape(env) for mode, env in envs.items()}
    assert shapes['sham__']['ordered_names'] == shapes['mask__']['ordered_names']
    assert shapes['sham__']['total_string_bytes'] == shapes['mask__']['total_string_bytes']
    save(OUT / 'dispatch' / 'scope.json', {'skipped': False, 'default_probe': default, 'probes': probes, 'environment_shapes': shapes,
          'sham_matches_true_default': sham_matches, 'masked_features_verified': mask_verified,
          'resolved_offsets_changed': changes, 'counterfactual_non_discriminating': not (sham_matches and mask_verified and any(changes.values())),
          'warning': 'Process-local mask is diagnostic only and never substitutes for true-default gates.'})
    order = ['mask__', 'sham__'] if REPLICA == 2 else ['sham__', 'mask__']
    for mode in order:
        env = envs[mode]
        for kind in ['normal', 'old_controls', 'history']:
            folder = OUT / 'dispatch' / mode / kind
            # Same-length mode and role paths keep paired child environment size/order matched.
            run_case(folder, kind, 'lifecycle_e2dd', env, s['selected_cores'][0])


def analyze_all():
    import analyze
    reports, failures = {}, {}
    for path in sorted(OUT.rglob('*.csv')):
        try:
            reports[str(path.relative_to(OUT))] = analyze.analyze(path)
        except Exception as error:
            failures[str(path.relative_to(OUT))] = str(error)
    save(OUT / 'sample-analysis.json', reports)
    save(OUT / 'sample-analysis-failures.json', failures)
    cases = {str(path.parent.relative_to(OUT)): json.loads(path.read_text()) for path in sorted(OUT.rglob('case.json'))}
    save(OUT / 'outcomes.json', {'cases': cases, 'analysis_failures': failures,
         'warning': 'Collection success is not security readiness; preserve every original failure/default gate and unsupported reason.'})
    print(json.dumps({'case_count': len(cases), 'raw_CSV_count': len(reports), 'analysis_failures': failures}), flush=True)


if __name__ == '__main__':
    phase = sys.argv[1]
    {'prepare': prepare, 'startup': startup, 'primary': lambda: core(0), 'secondary': lambda: core(1),
     'dispatch': dispatch, 'analyze': analyze_all}[phase]()
