#!/usr/bin/env python3
"""Matched native-x86 investigation; this workflow does not waive PR10 gates."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
OUT = Path(os.environ.get('PRATIQUE_DIAGNOSTIC_OUTPUT', tempfile.mkdtemp(prefix='pratique-timing-output-')))
OUT.mkdir(parents=True, exist_ok=True)
WORK = Path(tempfile.mkdtemp(prefix='pratique-timing-worktrees-'))
VARIANTS = {
    'original326': '32615a80b43280fb1fef3d36fa7d87261d5617f2',
    'lifecycle_e2dd': 'e2dd9a91b3d2af6495faa6319fb5384c374dd82f',
    'restored_d359': 'd359757bd8aadf198c9a4956f8e527170618a8c2',
}
FLAGS = '--cfg pratique_portable -C target-feature=-aes,-pclmulqdq'


def run(args, cwd=None, env=None, path=None, check=True):
    result = subprocess.run(args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if path:
        path.write_text(result.stdout)
    if check and result.returncode:
        print(result.stdout[-16000:])
        raise RuntimeError(f'command failed ({result.returncode}): {args!r}')
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(label, tree, stage, env):
    folder = OUT / label
    capture = folder / f'{stage}-rustc-command.json'
    env = {**env, 'PRATIQUE_COMPILER_CAPTURE': str(capture)}
    command = ['cargo', 'test', '--release', '--all-features', '--lib', '--no-run', '--message-format=json']
    result = run(command, cwd=tree, env=env, path=folder / f'{stage}-build.log')
    binary = None
    for line in result.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get('reason') == 'compiler-artifact' and item.get('executable'):
            binary = Path(item['executable'])
    assert binary and capture.exists(), 'missing executable/compiler capture'
    normal = folder / f'{stage}-normal-test-binary'
    shutil.copy2(binary, normal)
    run(['objdump', '-Cd', str(normal)], path=folder / f'{stage}-disassembly.txt')
    run(['nm', '-C', str(normal)], path=folder / f'{stage}-symbols.txt')
    record = {'command': command, 'normal_binary': str(normal), 'normal_sha256': digest(normal)}
    if stage == 'unmodified' and label == 'lifecycle_e2dd':
        actual = json.loads(capture.read_text())
        args = actual['argv'][:]
        emits = [i for i, arg in enumerate(args) if arg.startswith('--emit=')]
        assert len(emits) == 1
        args[emits[0]] = '--emit=dep-info,link,asm,llvm-ir'
        replay_env = {**env, **actual['package_environment']}
        replay = run(args, cwd=actual['cwd'], env=replay_env, path=folder / 'unmodified-emit-replay.log')
        record['expanded_emit_argv'] = args
        record['replayed_sha256'] = digest(binary)
        record['emit_replay_binary_identical'] = record['normal_sha256'] == record['replayed_sha256']
        # The preserved normal binary is authoritative for execution/disassembly.
        # Extra emit modes can change object/link metadata; retain differences.
        replay_binary = folder / 'unmodified-emit-replayed-test-binary'
        shutil.copy2(binary, replay_binary)
        run(['objdump', '-Cd', str(replay_binary)], path=folder / 'unmodified-emit-replayed-disassembly.txt')
        asm = folder / 'unmodified-compiler-emission'
        asm.mkdir()
        for path in Path(env['CARGO_TARGET_DIR']).rglob('pratique-*.ll'):
            shutil.copy2(path, asm / path.name)
        for path in Path(env['CARGO_TARGET_DIR']).rglob('pratique-*.s'):
            shutil.copy2(path, asm / path.name)
    (folder / f'{stage}-build-record.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'built': label, 'stage': stage, 'sha256': record['normal_sha256']}, sort_keys=True), flush=True)
    return normal


def main():
    assert sys.platform == 'linux' and os.uname().machine == 'x86_64'
    env = {**os.environ, 'RUSTUP_TOOLCHAIN': '1.87.0', 'RUSTFLAGS': FLAGS,
           'RUSTC_WRAPPER': str(HERE / 'capture_rustc.py'), 'PRATIQUE_TIMING_SECS': '3'}
    host = {key: run(args).stdout for key, args in {
        'rustc': ['rustc', '+1.87.0', '-vV'], 'cargo': ['cargo', '+1.87.0', '-V'],
        'lscpu': ['lscpu'], 'uname': ['uname', '-a'], 'openssl': ['openssl', 'version'],
        'linker': ['cc', '--version']}.items()}
    affinity = sorted(os.sched_getaffinity(0))
    host.update({'RUSTFLAGS': FLAGS, 'affinity': affinity, 'diagnostic_pinned_CPU': affinity[0],
                 'workflow_commit': run(['git', 'rev-parse', 'HEAD'], cwd=ROOT).stdout.strip(),
                 'variant_order': [list(VARIANTS), list(reversed(VARIANTS))]})
    (OUT / 'host-and-settings.json').write_text(json.dumps(host, indent=2) + '\n')
    binaries = {}
    source_inventory = {}
    expected_timing = run(['git', 'show', VARIANTS['lifecycle_e2dd'] + ':src/crypto/timing.rs'], cwd=ROOT).stdout
    for label, sha in VARIANTS.items():
        tree = WORK / label
        run(['git', 'worktree', 'add', '--detach', str(tree), sha], cwd=ROOT)
        assert (tree / 'src/crypto/timing.rs').read_text() == expected_timing
        folder = OUT / label
        folder.mkdir()
        source_inventory[label] = {'commit': sha, 'src_crypto_subtree': run(['git', 'rev-parse', 'HEAD:src/crypto'], cwd=tree).stdout.strip(),
            'files': {str(path.relative_to(tree)): digest(path) for path in sorted((tree / 'src/crypto').rglob('*.rs'))}}
        local_env = {**env, 'CARGO_TARGET_DIR': str(OUT / 'builds' / label)}
        normal = build(label, tree, 'unmodified', local_env)
        injected = tree / 'cleanroom/ghash_integration/timing_diagnostics/diagnostics.rs'
        injected.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HERE / 'diagnostics.rs', injected)
        timing = tree / 'src/crypto/timing.rs'
        timing.write_text(timing.read_text() + '\ninclude!(concat!(env!("CARGO_MANIFEST_DIR"), "/cleanroom/ghash_integration/timing_diagnostics/diagnostics.rs"));\n')
        diagnostic = build(label, tree, 'diagnostic', local_env)
        binaries[label] = {'unmodified': normal, 'diagnostic': diagnostic}
    (OUT / 'source-inventory.json').write_text(json.dumps(source_inventory, indent=2) + '\n')
    outcomes = {'unmodified_unpinned': [], 'unmodified_pinned': [], 'diagnostic_pinned': [],
                'warning': 'Investigation outputs do not satisfy or waive PR10 timing gates. Interpret controls and retain every failure.'}
    for label in VARIANTS:
        folder = OUT / label
        result = run([str(binaries[label]['unmodified']), '--exact', 'crypto::timing::ghash_multiplication_is_constant_time',
                      '--ignored', '--nocapture', '--test-threads=1'], env=env, path=folder / 'unmodified-unpinned-ghash.log', check=False)
        record = {'variant': label, 'exit_code': result.returncode}
        outcomes['unmodified_unpinned'].append(record)
        print(json.dumps({'unmodified_gate': record}), flush=True)
    for window, order in enumerate(host['variant_order']):
        for label in order:
            folder = OUT / label / f'window-{window}'
            folder.mkdir()
            local_env = {**env, 'PRATIQUE_DIAGNOSTIC_DIR': str(folder), 'PRATIQUE_DIAGNOSTIC_SECS': '3',
                         'PRATIQUE_DIAGNOSTIC_SEED': str(window)}
            gate_args = ['taskset', '-c', str(affinity[0]), str(binaries[label]['unmodified']), '--exact',
                         'crypto::timing::ghash_multiplication_is_constant_time', '--ignored', '--nocapture', '--test-threads=1']
            gate = run(gate_args, env=local_env, path=folder / 'unmodified-pinned-ghash.log', check=False)
            gate_record = {'variant': label, 'window': window, 'exit_code': gate.returncode}
            outcomes['unmodified_pinned'].append(gate_record)
            print(json.dumps({'unmodified_pinned_gate': gate_record}), flush=True)
            args = ['taskset', '-c', str(affinity[0]), str(binaries[label]['diagnostic']), '--exact',
                    'crypto::timing::pr10_ghash_timing_diagnostics', '--ignored', '--nocapture', '--test-threads=1']
            result = run(args, env=local_env, path=folder / 'diagnostic.log', check=False)
            controls_path = folder / 'positive-control-results.txt'
            controls = dict(line.split('=', 1) for line in controls_path.read_text().splitlines()) if controls_path.exists() else {}
            record = {'variant': label, 'window': window, 'seed': window, 'exit_code': result.returncode,
                      'positive_controls': controls, 'positive_controls_all_pass': bool(controls) and all(value == 'true' for value in controls.values())}
            outcomes['diagnostic_pinned'].append(record)
            print(json.dumps({'diagnostic_outcome': record}), flush=True)
    (OUT / 'outcomes.json').write_text(json.dumps(outcomes, indent=2) + '\n')
    run([sys.executable, str(HERE / 'analyze.py'), str(OUT)], path=OUT / 'sample-analysis-lines.jsonl')
    shutil.rmtree(OUT / 'builds')
    print(json.dumps(outcomes, indent=2), flush=True)


if __name__ == '__main__':
    main()
