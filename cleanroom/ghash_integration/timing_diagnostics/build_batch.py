#!/usr/bin/env python3
"""Build only the six-row batch diagnostic from owned frozen production source."""
import argparse
import json
import os
from pathlib import Path
import shutil

import build_h

HERE = Path(__file__).resolve().parent
ROOT, SOURCE, FLAGS = build_h.ROOT, build_h.SOURCE, build_h.FLAGS
run, digest = build_h.run, build_h.digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--target')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--emit-mode', choices=['link', 'all', 'only'], default='all')
    args = parser.parse_args()
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=True)
    tree = out / 'owned-e2dd-source'
    if not tree.exists():
        run(['git', 'worktree', 'add', '--detach', str(tree), SOURCE], out / 'worktree.log', cwd=ROOT)
    assert run(['git', 'rev-parse', 'HEAD'], out / 'source-head.txt', cwd=tree).stdout.strip() == SOURCE
    original = run(['git', 'show', SOURCE + ':src/crypto/timing.rs'], out / 'original-timing-source.txt', cwd=ROOT).stdout
    injected = original + '\ninclude!(' + json.dumps(str(HERE / 'batch_controls.rs')) + ');\n'
    timing = tree / 'src/crypto/timing.rs'; timing.write_text(injected)
    paths = run(['git', 'diff', '--name-only', 'HEAD'], out / 'owned-source-difference-paths.txt', cwd=tree).stdout.splitlines()
    assert paths == ['src/crypto/timing.rs'], paths
    status = run(['git', 'status', '--short', '--untracked-files=all'], out / 'owned-source-status.txt', cwd=tree).stdout.splitlines()
    assert status == [' M src/crypto/timing.rs'], status
    run(['git', 'diff', '--binary', 'HEAD'], out / 'owned-source-diff.patch', cwd=tree)
    inventory = {str(p.relative_to(tree)): digest(p) for p in sorted((tree / 'src').rglob('*.rs'))}
    (out / 'owned-source-inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')
    env = {**os.environ, 'RUSTUP_TOOLCHAIN': '1.87.0', 'RUSTFLAGS': FLAGS,
           'CARGO_TARGET_DIR': str(out / 'target'), 'RUSTC_WRAPPER': str(HERE / 'batch_capture_rustc.py'),
           'PRATIQUE_BATCH_CAPTURE': str(out / 'compiler-call.json'), 'PRATIQUE_BATCH_EMIT_MODE': args.emit_mode}
    command = ['cargo', 'test', '--all-features', '--lib', '--no-run', '--message-format=json']
    if not args.debug: command.append('--release')
    if args.target: command.extend(['--target', args.target])
    result = run(command, out / 'build.log', env=env, cwd=tree)
    capture = json.loads((out / 'compiler-call.json').read_text())
    assert capture['included_batch_source_sha256'] == digest(HERE / 'batch_controls.rs'), 'included source changed during build'
    assert timing.read_text() == injected
    assert inventory == {str(p.relative_to(tree)): digest(p) for p in sorted((tree / 'src').rglob('*.rs'))}
    manifest = {'production_source_commit': SOURCE, 'RUSTFLAGS': FLAGS, 'target': args.target,
                'debug': args.debug, 'emit_mode': args.emit_mode,
                'source_files': {n: digest(HERE / n) for n in ['batch_controls.rs', 'batch_capture_rustc.py']},
                'actual_owned_source_difference_paths': paths, 'only_timing_include_difference': True,
                'actual_owned_source_difference_sha256': digest(out / 'owned-source-diff.patch'),
                'actual_owned_source_inventory_sha256': digest(out / 'owned-source-inventory.json'),
                'identity_scope': 'Companion all-mode actual link and IR/assembly are from one declared invocation; sealed normal ELFs remain separate authority.'}
    if args.emit_mode != 'only':
        artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
        binaries = [Path(item['executable']) for item in artifacts if item.get('reason') == 'compiler-artifact' and item.get('executable')]
        assert len(binaries) == 1
        binary = out / 'batch-controls-test-binary'; shutil.copy2(binaries[0], binary)
        manifest['binary_sha256'] = digest(binary)
        run([str(binary), '--exact', 'crypto::timing::pr10_batch_fixture_storage_check', '--nocapture'], out / 'fixture-storage-unit.log', env=env)
    if args.emit_mode != 'link':
        for suffix in ['ll', 's']:
            emissions = list((out / 'target').rglob('pratique-*.' + suffix)); assert len(emissions) == 1, emissions
            destination = out / ('batch-controls.' + suffix); shutil.copy2(emissions[0], destination)
            manifest['emitted_' + suffix + '_sha256'] = digest(destination)
    (out / 'build-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2), flush=True)


if __name__ == '__main__': main()
