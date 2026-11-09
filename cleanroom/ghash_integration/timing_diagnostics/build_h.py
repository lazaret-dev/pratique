#!/usr/bin/env python3
"""Build H controls from owned e2dd source. Never runs downloaded artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = 'e2dd9a91b3d2af6495faa6319fb5384c374dd82f'
FLAGS = '--cfg pratique_portable -C target-feature=-aes,-pclmulqdq'


def run(args, output, env=None, cwd=None):
    with output.open('w') as log:
        result = subprocess.run(args, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT, text=True)
    result.stdout = output.read_text()
    if result.returncode:
        print(result.stdout[-12000:])
        raise RuntimeError(f'command failed: {args!r} ({result.returncode})')
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--target')
    parser.add_argument('--emit-only', action='store_true')
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    tree = out / 'owned-e2dd-source'
    if not tree.exists():
        run(['git', 'worktree', 'add', '--detach', str(tree), SOURCE], out / 'worktree.log', cwd=ROOT)
    assert run(['git', 'rev-parse', 'HEAD'], out / 'source-head.txt', cwd=tree).stdout.strip() == SOURCE
    timing = tree / 'src/crypto/timing.rs'
    original = run(['git', 'show', SOURCE + ':src/crypto/timing.rs'], out / 'original-timing-source.txt', cwd=ROOT).stdout
    injected = original + '\ninclude!(' + json.dumps(str(HERE / 'h_controls.rs')) + ');\n'
    timing.write_text(injected)
    paths = run(['git', 'diff', '--name-only', 'HEAD'], out / 'owned-source-difference-paths.txt', cwd=tree).stdout.splitlines()
    assert paths == ['src/crypto/timing.rs'], paths
    run(['git', 'diff', '--binary', 'HEAD'], out / 'owned-source-diff.patch', cwd=tree)
    status = run(['git', 'status', '--short', '--untracked-files=all'], out / 'owned-source-status.txt', cwd=tree).stdout.splitlines()
    assert status == [' M src/crypto/timing.rs'], status
    inventory = {str(path.relative_to(tree)): digest(path) for path in sorted((tree / 'src').rglob('*.rs'))}
    (out / 'owned-source-inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')
    # The only source injection is into this disposable owned-source build.
    env = {**os.environ, 'RUSTUP_TOOLCHAIN': '1.87.0', 'RUSTFLAGS': FLAGS,
           'CARGO_TARGET_DIR': str(out / 'target'), 'RUSTC_WRAPPER': str(HERE / 'h_capture_rustc.py'),
           'PRATIQUE_H_COMPILER_CAPTURE': str(out / 'compiler-call.json'),
           'PRATIQUE_H_EMIT_ONLY': str(int(args.emit_only))}
    command = ['cargo', 'test', '--all-features', '--lib', '--no-run', '--message-format=json']
    if not args.debug:
        command.append('--release')
    if args.target:
        command.extend(['--target', args.target])
    result = run(command, out / 'build.log', env=env, cwd=tree)
    capture = json.loads((out / 'compiler-call.json').read_text())
    assert capture['included_h_source_sha256'] == digest(HERE / 'h_controls.rs'), 'source changed during compilation'
    assert timing.read_text() == injected
    assert inventory == {str(path.relative_to(tree)): digest(path) for path in sorted((tree / 'src').rglob('*.rs'))}, 'owned build source changed during compilation'
    files = {'h_controls.rs': digest(HERE / 'h_controls.rs'),
             'h_capture_rustc.py': digest(HERE / 'h_capture_rustc.py')}
    manifest = {'production_source_commit': SOURCE, 'RUSTFLAGS': FLAGS, 'target': args.target,
                'debug': args.debug, 'emit_only': args.emit_only, 'source_files': files,
                'actual_owned_source_difference_paths': paths,
                'actual_owned_source_difference_sha256': digest(out / 'owned-source-diff.patch'),
                'actual_owned_source_inventory_sha256': digest(out / 'owned-source-inventory.json'),
                'only_timing_include_difference': True,
                'scope': 'Owned-source diagnostic build; sealed normal ELF remains runtime authority.'}
    if not args.emit_only:
        artifacts = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
        binaries = [Path(item['executable']) for item in artifacts
                    if item.get('reason') == 'compiler-artifact' and item.get('executable')]
        assert len(binaries) == 1
        binary = out / 'h-controls-test-binary'
        shutil.copy2(binaries[0], binary)
        manifest['binary_sha256'] = digest(binary)
        # This executable was just built from owned source, not an archive.
        run([str(binary), '--exact', 'crypto::timing::pr10_h_fixture_and_cleanup_check', '--nocapture'],
            out / 'fixture-cleanup-unit.log', env=env)
    else:
        for suffix in ['ll', 's']:
            emissions = list((out / 'target').rglob('pratique-*.' + suffix))
            assert len(emissions) == 1, emissions
            destination = out / ('h-controls.' + suffix)
            shutil.copy2(emissions[0], destination)
            manifest['emitted_' + suffix + '_sha256'] = digest(destination)
    (out / 'build-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
