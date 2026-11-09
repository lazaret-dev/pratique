#!/usr/bin/env python3
"""Build supplemental controls once, away from the fresh measured VMs."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import run as original

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUT = Path(os.environ['PRATIQUE_HISTORY_OUTPUT'])
OUT.mkdir(parents=True, exist_ok=True)
TREE = Path(tempfile.mkdtemp(prefix='pratique-history-builder-')) / 'e2dd'


def main():
    original.OUT = OUT
    (OUT / 'history').mkdir()
    original.run(['cc', '-O2', '-fno-builtin', str(HERE / 'memory_env_probe.c'), '-ldl', '-o', str(OUT / 'memory-env-probe')], path=OUT / 'probe-build.log')
    result = original.run([str(OUT / 'memory-env-probe')], path=OUT / 'builder-probe.json')
    json.loads(result.stdout)
    original.run(['git', 'worktree', 'add', '--detach', str(TREE), 'e2dd9a91b3d2af6495faa6319fb5384c374dd82f'], cwd=ROOT)
    target = TREE / 'src/crypto/timing.rs'
    for filename in ['diagnostics.rs', 'history_controls.rs']:
        target.write_text(target.read_text() + '\ninclude!(' + json.dumps(str(HERE / filename)) + ');\n')
    env = {**os.environ, 'RUSTUP_TOOLCHAIN': '1.87.0', 'RUSTFLAGS': original.FLAGS,
           'RUSTC_WRAPPER': str(HERE / 'capture_rustc.py'), 'CARGO_TARGET_DIR': str(OUT / 'build')}
    binary = original.build('history', TREE, 'diagnostic', env)
    shutil.copy2(binary, OUT / 'history-test-binary')
    original.run([str(OUT / 'history-test-binary'), '--exact', 'crypto::timing::pr10_history_control_storage_check'], path=OUT / 'storage-proof-unit.log')
    manifest = {'production_source_commit': 'e2dd9a91b3d2af6495faa6319fb5384c374dd82f',
                'workflow_commit': original.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT).stdout.strip(),
                'RUSTFLAGS': original.FLAGS,
                'files': {name: original.digest(OUT / name) for name in ['history-test-binary', 'memory-env-probe']},
                'source_files': {name: original.digest(HERE / name) for name in ['diagnostics.rs', 'history_controls.rs', 'memory_env_probe.c']}}
    (OUT / 'companion-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    shutil.rmtree(OUT / 'build')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
