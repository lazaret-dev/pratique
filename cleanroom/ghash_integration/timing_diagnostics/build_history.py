#!/usr/bin/env python3
"""Build supplemental controls once, away from the fresh measured VMs."""
import hashlib
import json
import os
from pathlib import Path
import re
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
    assembly = (OUT / 'history/diagnostic-disassembly.txt').read_text()
    match = re.search(r'^[0-9a-f]+ <pratique::crypto::timing::history_identical_zero_original_clear[^>]*>:(.*?)(?=^[0-9a-f]+ <|\Z)', assembly, re.M | re.S)
    assert match, 'focused generator symbol missing'
    body = match.group(1)
    (OUT / 'focused-generator-disassembly.txt').write_text(body)
    audit = {'conditional_extra_clear_call': 'memset' in body,
             'PRNG_work_retained': bool((re.search(r'\b(?:shr|shl|sal|sar)[bwlq]?\b', body) and re.search(r'\bxor[bwlq]?\b', body)) or 'Rng::next_u64' in body),
             'normal_byte_store_retained': bool(re.search(r'\bmov[b]?\s+%(?:[abcd][lh]|sil|dil|bpl|spl|r\d+b),\s*[^\n#]*\(', body)),
             'conditional_branch_retained': bool(re.search(r'\bj(?:e|ne|z|nz)\b', body)),
             'note': 'Source review plus these narrow optimized-code witnesses; not a generic disassembly proof.'}
    (OUT / 'focused-generator-assembly-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
    assert all(audit[k] for k in audit if k != 'note'), audit
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
