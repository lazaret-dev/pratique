#!/usr/bin/env python3
"""One owned-source compile emits the actual linked batch companion and IR/ASM."""
import json
import os
from pathlib import Path
import re
import shutil
import sys

import audit_batch
import build_batch
# Only ELF parsing helpers are imported; main is guarded. This module's OUT is
# unused here. No old compiler or archived script is invoked.
os.environ.setdefault('PRATIQUE_H_BUILD_OUTPUT', '/unused-batch-builder')
from build_h_companion import elapsed_got_targets, resolved_elapsed_calls

HERE = Path(__file__).resolve().parent
OUT = Path(os.environ.get('PRATIQUE_BATCH_BUILD_OUTPUT', '/private/tmp/batch-companion-build'))
SOURCE_FILES = ['batch_controls.rs', 'BATCH_PROTOCOL.md', 'build_batch.py', 'batch_capture_rustc.py',
                'audit_batch.py', 'build_batch_companion.py', 'run_batch.py', 'analyze.py', 'replay.py',
                'memory_env_probe.c', 'build_h.py', 'audit_h.py', 'build_h_companion.py']


def main():
    assert sys.platform == 'linux' and os.uname().machine == 'x86_64'
    OUT.mkdir(parents=True, exist_ok=True)
    sources = {name: build_batch.digest(HERE / name) for name in SOURCE_FILES}
    for name in SOURCE_FILES:
        target = OUT / 'diagnostic-sources' / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HERE / name, target)
    run = build_batch.run
    run(['cc', '-O2', '-fno-builtin', str(HERE / 'memory_env_probe.c'), '-ldl', '-o', str(OUT / 'memory-env-probe')], OUT / 'probe-build.log')
    run([str(OUT / 'memory-env-probe')], OUT / 'builder-probe.json')
    native = OUT / 'native'
    run([sys.executable, str(HERE / 'build_batch.py'), '--output', str(native), '--emit-mode', 'all'], OUT / 'native-stage.log')
    run([sys.executable, str(HERE / 'audit_batch.py'), str(native)], OUT / 'native-audit.log')
    binary = OUT / 'batch-controls-test-binary'; shutil.copy2(native / binary.name, binary)
    run(['objdump', '-Cd', str(binary)], OUT / 'actual-linked-disassembly.txt')
    run(['nm', '-C', str(binary)], OUT / 'actual-linked-symbols.txt')
    names = {name: 'pratique::crypto::timing::' + name for name in audit_batch.WANT}
    names.update({'production_ghash_constructor': 'pratique::crypto::ghash::GhashKey::new',
                  'production_ghash_hash': 'pratique::crypto::ghash::GhashKey::hash',
                  'production_ghash_wipe': 'pratique::crypto::ghash::GhashKey::wipe',
                  'production_preparation_transpose': 'pratique::crypto::clmul_batch_clean::transpose_in_place'})
    selected = OUT / 'actual-linked-selected'; selected.mkdir(exist_ok=True)
    active, body = None, []
    with (OUT / 'actual-linked-disassembly.txt').open() as source:
        for line in source:
            match = re.match(r'^[0-9a-f]+ <(.+)>:$', line.rstrip())
            if match:
                if active: (selected / (active + '.txt')).write_text(''.join(body))
                found = [name for name, symbol in names.items() if match.group(1) == symbol]
                active = found[0] if found else None; body = [line] if active else []
            elif active: body.append(line)
    if active: (selected / (active + '.txt')).write_text(''.join(body))
    assert all((selected / (name + '.txt')).exists() for name in names), names
    targets = elapsed_got_targets(binary); witnesses = {}
    for name in audit_batch.TIMERS:
        text = (selected / (name + '.txt')).read_text()
        clocks = resolved_elapsed_calls(text, targets)
        witnesses[name] = {'resolved_timestamp_calls': clocks,
                           'hash_call_count': len(re.findall(r'\bcall[^\n]*<pratique::crypto::ghash::GhashKey::hash>', text)),
                           'constructor_or_stored_key_wipe_call': bool(re.search(r'\bcall[^\n]*GhashKey::(?:new|wipe)>', text))}
        assert len(clocks) == 2 and witnesses[name]['hash_call_count'] == 1
        assert not witnesses[name]['constructor_or_stored_key_wipe_call']
    manifest = {'production_source_commit': build_batch.SOURCE,
                'diagnostic_commit': run(['git', 'rev-parse', 'HEAD'], OUT / 'diagnostic-head.txt', cwd=build_batch.ROOT).stdout.strip(),
                'source_files': sources, 'RUSTFLAGS': build_batch.FLAGS,
                'files': {name: build_batch.digest(OUT / name) for name in ['batch-controls-test-binary', 'memory-env-probe']},
                'actual_linked_witnesses': witnesses,
                'actual_linked_selected_hashes': {p.name: build_batch.digest(p) for p in sorted(selected.iterdir())},
                'actual_linked_disassembly_sha256': build_batch.digest(OUT / 'actual-linked-disassembly.txt'),
                'runtime_authority': 'Sealed e2dd normal ELF; companion literal must co-reproduce the corresponding row for counterfactual exclusions.',
                'limits': 'The same companion compile emits link/IR/ASM, but different rows/layout from sealed normal can change state. Producer arithmetic and state are intentionally perturbed by masks/observations; manual linked dataflow review remains required.'}
    assert sources == {name: build_batch.digest(HERE / name) for name in SOURCE_FILES}
    (OUT / 'batch-companion-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    run(['git', 'worktree', 'remove', '--force', str(native / 'owned-e2dd-source')], OUT / 'native-source-cleanup.log', cwd=build_batch.ROOT)
    shutil.rmtree(native / 'target')
    print(json.dumps(manifest, indent=2), flush=True)


if __name__ == '__main__': main()
