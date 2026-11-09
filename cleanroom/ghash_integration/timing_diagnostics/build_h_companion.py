#!/usr/bin/env python3
"""Build and preserve a current-H companion away from the measured VM."""
import json
import os
from pathlib import Path
import re
import shutil
import sys

import audit_h
import build_h

HERE = Path(__file__).resolve().parent
OUT = Path(os.environ['PRATIQUE_H_BUILD_OUTPUT'])
SOURCE_FILES = ['h_controls.rs', 'H_PROTOCOL.md', 'build_h.py', 'h_capture_rustc.py',
                'audit_h.py', 'build_h_companion.py', 'run_h.py', 'analyze.py', 'replay.py', 'memory_env_probe.c']


def main():
    assert sys.platform == 'linux' and os.uname().machine == 'x86_64'
    OUT.mkdir(parents=True, exist_ok=True)
    sources = {name: build_h.digest(HERE / name) for name in SOURCE_FILES}
    for name in SOURCE_FILES:
        destination = OUT / 'diagnostic-sources' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(HERE / name, destination)
    build_h.run(['cc', '-O2', '-fno-builtin', str(HERE / 'memory_env_probe.c'), '-ldl', '-o', str(OUT / 'memory-env-probe')], OUT / 'probe-build.log')
    build_h.run([str(OUT / 'memory-env-probe')], OUT / 'builder-probe.json')
    for name, arguments in [('native', []), ('emission', ['--target', 'x86_64-unknown-linux-gnu', '--emit-only'])]:
        build_h.run([sys.executable, str(HERE / 'build_h.py'), '--output', str(OUT / name)] + arguments,
                    OUT / (name + '-stage.log'))
    build_h.run([sys.executable, str(HERE / 'audit_h.py'), str(OUT / 'emission')], OUT / 'emission-audit.log')
    binary = OUT / 'h-controls-test-binary'
    shutil.copy2(OUT / 'native/h-controls-test-binary', binary)
    build_h.run(['objdump', '-Cd', str(binary)], OUT / 'actual-linked-disassembly.txt')
    build_h.run(['nm', '-C', str(binary)], OUT / 'actual-linked-symbols.txt')
    names = {name: 'pratique::crypto::timing::' + name for name in audit_h.WANT}
    names.update({'production_ghash_constructor': 'pratique::crypto::ghash::GhashKey::new',
                  'production_ghash_wipe': 'pratique::crypto::ghash::GhashKey::wipe',
                  'production_preparation_transpose': 'pratique::crypto::clmul_batch_clean::transpose_in_place'})
    selected = OUT / 'actual-linked-selected'
    selected.mkdir()
    active, body = None, []
    with (OUT / 'actual-linked-disassembly.txt').open() as source:
        for line in source:
            match = re.match(r'^[0-9a-f]+ <(.+)>:$', line.rstrip())
            if match:
                if active:
                    (selected / (active + '.txt')).write_text(''.join(body))
                matches = [name for name, symbol in names.items() if match.group(1) == symbol]
                active = matches[0] if matches else None
                body = [line] if active else []
            elif active:
                body.append(line)
    if active:
        (selected / (active + '.txt')).write_text(''.join(body))
    assert all((selected / (name + '.txt')).exists() for name in names)
    witnesses = {}
    for name in audit_h.TIMERS:
        text = (selected / (name + '.txt')).read_text()
        witnesses[name] = {'constructor_call_present': 'GhashKey::new' in text,
                           'timestamp_symbol_present': 'std::time::Instant::elapsed' in text,
                           'body_sha256': build_h.digest(selected / (name + '.txt'))}
        assert witnesses[name]['constructor_call_present'] and witnesses[name]['timestamp_symbol_present'], witnesses[name]
    for name in ['h_identical_original_history', 'h_equal_input']:
        text = (selected / (name + '.txt')).read_text()
        witnesses[name] = {'RNG_shifts_present': bool(re.search(r'\bshr[qwl]?\s+\$0xc,', text) and re.search(r'\bshl[qwl]?\s+\$0x19,', text)),
                           'vector_store_present': bool(re.search(r'\bmov(?:dqu|dqa|ups|aps)\s+%xmm\d+,[^\n]*\(', text)),
                           'body_sha256': build_h.digest(selected / (name + '.txt'))}
        assert witnesses[name]['RNG_shifts_present'] and witnesses[name]['vector_store_present'], witnesses[name]
    constructor = (selected / 'production_ghash_constructor.txt').read_text()
    assert len(re.findall(r'\bcall[^\n]*<[^>]*transpose_in_place>', constructor)) == 3
    native_manifest = json.loads((OUT / 'native/build-manifest.json').read_text())
    emitted_manifest = json.loads((OUT / 'emission/build-manifest.json').read_text())
    assert native_manifest['source_files']['h_controls.rs'] == emitted_manifest['source_files']['h_controls.rs'] == sources['h_controls.rs']
    assert sources == {name: build_h.digest(HERE / name) for name in SOURCE_FILES}
    manifest = {'production_source_commit': build_h.SOURCE, 'diagnostic_commit': build_h.run(
                ['git', 'rev-parse', 'HEAD'], OUT / 'diagnostic-head.txt', cwd=build_h.ROOT).stdout.strip(),
                'source_files': sources, 'RUSTFLAGS': build_h.FLAGS,
                'files': {name: build_h.digest(OUT / name) for name in ['h-controls-test-binary', 'memory-env-probe']},
                'actual_linked_witnesses': witnesses,
                'actual_linked_disassembly_sha256': build_h.digest(OUT / 'actual-linked-disassembly.txt'),
                'actual_linked_selected_hashes': {p.name: build_h.digest(p) for p in sorted(selected.iterdir())},
                'runtime_authority': 'The sealed unmodified normal ELFs remain production timing authority.',
                'limits': 'Linked disassembly is from the actual runtime companion. Narrow witnesses plus separate emission CFG review do not assert emission/binary identity or stage instruction-latency isolation.'}
    (OUT / 'h-companion-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    for name in ['native', 'emission']:
        tree = OUT / name / 'owned-e2dd-source'
        build_h.run(['git', 'worktree', 'remove', '--force', str(tree)], OUT / (name + '-source-cleanup.log'), cwd=build_h.ROOT)
        shutil.rmtree(OUT / name / 'target')
    print(json.dumps(manifest, indent=2), flush=True)


if __name__ == '__main__':
    main()
