#!/usr/bin/env python3
"""Capture one owned-source companion compile, including its actual link/emits."""
import hashlib
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
if '--test' in args and '--crate-name' in args and args[args.index('--crate-name') + 1] == 'pratique':
    original = args[:]
    mode = os.environ['PRATIQUE_BATCH_EMIT_MODE']
    if mode != 'link':
        positions = [i for i, arg in enumerate(args) if arg.startswith('--emit=')]
        assert len(positions) == 1
        args[positions[0]] = '--emit=dep-info,asm,llvm-ir' + (',link' if mode == 'all' else '')
    allowed = {'CARGO_MANIFEST_DIR', 'CARGO_MANIFEST_PATH', 'CARGO_CRATE_NAME', 'CARGO_BIN_NAME', 'CARGO_PRIMARY_PACKAGE', 'OUT_DIR'}
    env = {k: v for k, v in os.environ.items() if k in allowed or k.startswith('CARGO_PKG_')}
    Path(os.environ['PRATIQUE_BATCH_CAPTURE']).write_text(json.dumps({'original_argv': original,
        'executed_argv': args, 'cwd': os.getcwd(), 'package_environment': env, 'emit_mode': mode,
        'included_batch_source_sha256': hashlib.sha256(Path(__file__).with_name('batch_controls.rs').read_bytes()).hexdigest(),
        'identity_scope': 'all mode links the runtime companion in this SAME compile; no identity to sealed normal ELFs claimed.'}, indent=2) + '\n')
# Preserve Cargo's inherited jobserver descriptors instead of closing them in
# another subprocess. This wrapper itself never executes an archive artifact.
os.execvp(args[0], args)
