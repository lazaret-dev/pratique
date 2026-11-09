#!/usr/bin/env python3
"""Capture an owned-source test build; optionally emit only IR/asm, without linking."""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys

args = sys.argv[1:]
is_test = '--test' in args and '--crate-name' in args and args[args.index('--crate-name') + 1] == 'pratique'
if is_test:
    original = args[:]
    if os.environ.get('PRATIQUE_H_EMIT_ONLY') == '1':
        emit = [i for i, arg in enumerate(args) if arg.startswith('--emit=')]
        assert len(emit) == 1, args
        args[emit[0]] = '--emit=dep-info,asm,llvm-ir'
    allowed = {'CARGO_MANIFEST_DIR', 'CARGO_MANIFEST_PATH', 'CARGO_CRATE_NAME',
               'CARGO_BIN_NAME', 'CARGO_PRIMARY_PACKAGE', 'OUT_DIR'}
    env = {k: v for k, v in os.environ.items() if k in allowed or k.startswith('CARGO_PKG_')}
    Path(os.environ['PRATIQUE_H_COMPILER_CAPTURE']).write_text(json.dumps({
        'original_argv': original, 'executed_argv': args, 'cwd': os.getcwd(),
        'included_h_source_sha256': hashlib.sha256(Path(__file__).with_name('h_controls.rs').read_bytes()).hexdigest(),
        'package_environment': env, 'emit_only': args != original,
        'limit': 'Emission-only builds have no runtime-authority or binary-identity claim.'}, indent=2) + '\n')
sys.exit(subprocess.run(args).returncode)
