#!/usr/bin/env python3
"""Record the exact library-test compiler call without modifying it."""
import json
import os
from pathlib import Path
import subprocess
import sys

args = sys.argv[1:]
if '--test' in args and '--crate-name' in args and args[args.index('--crate-name') + 1] == 'pratique':
    allowed = {'CARGO_MANIFEST_DIR', 'CARGO_MANIFEST_PATH', 'CARGO_CRATE_NAME',
               'CARGO_BIN_NAME', 'CARGO_PRIMARY_PACKAGE', 'OUT_DIR'}
    env = {k: v for k, v in os.environ.items() if k in allowed or k.startswith('CARGO_PKG_')}
    Path(os.environ['PRATIQUE_COMPILER_CAPTURE']).write_text(json.dumps(
        {'argv': args, 'cwd': os.getcwd(), 'package_environment': env}, indent=2) + '\n')
sys.exit(subprocess.run(args).returncode)
