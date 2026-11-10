"""Retain a same-built ELF and bounded relevant disassembly; never execute the ELF."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time

ELF_LIMIT = 60_000_000
LIST_LIMIT = 5_000_000
DISASSEMBLY_LIMIT = 16_000_000
PAYLOAD_LIMIT = 90_000_000
CAPTURE_SECONDS = 90


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relevant(name):
    return (('timing' in name and any(s in name for s in ['ghash_', 'control_row', 'measure_seeded', 'coarse_tick']))
            or ('ghash' in name) or ('clmul' in name) or ('guarded' in name)
            or ('Instant' in name and any(s in name for s in ['elapsed', 'now'])))


def symbol_names(text):
    names = []
    for line in text.splitlines():
        fields = line.split(maxsplit=2)
        if len(fields) == 3 and fields[1].lower() in ['t', 'w'] and relevant(fields[2]):
            names.append(fields[2])
    return sorted(set(names), key=lambda n: (-1 if 'ghash_batch_hot_key_swap_controls' in n else
        0 if 'ghash_batch_intermediate_controls' in n else
        1 if 'control_row' in n else 2 if 'measure_seeded' in n else 3, n))


def capture(binary, output):
    binary, output = Path(binary), Path(output)
    directory = output / 'linked-evidence'
    directory.mkdir(parents=True, exist_ok=True)
    assert binary.stat().st_size <= ELF_LIMIT
    digest = sha(binary)
    retained = directory / 'compiled-test.elf'
    shutil.copyfile(binary, retained)
    retained.chmod(0o644)
    assert sha(retained) == digest
    deadline = time.monotonic() + CAPTURE_SECONDS
    versions = {}
    tool_errors = []
    for command in ['nm', 'objdump']:
        try:
            version = subprocess.check_output([command, '--version'], text=True, stderr=subprocess.STDOUT, timeout=5)
            versions[command] = {'available': True, 'path': shutil.which(command), 'version': version.splitlines()[0]}
        except Exception as e:
            versions[command] = {'available': False, 'path': shutil.which(command), 'error_type': type(e).__name__}
            tool_errors.append({'tool': command, 'stage': 'version', 'error_type': type(e).__name__})
    listings = {}
    for name, extra in [('symbols-raw.txt', []), ('symbols-demangled.txt', ['--demangle'])]:
        path = directory / name
        status = 'unavailable'
        with path.open('wb') as stream, (directory / (name + '.stderr.log')).open('wb') as errors_stream:
            if versions['nm']['available']:
                try:
                    subprocess.run(['nm', '-n', '--defined-only', *extra, str(binary)],
                                   stdout=stream, stderr=errors_stream, timeout=15, check=True)
                    status = 'complete'
                except Exception as e:
                    status = 'partial:' + type(e).__name__
                    tool_errors.append({'tool': 'nm', 'stage': name, 'error_type': type(e).__name__})
        original_bytes = path.stat().st_size
        if original_bytes > LIST_LIMIT:
            with path.open('r+b') as stream:
                stream.truncate(LIST_LIMIT)
            status = 'truncated_at_declared_limit'
        listings[name] = {'status': status, 'bytes': path.stat().st_size, 'original_bytes': original_bytes, 'sha256': sha(path)}
    names = symbol_names((directory / 'symbols-raw.txt').read_text(errors='replace'))
    selected, skipped = [], []
    disassembly = directory / 'selected-disassembly.txt'
    written = 0
    with disassembly.open('wb') as dest:
        for name in names:
            if not versions['objdump']['available'] or time.monotonic() >= deadline:
                skipped.append({'symbol': name, 'reason': 'tool unavailable or declared capture deadline; complete ELF retained'})
                continue
            if written >= DISASSEMBLY_LIMIT:
                skipped.append({'symbol': name, 'reason': 'declared text ceiling; complete ELF retained'})
                continue
            try:
                result = subprocess.run(['objdump', '-d', '--disassemble=' + name, str(binary)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        timeout=max(1, min(15, deadline - time.monotonic())), check=True)
            except Exception as e:
                skipped.append({'symbol': name, 'reason': 'optional disassembler error; complete ELF retained', 'error_type': type(e).__name__})
                continue
            if len(result.stdout) + written > DISASSEMBLY_LIMIT:
                skipped.append({'symbol': name, 'reason': 'would exceed declared text ceiling; complete ELF retained'})
                continue
            dest.write(result.stdout)
            selected.append({'symbol': name, 'offset_in_text': written, 'bytes': len(result.stdout),
                             'requested_label_present': (('<' + name + '>:').encode() in result.stdout)})
            written += len(result.stdout)
    record = {'schema': 'bounded-same-built-linked-evidence-v1', 'actual_ELF_sha256': digest,
              'actual_ELF_bytes': binary.stat().st_size, 'retained_ELF': str(retained.relative_to(output)),
              'tools': versions, 'symbol_listings': listings, 'selected': selected, 'omitted': skipped,
              'optional_capture_errors': tool_errors,
              'optional_capture_limit_seconds': CAPTURE_SECONDS,
              'disassembly_bytes': written, 'disassembly_sha256': sha(disassembly),
              'timed_work_retention_verified_by_this_script': False,
              'actual_linked_loop_and_ctor_drop_review': 'Pending independent read-only review before stage interpretation.',
              'scope': 'Capture completed before timing; ELF is read as data, never executed by this capture helper.'}
    (directory / 'linked-evidence.json').write_text(json.dumps(record, indent=2) + '\n')
    assert sum(p.stat().st_size for p in output.rglob('*') if p.is_file()) <= PAYLOAD_LIMIT
    assert sha(binary) == digest
    return record
