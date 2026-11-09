#!/usr/bin/env python3
"""Check committed primitive provenance copies and inspect their emitted assembly."""
import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from preparation_lifecycle import audit_preparation_source

ROOT = Path(__file__).resolve().parents[2]


def sbox_structure(source):
    code = re.sub(r'//[^\n]*', '', source)
    if re.search(r'\b(if|for|while|loop|match|unsafe)\b|\*|\.(get|get_unchecked)\s*\(', code):
        raise ValueError('S-box must remain an unrolled Boolean circuit')
    for index in re.findall(r'\b[A-Za-z_]\w*\s*\[([^\]]*)\]', code):
        if not re.fullmatch(r'[0-7]', index.strip()):
            raise ValueError('S-box source has a nonliteral plane index')


def assembly_summary(source):
    rejected, branches, calls = [], [], []
    for line in source.splitlines():
        match = re.match(r'\s+([a-z][a-z0-9_.]*)\s*(.*)', line)
        if not match:
            continue
        opcode, args = match.groups()
        if re.match(r'(?:[a-z0-9_.]*mul|[su]?madd|[su]?msub|m(?:la|ls)|[su]ml|umaal|[isu]?div|i(?:32|64)\.div)', opcode):
            rejected.append(line.strip())
        if re.fullmatch(r'(?:j\w*|b\.\w+|b(?:eq|ne|ge|gt|le|lt|hi|ls|hs|lo|cs|cc|mi|pl|vs|vc|eqz|nez|ltz|gez|gtz|lez|ltu|geu)|cbn?z|tbn?z|br_if|if)', opcode):
            branches.append(line.strip())
        if opcode in ('bl', 'blr', 'call', 'callq'):
            calls.append(line.strip())
    if rejected:
        raise ValueError('Unexpected multiplication/division: ' + repr(rejected))
    return {'sha256': hashlib.sha256(source.encode()).hexdigest(),
            'multiplication_or_division': rejected,
            'branches_for_manual_review': branches,
            'calls_for_manual_review': sorted(set(calls))}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--toolchain', default='1.87.0')
    parser.add_argument('--target', action='append', default=[])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    copies = [('src/crypto/aes_sbox_tower_clean.rs', 'cleanroom/aes_tower/sbox.rs'),
              ('src/crypto/clmul_batch_circuit.rs', 'cleanroom/clmul_feasibility/circuit.rs')]
    record = {'commands': [], 'copies': {}, 'assembly': {}}
    record['preparation_lifecycle'] = audit_preparation_source(
        (ROOT / 'src/crypto/clmul_batch_clean.rs').read_text(),
        (ROOT / 'src/crypto/ghash.rs').read_text(),
        (ROOT / 'cleanroom/clmul_feasibility/lib.rs').read_text())
    for production, cleanroom in copies:
        actual, original = (ROOT / production).read_bytes(), (ROOT / cleanroom).read_bytes()
        assert actual == original, production + ' differs from committed clean-room source'
        record['copies'][production] = hashlib.sha256(actual).hexdigest()
    sbox_structure((ROOT / copies[0][0]).read_text())
    # Source-structure negative controls complement functional stub/identity tests.
    for invalid in ['fn sbox(q: &[u64; 8]) { TABLE[q[0] as usize]; }',
                    'fn sbox(q: &[u64; 8]) { q[0] * q[1]; }',
                    'fn sbox(q: &[u64; 8]) { if q[0] != 0 {} }']:
        try:
            sbox_structure(invalid)
        except ValueError:
            continue
        raise AssertionError('Structural negative control was accepted')
    out = Path(tempfile.mkdtemp(prefix='pratique-production-primitive-audit-'))
    record['artifacts'] = str(out)
    wrapper = out / 'wrapper.rs'
    wrapper.write_text('''#![no_std]
#![forbid(unsafe_code)]
#[path = "''' + str(ROOT / 'src/crypto/aes_sbox_tower_clean.rs') + '''"] mod sbox;
#[path = "''' + str(ROOT / 'src/crypto/clmul_clean.rs') + '''"] mod scalar;
#[path = "''' + str(ROOT / 'src/crypto/clmul_batch_clean.rs') + '''"] mod batch;
pub fn aes_sbox(q: &[u64; 8]) -> [u64; 8] { sbox::sbox(q) }
pub fn clmul(a: u64, b: u64) -> u128 { scalar::clmul64_portable(a, b) }
pub fn empty() -> batch::PreparedPolynomial128x64 { batch::PreparedPolynomial128x64::empty() }
pub fn prepare(p: &mut batch::PreparedPolynomial128x64, b: &[u128; 64]) { p.prepare(b) }
pub fn aggregate(a: [u128; 64], b: &batch::PreparedPolynomial128x64) -> [u128; 2] { batch::clmul128_batch_xor_prepared(a, b) }
pub fn prepared_words(b: &mut batch::PreparedPolynomial128x64) -> [&mut [u64; 64]; 3] { b.words_mut() }
''')
    version = subprocess.check_output(['rustc', '+' + args.toolchain, '-vV'], text=True)
    record['compiler'] = version
    host = re.search(r'^host: (.+)$', version, re.M).group(1)
    for target in [host] + [target for target in args.target if target != host]:
        output = out / (target + '.s')
        flags = []
        if target.startswith('aarch64'):
            flags = ['-C', 'target-feature=-aes']
        elif target.startswith(('x86', 'i686')):
            flags = ['-C', 'target-feature=-aes,-pclmulqdq']
        command = ['rustc', '+' + args.toolchain, '--edition=2021', '-O',
                   '--crate-type=lib', '--emit=asm', '--target', target,
                   *flags, str(wrapper), '-o', str(output)]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        record['commands'].append({'argv': command, 'exit': result.returncode, 'output': result.stdout})
        if result.returncode:
            raise RuntimeError(result.stdout)
        record['assembly'][target] = assembly_summary(output.read_text())
    path = args.output or ROOT / 'cleanroom/ghash_integration/results' / ('production-assembly-' + args.toolchain + '.json')
    if not path.is_absolute():
        path = ROOT / path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2) + '\n')
    print(path)


if __name__ == '__main__':
    main()
