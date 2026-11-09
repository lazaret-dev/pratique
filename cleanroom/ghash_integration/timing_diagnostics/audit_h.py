#!/usr/bin/env python3
"""Narrow owned-source optimized-code witnesses; independent review still required."""
import hashlib
import json
from pathlib import Path
import re
import sys

TIMERS = ['h_time_full', 'h_time_prepared_hash', 'h_time_constructor_drop',
          'h_time_constructor_only', 'h_time_wipe_only', 'h_time_known_leak']
PRODUCERS = ['h_original_input', 'h_identical_original_history', 'h_equal_input']
WANT = TIMERS + PRODUCERS
EXTRA = {'production_ghash_constructor': 'ghash8GhashKey3new',
         'production_ghash_wipe': 'ghash8GhashKey4wipe',
         'production_preparation_transpose': 'clmul_batch_clean18transpose_in_place'}
SYMBOLS = {**{name: name for name in WANT}, **EXTRA}
LABEL = r'("[^"]+"|[-a-zA-Z0-9_.$]+)'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract(path, kind, out):
    name, buf = None, []
    with path.open() as source:
        for line in source:
            if name is None:
                start = line.startswith('define ') if kind == 'll' else line.startswith('_ZN') and line.rstrip().endswith(':')
                if start:
                    matches = [name for name, needle in SYMBOLS.items() if needle in line]
                    if matches:
                        name, buf = matches[0], [line]
            else:
                buf.append(line)
                end = line.rstrip() == '}' if kind == 'll' else line.startswith('\t.size\t')
                if end:
                    (out / (name + '.' + kind)).write_text(''.join(buf))
                    name, buf = None, []
    assert all((out / (name + '.' + kind)).exists() for name in SYMBOLS)


def timer_states(text):
    blocks = {}
    current = None
    for line in text.splitlines()[1:-1]:
        match = re.match('^' + LABEL + ':', line)
        if match:
            current = match.group(1)
            blocks[current] = []
        elif current is not None:
            blocks[current].append(line.strip())
    assert blocks
    stack = [(next(iter(blocks)), 0)]
    seen, events, returns = set(), {}, set()
    while stack:
        label, state = stack.pop()
        if (label, state) in seen:
            continue
        seen.add((label, state))
        lines = [line for line in blocks[label] if line and not line.startswith(';')]
        for line in lines:
            if not re.search(r'\b(call|invoke)\b', line):
                continue
            if 'Instant7elapsed' in line:
                assert state < 2, 'unexpected third timestamp'
                state += 1
                continue
            event = None
            for needle, description in [('GhashKey3new', 'constructor'), ('GhashKey4hash', 'hash'),
                                        ('GhashKey4wipe', 'wipe'), ('h_known_delay', 'known_delay'),
                                        ('llvm.memcpy', 'memcpy')]:
                if needle in line:
                    event = description
            if event:
                events.setdefault(event, set()).add(state)
        combined = ' '.join(lines)
        if any(line.startswith('ret ') for line in lines):
            returns.add(state)
            continue
        if any(line.startswith(('resume ', 'unreachable')) for line in lines):
            continue
        # Follow normal return edges only. Panic/unwind cleanup is preserved
        # in the extracted code but cannot masquerade as the normal boundary.
        if any(re.search(r'\binvoke\b', line) for line in lines):
            edges = re.findall(r'\bto label %' + LABEL, combined)
        else:
            edges = re.findall(r'\blabel %' + LABEL, combined)
        assert edges, (label, lines[-4:])
        stack.extend((edge, state) for edge in edges)
    assert returns == {2}, returns
    return {name: sorted(states) for name, states in events.items()}


def producer_witness(text):
    masked = re.findall(r'^\s*(%[-a-zA-Z0-9_.$]+) = and <16 x i8> ', text, re.M)
    output_stores = sum(bool(re.search(r'\bstore <16 x i8> ' + re.escape(value) + r', ptr ', text)) for value in masked)
    return {'RNG_shift12_operations': len(re.findall(r'lshr i64 [^\n]+, 12\b', text)),
            'RNG_shift25_operations': len(re.findall(r'shl i64 [^\n]+, 25\b', text)),
            'RNG_shift27_operations': len(re.findall(r'lshr i64 [^\n]+, 27\b', text)),
            'masked_vector_results': len(masked), 'masked_vector_output_stores': output_stores,
            'vector_output_store_width_bits': 128,
            'vector_output_stores': len(re.findall(r'\bstore <16 x i8> ', text)),
            'scalar_byte_masks': len(re.findall(r' = and i8 ', text)),
            'literal_class_branch': bool(re.search(r'br i1 %class,', text)),
            'allocation_calls': sum('__rust_alloc(' in line and not line.lstrip().startswith(';') for line in text.splitlines()),
            'note': 'Narrow IR witnesses plus extracted machine code; not a general equivalence proof.'}


def main():
    root = Path(sys.argv[1])
    out = root / 'selected'
    out.mkdir(exist_ok=True)
    for kind in ['ll', 's']:
        extract(root / ('h-controls.' + kind), kind, out)
    states = {name: timer_states((out / (name + '.ll')).read_text()) for name in TIMERS}
    required = {
        'h_time_full': {'constructor': [1], 'hash': [1], 'wipe': [1]},
        'h_time_prepared_hash': {'constructor': [0], 'hash': [1], 'wipe': [2]},
        'h_time_constructor_drop': {'constructor': [1], 'wipe': [1]},
        'h_time_constructor_only': {'constructor': [1], 'wipe': [2]},
        'h_time_wipe_only': {'constructor': [0], 'wipe': [1, 2]},
        'h_time_known_leak': {'constructor': [1], 'hash': [1], 'wipe': [1], 'known_delay': [1]},
    }
    for name, expected in required.items():
        assert all(states[name].get(event) == positions for event, positions in expected.items()), (name, states[name])
    producers = {name: producer_witness((out / (name + '.ll')).read_text()) for name in PRODUCERS}
    for name in ['h_identical_original_history', 'h_equal_input']:
        witness = producers[name]
        assert all(witness[key] == 16 for key in ['RNG_shift12_operations', 'RNG_shift25_operations',
                   'RNG_shift27_operations']), witness
        assert witness['masked_vector_results'] == witness['masked_vector_output_stores'] == 1, witness
        assert witness['scalar_byte_masks'] == 0, witness
    assert all(producers[name]['vector_output_stores'] == 1 for name in PRODUCERS), producers
    for name in PRODUCERS:
        machine = (out / (name + '.s')).read_text()
        producers[name]['machine_128_bit_vector_stores'] = len(re.findall(
            r'\bmov(?:dqu|dqa|ups|aps)\s+%xmm\d+,[^\n]*\(', machine))
        assert producers[name]['machine_128_bit_vector_stores'] == 1, producers[name]
    assert producers['h_original_input']['literal_class_branch']
    assert producers['h_identical_original_history']['literal_class_branch']
    assert not producers['h_equal_input']['literal_class_branch']
    constructor = (out / 'production_ghash_constructor.ll').read_text()
    preparation = {'in_place_transpose_calls': sum('transpose_in_place' in line and
                   not line.lstrip().startswith(';') for line in constructor.splitlines()),
                   'volatile_i128_zero_stores': len(re.findall(r'store volatile i128 0,', constructor)),
                   'note': 'Real shared constructor body remains callable by the opaque-reference timer wrappers; extracted body contains its preparation and raw-power wipes.'}
    assert preparation['in_place_transpose_calls'] == 3, preparation
    assert preparation['volatile_i128_zero_stores'] == 65, preparation
    report = {'boundary_states': states, 'state_legend': {'0': 'before start timestamp',
              '1': 'between start and stop timestamps', '2': 'after stop timestamp'},
              'all_normal_return_paths_have_two_timestamps': True, 'producers': producers,
              'retained_production_preparation': preparation,
              'emission_hashes': {kind: digest(root / ('h-controls.' + kind)) for kind in ['ll', 's']},
              'selected_file_hashes': {p.name: digest(p) for p in sorted(out.iterdir())},
              'limits': 'Emission-only test build, no sealed-binary identity claim. Caller cannot establish libc exit upper-register state. Independent actual-CFG/machine-code review remains required.'}
    (root / 'boundary-producer-audit.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
