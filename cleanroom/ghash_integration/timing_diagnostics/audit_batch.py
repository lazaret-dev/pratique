#!/usr/bin/env python3
"""Narrow batch call-boundary and producer witnesses, not an equivalence proof."""
import json
from pathlib import Path
import re
import sys

import audit_h

TIMERS = ['batch_time_data', 'batch_time_key', 'batch_time_positive']
PRODUCERS = ['batch_original_data', 'batch_identical_data', 'batch_equal_data',
             'batch_original_h', 'batch_identical_h', 'batch_equal_h']
WANT = TIMERS + PRODUCERS
EXTRA = {'production_ghash_constructor': 'ghash8GhashKey3new',
         'production_ghash_hash': 'ghash8GhashKey4hash',
         'production_ghash_wipe': 'ghash8GhashKey4wipe',
         'production_preparation_transpose': 'clmul_batch_clean18transpose_in_place'}


def main():
    root = Path(sys.argv[1]); out = root / 'selected'; out.mkdir(exist_ok=True)
    audit_h.SYMBOLS = {**{name: name for name in WANT}, **EXTRA}
    for kind in ['ll', 's']:
        audit_h.extract(root / ('batch-controls.' + kind), kind, out)
    states = {name: audit_h.timer_states((out / (name + '.ll')).read_text().replace('batch_delay', 'h_known_delay'))
              for name in TIMERS}
    for name, value in states.items():
        assert value.get('hash') == [1], (name, value)
        assert 'constructor' not in value and 'wipe' not in value, (name, value)
        if name == 'batch_time_positive': assert value.get('known_delay') == [1]
    producers = {}
    for name in PRODUCERS:
        ir = (out / (name + '.ll')).read_text(); machine = (out / (name + '.s')).read_text()
        producers[name] = {
            'RNG_shift12_IR': len(re.findall(r'lshr i64 [^\n]+, 12\b', ir)),
            'RNG_shift25_IR': len(re.findall(r'shl i64 [^\n]+, 25\b', ir)),
            'RNG_shift27_IR': len(re.findall(r'lshr i64 [^\n]+, 27\b', ir)),
            'IR_scalar_byte_stores': len(re.findall(r'\bstore i8 ', ir)),
            'IR_vector16_byte_stores': len(re.findall(r'\bstore <16 x i8> ', ir)),
            'IR_memset_calls': len(re.findall(r'\b(?:call|invoke) [^\n]*llvm.memset', ir)),
            'machine_scalar_byte_stores': len(re.findall(r'\bmovb\s+%[^,]+,[^\n]*\(', machine)),
            'machine_128bit_stores': len(re.findall(r'\bmov(?:dqu|dqa|ups|aps)\s+%xmm\d+,[^\n]*\(', machine)),
            'machine_low_byte_LEA_ADD_present': bool(re.search(r'\blea[lq]?\s', machine) and re.search(r'\badd[lq]?\s', machine)),
            'opaque_barrier_sites': ir.count('asm sideeffect'),
            'note': 'Counts include scratch/output paths; manual actual dataflow/unrolling/extra-clear review is required.'}
        assert producers[name]['RNG_shift12_IR'] > 0, (name, producers[name])
    result = {'boundary_states': states,
              'state_legend': {'0': 'before start timestamp', '1': 'between timestamps', '2': 'after stop timestamp'},
              'producer_witnesses': producers,
              'selected_file_hashes': {p.name: audit_h.digest(p) for p in sorted(out.iterdir())},
              'emission_hashes': {k: audit_h.digest(root / ('batch-controls.' + k)) for k in ['ll', 's']},
              'limits': 'This identifies emitted call placement, not pure hash instruction latency, full prior-store completion, sealed ELF identity, or preparation-state equivalence. The masked controls deliberately add arithmetic/observations.'}
    (root / 'boundary-producer-audit.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__': main()
