#!/usr/bin/env python3
"""Describe complete saved diagnostic samples; no validation rule is relaxed."""
from collections import Counter
import csv
import json
import math
from pathlib import Path
import statistics
import sys


def analyze(path):
    with path.open() as f:
        rows = [{k: int(v) for k, v in row.items()} for row in csv.DictReader(f)]
    times = sorted(row['duration_ns'] for row in rows)
    quantile = lambda xs, p: xs[int((len(xs) - 1) * p)]
    crops = []
    for keep in [1.0, .999, .99, .95, .9, .75, .5]:
        cutoff = 2**32 - 1 if keep == 1 else quantile(times, keep)
        diffs = []
        for i in range(0, len(rows), 16):
            classes = [[r['duration_ns'] for r in rows[i:i + 16]
                        if r['class'] == c and r['duration_ns'] <= cutoff] for c in [0, 1]]
            if all(classes):
                diffs.append(statistics.mean(classes[1]) - statistics.mean(classes[0]))
        insufficient = len(diffs) < 2
        mean = statistics.mean(diffs) if not insufficient else None
        se = statistics.stdev(diffs) / math.sqrt(len(diffs)) if not insufficient else None
        t = 0.0 if insufficient else (mean / se if se else (0 if mean == 0 else math.copysign(float('inf'), mean)))
        crops.append({'keep': keep, 'cutoff_ns': cutoff, 'blocks': len(diffs),
                      'random_minus_fixed_ns': mean, 'SE_ns': se,
                      'insufficient_surviving_pairs': insufficient,
                      'signed_t': t if math.isfinite(t) else ('+Infinity' if t > 0 else '-Infinity')})
    classes = {}
    for c in [0, 1]:
        subset = [r for r in rows if r['class'] == c]
        ts = sorted(r['duration_ns'] for r in subset)
        unique = sorted(set(ts))
        tick_gcd = 0
        for a, b in zip(unique, unique[1:]):
            tick_gcd = math.gcd(tick_gcd, b - a)
        classes[str(c)] = {'samples': len(ts), 'mean_ns': statistics.mean(ts),
            'stdev_ns': statistics.stdev(ts), 'quantiles_ns': {str(p): quantile(ts, p) for p in [0, .01, .1, .5, .9, .95, .99, .999, 1]},
            'duration_histogram_top32': Counter(ts).most_common(32),
            'duration_quantization_gcd_ns': tick_gcd,
            'input_cacheline_offset': dict(sorted(Counter(r['input_address'] % 64 for r in subset).items())),
            'timed_cacheline_offset': dict(sorted(Counter(r['timed_address'] % 64 for r in subset).items())),
            'input_page_offset': dict(sorted(Counter(r['input_address'] % 4096 for r in subset).items())),
            'timed_page_offset': dict(sorted(Counter(r['timed_address'] % 4096 for r in subset).items())),
            'unique_timed_addresses': len(set(r['timed_address'] for r in subset)),
            'mean_duration_by_timed_cacheline_offset': {
                str(offset): statistics.mean(r['duration_ns'] for r in subset if r['timed_address'] % 64 == offset)
                for offset in sorted(set(r['timed_address'] % 64 for r in subset))}}
    return {'path': str(path), 'samples': len(rows), 'classes': classes, 'crops': crops}


if __name__ == '__main__':
    root = Path(sys.argv[1])
    report = {str(p.relative_to(root)): analyze(p) for p in sorted(root.rglob('*.csv'))}
    (root / 'sample-analysis.json').write_text(json.dumps(report, indent=2) + '\n')
    for name, data in report.items():
        peak = max(data['crops'], key=lambda row: abs(float(row['signed_t'])))
        print(json.dumps({'case': name, 'samples': data['samples'], 'peak': peak}, sort_keys=True))
