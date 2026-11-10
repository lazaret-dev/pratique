"""Owned synthetic text/metadata/process mocks only; executes no diagnostic binary."""
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import run as c


def report(name, values=None, reps=1):
    values = values or [0.1] * 7
    return (f'{name} n=   1024' + (f' x{reps}' if reps > 1 else '')
            + f' median 5058 ns  |t| uncropped {abs(values[0]):.1f}  max {max(map(abs, values)):.1f}  no leak detected\n')


def original(failed=None, unconfirmed=None):
    lines = ['running 1 test\ntest ' + c.GATE + ' ... ']
    for name in c.NAMES:
        repeat = name in [failed, unconfirmed]
        first = ([0.0, 1.0, 3.0, 8.2, 7.0, 4.1, 1.2] if name == failed
                 else [0.0, -0.8, 10.9, 10.2, 9.1, 5.5, 1.6] if repeat else None)
        lines.append(report(name, first))
        if repeat:
            lines.append(f'    above 4.5; measuring {json.dumps(name)} again with fresh inputs\n')
            lines.append(report(name, [0.0, -0.9, 2.3, 8.7, 8.0, 6.1, 2.8] if name == failed
                                else [0.0, 0.5, 0.3, 9.0, 8.8, 7.2, 4.0]))
            lines.append('    came back: recorded as a failure\n' if name == failed else '    did not come back at the same statistic with the same sign: noise, not recorded\n')
    if failed:
        lines.append('thread panicked at:\ntiming depends on the input:\n  ' + failed + ': t = +8.2 at p95.0 and +8.7 at the same statistic on a repeat with fresh inputs\n')
        lines.append('test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 36.21s\n')
    else:
        lines.append('ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 24.00s\n')
    return ''.join(lines)


def controls(confirmed=(), reps=1):
    lines = ['running 1 test\ntest ' + c.CONTROL + ' ... ']
    for name in c.CONTROL_NAMES:
        for seed in [0, 1]:
            values = [0.1, -0.8, 10.9, 10.2, 9.1, 5.5, 1.6] if seed == 0 else [0.0, 0.5, 0.3, 9.0, 8.8, 7.2, 4.0]
            lines.append(report(name, values, reps))
            lines.append('    signed t: ' + '  '.join(f'{label}:{value:+.1f}' for label, value in zip(c.LABELS, values)) + '\n')
            lines.append('    per call: keep 1: +0.123 +- 0.012 ns  keep 0.95: -0.456 +- 0.023 ns  keep 0.75: +0.789 +- 0.034 ns  keep 0.5: -0.012 +- 0.045 ns\n')
        lines.append('    unchanged judge: ' + (f'CONFIRMED ({name}: synthetic fixture)' if name in confirmed else 'not confirmed') + '\n')
    lines.append('ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 42.0s\n')
    return ''.join(lines)


class TextAndSchema(unittest.TestCase):
    def test_original_summary_is_authority_not_maximum_pair(self):
        r = c.parse_original(original(unconfirmed=c.NAMES[4]), 0)
        self.assertTrue(r['complete'])
        self.assertEqual(r['confirmed_rows'], [])
        self.assertEqual(r['fresh_rechecks'], [c.NAMES[4]])
        self.assertEqual(r['rows'][c.NAMES[4]][0]['printed_max_abs_t']['value'], 10.9)
        self.assertEqual(r['rows'][c.NAMES[4]][1]['printed_max_abs_t']['value'], 9.0)
        failed = c.parse_original(original(failed=c.NAMES[6]), 101)
        self.assertTrue(failed['complete'])
        self.assertEqual(failed['confirmed_rows'], [c.NAMES[6]])

    def test_full_text_after_panic_and_partial_fail_closed(self):
        text = original(failed=c.NAMES[6])
        marker = text.index('thread panicked')
        reordered = text[marker:text.index('test result:', marker)] + text[:marker] + text[text.index('test result:', marker):]
        self.assertTrue(c.parse_original(reordered, 101)['complete'])
        for bad, code in [(text, 0), (text, 'timeout'), (text + 'test result: FAILED. 0 passed; 1 failed; 0 ignored;\n', 101),
                          (text.replace(c.NAMES[0], 'unknown row'), 101), (text.replace('above 4.5; measuring', 'missing announcement'), 101)]:
            self.assertFalse(c.parse_original(bad, code)['complete'])

    def test_control_four_views_all_signs_reps_and_printed_judge(self):
        text = controls([c.CONTROL_NAMES[3]], reps=3)
        r = c.parse_controls(text, 0)
        self.assertTrue(r['complete'])
        self.assertEqual(len(r['reports']), 14)
        self.assertEqual([v['seed'] for v in r['reports']], [0, 1] * 7)
        self.assertTrue(all(v['reps'] == 3 for v in r['reports']))
        self.assertEqual(len(r['reports'][0]['signed_t']), 7)
        self.assertEqual(len(r['reports'][0]['per_call']), 4)
        self.assertEqual(r['reports'][0]['per_call'][1]['difference_ns']['value'], -0.456)
        self.assertEqual([j['confirmed'] for j in r['judges']], [False, False, False, True, False, False, False])
        # The displayed p95 pair is large, but the displayed original first peak is p99.
        self.assertFalse(r['judges'][0]['confirmed'])

    def test_control_partial_duplicate_misbound_and_wrong_exit_rejected(self):
        text = controls()
        for bad, code in [(text, 101), (text, 'timeout'), (text.replace('signed t:', 'missing signed t:', 1), 0),
                          (text.replace('keep 0.95:', 'keep 0.90:', 1), 0),
                          (text.replace(c.CONTROL_NAMES[1], c.CONTROL_NAMES[0], 1), 0),
                          (text.replace('unchanged judge: not confirmed', 'unchanged judge: unknown', 1), 0),
                          (text + 'test result: ok. 1 passed; 0 failed; 0 ignored;\n', 0),
                          (text.replace('unchanged judge: not confirmed', 'unchanged judge: CONFIRMED (another row: why)', 1), 0)]:
            self.assertFalse(c.parse_controls(bad, code)['complete'])

    def test_nonfinite_display_is_retained_in_strict_json(self):
        r = c.parse_controls(controls().replace('uncropped:+0.1', 'uncropped:+inf', 1).replace('keep 1: +0.123', 'keep 1: NaN', 1), 0)
        self.assertTrue(r['complete'])
        self.assertIsNone(r['reports'][0]['signed_t'][0]['value'])
        self.assertEqual(r['reports'][0]['signed_t'][0]['display'], '+inf')
        json.dumps(r, allow_nan=False)


class Sequencing(unittest.TestCase):
    def setup_root(self, tmp):
        root = Path(tmp)
        (root / 'host').mkdir()
        c.save(root / 'host/selection.json', {'matched_8370C': True})
        binary = root / 'inert-file'
        binary.write_text('not an executable')
        c.save(root / 'binary.json', {'path': str(binary), 'sha256': c.sha(binary)})
        return root

    def test_all_six_attempts_continue_after_101_and_collector_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.setup_root(tmp)
            calls = []
            def fake(record, binary, directory):
                calls.append((record['kind'], record['iteration']))
                return {**record, 'execution': 'finished', 'exit_code': [101, 'collector_error', 0, 0, 101, 0][len(calls)-1]}
            with patch.dict(c.os.environ, {'PRATIQUE_CLASS_OUTPUT': str(root)}), patch.object(c, 'verify'):
                c.run_all(fake)
            self.assertEqual(calls, [('gate', 1), ('control', 1), ('gate', 2), ('control', 2), ('gate', 3), ('control', 3)])
            self.assertEqual(len(c.read(root / 'six-slots.json')), 6)

    def test_unsafe_cleanup_retains_all_slots_without_overlap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.setup_root(tmp)
            calls = []
            def fake(record, binary, directory):
                calls.append(record['slot'])
                return {**record, 'execution': 'finished', 'exit_code': 'timeout', 'cleanup_incomplete': True}
            with patch.dict(c.os.environ, {'PRATIQUE_CLASS_OUTPUT': str(root)}), patch.object(c, 'verify'):
                c.run_all(fake)
            self.assertEqual(calls, [1])
            slots = c.read(root / 'six-slots.json')
            self.assertTrue(all(r['execution'] == 'not_attempted' and 'reason' in r for r in slots[1:]))

    def test_timeout_kills_owned_process_group(self):
        class Fake:
            pid = 123456
            calls = 0
            def wait(self, timeout):
                self.calls += 1
                if self.calls == 1:
                    raise subprocess.TimeoutExpired('inert mock', timeout)
                return -15
        with tempfile.TemporaryDirectory() as tmp, patch.object(c.subprocess, 'Popen', return_value=Fake()), patch.object(c.os, 'killpg') as kill:
            result = c.execute_case(c.planned()[0], Path('/inert-mock'), Path(tmp), timeout=1)
            self.assertEqual(result['exit_code'], 'timeout')
            self.assertEqual([x.args[1] for x in kill.call_args_list], [c.signal.SIGTERM, c.signal.SIGKILL])

    def test_complete_finding_exports_every_available_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            slots = c.planned()
            for r in slots:
                r.update(execution='finished', exit_code=101 if r['kind'] == 'gate' else 0)
                directory = root / ('%02d-%s-%d' % (r['slot'], r['kind'], r['iteration']))
                directory.mkdir()
                text = original(failed=c.NAMES[6]) if r['kind'] == 'gate' else controls([c.CONTROL_NAMES[0]])
                (directory / 'stdout-stderr.log').write_text(text)
            c.save(root / 'six-slots.json', slots)
            c.save(root / 'binary-window-identity.json', {'identity_unchanged': True})
            with patch.dict(c.os.environ, {'PRATIQUE_CLASS_OUTPUT': str(root)}):
                self.assertEqual(c.summarize(), 0)
            result = c.read(root / 'results.json')
            self.assertTrue(result['collection_complete'])
            self.assertFalse(result['causal_or_security_closure'])
            self.assertIsNone(result['control_health'])
            with (root / 'control-per-call.csv').open() as f:
                self.assertEqual(len(list(csv.DictReader(f))), 168)
            with (root / 'control-signed-t.csv').open() as f:
                self.assertEqual(len(list(csv.DictReader(f))), 294)
            json.dumps(result, allow_nan=False)
            # A duplicated complete gate cannot impersonate the missing control slot.
            duplicated = [dict(r) for r in slots]
            duplicated[1] = dict(duplicated[0])
            c.save(root / 'six-slots.json', duplicated)
            with patch.dict(c.os.environ, {'PRATIQUE_CLASS_OUTPUT': str(root)}):
                self.assertEqual(c.summarize(), 1)
            self.assertFalse(c.read(root / 'results.json')['slot_schema_valid'])
            # Nor can complete records silently change the declared native order.
            c.save(root / 'six-slots.json', slots[::-1])
            with patch.dict(c.os.environ, {'PRATIQUE_CLASS_OUTPUT': str(root)}):
                self.assertEqual(c.summarize(), 1)
            self.assertFalse(c.read(root / 'results.json')['slot_schema_valid'])


if __name__ == '__main__':
    unittest.main()
