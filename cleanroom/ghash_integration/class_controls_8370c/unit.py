"""Owned synthetic text/metadata/process mocks only; executes no diagnostic binary."""
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import run as c
import capture_linked as linked


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


def controls(confirmed=(), reps=1, group='control'):
    names = {'control': c.CONTROL_NAMES, 'intermediate': c.INTERMEDIATE_NAMES, 'swap': c.SWAP_NAMES}[group]
    selector = {'control': c.CONTROL, 'intermediate': c.INTERMEDIATE, 'swap': c.SWAP}[group]
    lines = ['running 1 test\ntest ' + selector + ' ... ']
    if group != 'control':
        lines.append('clock: coarse_tick() = None\n')
    for index, name in enumerate(names):
        if group == 'swap' and index in [0, 2]:
            lines.append('slots: 0x1000 and 0x2000\n' if index == 0 else 'slots: 0x5000 and 0x6000\n')
        for seed in [0, 1]:
            values = [0.1, -0.8, 10.9, 10.2, 9.1, 5.5, 1.6] if seed == 0 else [0.0, 0.5, 0.3, 9.0, 8.8, 7.2, 4.0]
            lines.append(report(name, values, reps))
            lines.append('    signed t: ' + '  '.join(f'{label}:{value:+.1f}' for label, value in zip(c.LABELS, values)) + '\n')
            lines.append('    per call: keep 1: +0.123 +- 0.012 ns  keep 0.95: -0.456 +- 0.023 ns  keep 0.75: +0.789 +- 0.034 ns  keep 0.5: -0.012 +- 0.045 ns\n')
        lines.append('    unchanged judge: ' + (f'CONFIRMED ({name}: synthetic fixture)' if name in confirmed else 'not confirmed') + '\n')
    lines.append('ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 42.0s\n')
    return ''.join(lines)


class TextAndSchema(unittest.TestCase):
    def test_swap_names_slot_order_alignment_and_class_directions(self):
        text = controls([c.SWAP_NAMES[0]], group='swap')
        r = c.parse_controls(text, 0, 'swap')
        self.assertTrue(r['complete'])
        self.assertEqual(len(r['reports']), 8)
        self.assertEqual([v['after_report'] for v in r['printed_slot_records']], [0, 4])
        self.assertTrue(all(v['wrapper_page_aligned'] for v in r['printed_slot_records']))
        self.assertEqual([v['printed_stride_bytes'] for v in r['printed_slot_records']], [4096, 4096])
        self.assertIn('zero H', r['reports'][0]['class0_description'])
        self.assertIn('zero H', r['reports'][2]['class1_description'])
        self.assertEqual({len(n) for n in c.SWAP_NAMES}, {56})
        for bad in [text.replace('slots: 0x1000 and 0x2000\n', ''),
                    text.replace('0x1000 and', '0x1100 and', 1),
                    text.replace('slots: 0x1000 and 0x2000\n', '') + 'slots: 0x1000 and 0x2000\n',
                    text + 'slots: 0x9000 and 0xa000\n']:
            self.assertFalse(c.parse_controls(bad, 0, 'swap')['complete'])

    def test_intermediate_rows_use_actual_classes_and_only_observe_fresh_clock(self):
        text = controls([c.INTERMEDIATE_NAMES[0]], group='intermediate')
        r = c.parse_controls(text, 0, 'intermediate')
        self.assertTrue(r['complete'])
        self.assertEqual(len(r['reports']), 8)
        self.assertEqual(r['fresh_clock_observation'], 'None')
        self.assertIn('Only that printed independent', r['fresh_clock_observation_limit'])
        self.assertIn('index 0: zero H', r['reports'][0]['class0_description'])
        self.assertIn('index 1: fixed other nonzero H', r['reports'][0]['class1_description'])
        self.assertNotIn('random', r['reports'][0]['class1_description'])
        self.assertIn('repeated 128 times', r['reports'][4]['class0_description'])
        self.assertIn('random H on zero DATA', r['reports'][6]['class1_description'])
        for bad in [text.replace('clock: coarse_tick() = None\n', ''),
                    text + 'clock: coarse_tick() = None\n',
                    text.replace(c.INTERMEDIATE_NAMES[1], c.INTERMEDIATE_NAMES[0], 1)]:
            self.assertFalse(c.parse_controls(bad, 0, 'intermediate')['complete'])
        some = c.parse_controls(text.replace('coarse_tick() = None', 'coarse_tick() = Some(42)'), 0, 'intermediate')
        self.assertTrue(some['complete'])
        self.assertEqual(some['fresh_clock_observation'], 'Some(42)')

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
        c.save(root / 'binary.json', {'path': str(binary), 'sha256': c.sha(binary), 'source_commit': 'a' * 40})
        return root

    def test_all_six_attempts_continue_after_101_and_collector_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.setup_root(tmp)
            calls = []
            def fake(record, binary, directory):
                calls.append((record['kind'], record['iteration']))
                return {**record, 'execution': 'finished', 'exit_code': [101, 'collector_error', 0, 0, 101, 0][len(calls)-1]}
            with patch.dict(c.os.environ, {'PRATIQUE_CLASS_OUTPUT': str(root), 'PRATIQUE_EXPECTED_SOURCE_COMMIT': 'a' * 40}), patch.object(c, 'verify'):
                c.run_all(fake)
            self.assertEqual(calls, [('gate', 1), ('swap', 1), ('gate', 2), ('swap', 2), ('gate', 3), ('swap', 3)])
            self.assertEqual(len(c.read(root / 'six-slots.json')), 6)

    def test_unsafe_cleanup_retains_all_slots_without_overlap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.setup_root(tmp)
            calls = []
            def fake(record, binary, directory):
                calls.append(record['slot'])
                return {**record, 'execution': 'finished', 'exit_code': 'timeout', 'cleanup_incomplete': True}
            with patch.dict(c.os.environ, {'PRATIQUE_CLASS_OUTPUT': str(root), 'PRATIQUE_EXPECTED_SOURCE_COMMIT': 'a' * 40}), patch.object(c, 'verify'):
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
                text = original(failed=c.NAMES[6]) if r['kind'] == 'gate' else controls([c.SWAP_NAMES[0]], group='swap')
                (directory / 'stdout-stderr.log').write_text(text)
            c.save(root / 'six-slots.json', slots)
            retained = root/'linked-evidence/compiled-test.elf'
            retained.parent.mkdir();retained.write_bytes(b'inert ELF fixture, never executable')
            digest = c.sha(retained)
            c.save(root/'linked-evidence/linked-evidence.json', {'actual_ELF_sha256': digest})
            window = {'identity_unchanged': True, 'before_sha256': digest, 'after_sha256': digest}
            source = {'diagnostic_source_commit': 'a' * 40, 'base_production_commit': c.BASE,
                'patch_sha256': c.PATCH_SHA, 'second_patch_sha256': c.SECOND_PATCH_SHA,
                'prior_diagnostic_commit': c.PRIOR_DIAGNOSTIC, 'first_patch_timing_sha256': c.FIRST_TIMING_SHA,
                'third_patch_sha256': c.THIRD_PATCH_SHA, 'second_diagnostic_commit': c.SECOND_DIAGNOSTIC,
                'second_patch_timing_sha256': c.SECOND_TIMING_SHA, 'patched_timing_sha256': c.TIMING_SHA,
                'toolchain': '1.87.0', 'RUSTFLAGS': c.FLAGS, 'PRATIQUE_TIMING_SECS': '3'}
            binary = {'source_commit': 'a' * 40, 'sha256': digest}
            c.save(root / 'binary-window-identity.json', window)
            c.save(root / 'source-binding.json', source)
            c.save(root / 'binary.json', binary)
            env = {'PRATIQUE_CLASS_OUTPUT': str(root), 'PRATIQUE_EXPECTED_SOURCE_COMMIT': 'a' * 40}
            with patch.dict(c.os.environ, env):
                self.assertEqual(c.summarize(), 0)
            result = c.read(root / 'results.json')
            self.assertTrue(result['collection_complete'])
            self.assertFalse(result['causal_or_security_closure'])
            self.assertIsNone(result['control_health'])
            self.assertTrue(result['retained_ELF_integrity_valid'])
            self.assertIn('one hot hash per repetition', result['actual_linked_work_retention_review'])
            self.assertIn('same-base post-swap', result['actual_linked_work_retention_review'])
            with (root / 'control-per-call.csv').open() as f:
                self.assertEqual(len(list(csv.DictReader(f))), 96)
            with (root / 'control-signed-t.csv').open() as f:
                self.assertEqual(len(list(csv.DictReader(f))), 168)
            self.assertEqual(len(result['derived_swap_effects']), 48)
            with (root / 'derived-swap-effects-95-75.csv').open() as f:
                self.assertEqual(len(list(csv.DictReader(f))), 24)
            json.dumps(result, allow_nan=False)
            # A duplicated complete gate cannot impersonate the missing control slot.
            duplicated = [dict(r) for r in slots]
            duplicated[1] = dict(duplicated[0])
            c.save(root / 'six-slots.json', duplicated)
            with patch.dict(c.os.environ, env):
                self.assertEqual(c.summarize(), 1)
            self.assertFalse(c.read(root / 'results.json')['slot_schema_valid'])
            # Nor can complete records silently change the declared native order.
            c.save(root / 'six-slots.json', slots[::-1])
            with patch.dict(c.os.environ, env):
                self.assertEqual(c.summarize(), 1)
            self.assertFalse(c.read(root / 'results.json')['slot_schema_valid'])
            c.save(root / 'six-slots.json', slots)
            for name, bad in [('source-binding.json', None),
                              ('source-binding.json', {**source, 'diagnostic_source_commit': 'c' * 40}),
                              ('binary.json', {**binary, 'source_commit': 'c' * 40}),
                              ('binary.json', {**binary, 'sha256': 'bad hash'}),
                              ('binary-window-identity.json', {**window, 'after_sha256': 'c' * 64})]:
                if bad is None:
                    (root / name).unlink()
                else:
                    c.save(root / name, bad)
                with patch.dict(c.os.environ, env):
                    self.assertEqual(c.summarize(), 1)
                self.assertFalse(c.read(root / 'results.json')['source_and_binary_identity_valid'])
                c.save(root / 'source-binding.json', source)
                c.save(root / 'binary.json', binary)
                c.save(root / 'binary-window-identity.json', window)
            (root / 'source-binding.json').write_text('{malformed')
            with patch.dict(c.os.environ, env):
                self.assertEqual(c.summarize(), 1)
            self.assertFalse(c.read(root / 'results.json')['source_and_binary_identity_valid'])


class LinkedCaptureMocks(unittest.TestCase):
    def test_missing_optional_tools_retain_ELF_without_suppressing_the_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp);binary = root/'inert-input';binary.write_bytes(b'inert test bytes')
            output = root/'output';output.mkdir()
            with patch.object(linked.subprocess, 'check_output', side_effect=FileNotFoundError), \
                 patch.object(linked.subprocess, 'run') as process:
                result = linked.capture(binary, output)
            self.assertFalse(process.called)
            self.assertEqual(result['actual_ELF_sha256'], c.sha(binary))
            self.assertEqual(c.sha(output/'linked-evidence/compiled-test.elf'), c.sha(binary))
            self.assertEqual(len(result['optional_capture_errors']), 2)
            self.assertFalse(result['tools']['objdump']['available'])
            self.assertEqual(result['symbol_listings']['symbols-raw.txt']['status'], 'unavailable')
            self.assertFalse(result['timed_work_retention_verified_by_this_script'])

    def test_relevant_symbols_bounded_capture_and_ELF_identity_without_execution(self):
        names = ['_ZN8pratique6crypto6timing33ghash_batch_intermediate_controls17h111E',
                 '_ZN8pratique6crypto6timing14measure_seeded17h222E',
                 '_ZN8pratique6crypto5ghash8GhashKey4hash17h333E',
                 '_ZN8pratique6crypto3aes6unused17h444E']
        text = ''.join(f'{i:016x} t {n}\n' for i, n in enumerate(names))
        self.assertEqual(linked.symbol_names(text)[0], names[0])
        self.assertNotIn(names[-1], linked.symbol_names(text))
        self.assertIn(names[2], linked.symbol_names(text))
        commands = []
        def fake_run(argv, **kwargs):
            commands.append(argv)
            if argv[0] == 'nm':
                kwargs['stdout'].write(text.encode())
                return SimpleNamespace(returncode=0)
            self.assertEqual(argv[0], 'objdump')
            name = argv[2].split('=', 1)[1]
            return SimpleNamespace(stdout=(f'0000 <{name}>:\n 00: 90 nop\n').encode(), stderr=b'', returncode=0)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp);binary = root/'inert-input';binary.write_bytes(b'ELF fixture, never executable')
            output = root/'output';output.mkdir()
            with patch.object(linked.subprocess, 'run', side_effect=fake_run), \
                 patch.object(linked.subprocess, 'check_output', return_value='mock tool version\n'), \
                 patch.object(linked, 'DISASSEMBLY_LIMIT', 130):
                result = linked.capture(binary, output)
            self.assertEqual(result['actual_ELF_sha256'], c.sha(binary))
            self.assertEqual(c.sha(output/'linked-evidence/compiled-test.elf'), c.sha(binary))
            self.assertLessEqual(result['disassembly_bytes'], 130)
            self.assertTrue(result['omitted'])
            self.assertFalse(result['timed_work_retention_verified_by_this_script'])
            self.assertTrue(all(argv[0] in ['nm', 'objdump'] for argv in commands))


class DerivedContrasts(unittest.TestCase):
    def fixture(self, forward='+6.000', reverse='-2.000'):
        parsed = c.parse_controls(controls(group='swap'), 0, 'swap')
        for report in parsed['reports']:
            is_forward = report['name'] in [c.SWAP_NAMES[0], c.SWAP_NAMES[2]]
            for point in report['per_call']:
                point['difference_ns'] = c.token(forward if is_forward else reverse)
                point['standard_error_ns'] = c.token('0.300' if is_forward else '0.400')
        return [{'case': {'kind': 'swap', 'iteration': 1}, 'parsed': parsed}]

    def test_exact_pair_seed_crop_signs_Cov0_SE_and_no_new_judge(self):
        records = c.derive_swap_effects(self.fixture())
        self.assertEqual(len(records), 16)
        self.assertEqual(len({(v['pair'], v['seed'], v['keep']) for v in records}), 16)
        for value in records:
            self.assertEqual(value['value_effect_ns_from_printed_means'], '+4.0000')
            self.assertEqual(value['slot_effect_ns_from_printed_means'], '+2.0000')
            self.assertEqual(value['SE_if_zero_cross_row_covariance_ns'], '0.2500')
            self.assertIsNone(value['derived_judge'])
            self.assertIn('zero covariance is an approximation', value['cross_row_covariance'])
            self.assertIn('own pooled crop cutoff', value['model_limit'])
        reversed_values = c.derive_swap_effects(self.fixture('-2.000', '+6.000'))
        self.assertTrue(all(v['value_effect_ns_from_printed_means'] == '-4.0000' and v['slot_effect_ns_from_printed_means'] == '+2.0000' for v in reversed_values))
        # Distinct values in every join dimension catch seed/crop/pair/iteration reuse.
        crossed = self.fixture() + self.fixture()
        for iteration, item in enumerate(crossed, 1):
            item['case']['iteration'] = iteration
            for report in item['parsed']['reports']:
                row = c.SWAP_NAMES.index(report['name']);pair, reverse = divmod(row, 2)
                base = 100 * iteration + 10 * pair
                for crop, point in enumerate(report['per_call']):
                    delta = base - 1 + report['seed'] - crop if reverse else base + 3 + 2 * report['seed'] + 2 * crop
                    point['difference_ns'] = c.token(f'{delta:+.3f}')
        result = c.derive_swap_effects(crossed)
        self.assertEqual(len(result), 32)
        for value in result:
            crop = c.KEEPS.index(value['keep']);pair = 0 if value['pair'] == 'zero_nonzero' else 1
            expected_value = 2 + .5 * value['seed'] + 1.5 * crop
            expected_slot = 100 * value['iteration'] + 10 * pair + 1 + 1.5 * value['seed'] + .5 * crop
            self.assertEqual(value['value_effect_ns_from_printed_means'], f'{expected_value:+.4f}')
            self.assertEqual(value['slot_effect_ns_from_printed_means'], f'{expected_slot:+.4f}')

    def test_nonfinite_or_incomplete_pairs_are_not_fabricated(self):
        records = self.fixture()
        records[0]['parsed']['reports'][0]['per_call'][0]['difference_ns'] = c.token('NaN')
        result = c.derive_swap_effects(records)
        self.assertFalse(result[0]['derived_available'])
        self.assertIsNone(result[0]['value_effect_ns_from_printed_means'])
        records[0]['parsed']['complete'] = False
        self.assertEqual(c.derive_swap_effects(records), [])


if __name__ == '__main__':
    unittest.main()
