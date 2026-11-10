#!/usr/bin/env python3
"""Administrative regressions; no downloaded/native project code is executed.

Fixture logs are the retained completed A3 artifact, supplied explicitly.
These are collector tests, never timing/security passes.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run as runner

options = argparse.ArgumentParser()
options.add_argument('--baseline-source', type=Path, required=True)
options.add_argument('--artifact', type=Path, required=True)
ARGS, remaining = options.parse_known_args()
PARSER_PATH = ARGS.baseline_source / 'cleanroom/ghash_integration/class_controls_8370c/run.py'
assert runner.sha(PARSER_PATH) == runner.CONFIG['parser_sha256']
spec = importlib.util.spec_from_file_location('frozen_parser_test', PARSER_PATH)
PARSER = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PARSER)
FIXTURE_LOGS = {'gate': ARGS.artifact / '01-gate-1/stdout-stderr.log',
                'swap': ARGS.artifact / '02-swap-1/stdout-stderr.log'}
assert all(p.is_file() for p in FIXTURE_LOGS.values())


class Collector(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='pratique-paired-admin-test-')
        self.root = Path(self.temp.name)
        self.environment = patch.dict(os.environ, {'PRATIQUE_PAIR_OUTPUT': str(self.root),
                                                  'GITHUB_WORKSPACE': str(self.root / 'workspace')})
        self.environment.start()
        self.config = runner.CONFIG.copy()
        runner.CONFIG = {**self.config, 'candidate_commit': '1'*40}
        runner.CANCELLED = False
        self.verify = patch.object(runner, 'verify', return_value={})
        self.verify.start()
        self.parser = patch.object(runner, 'parser_module', return_value=PARSER)
        self.parser.start()
        for version in runner.VERSIONS:
            binary = self.root / (version + '.fixture')
            binary.write_bytes(('Unexecuted public fixture: ' + version).encode())
            root = self.root / version
            (root / 'linked-evidence').mkdir(parents=True)
            shutil.copyfile(binary, root / 'linked-evidence/compiled-test.elf')
            runner.save(root / 'binary.json', {'path': str(binary), 'sha256': runner.sha(binary),
                                              'source_commit': runner.CONFIG[version + '_commit']})
        for phase in ['correctness', 'profile']:
            records = []
            for v in runner.VERSIONS:
                binary = self.root / (v + '.fixture')
                directory = self.root / ('auxiliary-' + phase + '-' + v)
                directory.mkdir()
                log = directory / 'stdout-stderr.log'
                log.write_text('test result: ok. ' + ('191' if phase == 'correctness' else '1')
                               + ' passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n')
                selector = 'crypto::' if phase == 'correctness' else 'crypto::integration_profile::release_profile'
                args = (['--nocapture', '--test-threads=1'] if phase == 'correctness' else
                        ['--exact', '--ignored', '--nocapture', '--test-threads=1'])
                record = {'version': v, 'passed': True, 'source_commit': runner.CONFIG[v + '_commit'],
                          'binary_sha256': runner.sha(binary), 'binary_sha256_after': runner.sha(binary),
                          'execution': 'finished', 'exit_code': 0, 'stdout_stderr_sha256': runner.sha(log),
                          'argv': [str(binary), selector, *args], 'timeout_seconds': 60}
                records.append(record)
                runner.save(directory / 'case.json', record)
            runner.save(self.root / ('auxiliary-' + phase + '.json'),
                        records)

    def tearDown(self):
        self.parser.stop()
        self.verify.stop()
        self.environment.stop()
        runner.CONFIG = self.config
        runner.CANCELLED = False
        self.temp.cleanup()

    def fake(self, case, binary, directory):
        directory.mkdir(parents=True)
        log = directory / 'stdout-stderr.log'
        shutil.copyfile(FIXTURE_LOGS[case['kind']], log)
        result = {**case, 'execution': 'finished', 'exit_code': 101 if case['kind'] == 'gate' else 0,
                  'stdout_stderr_sha256': runner.sha(log), 'timeout_seconds': runner.CASE_SECONDS,
                  'argv': [str(binary), case['selector'], '--exact', '--ignored', '--nocapture', '--test-threads=1']}
        runner.save(directory / 'case.json', result)
        return result

    def test_twenty_fixed_counterbalanced_calls_despite_gate_failures(self):
        self.assertEqual(runner.run_all(self.fake), 0)
        slots = runner.load(self.root / 'twenty-slots.json')
        self.assertEqual(len(slots), 20)
        self.assertEqual(sum(s['exit_code'] == 101 for s in slots), 10)
        self.assertEqual([s['version'] for s in slots[:8]],
                         ['baseline', 'baseline', 'candidate', 'candidate',
                          'candidate', 'candidate', 'baseline', 'baseline'])
        for version in runner.VERSIONS:
            self.assertEqual([s['kind'] for s in slots if s['version'] == version], ['gate', 'swap']*5)

    def test_interruption_flag_stops_remaining_slots(self):
        calls = []
        def interrupted(case, binary, directory):
            calls.append(case['slot'])
            return {**self.fake(case, binary, directory), 'interrupted': True}
        runner.run_all(interrupted)
        slots = runner.load(self.root / 'twenty-slots.json')
        self.assertEqual(calls, [1])
        self.assertTrue(all(s['execution'] == 'not_attempted' for s in slots[1:]))
        self.assertTrue(all('reason' in s for s in slots[1:]))

    def test_unsafe_cleanup_stops_remaining_slots(self):
        calls = []
        def unsafe(case, binary, directory):
            calls.append(case['slot'])
            return {**self.fake(case, binary, directory), 'cleanup_incomplete': 'fixture'}
        self.assertNotEqual(runner.run_all(unsafe), 0)
        self.assertEqual(calls, [1])

    def test_last_timing_unsafe_returns_failure_for_dependent_stage(self):
        calls = []
        def unsafe_last(case, binary, directory):
            calls.append(case['slot'])
            record = self.fake(case, binary, directory)
            if case['slot'] == 20:
                record['cleanup_incomplete'] = 'fixture'
            return record
        self.assertNotEqual(runner.run_all(unsafe_last), 0)
        self.assertEqual(len(calls), 20)

    def test_second_correctness_unsafe_cannot_start_timing(self):
        def fake_aux(case, binary, directory, timeout):
            log = directory / 'stdout-stderr.log'
            return {**case, 'execution': 'finished', 'exit_code': 0,
                    'stdout_stderr_sha256': runner.sha(log), 'timeout_seconds': timeout,
                    'argv': [str(binary), case['selector'], *case['test_arguments']],
                    **({'cleanup_incomplete': 'fixture'} if case['version'] == 'candidate' else {})}
        with patch.object(runner, 'execute_case', side_effect=fake_aux):
            self.assertNotEqual(runner.auxiliary('correctness'), 0)
        records = runner.load(self.root / 'auxiliary-correctness.json')
        self.assertTrue(records[0]['passed'])
        self.assertFalse(records[1]['passed'])

    def test_modified_binary_is_rejected_before_its_next_call(self):
        calls = []
        def modify(case, binary, directory):
            calls.append(case['slot'])
            if case['slot'] == 1:
                (self.root / 'candidate.fixture').write_bytes(b'changed fixture')
            return self.fake(case, binary, directory)
        with self.assertRaises(AssertionError):
            runner.run_all(modify)
        self.assertEqual(calls, [1, 2])

    def test_keyboardinterrupt_is_recorded_and_sets_cancellation(self):
        process = Mock(pid=123456)
        process.wait.side_effect = [KeyboardInterrupt(), 0, 0]
        with patch.object(runner.subprocess, 'Popen', return_value=process), patch.object(runner.os, 'killpg') as kill:
            record = runner.execute_case(runner.planned()[0], self.root / 'baseline.fixture', self.root / 'interrupt')
        self.assertTrue(record['interrupted'])
        self.assertTrue(runner.CANCELLED)
        self.assertEqual([c.args for c in kill.call_args_list],
                         [(123456, signal.SIGTERM), (123456, signal.SIGKILL)])

    def test_full_retention_is_distinct_from_security_or_gate_success(self):
        runner.run_all(self.fake)
        self.assertEqual(runner.summarize(), 0)
        result = runner.load(self.root / 'results.json')
        self.assertTrue(result['collection_complete'])
        self.assertFalse(result['causal_or_security_closure'])
        self.assertTrue(all(result['candidate']['gate_confirmed_rows'].values()))
        for version in runner.VERSIONS:
            derived = runner.load(self.root / version / 'derived-swap-effects.json')
            self.assertEqual(len(derived), 80)
            self.assertEqual({r['iteration'] for r in derived}, {1, 2, 3, 4, 5})

    def test_wrong_source_in_one_slot_is_incomplete(self):
        runner.run_all(self.fake)
        slots = runner.load(self.root / 'twenty-slots.json')
        slots[3]['source_commit'] = '2'*40
        runner.save(self.root / 'twenty-slots.json', slots)
        self.assertEqual(runner.summarize(), 1)

    def test_missing_slot_is_incomplete(self):
        runner.run_all(self.fake)
        slots = runner.load(self.root / 'twenty-slots.json')
        runner.save(self.root / 'twenty-slots.json', slots[:-1])
        self.assertEqual(runner.summarize(), 1)

    def test_retained_elf_mismatch_is_incomplete(self):
        runner.run_all(self.fake)
        (self.root / 'candidate/linked-evidence/compiled-test.elf').write_bytes(b'changed fixture')
        self.assertEqual(runner.summarize(), 1)

    def test_unsafe_or_unbound_completed_logs_are_incomplete(self):
        runner.run_all(self.fake)
        original = runner.load(self.root / 'twenty-slots.json')
        directory = self.root / '01-baseline-gate-1'
        for field, value in [('interrupted', True), ('cleanup_incomplete', 'fixture'),
                             ('execution', 'started'), ('stdout_stderr_sha256', None),
                             ('argv', ['wrong arguments']), ('timeout_seconds', 1)]:
            with self.subTest(field=field):
                slots = json.loads(json.dumps(original))
                slots[0][field] = value
                runner.save(self.root / 'twenty-slots.json', slots)
                runner.save(directory / 'case.json', slots[0])
                self.assertEqual(runner.summarize(), 1)
                self.assertTrue(runner.load(self.root / 'results.json')['binding_errors'])
                self.assertTrue((self.root / 'SHA256SUMS.json').exists())

    def test_changed_log_keeps_results_and_manifest(self):
        runner.run_all(self.fake)
        with (self.root / '01-baseline-gate-1/stdout-stderr.log').open('a') as stream:
            stream.write('\nchanged public fixture\n')
        self.assertEqual(runner.summarize(), 1)
        self.assertTrue(runner.load(self.root / 'results.json')['binding_errors'])
        self.assertTrue((self.root / 'SHA256SUMS.json').exists())

    def test_malformed_metadata_keeps_results_and_manifest(self):
        runner.run_all(self.fake)
        (self.root / 'twenty-slots.json').write_text('not valid json')
        self.assertEqual(runner.summarize(), 1)
        self.assertFalse(runner.load(self.root / 'results.json')['collection_complete'])
        self.assertTrue((self.root / 'SHA256SUMS.json').exists())


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *remaining])
