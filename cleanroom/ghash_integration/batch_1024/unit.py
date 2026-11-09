#!/usr/bin/env python3
"""Owned metadata/schema mocks only; no archived program or native test runs."""
import contextlib,importlib.util,io,json,os,signal,subprocess,tempfile,unittest
from pathlib import Path
from unittest import mock
import coordinate as c

PASS='test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 25s\n'
FAIL=PASS.replace('ok. 1 passed; 0 failed','FAILED. 0 passed; 1 failed')
def report(name,peak=1):return name+f'    n= 1024 median 8000 ns  |t| uncropped 0.1 max {peak:.1f} no leak detected\n'
def original(failed=None,unconfirmed=False):
    text='test crypto::timing::ghash_multiplication_is_constant_time ... '
    for i,name in enumerate(c.NAMES):
        repeat=name==failed or (unconfirmed and i==0)
        text+=report(name,6 if repeat else 1)
        if repeat:text+='    above 4.5; measuring '+json.dumps(name)+' again with fresh inputs\n'+report(name,7 if name==failed else 2)
    if failed:text+='thread panicked at timing.rs:1:\ntiming depends on the input:\n  '+failed+': t = +6.0 and +7.0 on repeat\n'+FAIL
    else:text+=PASS
    return text

class BatchContract(unittest.TestCase):
    def test_original_timing_failure_is_complete_finding_and_unconfirmed_preserved(self):
        failed=c.parse_original(original(c.NAMES[4]),101)
        self.assertTrue(failed['complete']);self.assertEqual(failed['confirmed_rows'],[c.NAMES[4]])
        self.assertEqual(len(failed['rows'][c.NAMES[0]]),1)
        unconfirmed=c.parse_original(original(unconfirmed=True),0)
        self.assertTrue(unconfirmed['complete']);self.assertFalse(unconfirmed['confirmed_rows']);self.assertEqual(unconfirmed['fresh_rechecks'],[c.NAMES[0]])
        infinite=c.parse_original(original(c.NAMES[4]).replace('max 6.0','max inf').replace('max 7.0','max inf'),101)
        self.assertTrue(infinite['complete']);self.assertEqual(infinite['rows'][c.NAMES[4]][0]['printed_max_abs_t'],'+Infinity')
        json.dumps(infinite,allow_nan=False)
        unknown=c.parse_original(original().replace('max 1.0','max NaN'),0)
        self.assertIsNone(unknown['rows'][c.NAMES[0]][0]['printed_max_abs_t']);json.dumps(unknown,allow_nan=False)
        for text,exit_code in [(original(c.NAMES[2]),0),(original(),101),(original().replace(PASS,FAIL),101),(original(c.NAMES[4]).replace('timing depends on the input:','other panic:'),101),(original().replace(c.NAMES[-1],'unknown row'),0),(original(c.NAMES[4]).replace('above 4.5; measuring','unrelated'),101)]:
            with self.subTest(exit=exit_code):self.assertFalse(c.parse_original(text,exit_code)['complete'])

    def test_repeat_paths_environment_and_new_VM_identity_are_disjoint(self):
        first=c.environment(1);second=c.environment(2)
        self.assertNotEqual(first['RUNNER_TEMP'],second['RUNNER_TEMP'])
        self.assertNotEqual(first['PRATIQUE_FOCUSED_OUTPUT'],second['PRATIQUE_FOCUSED_OUTPUT'])
        self.assertEqual(first['PRATIQUE_PAIRED_VM_OUTPUT'],second['PRATIQUE_PAIRED_VM_OUTPUT'])
        self.assertEqual(first.get('GITHUB_SHA'),os.environ.get('GITHUB_SHA'))
        self.assertNotIn('PRATIQUE_BATCH_REPLICA',first);self.assertNotIn('PRATIQUE_REPLICA',first)
        with mock.patch.dict(os.environ,second):
            spec=importlib.util.spec_from_file_location('coordinator_reloaded_metadata_only',Path(c.__file__))
            loaded=importlib.util.module_from_spec(spec);spec.loader.exec_module(loaded)
            self.assertEqual(loaded.OUT,c.OUT);self.assertEqual(loaded.ENVROOT,c.ENVROOT)

    def test_all_four_native_phases_continue_after_first_failure(self):
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(c,'OUT',Path(tmp)):
            for failure in [101,1,'timeout','collector_error']:
                calls=[]
                def runner(path,label,argv,env,seconds):
                    calls.append((path.name,label,seconds));return {'exit_code':failure if len(calls)==1 else 0}
                checker=mock.Mock(return_value=True)
                c.sequence(1,{'selected_cpu':3},runner,checker);c.sequence(2,{'selected_cpu':3},runner,checker)
                self.assertEqual([(t,p) for t,p,_ in calls],[('trial-1','original'),('trial-1','focused'),('trial-2','original'),('trial-2','focused')])
                self.assertEqual([s for _,_,s in calls],[110,175,110,175])
            calls=[]
            c.sequence(2,{'selected_cpu':3},lambda *args:calls.append(args),mock.Mock(side_effect=ValueError('bad immutable stage')))
            self.assertFalse(calls)

    def test_timeout_cleanup_targets_session_and_retains_timeout(self):
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(c.subprocess,'Popen') as popen,mock.patch.object(c.os,'killpg') as kill,contextlib.redirect_stdout(io.StringIO()):
            p=popen.return_value;p.pid=12345;p.wait.side_effect=[subprocess.TimeoutExpired('mock',1),0,0]
            value=c.phase(Path(tmp),'mock-phase',['owned-placeholder'],{},1)
            self.assertEqual(value['exit_code'],'timeout');self.assertTrue(popen.call_args.kwargs['start_new_session'])
            self.assertEqual(kill.call_args_list,[mock.call(12345,signal.SIGTERM),mock.call(12345,signal.SIGKILL)])

    def test_interruption_and_cleanup_error_preserve_incomplete_and_prevent_overlap(self):
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(c,'OUT',Path(tmp)),mock.patch.object(c.subprocess,'Popen') as popen,mock.patch.object(c.os,'killpg'),contextlib.redirect_stdout(io.StringIO()):
            p=popen.return_value;p.pid=12345;p.wait.side_effect=[KeyboardInterrupt(),0,0]
            with self.assertRaises(SystemExit):c.phase(Path(tmp),'interrupted',['owned-placeholder'],{},1)
            self.assertEqual(c.read(Path(tmp)/'interrupted.json')['exit_code'],'interrupted')
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(c,'OUT',Path(tmp)),mock.patch.object(c.subprocess,'Popen') as popen,mock.patch.object(c.os,'killpg',side_effect=PermissionError('mock')),contextlib.redirect_stdout(io.StringIO()):
            p=popen.return_value;p.pid=12345;p.wait.side_effect=[subprocess.TimeoutExpired('mock',1),0,0]
            result=c.phase(Path(tmp),'cleanup-error',['owned-placeholder'],{},1)
            self.assertTrue(result['cleanup_incomplete']);self.assertTrue((Path(tmp)/'native-cleanup-unsafe.json').exists())
            with self.assertRaises(AssertionError):c.valid_stage(2,{})

    def test_core_and_frozen_identity_metadata_fail_closed(self):
        plan={'current_job_commit':'new-job-head','selected_cpu':2}
        good={'current_job_commit':'new-job-head','checkout_commit':'new-job-head','artifact_diagnostic_commit':c.frozen()['artifact_diagnostic_commit'],
            'production_source_commit':c.frozen()['production_source_commit'],'selected_cpu':2,'affinity':[2],
            'immutable_input':{'archive_sha256':c.frozen()['archive_sha256'],'files':c.frozen()['files']},'adapter_source_hashes':c.identity()['focused_source_files']}
        c.validate_metadata(good,plan)
        for changes in [{'selected_cpu':3},{'affinity':[0,2]},{'current_job_commit':c.frozen()['artifact_diagnostic_commit']},{'artifact_diagnostic_commit':'wrong'},{'adapter_source_hashes':{}}]:
            with self.assertRaises((AssertionError,KeyError)):c.validate_metadata({**good,**changes},plan)

    def test_missing_partial_aggregate_keeps_all40_slots_and_audits(self):
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(c,'OUT',Path(tmp)):
            missing=c.summarize_trial(1,{'vm':6})
            self.assertEqual(missing['focused']['classification'],'incomplete');self.assertIsNone(missing['focused']['positive_miss'])
            self.assertIsNone(missing['focused']['footer']);self.assertFalse(missing['original']['complete'])
            self.assertEqual(missing['post_CI_full_focused_raw_priority_reasons'],['predeclared_audit_no_substitution'])
        supplied={'vm':1,'trials':[{'vm':1,'trial':1,'original':{'complete':True,'confirmed_rows':[c.NAMES[4]]},'focused':{'classification':'complete_unhealthy','row_confirmations':{'negative_identical_equal':True}}}]}
        result=c.aggregate({1:supplied})
        self.assertEqual(len(result['trials']),40);self.assertEqual(result['missing_trial_slots'],39)
        self.assertEqual(result['planned_native_child_slots'],80);self.assertEqual(result['original_completed_confirmed_trials'],1)
        self.assertEqual(result['focused_classifications'],{'complete_healthy':0,'complete_unhealthy':1,'incomplete':39})
        self.assertEqual(result['quiet_audit_slots'],[[1,1],[6,1],[11,1],[16,1]])
        self.assertIsNone(next(iter(result['CPU_feature_groups'].values()))['cpu']['flags'])

    def test_frozen_source_guards_and_budget(self):
        c.guards();self.assertEqual(len(c.identity()['focused_source_files']),5);self.assertEqual(len(c.frozen()['source_files']),13)
        self.assertLess(2*(c.ORIGINAL_SECONDS+c.FOCUSED_SECONDS+8),2*5*60)
        self.assertLess(2*(c.REPORT_SECONDS+4),2*60)
        self.assertEqual(1+1+3+5+5+2+1,18)

if __name__=='__main__':unittest.main(verbosity=2)
