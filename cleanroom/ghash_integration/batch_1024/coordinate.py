#!/usr/bin/env python3
"""Fixed20 VMs ×2 paired original/focused GHASH trials; no outcome stopping."""
import hashlib,importlib,json,math,os,re,shutil,signal,subprocess,sys,time,zipfile
from pathlib import Path

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
FOCUSED=HERE.parent/'focused_1024';LEGACY=HERE.parent/'timing_diagnostics'
TEMP=Path(os.environ.get('RUNNER_TEMP','/private/tmp'))
OUT=Path(os.environ.get('PRATIQUE_PAIRED_VM_OUTPUT',str(TEMP/'paired-ghash-output')))
ENVROOT=Path(os.environ.get('PRATIQUE_PAIRED_ENV_ROOT',str(TEMP/'paired-ghash-environments')))
VM=int(os.environ.get('PRATIQUE_REGRESSION_VM_ID','1'))
ORIGINAL_SECONDS=110;FOCUSED_SECONDS=175;REPORT_SECONDS=45;PREPARE_SECONDS=40
QUIET_AUDIT=[1,6,11,16]
NAMES=[
 'ghash [Portable] data blocks: 0 vs random (fixed H)',
 'ghash [Portable] data blocks: all ones vs random (fixed H)',
 'ghash [Portable] hash key H: 0 vs random',
 'ghash [Portable] hash key H: all ones vs random',
 'ghash [Portable] batch 1024 data: 0 vs random',
 'ghash [Portable] batch 1024 prepared H: 0 vs random',
 'ghash [Portable] batch 2049 data: 0 vs random',
 'ghash [Portable] batch 2049 prepared H: 0 vs random']

def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    return h.hexdigest()
def save(p,v):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(v,indent=2,allow_nan=False)+'\n')
def read(p):return json.loads(p.read_text())
def obj(v):return v if isinstance(v,dict) else {}
def identity():return read(HERE/'identity.json')
def frozen():return read(FOCUSED/'frozen_identity.json')
def guards():
    for name,h in identity()['focused_source_files'].items():assert sha(ROOT/name)==h,name
    assert len(frozen()['source_files'])==13
    for name,h in frozen()['source_files'].items():assert sha(LEGACY/name)==h,name
def inventory():
    paths=[HERE/n for n in ['coordinate.py','identity.json','unit.py','PROTOCOL.md']]+[ROOT/'.github/workflows/pr10-ghash-1024-batch.yml']
    return {str(p.relative_to(ROOT)):sha(p) for p in paths}
def layout(trial):
    assert trial in [1,2]
    return OUT/f'trial-{trial}',ENVROOT/f'trial-{trial}'
def environment(trial):
    output,temp=layout(trial)
    return {**os.environ,'RUNNER_TEMP':str(temp),'PRATIQUE_FOCUSED_OUTPUT':str(output),'PRATIQUE_PAIRED_TRIAL':str(trial),
        'PRATIQUE_PAIRED_VM_OUTPUT':str(OUT),'PRATIQUE_PAIRED_ENV_ROOT':str(ENVROOT)}
def footer(text):
    matches=re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',text,re.M)
    if len(matches)!=1:return None
    status,p,f,i=matches[0]
    if int(p)+int(f)!=1 or i!='0' or (status=='ok')!=(f=='0'):return None
    return {'status':status,'passed':int(p),'failed':int(f)}

def cleanup(process,record):
    """Kill only this launched session/group, including a surviving ELF child."""
    actions=[]
    for sig in [signal.SIGTERM,signal.SIGKILL]:
        try:os.killpg(process.pid,sig);actions.append(signal.Signals(sig).name)
        except ProcessLookupError:pass
        except OSError as e:record['cleanup_incomplete']=True;record['cleanup_error']=repr(e)
        if sig==signal.SIGTERM:
            try:process.wait(timeout=2)
            except subprocess.TimeoutExpired:pass
    try:process.wait(timeout=2)
    except subprocess.TimeoutExpired:record['cleanup_incomplete']=True
    record['process_group_cleanup_signals']=actions
def phase(path,label,argv,env,seconds):
    record={'label':label,'argv':argv,'timeout_seconds':seconds,'execution_state':'starting'}
    save(path/(label+'.json'),record);started=time.monotonic();process=None;interrupted=False
    try:
        with (path/(label+'.stdout.log')).open('w') as log:
            process=subprocess.Popen(argv,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            record['process_group_id']=process.pid
            try:record['exit_code']=process.wait(timeout=seconds)
            except subprocess.TimeoutExpired:record['exit_code']='timeout'
    except (KeyboardInterrupt,SystemExit) as e:record['exit_code']='interrupted';record['error']=type(e).__name__;interrupted=True
    except Exception as e:record['exit_code']='collector_error';record['error']=repr(e)
    finally:
        if process:cleanup(process,record)
        if record.get('cleanup_incomplete'):save(OUT/'native-cleanup-unsafe.json',record)
    record.update(execution_state='finished',elapsed_seconds=time.monotonic()-started)
    save(path/(label+'.json'),record)
    print(json.dumps({'phase':label,'exit_code':record['exit_code'],'elapsed_seconds':record['elapsed_seconds']}),flush=True)
    if interrupted:raise SystemExit('Interrupted phase was cleaned up; partial evidence retained.')
    return record

def stage_original():
    info=identity()['original'];archive=TEMP/'phase1.zip'
    assert archive.stat().st_size==info['archive_bytes'] and sha(archive)==info['archive_sha256']
    with zipfile.ZipFile(archive) as z:
        assert len(z.namelist())==len(set(z.namelist()))
        for name in [info['binary_member'],info['record_member']]:
            target=OUT/'sealed-input'/name;assert target.resolve().is_relative_to((OUT/'sealed-input').resolve())
            target.parent.mkdir(parents=True,exist_ok=True)
            with z.open(name) as src,target.open('wb') as dst:shutil.copyfileobj(src,dst,1<<20)
    binary=OUT/'sealed-input'/info['binary_member']
    assert sha(binary)==info['binary_sha256']
    assert read(OUT/'sealed-input'/info['record_member'])['normal_sha256']==info['binary_sha256']
    binary.chmod(0o755)

def validate_metadata(settings,plan):
    assert settings['current_job_commit']==plan['current_job_commit']
    assert settings['checkout_commit']==plan['current_job_commit']
    assert settings['artifact_diagnostic_commit']==frozen()['artifact_diagnostic_commit']
    assert settings['production_source_commit']==frozen()['production_source_commit']
    assert settings['selected_cpu']==plan['selected_cpu'] and settings['affinity']==[plan['selected_cpu']]
    assert settings['immutable_input']['archive_sha256']==frozen()['archive_sha256']
    assert settings['immutable_input']['files']==frozen()['files']
    assert settings['adapter_source_hashes']==identity()['focused_source_files']
def valid_stage(trial,plan):
    assert not (OUT/'native-cleanup-unsafe.json').exists(),'prior process-group cleanup unresolved; no overlapping execution'
    guards();assert inventory()==plan['coordinator_sources']
    output,_=layout(trial);validate_metadata(read(output/'settings.json'),plan)
    for name,h in frozen()['files'].items():assert sha(output/'immutable-input'/name)==h
    assert sha(OUT/'sealed-input'/identity()['original']['binary_member'])==identity()['original']['binary_sha256']
    return True

def prepare():
    assert sys.platform=='linux' and os.uname().machine=='x86_64'
    assert 1<=VM<=20 and not (OUT/'vm-plan.json').exists(),'fixed VM slot; no restart'
    OUT.mkdir(parents=True,exist_ok=True)
    affinity=sorted(os.sched_getaffinity(0));assert affinity
    head=subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip()
    plan={'vm':VM,'planned_trials':[1,2],'current_job_commit':os.environ['GITHUB_SHA'],'selected_cpu':affinity[0],
        'allowed_affinity_before_pin':affinity,'coordinator_sources':inventory(),'stage':{},'scope':'Fixed20 VMs×2 paired trials; all80 native slots retained, no replacement or outcome stopping.'}
    save(OUT/'vm-plan.json',plan)
    assert head==plan['current_job_commit']
    assert 'PRATIQUE_BATCH_REPLICA' not in os.environ and 'PRATIQUE_REPLICA' not in os.environ
    guards();stage_original()
    archive=TEMP/'focused-binary.zip'
    assert archive.stat().st_size==frozen()['archive_bytes'] and sha(archive)==frozen()['archive_sha256']
    for trial in [1,2]:
        output,temp=layout(trial);output.mkdir(parents=True,exist_ok=True);temp.mkdir(parents=True,exist_ok=True)
        try:os.link(archive,temp/'focused-binary.zip');link='hardlink'
        except OSError:shutil.copyfile(archive,temp/'focused-binary.zip');link='copy'
        p=phase(output,'prepare',['taskset','-c',str(plan['selected_cpu']),sys.executable,str(FOCUSED/'focused.py'),'prepare'],environment(trial),PREPARE_SECONDS)
        try:valid_stage(trial,plan);valid=p['exit_code']==0;error=None
        except Exception as e:valid=False;error=repr(e)
        plan['stage'][str(trial)]={'valid':valid,'error':error,'archive_staging':link,'phase_exit':p['exit_code']}
        save(OUT/'vm-plan.json',plan)
    if not all(x['valid'] for x in plan['stage'].values()):raise SystemExit('One or more stages invalid; later valid trials still run.')

def reference(trial):
    plan=read(OUT/'vm-plan.json');valid_stage(trial,plan)
    sys.path.insert(0,str(LEGACY));old=importlib.import_module('run_batch')
    output,_=layout(trial);old.OUT=output;old.INPUT=OUT/'sealed-input';old.COMPANION=output/'immutable-input';old.replay.COMPANION=old.COMPANION
    # Existing helper keeps the exact sealed selector, timing budget, recorder
    # and original judge. An original child101 is a finding, not wrapper failure.
    old.run_case(output/'sealed-original','normal')

def sequence(trial,plan,runner=phase,checker=valid_stage):
    output,_=layout(trial);output.mkdir(parents=True,exist_ok=True);env=environment(trial)
    commands=[('original',[sys.executable,str(HERE/'coordinate.py'),'reference',str(trial)],ORIGINAL_SECONDS),
        ('focused',[sys.executable,str(FOCUSED/'focused.py'),'run'],FOCUSED_SECONDS)]
    results={}
    for label,argv,seconds in commands:
        try:checker(trial,plan)
        except Exception as e:
            results[label]={'execution_state':'skipped','reason':'immutable/source/core staging invalid','error':repr(e)}
            save(output/(label+'.json'),results[label]);continue
        # No decision here depends on any preceding child, health or report exit.
        try:
            results[label]=runner(output,label,['taskset','-c',str(plan['selected_cpu']),*argv],env,seconds)
            if results[label].get('cleanup_incomplete'):save(OUT/'native-cleanup-unsafe.json',results[label])
        except Exception as e:
            results[label]={'execution_state':'collector_error','error':repr(e)};save(output/(label+'.json'),results[label])
    return results

def trial(number):
    plan=read(OUT/'vm-plan.json');assert 1<=plan['vm']<=20
    output,_=layout(number);assert not (output/'trial-started.json').exists(),'no retry'
    save(output/'trial-started.json',{'trial':number,'vm':plan['vm'],'time':time.time()})
    sequence(number,plan)

def reports():
    plan=read(OUT/'vm-plan.json')
    # Both native paired trials finish before either linear CSV report starts.
    for number in [1,2]:
        output,_=layout(number);output.mkdir(parents=True,exist_ok=True)
        try:
            guards();assert inventory()==plan['coordinator_sources']
            phase(output,'report',['taskset','-c',str(plan['selected_cpu']),sys.executable,str(FOCUSED/'focused.py'),'report'],environment(number),REPORT_SECONDS)
        except Exception as e:save(output/'report.json',{'execution_state':'collector_error','error':repr(e)})

def parse_original(text,exit_code):
    rows={name:[] for name in NAMES};unknown=[]
    for line in text.splitlines():
        for name in NAMES:
            # The initial row can share the Rust harness's 'test ...' line.
            match=re.search(re.escape(name)+r'\s+n=\s*(\d+)\s+median\s+(\d+) ns\s+\|t\| uncropped\s+([0-9.]+|inf|NaN)\s+max\s+([0-9.]+|inf|NaN)',line)
            if match:
                value=float(match[4]);value=value if math.isfinite(value) else ('+Infinity' if value>0 else None)
                rows[name].append({'display':line,'samples':int(match[1]),'median_ns':int(match[2]),'printed_max_abs_t':value})
    marker='timing depends on the input:\n';summary=text.rsplit(marker,1)[1] if marker in text else ''
    confirmed=[];summary_lines=re.findall(r'^  (ghash[^\n]+)$',summary,re.M)
    for line in summary_lines:
        matches=[n for n in NAMES if line.startswith(n+': ')]
        if len(matches)!=1:unknown.append(line)
        else:confirmed.append(matches[0])
    f=footer(text);timing_failure=bool(confirmed)
    reports_complete=all(1<=len(v)<=2 for v in rows.values())
    # Printed maxima are rounded; do not replay the exact judge from them.
    repeats=[n for n,v in rows.items() if len(v)==2]
    repeats_announced=[n for n in NAMES if re.search(r'above 4\.5; measuring '+re.escape(json.dumps(n))+r' again with fresh inputs',text)]
    complete=(reports_complete and set(repeats)==set(repeats_announced) and not unknown
        and len(confirmed)==len(set(confirmed)) and set(confirmed)<=set(repeats)
        and ((exit_code==0 and f=={'status':'ok','passed':1,'failed':0} and not timing_failure and marker not in text)
             or (exit_code==101 and f=={'status':'FAILED','passed':0,'failed':1} and timing_failure and text.count(marker)==1)))
    return {'complete':complete,'child_exit':exit_code,'footer':f,'confirmed_rows':confirmed,'final_summary_lines':summary_lines,
        'unknown_summary_lines':unknown,'rows':rows,'fresh_rechecks':repeats,'fresh_rechecks_announced':repeats_announced,
        'judge_source':'Unchanged final summary only; one-decimal reports do not support exact judge reconstruction.'}

def safe_json(path):
    try:
        v=read(path)
        return v if isinstance(v,dict) else {'load_error':'not an object'}
    except Exception as e:return {'load_error':repr(e)}
def cpu_metadata(settings):
    text=obj(settings.get('lscpu')).get('output','');info=settings.get('proc_cpuinfo','');probe=obj(settings.get('same_core_default_probe'))
    if not isinstance(text,str):text=''
    def field(name):
        m=re.search(r'^'+re.escape(name)+r':\s*(.+)$',text,re.M);return m[1].strip() if m else None
    flags=re.search(r'^flags\s*:\s*(.+)$',info,re.M) if isinstance(info,str) else None
    return {'model_name':field('Model name'),'family':field('CPU family'),'model':field('Model'),'stepping':field('Stepping'),
        'flags':sorted(flags[1].split()) if flags else None,'XCR0':probe.get('xcr0_hex'),'active_AVX512F':probe.get('active_AVX512F')}
def summarize_trial(number,plan):
    output,_=layout(number);settings=safe_json(output/'settings.json');focused=safe_json(output/'outcomes.json')
    original_case=safe_json(output/'sealed-original/case.json');log=output/'sealed-original/run.log'
    original=parse_original(log.read_text() if log.exists() else '',original_case.get('exit_code'))
    original['child_elapsed_seconds']=original_case.get('elapsed_seconds')
    phases={name:safe_json(output/(name+'.json')) for name in ['original','focused','report']}
    try:valid_stage(number,plan);stage=True
    except Exception:stage=False
    original['complete']=bool(original['complete'] and stage and phases['original'].get('exit_code')==0 and original_case.get('cpu')==plan.get('selected_cpu')
        and original_case.get('binary_sha256')==identity()['original']['binary_sha256'])
    complete=bool(focused.get('collection_complete') is True and stage and phases['focused'].get('exit_code')==0
        and phases['report'].get('exit_code')==(0 if focused.get('control_health') else 1))
    health=focused.get('control_health') if complete else None
    status=obj(focused.get('original_control_status'));flags=obj(status.get('booleans')).copy()
    raw_status=output/'DATA-controls/batch-control-results.txt'
    if not flags and raw_status.exists():
        for line in raw_status.read_text().splitlines():
            key,sep,value=line.partition('=')
            if sep and value in ['true','false'] and key not in flags:flags[key]=value=='true'
    row_flags={name:flags.get(name+'_confirmed_failure') for name in frozen()['rows']}
    reasons=['original:'+name for name in original['confirmed_rows']]
    reasons+=['focused:'+name for name,value in row_flags.items() if name!='positive_matched' and value is True]
    detected=flags.get('positive_matched_detected');positive_confirmed=row_flags.get('positive_matched')
    positive_miss=True if detected is False or positive_confirmed is False else False if detected is True and positive_confirmed is True else None
    if positive_miss:reasons.append('matched_positive_miss')
    if plan.get('vm') in QUIET_AUDIT and number==1:reasons.append('predeclared_audit_no_substitution')
    case=obj(focused.get('case',safe_json(output/'DATA-controls/case.json')))
    focus_log=output/'DATA-controls/run.log';focus_text=focus_log.read_text() if focus_log.exists() else ''
    return {'vm':plan.get('vm'),'trial':number,'selected_cpu':plan.get('selected_cpu'),'cpu':cpu_metadata(settings),'stage_valid':stage,'phases':phases,
        'original':original,'focused':{'classification':'complete_healthy' if complete and health else 'complete_unhealthy' if complete else 'incomplete',
            'collection_complete':complete,'control_health':health,'child_exit':case.get('exit_code'),'child_elapsed_seconds':case.get('elapsed_seconds'),
            'row_confirmations':row_flags,'positive_miss':positive_miss,'full_status_validated':bool(focused.get('original_control_status')),
            'sensitivity':flags.get('sensitivity'),'early_exit':flags.get('early_exit'),'final_calibration_in_range':flags.get('calibration_final_in_range'),
            'calibration_final_ratio':status.get('calibration_final_ratio'),'raw_CSV_count':focused.get('raw_CSV_count'),
            'fixture_file_count':focused.get('fixture_file_count'),'validated_pairs':focused.get('successfully_validated_pairs'),
            'footer':footer(focus_text),'original_control_fields':status.get('original_fields'),
            'caught_health_panic_log_present':'panicked' in focus_text,
            'Rust_report_and_result_lines':[line for line in focus_text.splitlines() if re.search(r'^(?:literal|identical_history|equal_variable|negative_identical_equal|positive_matched)\s+n=',line) or line.startswith('BATCH result ')]},
        'focused_case_same_core':plan.get('selected_cpu') is not None and case.get('cpu')==plan.get('selected_cpu'),
        'paired_DATA1024_comparison_prerequisites':bool(original['complete'] and NAMES[4] in original['confirmed_rows'] and complete and health and row_flags.get('literal') is True),
        'post_CI_full_focused_raw_priority_reasons':reasons,'raw_reconstruction_performed':False,
        'causal_or_security_closure':False}

def summarize():
    plan=safe_json(OUT/'vm-plan.json');plan.setdefault('vm',VM)
    results=[summarize_trial(n,plan) for n in [1,2]]
    summary={'schema':'fixed20-vm-paired-ghash-v1','vm':VM,'job_head':os.environ.get('GITHUB_SHA'),'planned_native_child_slots':4,
        'coordinator_sources':inventory(),'immutable_identity':identity(),'focused_identity':frozen(),'trials':results,
        'policy':'20VM×2 fixed paired trials; no replacements/retries/model selection/stop on finding. Seeds are shared; trials cluster within VM; physical host reuse is possible.',
        'post_CI_coverage':'Only metadata/linear native checks here; full raw priority = any original/nonpositive confirmation or positive miss plus VM1/6/11/16 trial1, no substitution.'}
    save(OUT/'vm-summary.json',summary)
    print('FOCUSED_BATCH_VM_SUMMARY '+json.dumps(summary,separators=(',',':')),flush=True)

def aggregate(reports):
    slots=[]
    for vm in range(1,21):
        supplied={t.get('trial'):t for t in reports.get(vm,{}).get('trials',[]) if isinstance(t,dict)}
        for trial in [1,2]:
            slots.append(supplied.get(trial,{'vm':vm,'trial':trial,'original':{'complete':False,'confirmed_rows':[]},'focused':{'classification':'incomplete'},'missing':True}))
    groups={}
    for t in slots:
        cpu=t.get('cpu',{'model_name':None,'family':None,'model':None,'stepping':None,'flags':None,'XCR0':None,'active_AVX512F':None})
        key=hashlib.sha256(json.dumps(cpu,sort_keys=True).encode()).hexdigest()
        g=groups.setdefault(key,{'cpu':cpu,'VM_ids':set(),'trial_slots':0,'original_complete':0,'original_confirmed_complete':0,
            'original_confirmed_rows':{n:0 for n in NAMES},'focused_classifications':{k:0 for k in ['complete_healthy','complete_unhealthy','incomplete']},
            'focused_confirmed_rows_complete':{n:0 for n in frozen()['rows']}})
        g['VM_ids'].add(t['vm']);g['trial_slots']+=1;g['original_complete']+=t['original'].get('complete') is True
        if t['original'].get('complete'):
            g['original_confirmed_complete']+=bool(t['original'].get('confirmed_rows'))
            for name in t['original'].get('confirmed_rows',[]):g['original_confirmed_rows'][name]+=1
        kind=t['focused'].get('classification','incomplete');g['focused_classifications'][kind]+=1
        if kind!='incomplete':
            for name,value in t['focused'].get('row_confirmations',{}).items():g['focused_confirmed_rows_complete'][name]+=value is True
    for group in groups.values():group['VM_ids']=sorted(group['VM_ids'])
    return {'planned_VM_slots':20,'planned_paired_trials':40,'planned_native_child_slots':80,'trials':slots,'CPU_feature_groups':groups,
        'original_complete':sum(t['original'].get('complete') is True for t in slots),
        'original_completed_confirmed_trials':sum(t['original'].get('complete') is True and bool(t['original'].get('confirmed_rows')) for t in slots),
        'original_summary_signal_trials_including_partial':sum(bool(t['original'].get('confirmed_rows')) for t in slots),
        'focused_classifications':{kind:sum(t['focused'].get('classification')==kind for t in slots) for kind in ['complete_healthy','complete_unhealthy','incomplete']},
        'missing_trial_slots':sum(t.get('missing') is True for t in slots),'quiet_audit_slots':[[vm,1] for vm in QUIET_AUDIT],
        'rate_limit':'Empirical clustered trial counts, not40 independent physical CPUs or universal constant-time proof.'}

if __name__=='__main__':
    # Cooperate with CI step cancellation so finally cleans the owned session.
    def interrupted(signum,frame):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,interrupted)
    action=sys.argv[1]
    if action=='prepare':prepare()
    elif action=='trial':trial(int(sys.argv[2]))
    elif action=='reference':reference(int(sys.argv[2]))
    elif action=='reports':reports()
    elif action=='summarize':summarize()
    elif action=='aggregate':
        source=Path(sys.argv[2]);reports={}
        for p in source.rglob('vm-summary.json'):
            v=read(p);vm=int(v['vm']);assert 1<=vm<=20 and vm not in reports,'duplicate/out-of-range VM summary'
            reports[vm]=v
        save(source/'aggregate-metadata.json',aggregate(reports))
    else:raise SystemExit('unknown action')
