#!/usr/bin/env python3
"""One exploratory DATA1024 selector using immutable reviewed Linux bytes."""
import csv,hashlib,importlib,json,math,os,re,shutil,sys,zipfile
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
ORIGINAL=HERE.parent/'timing_diagnostics'
OUT=Path(os.environ.get('PRATIQUE_FOCUSED_OUTPUT',str(Path(os.environ.get('RUNNER_TEMP','/private/tmp'))/'focused-1024-output')))
STAGED=OUT/'immutable-input'
REFERENCE='ghash [Portable] batch 1024 data: 0 vs random'
HEADER=['duration_ns','class','input_address','timed_address','data_address','key_address','batch','sample','fixture_rng_before','fixture_h_value']

def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1<<20),b''):h.update(block)
    return h.hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,indent=2,allow_nan=False)+'\n')
def identity():return json.loads((HERE/'frozen_identity.json').read_text())
def adapter_inventory():
    paths=[HERE/name for name in ['focused.py','frozen_identity.json','unit.py','PROTOCOL.md']]
    paths.append(ROOT/'.github/workflows/pr10-ghash-1024-focused.yml')
    return {str(p.relative_to(ROOT)):sha(p) for p in paths}
def source_guards(frozen):
    assert len(frozen['source_files'])==13
    for name,h in frozen['source_files'].items():assert sha(ORIGINAL/name)==h,name
def modules():
    source_guards(identity())
    sys.path.insert(0,str(ORIGINAL))
    old=importlib.import_module('run_batch')
    old.OUT=OUT;old.COMPANION=STAGED;old.replay.COMPANION=STAGED
    return old

def stage_archive(archive,dest):
    """Data-only staging is safe to validate locally; no archived code is loaded."""
    frozen=identity();source_guards(frozen)
    assert archive.stat().st_size==frozen['archive_bytes']
    assert sha(archive)==frozen['archive_sha256'],'immutable archive digest mismatch'
    wanted=['batch-companion-manifest.json',*frozen['files'],'native/fixture-storage-unit.log']
    wanted+=['diagnostic-sources/'+name for name in frozen['source_files']]
    with zipfile.ZipFile(archive) as z:
        assert len(z.namelist())==len(set(z.namelist())),'duplicate ZIP member'
        for name in wanted:
            target=dest/name;target.parent.mkdir(parents=True,exist_ok=True)
            assert target.resolve().is_relative_to(dest.resolve())
            with z.open(name) as src,target.open('wb') as dst:shutil.copyfileobj(src,dst,1<<20)
            target.chmod(0o644)
    assert sha(dest/'batch-companion-manifest.json')==frozen['manifest_sha256']
    manifest=json.loads((dest/'batch-companion-manifest.json').read_text())
    assert manifest['production_source_commit']==frozen['production_source_commit']
    assert manifest['diagnostic_commit']==frozen['artifact_diagnostic_commit']
    for field in ['source_files','files','RUSTFLAGS']:assert manifest[field]==frozen[field],field
    for name,h in frozen['source_files'].items():assert sha(dest/'diagnostic-sources'/name)==h
    for name,h in frozen['files'].items():assert sha(dest/name)==h
    receipt={'archive_sha256':frozen['archive_sha256'],'archive_bytes':frozen['archive_bytes'],'artifact_id':frozen['artifact_id'],
        'artifact_diagnostic_commit':frozen['artifact_diagnostic_commit'],'production_source_commit':frozen['production_source_commit'],
        'source_guards':13,'files':frozen['files'],'staged_regular_data_only':True,'archived_code_executed_here':False}
    save(dest/'stage-receipt.json',receipt)
    return receipt

def prepare():
    assert sys.platform=='linux' and os.uname().machine=='x86_64','native Linux x86_64 only'
    receipt=stage_archive(Path(os.environ['RUNNER_TEMP'])/'focused-binary.zip',STAGED)
    old=modules()
    for name in identity()['files']:(STAGED/name).chmod(0o755)
    for name in ['PRATIQUE_TIMING_REPS','PRATIQUE_TIMING_TICK_NS','PRATIQUE_TIMING_TICKS']:assert name not in os.environ,name
    assert not os.environ.get('GLIBC_TUNABLES'),'true default dispatch only'
    affinity=sorted(os.sched_getaffinity(0));assert affinity;cpu=affinity[0]
    probe=old.replay.probe(os.environ.copy(),cpu)
    lib=Path(probe['memory']['memcpy']['library']).resolve()
    head=old.replay.command(['git','-C',str(ROOT),'rev-parse','HEAD']);assert head['exit_code']==0
    settings={'scope':'ONE exploratory DATA1024 companion group, UNGATED, one pinned default Ubuntu24 core. No sealed normal gate, other selector, host hunting, repeat job or compiler.',
        'current_job_commit':os.environ['GITHUB_SHA'],'checkout_commit':head['output'].strip(),
        'artifact_diagnostic_commit':identity()['artifact_diagnostic_commit'],'production_source_commit':identity()['production_source_commit'],
        'adapter_source_hashes':adapter_inventory(),
        'immutable_input':receipt,'selected_cpu':cpu,'affinity':affinity,'seeds':[0,1],'seconds_per_row_seed':3,
        'lscpu':old.replay.command(['lscpu']),'uname':old.replay.command(['uname','-a']),'proc_cpuinfo':old.replay.optional(Path('/proc/cpuinfo')),
        'glibc':old.replay.command(['ldd','--version']),'same_core_default_probe':probe,
        'libc_file':{'path':str(lib),'sha256':sha(lib),'ELF_notes':old.replay.command(['readelf','-n',str(lib)])},
        'frequency_before_window':old.replay.frequency(),'environment_shape':old.replay.env_shape(os.environ),
        'runner':{k:os.environ.get(k) for k in ['ImageOS','ImageVersion','GITHUB_RUN_ID','GITHUB_SHA','GITHUB_RUN_ATTEMPT']},
        'sealed_original_co_reproduction':'UNMEASURED; causal exclusion/security closure unavailable'}
    assert settings['current_job_commit']==settings['checkout_commit']
    save(OUT/'settings.json',settings)
    print(json.dumps({'prepared':True,'selected_cpu':cpu,'binary_sha256':receipt['files']['batch-controls-test-binary'],'source_guards':13}),flush=True)

def run():
    old=modules();s=json.loads((OUT/'settings.json').read_text())
    assert s['adapter_source_hashes']==adapter_inventory()
    for name,h in identity()['files'].items():assert sha(STAGED/name)==h
    assert s['immutable_input']['archive_sha256']==identity()['archive_sha256']
    # Deliberately bypass only the OLD sealed-preflight trigger wrapper. Reuse
    # its unchanged exact selector/environment/timeout/recording implementation.
    case=old.run_case(OUT/'DATA-controls','DATA')
    assert s['adapter_source_hashes']==adapter_inventory()
    save(OUT/'adapter-return.json',{'collector_returned':True,'child_exit_code':case['exit_code'],'separate_from_control_health':True})

def footer(text):
    matches=re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',text,re.M)
    return matches==[('ok','1','0','0')]
def parse_status(text):
    result={}
    for line in text.splitlines():
        key,sep,value=line.partition('=')
        if not sep or not key or key in result:raise ValueError('malformed/duplicate status field')
        result[key]=value
    if result.get('kind')!='DATA':raise ValueError('wrong control group')
    bools=['sensitivity','early_exit','calibration_final_in_range','positive_matched_detected','positive_matched_healthy']
    bools += [name+'_confirmed_failure' for name in identity()['rows']]
    rounds=sorted({int(m[1]) for key in result if (m:=re.fullmatch(r'calibration_round([0-3])_iterations',key))})
    if not rounds or rounds!=list(range(len(rounds))) or len(rounds)>4:raise ValueError('missing/noncontiguous calibration history')
    bools += [f'calibration_round{i}_in_range' for i in rounds]
    if any(result.get(key) not in ['true','false'] for key in bools):raise ValueError('missing/malformed Boolean status')
    expected={'kind','calibration_target_ns','calibration_initial128_ns',*bools}
    expected.update('calibration_'+suffix+'_'+field for suffix in [*(f'round{i}' for i in rounds),'final'] for field in ['iterations','cost_ns','ratio'])
    if set(result)!=expected:raise ValueError('missing/unexpected status field')
    decoded={key:result[key]=='true' for key in bools}
    target=float(result['calibration_target_ns']);initial=float(result['calibration_initial128_ns'])
    if not math.isfinite(target) or target<=0 or not math.isfinite(initial) or initial<=0:raise ValueError('invalid calibration cost')
    for suffix in [*(f'round{i}' for i in rounds),'final']:
        prefix='calibration_'+suffix;iterations=int(result[prefix+'_iterations']);cost=float(result[prefix+'_cost_ns']);ratio=float(result[prefix+'_ratio'])
        if iterations<=0 or not math.isfinite(cost) or cost<0 or not math.isfinite(ratio) or not math.isclose(ratio,cost/target,rel_tol=2e-15,abs_tol=0):raise ValueError('invalid calibration arithmetic')
        if decoded[prefix+'_in_range']!=(.015<=ratio<=.025):raise ValueError('calibration band/status mismatch')
    if any(decoded[f'calibration_round{i}_in_range'] for i in rounds[:-1]):raise ValueError('history continues after original in-band break')
    if len(rounds)<4 and not decoded[f'calibration_round{rounds[-1]}_in_range']:raise ValueError('incomplete bounded calibration history')
    if decoded['positive_matched_healthy']!=(decoded['calibration_final_in_range'] and decoded['positive_matched_detected']):raise ValueError('matched-positive health/status mismatch')
    if decoded['positive_matched_detected'] and not decoded['positive_matched_confirmed_failure']:raise ValueError('positive detection/judge mismatch')
    return {'original_fields':result,'booleans':decoded,'calibration_round_count':len(rounds),'calibration_final_ratio':float(result['calibration_final_ratio'])}

def validate_pair(csv_path,fixture_path,name,seed,metadata):
    """Bind complete CSVs to matching warmup+measured fixture records."""
    with csv_path.open() as f:
        reader=csv.DictReader(f)
        if reader.fieldnames!=HEADER:raise ValueError('unexpected/missing CSV schema')
        rows=[]
        for row in reader:
            if None in row or any(v is None for v in row.values()):raise ValueError('malformed CSV record')
            rows.append({k:int(v) for k,v in row.items()})
    if not rows or len(rows)%1024:raise ValueError('missing/incomplete measured batch')
    batches=len(rows)//1024
    with fixture_path.open() as f:
        expected=f'reference={json.dumps(REFERENCE)} seed={seed} reps=1 first_batch=warmup metadata=out_of_band'
        if f.readline().strip()!=expected:raise ValueError('fixture reference/seed mismatch')
        fixtures=[]
        for line in f:
            values=[int(x) for x in line.strip().split(',')]
            if len(values)!=5:raise ValueError('malformed fixture record')
            fixtures.append(values)
    if len(fixtures)!=(batches+1)*1024:raise ValueError('missing/extra warmup or fixture record')
    for i,(batch,sample,c,before,h) in enumerate(fixtures):
        if (batch,sample)!=divmod(i,1024) or c not in [0,1] or not 0<=before<1<<64 or h!=0:raise ValueError('invalid DATA fixture sequence/sentinel')
    for i,row in enumerate(rows):
        batch=1+i//1024;sample=i%1024
        if (row['batch'],row['sample'])!=(batch,sample) or row['class'] not in [0,1] or not 0<=row['duration_ns']<1<<32:raise ValueError('invalid measured order/class/duration')
        if [batch,sample,row['class'],row['fixture_rng_before'],row['fixture_h_value']]!=fixtures[1024+i]:raise ValueError('CSV/fixture binding mismatch')
        if min(row[k] for k in ['input_address','timed_address','data_address','key_address'])<=0 or row['timed_address']!=row['data_address']:raise ValueError('invalid DATA pointer contract')
    for at in range(0,len(rows),16):
        if sum(r['class'] for r in rows[at:at+16])!=8:raise ValueError('incomplete original paired class block')
    if metadata!=(batches+1,0):raise ValueError('original metadata batch/native-tick mismatch')
    return {'measured_samples':len(rows),'fixture_samples':len(fixtures),'measured_batches':batches,'fixture_H_field':'unused zero DATA sentinel; actual fixed H is original nonzero fixture'}

def assess(case,text,validated_pairs,errors,status):
    argv=case.get('argv',[])
    contract=(isinstance(argv,list) and case.get('kind')=='DATA' and case.get('execution_state')=='finished' and case.get('exit_code')==0
        and case.get('binary_sha256')==identity()['files']['batch-controls-test-binary'] and '--exact' in argv
        and len(argv)>argv.index('--exact')+1 and argv[argv.index('--exact')+1]==identity()['selector'] and footer(text))
    complete=contract and len(validated_pairs)==10 and not errors
    b=status.get('booleans',{})
    healthy=all(b.get(k) is True for k in ['sensitivity','early_exit','calibration_final_in_range','positive_matched_detected','positive_matched_healthy']) and b.get('negative_identical_equal_confirmed_failure') is False
    return bool(complete),bool(healthy)

def report():
    source_guards(identity());folder=OUT/'DATA-controls';errors={};pairs={};case={};status={}
    try:
        case=json.loads((folder/'case.json').read_text())
        if not isinstance(case,dict):raise ValueError('case must be an object')
    except Exception as e:case={};errors['case']=repr(e)
    s={}
    try:
        s=json.loads((OUT/'settings.json').read_text())
        assert s['artifact_diagnostic_commit']==identity()['artifact_diagnostic_commit']
        assert s['production_source_commit']==identity()['production_source_commit']
        assert s['current_job_commit']==os.environ['GITHUB_SHA']
        assert s['adapter_source_hashes']==adapter_inventory()
        expected_argv=['taskset','-c',str(s['selected_cpu']),str(STAGED/'batch-controls-test-binary'),'--exact',identity()['selector'],'--ignored','--nocapture','--test-threads=1']
        assert case.get('argv')==expected_argv and case.get('cpu')==s['selected_cpu']
    except Exception as e:s={};errors['settings_or_invocation']=repr(e)
    text=(folder/'run.log').read_text() if (folder/'run.log').exists() else ''
    try:status=parse_status((folder/'batch-control-results.txt').read_text())
    except Exception as e:errors['status']=repr(e)
    names=identity()['rows'];expected={f'{name}-seed{seed}' for name in names for seed in [0,1]}
    csvs={p.stem for p in folder.glob('*.csv')};fixtures={p.name.removesuffix('.fixtures.txt') for p in folder.glob('*.fixtures.txt')}
    if csvs!=expected or fixtures!=expected:errors['pair_set']='Missing/unexpected five-row/two-seed CSV or fixture member'
    metadata={}
    pattern=r'^BATCH metadata name=(\w+) seed=([01]) kind=Data I_size=24 Vec_header=24 fixed_data_address=(\d+) fixed_key_address=(\d+) batches=(\d+) native_tick=(\d+) reps=1$'
    for name,seed,data,key,batches,tick in re.findall(pattern,text,re.M):
        stem=f'{name}-seed{seed}'
        if stem in metadata or min(int(data),int(key))<=0:errors['metadata-'+stem]='duplicate/invalid metadata'
        metadata[stem]=(int(batches),int(tick))
    if metadata.keys()!=expected:errors['metadata_set']='Missing/unexpected original metadata'
    for name in names:
        for seed in [0,1]:
            stem=f'{name}-seed{seed}';path=folder/(stem+'.csv')
            try:
                pairs[stem]=validate_pair(path,folder/(stem+'.fixtures.txt'),name,seed,metadata.get(stem))
            except Exception as e:errors[stem]=repr(e)
    results=re.findall(r'^BATCH result kind=DATA row=(\w+) confirmed_failure=(None|Some\([^\n]*\))$',text,re.M)
    logged={name:value!='None' for name,value in results}
    if len(results)!=5 or set(logged)!=set(names):errors['result_set']='Missing/duplicate/unexpected original judge row'
    elif status and any(logged[name]!=status['booleans'][name+'_confirmed_failure'] for name in names):errors['result_status']='Original judge/status mismatch'
    complete,healthy=assess(case,text,pairs,errors,status)
    b=status.get('booleans',{})
    save(OUT/'structural-pair-checks.json',pairs)
    outcome={'scope':'ONE UNGATED exploratory existing DATA1024 group, not original-gate validation','current_job_commit':s.get('current_job_commit'),
        'artifact_diagnostic_commit':identity()['artifact_diagnostic_commit'],'production_source_commit':identity()['production_source_commit'],
        'adapter_source_hashes':s.get('adapter_source_hashes'),
        'case':case,'raw_CSV_count':len(csvs),'fixture_file_count':len(fixtures),'successfully_validated_pairs':len(pairs),'pair_checks':pairs,
        'descriptive_statistics_deferred_to_post_CI':True,'descriptive_analyzer_executed_in_native_job':False,
        'analysis_errors':errors,'successful_one_test_footer':footer(text),'collection_complete':complete,'control_health':healthy,
        'original_control_status':status,'literal_confirmed_signal':b.get('literal_confirmed_failure'),
        'sealed_original_co_reproduction':'UNMEASURED','causal_exclusion_or_security_closure':False,
        'warning':'Exact reviewed companion bytes reused; original sealed failure co-reproduction is absent. A quiet literal/control is inconclusive. Descriptive sample analysis does not replace the unchanged Rust judge/status. All prior failures/PR10 HOLD persist.'}
    save(OUT/'outcomes.json',outcome)
    print(json.dumps({k:outcome[k] for k in ['collection_complete','control_health','raw_CSV_count','fixture_file_count','successfully_validated_pairs','literal_confirmed_signal','analysis_errors']}),flush=True)
    if not complete or not healthy:raise SystemExit('Incomplete or unhealthy exploratory diagnostic; preserve all data without waiver.')

def analyze_raw():
    """Optional owned-Python post-CI work; never executes an archived binary."""
    old=modules();folder=OUT/'DATA-controls';rows={};errors={}
    expected={f'{name}-seed{seed}' for name in identity()['rows'] for seed in [0,1]}
    paths={p.stem:p for p in folder.glob('*.csv')}
    if paths.keys()!=expected:errors['row_set']='Missing/unexpected raw CSV'
    for name,path in sorted(paths.items()):
        try:rows[name]=old.analyze.analyze(path)
        except Exception as e:errors[name]=repr(e)
    save(OUT/'sample-analysis.json',rows)
    save(OUT/'post-CI-analysis-status.json',{'successfully_analyzed_pairs':len(rows),'errors':errors,
        'all_ten_analyzed':len(rows)==10 and not errors,'native_code_executed':False,
        'scope':'Descriptive only; unchanged original Rust judge/status and historical failures are retained.'})
    if len(rows)!=10 or errors:raise SystemExit('Post-CI analysis incomplete; preserve all partial results.')

if __name__=='__main__':
    if sys.argv[1]=='analyze-raw':
        OUT=Path(sys.argv[2]).resolve();STAGED=OUT/'immutable-input';analyze_raw()
    else:{'prepare':prepare,'run':run,'report':report}[sys.argv[1]]()
