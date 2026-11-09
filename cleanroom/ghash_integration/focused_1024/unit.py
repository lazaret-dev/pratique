#!/usr/bin/env python3
"""Source-only schema/health/partial-evidence fixtures; no artifact execution."""
import csv,json,tempfile,unittest
from pathlib import Path
import focused as f

PASS='test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 30 filtered out; finished in 30.0s\n'
FAIL=PASS.replace('ok. 1 passed; 0 failed','FAILED. 0 passed; 1 failed')
def status(final=.02,sensitivity=True):
    values={'sensitivity':str(sensitivity).lower(),'early_exit':'true','kind':'DATA',
        'calibration_target_ns':'10000','calibration_initial128_ns':'200',
        'calibration_round0_iterations':'128','calibration_round0_cost_ns':'200','calibration_round0_ratio':'.02','calibration_round0_in_range':'true',
        'calibration_final_iterations':'128','calibration_final_cost_ns':str(10000*final),'calibration_final_ratio':str(final),'calibration_final_in_range':str(.015<=final<=.025).lower(),
        'positive_matched_detected':'true','positive_matched_healthy':str(.015<=final<=.025).lower()}
    values.update({name+'_confirmed_failure':str(name=='positive_matched').lower() for name in f.identity()['rows']})
    return '\n'.join(k+'='+v for k,v in values.items())+'\n'
def case():return {'kind':'DATA','execution_state':'finished','exit_code':0,'binary_sha256':f.identity()['files']['batch-controls-test-binary'],'argv':['--exact',f.identity()['selector']]}
def pair(root):
    path=root/'literal-seed0.csv';fixtures=root/'literal-seed0.fixtures.txt'
    with path.open('w') as out:
        writer=csv.writer(out);writer.writerow(f.HEADER)
        for i in range(1024):writer.writerow([100+i%3,int(i%16>=8),4096+i*24,8192+i*1024,8192+i*1024,12288,1,i,1+i,0])
    with fixtures.open('w') as out:
        out.write(f'reference={json.dumps(f.REFERENCE)} seed=0 reps=1 first_batch=warmup metadata=out_of_band\n')
        for batch in [0,1]:
            for i in range(1024):out.write(f'{batch},{i},{int(i%16>=8)},{1+i},0\n')
    return path,fixtures

class FocusedContract(unittest.TestCase):
    def test_original_sources_still_frozen(self):
        f.source_guards(f.identity());self.assertEqual(f.identity()['selector'],'crypto::timing::pr10_batch_data_controls')

    def test_complete_is_separate_from_health(self):
        rows={str(i):{} for i in range(10)};good=f.parse_status(status())
        self.assertEqual(f.assess(case(),PASS,rows,{},good),(True,True))
        for bad in [f.parse_status(status(.0268)),f.parse_status(status(sensitivity=False))]:
            self.assertEqual(f.assess(case(),PASS,rows,{},bad),(True,False))
        for changed in [{'exit_code':'timeout'},{'exit_code':101},{'argv':None},{'execution_state':'running'},{'binary_sha256':'wrong'}]:
            self.assertFalse(f.assess({**case(),**changed},PASS,rows,{},good)[0])
        for log in ['',FAIL,PASS+PASS,PASS.replace('1 passed','0 passed')]:self.assertFalse(f.assess(case(),log,rows,{},good)[0])
        self.assertFalse(f.assess(case(),PASS,{'partial':{}},{},good)[0])
        self.assertFalse(f.assess(case(),PASS,rows,{'literal':'bad'},good)[0])

    def test_status_missing_duplicate_malformed_and_band_mismatch(self):
        good=status()
        for bad in [good.replace('sensitivity=true\n',''),good+'kind=DATA\n',good.replace('early_exit=true','early_exit=yes'),good.replace('calibration_final_in_range=true','calibration_final_in_range=false'),good+'unexpected=true\n',good.replace('calibration_round0_ratio=.02','calibration_round0_ratio=.03'),good.replace('positive_matched_confirmed_failure=true','positive_matched_confirmed_failure=false')]:
            with self.subTest(text=bad):
                with self.assertRaises((ValueError,KeyError)):f.parse_status(bad)

    def test_pair_binding_full_batches_and_sentinel(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path,fixtures=pair(root)
            self.assertEqual(f.validate_pair(path,fixtures,'literal',0,(2,0))['measured_samples'],1024)
            with self.assertRaises(ValueError):f.validate_pair(path,fixtures,'literal',1,(2,0))
            with self.assertRaises(ValueError):f.validate_pair(path,fixtures,'literal',0,(3,0))
            with self.assertRaises(ValueError):f.validate_pair(path,fixtures,'literal',0,(2,2))
            original=path.read_text();lines=original.splitlines()
            for bad in ['\n'.join(lines[:-1])+'\n',original.replace(',1,0,1,0\n',',1,0,2,0\n',1),original.replace('duration_ns','time_ns',1)]:
                path.write_text(bad)
                with self.assertRaises((ValueError,KeyError)):f.validate_pair(path,fixtures,'literal',0,(2,0))
            path.write_text(original);text=fixtures.read_text();fixtures.write_text('\n'.join(text.splitlines()[:-1])+'\n')
            with self.assertRaises(ValueError):f.validate_pair(path,fixtures,'literal',0,(2,0))

if __name__=='__main__':unittest.main(verbosity=2)
