"""Interrupt explicit custody reconciliation on real disposable LUKS2 headers."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location('observer', Path(__file__).with_name('matrix.py'))
observer = importlib.util.module_from_spec(spec); spec.loader.exec_module(observer)
WORKER = '''import importlib.util,sys
p=sys.argv.pop(1); c=sys.argv.pop(1)
s=importlib.util.spec_from_file_location('reconcile',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
m.CRYPTSETUP=c
m.ENV=dict(m.os.environ,LC_ALL='C')
m.LOCKDIR=m.Path(sys.argv[1]).parent
raise SystemExit(m.main())
'''


def run(script, output):
    executable = shutil.which('cryptsetup', path=os.environ['PATH']+':/usr/sbin')
    if not executable: raise ValueError('real Linux cryptsetup required')
    frozen_source = script.read_bytes()
    report = {'schema':'regalia.recovery-reconciliation-matrix/v1', 'status':'failed',
              'script_sha256':hashlib.sha256(frozen_source).hexdigest(),
              'cryptsetup':observer.cs(executable,['--version']).stdout.strip(),
              'production_approved':False,'cases':[]}
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='regalia-reconcile-') as temp:
            directory = Path(temp); (directory/'bin').mkdir()
            script = directory / 'reconcile-under-test.py'; script.write_bytes(frozen_source)
            shim=directory/'bin/cryptsetup'; shim.write_text(observer.SHIM);shim.chmod(0o700)
            calls=directory/'calls.jsonl'
            alphabet='cbdefghijklnrtuv'
            random_key=lambda:'-'.join(''.join(secrets.choice(alphabet) for _ in range(8)) for _ in range(8))
            keys={'installer':secrets.token_hex(32),'old':random_key(),'new':random_key(),'unknown':random_key()}
            base=directory/'base.img';base.touch();os.truncate(base,32<<20)
            observer.cs(executable,['luksFormat','--type','luks2','--batch-mode','--pbkdf','pbkdf2','--pbkdf-force-iterations','1000',str(base)],keys['installer'])
            for slot,name in [('1','old'),('2','new'),('3','unknown')]:
                with tempfile.TemporaryFile() as current, tempfile.TemporaryFile() as added:
                    current.write(keys['installer'].encode());current.seek(0);added.write(keys[name].encode());added.seek(0)
                    subprocess.run([executable,'luksAddKey','--batch-mode','--pbkdf','pbkdf2','--pbkdf-force-iterations','1000','--new-key-slot',slot,'--key-file',f'/proc/self/fd/{current.fileno()}',str(base),f'/proc/self/fd/{added.fileno()}'],pass_fds=(current.fileno(),added.fileno()),capture_output=True,check=True,timeout=30)
            for token in [{'type':'systemd-recovery','keyslots':['1']},{'type':'systemd-recovery','keyslots':[]}]:
                subprocess.run([executable,'token','import','--json-file','-',str(base)],input=json.dumps(token),text=True,capture_output=True,check=True,timeout=30)
            observer.cs(executable,['config','--priority','ignore','--key-slot','2',str(base)])
            untouched=observer.header(executable,base)['keyslots']
            image=directory/'trial.img'
            def invoke(point=0,fault='',keep='2',retire='1',supplied=None):
                calls.unlink(missing_ok=True)
                env=dict(os.environ,MATRIX_CALLS=str(calls),MATRIX_CRYPTSETUP=executable,MATRIX_POINT=str(point),MATRIX_FAULT=fault)
                proc=subprocess.Popen(['python3','-I','-c',WORKER,str(script),str(shim),str(image),'--keep-slot',keep,'--retire-slot',retire],
                                      env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                try: out,err=proc.communicate(('\n'.join(supplied or [keys['new'],keys['old']])+'\n').encode(),timeout=60)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid,signal.SIGKILL);proc.communicate();raise ValueError('reconciliation timeout')
                recorded=[json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
                public=(out+err).decode(errors='replace')+json.dumps(recorded)
                if any(k in public for k in keys.values()):raise ValueError('fixture secret escaped')
                if point == 0 and 'REFUSED:' in public:
                    print(public[:1500],flush=True)
                return proc.returncode,recorded
            shutil.copyfile(base,image)
            _,baseline=invoke()
            def final_valid():
                actual=observer.header(executable,image)
                state=observer.observe(executable,image,keys)
                return (actual['keyslots'].get('0')==untouched['0'] and actual['keyslots'].get('3')==untouched['3']
                        and '1' not in actual['keyslots'] and state['opens_boot']['new']
                        and state['opens_boot']['installer'] and state['opens_boot']['unknown']
                        and [t['keyslots'] for t in actual['tokens'].values() if t['type']=='systemd-recovery']==[['2']]
                        and actual['keyslots']['2'].get('priority',1)!=0)
            if not final_valid():raise ValueError('baseline reconciliation failed')
            for point in range(1,len(baseline)+1):
                for fault in observer.FAULTS:
                    shutil.copyfile(base,image);code,actual=invoke(point,fault)
                    if point>len(actual):raise ValueError('planned fault point was not reached')
                    meta=observer.header(executable,image)
                    if meta['keyslots'].get('0')!=untouched['0'] or meta['keyslots'].get('3')!=untouched['3']:
                        raise ValueError('unselected slot changed')
                    if not observer.opens(executable,image,keys['installer']) or not observer.opens(executable,image,keys['unknown']):
                        raise ValueError('unselected unlock path lost')
                    invoke()
                    if not final_valid():raise ValueError('explicit same-selection retry did not reconcile')
                    report['cases'].append({'point':point,'call':baseline[point-1][0],'fault':fault,'injection_reached':True,'exit_code':code,'retry_reconciled':True,'unknown_slots_preserved':True})
            # Wrong cards and a slot owned by another non-recovery token must refuse
            # before any mutation, even though the operator names explicit slots.
            for supplied in [[keys['old'],keys['old']],[keys['new'],keys['unknown']]]:
                shutil.copyfile(base,image);before=observer.header(executable,image);invoke(supplied=supplied)
                if observer.header(executable,image)!=before:raise ValueError('bad card changed the header')
            shutil.copyfile(base,image)
            subprocess.run([executable,'token','add','--key-description','regalia-fixture-reference','--key-slot','2',str(image)],capture_output=True,check=True,timeout=30)
            before=observer.header(executable,image);invoke()
            if observer.header(executable,image)!=before:raise ValueError('non-recovery-owned slot was changed')
            report.update(status='passed',cases_executed=len(report['cases']),fault_points_reached=len(report['cases']),
                          negative_controls=3,unknown_keys_retained=True,scope='Command boundaries and explicit same-card retries, not internal sector writes')
    finally:
        report['elapsed_seconds']=round(time.monotonic()-started,3)
        output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2)+'\n')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--script',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();d=run(args.script.resolve(),args.output)
    print(json.dumps({k:v for k,v in d.items() if k!='cases'},indent=2))
