"""Enumerate recovery command crash points on disposable file-backed LUKS2 headers.

This is a laboratory observer, not a production repair tool. Findings do not grant
release admission. Keys are random fixtures and never included in the report.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import tempfile
import time

FAULTS = ('fail_before', 'fail_after', 'term_after', 'kill_before', 'kill_after')
SHIM = '''#!/usr/bin/python3
import json,os,pathlib,signal,subprocess,sys
log=pathlib.Path(os.environ['MATRIX_CALLS'])
prior=log.read_text().splitlines() if log.exists() else []
with log.open('a') as stream: stream.write(json.dumps(sys.argv[1:])+'\\n')
index=len(prior)+1
hit=index==int(os.environ.get('MATRIX_POINT','0'))
fault=os.environ.get('MATRIX_FAULT','')
if index==int(os.environ.get('MATRIX_PREFAIL','0')): sys.exit(1)
if hit and fault=='fail_before': sys.exit(1)
if hit and fault=='kill_before': os.killpg(os.getpgrp(),signal.SIGKILL)
result=subprocess.run([os.environ['MATRIX_CRYPTSETUP'],*sys.argv[1:]],close_fds=False)
if hit and fault=='fail_after': sys.exit(1)
if hit and fault in ('term_after','kill_after'):
 os.killpg(os.getpgrp(),signal.SIGTERM if fault=='term_after' else signal.SIGKILL)
sys.exit(result.returncode)
'''


def cs(executable, args, value=None, check=True):
    with tempfile.TemporaryFile() as handle:
        if value is not None:
            handle.write(value.encode()); handle.seek(0)
            args = [*args, '--key-file', f'/proc/self/fd/{handle.fileno()}']
        return subprocess.run([executable, *args], pass_fds=(handle.fileno(),),
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              check=check, timeout=30)


def header(executable, image):
    return json.loads(cs(executable, ['luksDump', '--dump-json-metadata', str(image)]).stdout)


def opens(executable, image, value, slot=None):
    args = ['open', '--test-passphrase', str(image)]
    if slot is not None: args += ['--key-slot', str(slot)]
    return cs(executable, args, value, check=False).returncode == 0


def observe(executable, image, values):
    meta = header(executable, image)
    slots = sorted(meta['keyslots'], key=int)
    tokens = {i: {'type': t['type'], 'keyslots': t['keyslots']}
              for i, t in meta['tokens'].items()}
    return {'keyslots': slots, 'tokens': tokens,
            'priorities': {slot:meta['keyslots'][slot].get('priority',1) for slot in slots},
            'opens_boot': {name:opens(executable,image,value) for name,value in values.items()},
            'opens_slots': {name: [s for s in slots if opens(executable, image, value, s)]
                            for name, value in values.items()}}


def clean_recovery(state):
    recovery = [s for t in state['tokens'].values() if t['type'] == 'systemd-recovery' for s in t['keyslots']]
    orphans = any(not t['keyslots'] for t in state['tokens'].values())
    fixture = set(state['keyslots']) - {'0'}
    return (len(recovery) == 1 and set(recovery) == fixture and not orphans
            and state.get('priorities',{}).get(recovery[0],1) != 0)


def invoke(script, image, inputs, executable, directory, point=0, fault='', prefail=0):
    log = directory / 'calls.jsonl'
    log.unlink(missing_ok=True)
    environment = dict(os.environ, PATH=str(directory / 'bin') + ':' + os.environ['PATH'],
                       MATRIX_CALLS=str(log), MATRIX_CRYPTSETUP=executable,
                       MATRIX_POINT=str(point), MATRIX_FAULT=fault, MATRIX_PREFAIL=str(prefail))
    reader, writer = os.pipe()
    if fault == 'closed_stderr': os.close(reader)
    process = subprocess.Popen(['bash', str(script), '--' + inputs[0], str(image)],
        env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=writer if fault == 'closed_stderr' else subprocess.PIPE, start_new_session=True)
    os.close(writer)
    if fault != 'closed_stderr': os.close(reader)
    try:
        output, error = process.communicate(('\n'.join(inputs[1:])+'\n').encode(), timeout=45)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        output, error = process.communicate()
        raise ValueError('recovery script timed out')
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return process.returncode, (output+(error or b'')).decode(errors='replace'), calls


def reconcile_fixture(executable, image, values, state):
    """Explicit laboratory repair: keep the old key if present, otherwise the new.

    The operator has all disposable fixture keys and authenticates every slot. No
    analogous automatic deletion is authorized for production custody material.
    """
    keep = (state['opens_slots']['old'] or state['opens_slots']['new'])
    if not keep: return False
    # Duplicate slots can hold the same known fixture key after a blind retry.
    # The laboratory oracle proves every candidate before choosing one.
    selected = keep[0]
    cs(executable,['config','--priority','normal','--key-slot',selected,str(image)])
    for slot in state['keyslots']:
        if slot not in ('0', selected):
            cs(executable, ['luksKillSlot', '--batch-mode', str(image), slot])
    current = header(executable, image)
    for token, data in current['tokens'].items():
        if not data['keyslots'] or data['keyslots'] != [selected]:
            cs(executable, ['token', 'remove', '--token-id', token, str(image)])
    current = header(executable, image)
    if not any(t['type'] == 'systemd-recovery' and t['keyslots'] == [selected] for t in current['tokens'].values()):
        token = json.dumps({'type':'systemd-recovery', 'keyslots':[selected]})
        subprocess.run([executable,'token','import','--json-file','-',str(image)],
                       input=token, text=True, capture_output=True, check=True, timeout=30)
    final = observe(executable, image, values)
    return clean_recovery(final) and final['opens_boot']['installer'] and (
        final['opens_boot']['old'] or final['opens_boot']['new'])


def run(script, output):
    executable = shutil.which('cryptsetup', path=os.environ['PATH']+':/usr/sbin')
    if not executable or not Path('/proc/self/fd').is_dir():
        raise ValueError('Linux with real cryptsetup is required; no skipping')
    script = script.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {'schema':'regalia.recovery-crash-matrix/v1', 'status':'failed', 'production_approved':False,
              'script_sha256':hashlib.sha256(script.read_bytes()).hexdigest(),
              'cryptsetup':cs(executable, ['--version']).stdout.strip(), 'cases':[],
              'scope':'Every cryptsetup call on successful and single-failure cleanup paths; command boundaries, not internal sector writes'}
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='regalia-luks-matrix-') as temp:
            directory = Path(temp)
            (directory/'bin').mkdir()
            shim=directory/'bin/cryptsetup';shim.write_text(SHIM);shim.chmod(0o700)
            alphabet='cbdefghijklnrtuv'
            recovery=lambda: '-'.join(''.join(secrets.choice(alphabet) for _ in range(8)) for _ in range(8))
            values={'installer':secrets.token_hex(32), 'old':recovery(), 'new':recovery()}
            base=directory/'base.img';base.touch();base.write_bytes(b'');os.truncate(base,32<<20)
            cs(executable,['luksFormat','--type','luks2','--batch-mode','--pbkdf','pbkdf2',
                           '--pbkdf-force-iterations','1000',str(base)],values['installer'])
            enrolled=directory/'enrolled.img';shutil.copyfile(base,enrolled)
            code, text, _=invoke(script,enrolled,['enrol',values['installer'],values['old']],executable,directory)
            if code: raise ValueError('baseline enrol failed')
            for mode in ('enrol','replace'):
                baseline=base if mode=='enrol' else enrolled
                inputs=[mode, values['installer'] if mode=='enrol' else values['old'],
                        values['old'] if mode=='enrol' else values['new']]
                image=directory/'trial.img';shutil.copyfile(baseline,image)
                code, text, calls=invoke(script,image,inputs,executable,directory)
                if code or not clean_recovery(observe(executable,image,values)):
                    raise ValueError('successful baseline does not have a clean recovery header')
                scenarios=[(index,fault,0,calls[index-1][0]) for index in range(1,len(calls)+1) for fault in FAULTS]+[(0,'closed_stderr',0,'stderr')]
                # Discover cleanup paths reached after each possible command refusal.
                # Then interrupt every subsequent command in those paths as well.
                for primary in range(1,len(calls)+1):
                    shutil.copyfile(baseline,image)
                    _, _, cleanup_calls=invoke(script,image,inputs,executable,directory,primary,'fail_before')
                    for index in range(primary+1,len(cleanup_calls)+1):
                        scenarios.extend((index,fault,primary,cleanup_calls[index-1][0]) for fault in FAULTS)
                for index, fault, primary, operation in scenarios:
                    shutil.copyfile(baseline,image)
                    before=observe(executable,image,values)
                    code, text, actual=invoke(script,image,inputs,executable,directory,index,fault,primary)
                    # No fixture secret may reach diagnostics, argv or evidence.
                    public=text+json.dumps(actual)
                    if any(secret in public for secret in values.values()):
                        raise ValueError('fixture secret leaked to diagnostics or arguments')
                    after=observe(executable,image,values)
                    available=after['opens_boot']['installer'] and (mode=='enrol' or (
                        after['opens_boot']['old'] or after['opens_boot']['new']))
                    reached = not index or index <= len(actual)
                    if not available:
                        report['cases'].append({'mode':mode,'point':index,'primary_failure':primary,'fault':fault,
                            'state':after,'unlock_available':False,'findings':['unlock_path_destroyed']})
                        raise ValueError('a valid pre-existing unlock path was destroyed')
                    issues=[]
                    if not reached: issues.append('cleanup_path_point_not_reached')
                    if 'Nothing was changed' in text and before != after: issues.append('unchanged_claim_contradicts_header')
                    if after != before and not clean_recovery(after): issues.append('header_needs_reconciliation')
                    # A normal retry is observed independently of the fault injection.
                    retry_code, _, _=invoke(script,image,inputs,executable,directory)
                    retried=observe(executable,image,values)
                    native_clean=clean_recovery(retried)
                    if not native_clean: issues.append('ordinary_retry_does_not_reconcile')
                    repaired=reconcile_fixture(executable,image,values,retried) if (
                        retried['opens_slots']['old'] or retried['opens_slots']['new']) else mode=='enrol'
                    if not repaired: raise ValueError('explicit fixture reconciliation failed')
                    report['cases'].append({'mode':mode,'point':index,'fault':fault,'exit_code':code,
                        'call':operation, 'primary_failure':primary, 'injection_reached':reached, 'actual_call_count':len(actual), 'state':after,
                        'unlock_available':available,'ordinary_retry_clean':native_clean,
                        'fixture_reconciliation_clean':repaired,'findings':issues})
                    print(f'{mode} point={index} prefail={primary} {fault}: observed, unlock preserved',flush=True)
        findings=sum(bool(c['findings']) for c in report['cases'])
        report.update(status='completed-with-findings' if findings else 'passed', finding_cases=findings,
                      cases_executed=len(report['cases']), fault_points_reached=sum(c['injection_reached'] for c in report['cases']), release_admissible=not findings)
    finally:
        report['elapsed_seconds']=round(time.monotonic()-started,3)
        output.write_text(json.dumps(report,indent=2)+'\n')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--script',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    result=run(**vars(args))
    print(json.dumps({k:v for k,v in result.items() if k!='cases'},indent=2))
    if result['status'] != 'passed': raise SystemExit(1)

if __name__=='__main__': main()
