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
import threading
from contextlib import contextmanager
import time
from concurrent.futures import ThreadPoolExecutor

FAULTS = ('fail_before', 'fail_after', 'term_after', 'kill_before', 'kill_after')
# Inside one call: the N-th fsync of that cryptsetup process is answered by strace with a KILL (the
# whole run dies with it), a TERM (sent to the whole run once the call returns) or EIO (a failing write).
SYNC_FAULTS = ('sync_kill', 'sync_term', 'sync_eio')
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
command=[os.environ['MATRIX_CRYPTSETUP'],*sys.argv[1:]]
strace=os.environ.get('MATRIX_STRACE','')
counts=os.environ.get('MATRIX_SYNCS','')
trace=log.with_suffix('.trace')
if hit and fault.startswith('sync_'):
 inject={'sync_kill':'signal=KILL','sync_term':'signal=TERM','sync_eio':'error=EIO'}[fault]
 command=[strace,'-f','-qq','-o','/dev/null','-e','trace=fsync','-e','inject=fsync:%s:when=%s'%(inject,os.environ['MATRIX_SYNC']),*command]
elif counts:
 trace.unlink(missing_ok=True)
 command=[strace,'-f','-qq','-o',str(trace),'-e','trace=fsync',*command]
result=subprocess.run(command,close_fds=False)
if counts and not (hit and fault.startswith('sync_')):
 synced=sum('fsync(' in line for line in trace.read_text().splitlines()) if trace.exists() else 0
 with open(counts,'a') as stream: stream.write('%d %d\\n'%(index,synced))
if hit and fault=='sync_kill' and result.returncode in (-9,137): os.killpg(os.getpgrp(),signal.SIGKILL)
if hit and fault=='sync_term': os.killpg(os.getpgrp(),signal.SIGTERM)
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
    return {'keyslots': slots, 'tokens': tokens, 'state': header_state(meta),
            'priorities': {slot:meta['keyslots'][slot].get('priority',1) for slot in slots},
            'opens_boot': {name:opens(executable,image,value) for name,value in values.items()},
            'opens_slots': {name: [s for s in slots if opens(executable, image, value, s)]
                            for name, value in values.items()}}


def header_state(meta):
    """The header's state as #175 names it, read here independently of the script under test."""
    slots = meta.get('keyslots') or {}
    named, owner, empty, unknown = set(), {}, [], False
    for token_id, token in (meta.get('tokens') or {}).items():
        listed = [str(s) for s in token.get('keyslots') or []]
        live = [s for s in listed if s in slots]
        named.update(live)
        if token.get('type') != 'systemd-recovery': continue
        if not live: empty.append(token_id); continue
        if len(listed) != 1 or listed[0] in owner: unknown = True; continue
        owner[listed[0]] = token
    if any((slots[s] or {}).get('priority') == 0 for s in owner): unknown = True
    def generation(token):
        value = token.get('regalia_generation', 0)
        return value if type(value) is int and 0 <= value < 2**31 else None
    pair = False
    if len(owner) == 2 and not unknown:
        first, second = owner
        marked = [1 for new, old in ((first, second), (second, first))
                  if str(owner[new].get('regalia_replaces')) == old
                  and owner[new].get('regalia_replaces_salt') == slots[old].get('kdf', {}).get('salt')
                  and None not in (generation(owner[new]), generation(owner[old]))
                  and generation(owner[new]) == generation(owner[old]) + 1]
        pair = len(marked) == 1
        unknown = not pair
    elif len(owner) > 2:
        unknown = True
    if unknown: return 'unknown'
    if empty: return 'orphan-token'
    if not owner: return 'no-recovery'
    if pair: return 'added-unproven'
    if set(slots) - named: return 'orphan-keyslot'
    return 'clean'


def reported_state(text):
    """The last state the script printed, or None when it printed none (it was killed)."""
    found = [line.split(' ', 2)[1] for line in text.splitlines() if line.startswith('STATE: ')]
    return found[-1] if found else None


def clean_recovery(state):
    recovery = [s for t in state['tokens'].values() if t['type'] == 'systemd-recovery' for s in t['keyslots']]
    orphans = any(not t['keyslots'] for t in state['tokens'].values())
    fixture = set(state['keyslots']) - {'0'}
    return (len(recovery) == 1 and set(recovery) == fixture and not orphans
            and state.get('priorities',{}).get(recovery[0],1) != 0)


def invoke(script, image, inputs, executable, directory, point=0, fault='', prefail=0, sync=0, counts=None):
    log = directory / 'calls.jsonl'
    log.unlink(missing_ok=True)
    environment = dict(os.environ, PATH=str(directory / 'bin') + ':' + os.environ['PATH'],
                       MATRIX_CALLS=str(log), MATRIX_CRYPTSETUP=executable, MATRIX_STRACE=STRACE or '',
                       MATRIX_POINT=str(point), MATRIX_FAULT=fault, MATRIX_PREFAIL=str(prefail),
                       MATRIX_SYNC=str(sync), MATRIX_SYNCS=str(counts or ''))
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


# Calls that write the LUKS2 header; the rest only read it.
WRITES = {'luksAddKey', 'luksKillSlot', 'luksRemoveKey', 'luksChangeKey', 'token', 'config', 'luksFormat'}
WORKERS = max(2, os.cpu_count() or 2)
_free = []
_roots = []
_guard = threading.Lock()


@contextmanager
def workspace():
    """A private directory for one scenario: its shim, its call log, its image. Directories are
    reused, and the image is removed after every scenario (each is a full 32 MiB copy)."""
    with _guard:
        directory = _free.pop() if _free else None
    if directory is None:
        directory = Path(tempfile.mkdtemp(prefix='regalia-luks-matrix-worker-'))
        (directory/'bin').mkdir()
        shim = directory/'bin/cryptsetup'; shim.write_text(SHIM); shim.chmod(0o700)
        with _guard: _roots.append(directory)
    try:
        yield directory
    finally:
        (directory/'trial.img').unlink(missing_ok=True)
        with _guard: _free.append(directory)


def trial(script, executable, mode, baseline, inputs, values, scenario):
    with workspace() as directory:
        return _trial(script, executable, mode, baseline, inputs, values, scenario, directory)


def _trial(script, executable, mode, baseline, inputs, values, scenario, directory):
    index, fault, primary, operation, sync = scenario
    image = directory/'trial.img'
    shutil.copyfile(baseline,image)
    before=observe(executable,image,values)
    code, text, actual=invoke(script,image,inputs,executable,directory,index,fault,primary,sync)
    # No fixture secret may reach diagnostics, argv or evidence.
    public=text+json.dumps(actual)
    if any(secret in public for secret in values.values()):
        raise ValueError('fixture secret leaked to diagnostics or arguments')
    after=observe(executable,image,values)
    available=after['opens_boot']['installer'] and (mode=='enrol' or (
        after['opens_boot']['old'] or after['opens_boot']['new']))
    reached = not index or index <= len(actual)
    if not available:
        raise ValueError('a valid pre-existing unlock path was destroyed: %s' % json.dumps(
            {'mode':mode,'point':index,'sync':sync,'primary_failure':primary,'fault':fault,'state':after}))
    issues=[]; observations=[]
    if not reached: issues.append('cleanup_path_point_not_reached')
    if ('Nothing was changed' in text or 'as it was before this run' in text) and before != after:
        issues.append('unchanged_claim_contradicts_header')
    # The state the script printed last is the header's, read independently here. "unreadable" is
    # the script saying it could not read the header, which is no claim about it.
    said=reported_state(text)
    if said not in (None, 'unreadable') and said != after['state']: issues.append('reported_state_contradicts_header')
    # Not a finding: any script that writes the header more than once leaves a changed header that
    # is not clean when it is killed between two writes. The gate is that the ordinary retry
    # reconciles it (below).
    if after != before and not clean_recovery(after): observations.append('header_needs_reconciliation')
    # A normal retry is observed independently of the fault injection.
    invoke(script,image,inputs,executable,directory)
    retried=observe(executable,image,values)
    native_clean=clean_recovery(retried)
    if not native_clean: issues.append('ordinary_retry_does_not_reconcile')
    repaired=reconcile_fixture(executable,image,values,retried) if (
        retried['opens_slots']['old'] or retried['opens_slots']['new']) else mode=='enrol'
    if not repaired: raise ValueError('explicit fixture reconciliation failed')
    return {'mode':mode,'point':index,'fault':fault,'sync':sync,'exit_code':code,
            'reported_state':said,'observations':observations,
            'call':operation, 'primary_failure':primary, 'injection_reached':reached, 'actual_call_count':len(actual), 'state':after,
            'unlock_available':available,'ordinary_retry_clean':native_clean,
            'fixture_reconciliation_clean':repaired,'findings':issues}


STRACE = shutil.which('strace')


def run(script, output):
    executable = shutil.which('cryptsetup', path=os.environ['PATH']+':/usr/sbin')
    if not executable or not Path('/proc/self/fd').is_dir():
        raise ValueError('Linux with real cryptsetup is required; no skipping')
    if not STRACE:
        raise ValueError('strace is required for the faults inside a call; no skipping')
    script = script.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {'schema':'regalia.recovery-crash-matrix/v1', 'status':'failed', 'production_approved':False,
              'script_sha256':hashlib.sha256(script.read_bytes()).hexdigest(),
              'cryptsetup':cs(executable, ['--version']).stdout.strip(), 'cases':[],
              'scope':'Every cryptsetup call on successful and single-failure cleanup paths, and every fsync inside each call that writes the header (KILL, TERM, EIO); not physical power loss'}
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
                counts=directory/'syncs.txt'; counts.unlink(missing_ok=True)
                code, text, calls=invoke(script,image,inputs,executable,directory,counts=counts)
                if code or not clean_recovery(observe(executable,image,values)):
                    raise ValueError('successful baseline does not have a clean recovery header')
                syncs={int(i):int(n) for i,n in (line.split() for line in counts.read_text().splitlines())}
                report.setdefault('syncs',{})[mode]={' '.join(calls[i-1][:2]):n for i,n in sorted(syncs.items()) if n}
                scenarios=[(index,fault,0,calls[index-1][0],0) for index in range(1,len(calls)+1) for fault in FAULTS]+[(0,'closed_stderr',0,'stderr',0)]
                # Every header sync of every call that writes one, each with KILL, TERM and EIO.
                scenarios.extend((index,fault,0,calls[index-1][0],n) for index,count in sorted(syncs.items())
                                 for n in range(1,count+1) for fault in SYNC_FAULTS)
                # Discover cleanup paths reached after each possible command refusal. Then interrupt
                # every later command in those paths that WRITES the header: a read there can change
                # what is printed, not what the header holds, and the reported state is checked anyway.
                def discover(primary):
                    with workspace() as work:
                        image=work/'trial.img'; shutil.copyfile(baseline,image)
                        return primary, invoke(script,image,inputs,executable,work,primary,'fail_before')[2]
                with ThreadPoolExecutor(WORKERS) as pool:
                    for primary, cleanup_calls in pool.map(discover, range(1,len(calls)+1)):
                        for index in range(primary+1,len(cleanup_calls)+1):
                            if cleanup_calls[index-1][0] in WRITES:
                                scenarios.extend((index,fault,primary,cleanup_calls[index-1][0],0) for fault in FAULTS)
                with ThreadPoolExecutor(WORKERS) as pool:
                    for case in pool.map(lambda scenario: trial(script,executable,mode,baseline,inputs,values,scenario), scenarios):
                        report['cases'].append(case)
                        print(f"{mode} point={case['point']} sync={case.get('sync',0)} prefail={case['primary_failure']} {case['fault']}: observed, unlock preserved{' FINDINGS '+','.join(case['findings']) if case['findings'] else ''}",flush=True)
        findings=sum(bool(c['findings']) for c in report['cases'])
        report.update(status='completed-with-findings' if findings else 'passed', finding_cases=findings,
                      cases_executed=len(report['cases']),
                      observations={name:sum(name in c.get('observations',[]) for c in report['cases']) for name in ('header_needs_reconciliation',)},
                      findings={name:sum(name in c['findings'] for c in report['cases']) for name in sorted({f for c in report['cases'] for f in c['findings']})},
                      fault_points_reached=sum(c['injection_reached'] for c in report['cases']), release_admissible=not findings)
    finally:
        for root in _roots: shutil.rmtree(root, ignore_errors=True)
        _roots.clear(); _free.clear()
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
