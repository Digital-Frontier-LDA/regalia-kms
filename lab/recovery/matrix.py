"""Enumerate recovery command crash points on disposable file-backed LUKS2 headers.

This is a laboratory observer, not a production repair tool. Findings do not grant
release admission. Keys are random fixtures and never included in the report.

Level 1 starts from a clean header: every cryptsetup call of the run, every header-writing call
after a single command failure, and every fsync inside each header-writing call, under each fault.
Level 2 (#175) starts from every distinct header a level-1 fault left behind and faults the
header writes of the run that resumes it (the operator's next run after a crash), then checks
that a third, ordinary run finishes it.
"""
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
import threading
from contextlib import contextmanager
import time
from concurrent.futures import ThreadPoolExecutor

FAULTS = ('fail_before', 'fail_after', 'term_after', 'kill_before', 'kill_after')
# Inside one call: the N-th fsync of that cryptsetup process is answered by strace with a KILL (the
# whole run dies with it), a TERM (sent to the whole run once the call returns) or EIO (a failing write).
SYNC_FAULTS = ('sync_kill', 'sync_term', 'sync_eio')
# What strace writes when each injection really happened (measured, strace 6.x): a sync fault counts
# only when its trace shows this after at least N fsyncs.
FIRED = {'sync_kill': '+++ killed by SIGKILL +++', 'sync_term': '--- SIGTERM {si_signo=SIGTERM, si_code=SI_KERNEL}', 'sync_eio': '(INJECTED)'}
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
fired=log.with_suffix('.fired')
if hit and fault.startswith('sync_'):
 inject={'sync_kill':'signal=KILL','sync_term':'signal=TERM','sync_eio':'error=EIO'}[fault]
 trace.unlink(missing_ok=True)
 command=[strace,'-f','-qq','-o',str(trace),'-e','trace=fsync','-e','inject=fsync:%s:when=%s'%(inject,os.environ['MATRIX_SYNC']),*command]
elif counts:
 trace.unlink(missing_ok=True)
 command=[strace,'-f','-qq','-o',str(trace),'-e','trace=fsync',*command]
result=subprocess.run(command,close_fds=False)
if hit and fault.startswith('sync_'):
 lines=trace.read_text().splitlines() if trace.exists() else []
 synced=sum('fsync(' in line for line in lines)
 if synced>=int(os.environ['MATRIX_SYNC']) and any(os.environ['MATRIX_FIRED'] in line for line in lines): fired.write_text('fired')
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
# A stand-in for the TPM keyslot's token: the header only, no TPM. Every fault and every retry must
# leave its keyslot and this token byte-identical.
TPM_TOKEN = {'type': 'systemd-tpm2', 'keyslots': ['1'], 'tpm2-blob': 'AA==', 'tpm2-pcrs': [7],
             'tpm2-pcr-bank': 'sha256', 'tpm2-primary-alg': 'ecc', 'tpm2-policy-hash': '00'}
TPM_SLOT = '1'


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


def opens_nothing(executable, image, value):
    """cryptsetup's own "no key available with this passphrase" (exit 2), never a failed read."""
    return cs(executable, ['open', '--test-passphrase', str(image)], value, check=False).returncode == 2


def observe(executable, image, values):
    """Read a header and try every key, on a COPY: cryptsetup repairs a header whose secondary copy
    is stale on any load (a read-only isLuks included), so observing the image a run will use would
    change what that run sees (#175: level-2 sync faults that never fired)."""
    with tempfile.TemporaryDirectory(prefix='regalia-luks-observe-') as temp:
        copy = Path(temp)/'observed.img'
        shutil.copyfile(image, copy)
        return _observe(executable, copy, values)


def _observe(executable, image, values):
    meta = header(executable, image)
    slots = sorted(meta['keyslots'], key=int)
    tokens = {i: {'type': t['type'], 'keyslots': t['keyslots']}
              for i, t in meta['tokens'].items()}
    return {'keyslots': slots, 'tokens': tokens, 'state': header_state(meta),
            'marks': {i: sorted(k for k in t if k.startswith('regalia_')) for i, t in meta['tokens'].items()},
            'tpm': [meta['keyslots'].get(TPM_SLOT), [t for t in meta['tokens'].values() if t.get('type') == 'systemd-tpm2']],
            'priorities': {slot:meta['keyslots'][slot].get('priority',1) for slot in slots},
            'opens_boot': {name:opens(executable,image,value) for name,value in values.items()},
            'opens_slots': {name: [s for s in slots if opens(executable, image, value, s)]
                            for name, value in values.items()}}


def header_state(meta):
    """The header's state as #175 names it, written here separately from recovery_state.py (which
    the script and recovery-reconcile.py share) so that a bug in one is not agreed with by the other."""
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


def _header_bytes_digest(stream):
    """Whether the two LUKS2 binary headers disagree (a write was cut between them): the primary at 0,
    the secondary right after the primary's metadata area. Returns 'stale' or 'same'."""
    primary = stream.read(4096)
    size = int.from_bytes(primary[8:16], 'big')        # hdr_size: binary header plus JSON area
    stream.seek(0); first = stream.read(size)
    stream.seek(size); second = stream.read(size)
    seqid = lambda block: int.from_bytes(block[16:24], 'big')
    return 'same' if seqid(first) == seqid(second) else 'stale'


def reported_state(text):
    """The last state the script printed, or None when it printed none (it was killed)."""
    found = [line.split(' ', 2)[1] for line in text.splitlines() if line.startswith('STATE: ')]
    return found[-1] if found else None


# The key that must own the one recovery keyslot when a run of this mode has finished, and the one
# that must open nothing. Enrol leaves the installer's passphrase (commissioning wipes it later), so
# its finished state is orphan-keyslot with exactly the installer's keyslot unnamed.
OWNER = {'enrol': ('old', None), 'replace': ('new', 'old')}
FINISHED = {'enrol': ('orphan-keyslot', ['0']), 'replace': ('clean', [])}


def finished(mode, state, tpm, spent_refused):
    """Why `state` is not a finished run of `mode`, or None. Shape AND which key: the recovery
    keyslot must be the expected key's, the spent key must open nothing, the TPM stand-in untouched."""
    expected, unnamed = FINISHED[mode]
    owner, spent = OWNER[mode]
    recovery = [s for t in state['tokens'].values() if t['type'] == 'systemd-recovery' for s in t['keyslots']]
    named = {s for t in state['tokens'].values() for s in t['keyslots']}
    if state['state'] != expected: return 'state %s, not %s' % (state['state'], expected)
    if sorted(set(state['keyslots']) - named) != unnamed: return 'unnamed keyslots %s' % sorted(set(state['keyslots']) - named)
    if len(recovery) != 1: return '%d recovery keyslots' % len(recovery)
    if state['opens_slots'][owner] != recovery: return 'the recovery keyslot is not the %s key\'s' % owner
    if state['priorities'].get(recovery[0], 1) == 0: return 'the recovery keyslot has priority ignore'
    if spent and not spent_refused: return 'the %s key still opens, or cannot be shown to open nothing' % spent
    if state['tpm'] != tpm: return 'the TPM keyslot or its token changed'
    if not state['opens_boot']['tpm']: return 'the TPM stand-in no longer opens'
    return None


def invoke(script, image, inputs, executable, directory, point=0, fault='', prefail=0, sync=0, counts=None):
    log = directory / 'calls.jsonl'
    log.unlink(missing_ok=True)
    log.with_suffix('.fired').unlink(missing_ok=True)
    environment = dict(os.environ, PATH=str(directory / 'bin') + ':' + os.environ['PATH'],
                       MATRIX_CALLS=str(log), MATRIX_CRYPTSETUP=executable, MATRIX_STRACE=STRACE or '',
                       MATRIX_POINT=str(point), MATRIX_FAULT=fault, MATRIX_PREFAIL=str(prefail),
                       MATRIX_SYNC=str(sync), MATRIX_SYNCS=str(counts or ''), MATRIX_FIRED=FIRED.get(fault, ''))
    reader, writer = os.pipe()
    if fault == 'closed_stderr': os.close(reader)
    process = subprocess.Popen(['bash', str(script), '--' + inputs[0], str(image)],
        env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=writer if fault == 'closed_stderr' else subprocess.PIPE, start_new_session=True)
    os.close(writer)
    if fault != 'closed_stderr': os.close(reader)
    try:
        output, error = process.communicate(('\n'.join(inputs[1:])+'\n').encode(), timeout=60)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        output, error = process.communicate()
        raise ValueError('recovery script timed out')
    calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    fired = log.with_suffix('.fired').exists()
    return process.returncode, (output+(error or b'')).decode(errors='replace'), calls, fired


def reconcile_fixture(executable, image, values, state, mode, reconciler=None):
    """Repair a header the ordinary retry did not finish, as a custodian would: keep the newest key
    that opens a recovery slot, retire every other slot except the installer's and the TPM's, each
    proven by a card. With `reconciler`, it is deploy/baremetal/recovery-reconcile.py itself."""
    name = 'new' if state['opens_slots']['new'] else 'old'
    keep = state['opens_slots'][name]
    if not keep: return False
    keep = keep[0]
    spare = {TPM_SLOT, keep} | ({'0'} if mode == 'enrol' else set())
    retire, cards = [], []
    for slot in state['keyslots']:
        if slot in spare: continue
        holders = [n for n in ('old', 'new') if slot in state['opens_slots'][n]]
        if not holders: raise ValueError('the custodian cannot prove slot %s with any card' % slot)
        retire.append(slot); cards.append(values[holders[0]])
    if reconciler is None:
        cs(executable,['config','--priority','normal','--key-slot',keep,str(image)])
        for slot in retire:
            cs(executable, ['luksKillSlot', '--batch-mode', str(image), slot])
        current = header(executable, image)
        for token, data in current['tokens'].items():
            if data['type'] == 'systemd-recovery' and data['keyslots'] != [keep]:
                cs(executable, ['token', 'remove', '--token-id', token, str(image)])
        current = header(executable, image)
        if not any(t['type'] == 'systemd-recovery' and t['keyslots'] == [keep] for t in current['tokens'].values()):
            subprocess.run([executable,'token','import','--json-file','-',str(image)],
                           input=json.dumps({'type':'systemd-recovery', 'keyslots':[keep]}), text=True, capture_output=True, check=True, timeout=30)
    else:
        spec = importlib.util.spec_from_file_location('recovery_reconcile_under_test', reconciler)
        repair = importlib.util.module_from_spec(spec); spec.loader.exec_module(repair)
        repair.CRYPTSETUP = executable
        repair.reconcile(image, keep, retire, values[name], cards)
    final = observe(executable, image, values)
    return bool(final['opens_boot'][name] and final['opens_boot']['tpm'] and len(
        [s for t in final['tokens'].values() if t['type'] == 'systemd-recovery' for s in t['keyslots']]) == 1)


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


class Context:
    def __init__(self, script, executable, mode, inputs, values, tpm, reconciler, keep_dir):
        self.script, self.executable, self.mode, self.inputs = script, executable, mode, inputs
        self.values, self.tpm, self.reconciler, self.keep_dir = values, tpm, reconciler, keep_dir
        self.kept = {}


def spent_refused(ctx, image):
    spent = OWNER[ctx.mode][1]
    return spent is None or opens_nothing(ctx.executable, image, ctx.values[spent])


def trial(ctx, baseline, scenario, level):
    with workspace() as directory:
        return _trial(ctx, baseline, scenario, level, directory)


def _trial(ctx, baseline, scenario, level, directory):
    index, fault, primary, operation, sync = scenario
    executable, values, mode = ctx.executable, ctx.values, ctx.mode
    image = directory/'trial.img'
    shutil.copyfile(baseline,image)
    before=observe(executable,image,values)   # on a copy: the image the run gets is the baseline's bytes
    code, text, actual, fired=invoke(ctx.script,image,ctx.inputs,executable,directory,index,fault,primary,sync)
    # The header exactly as the fault left it, before anything reads it (a read can repair it).
    left = directory/'left.img'
    shutil.copyfile(image, left)
    # No fixture secret may reach diagnostics, argv or evidence.
    public=text+json.dumps(actual)
    if any(secret in public for secret in values.values()):
        raise ValueError('fixture secret leaked to diagnostics or arguments')
    after=observe(executable,image,values)
    available=after['opens_boot']['tpm'] and after['tpm']==ctx.tpm and (
        after['opens_boot']['installer'] if mode=='enrol' else (after['opens_boot']['old'] or after['opens_boot']['new']))
    # A sync fault is reached only when strace's trace shows it fired; a call fault when the call ran.
    reached = fired if fault.startswith('sync_') else (not index or index <= len(actual))
    if not available:
        raise ValueError('a valid pre-existing unlock path was destroyed: %s' % json.dumps(
            {'mode':mode,'level':level,'point':index,'sync':sync,'primary_failure':primary,'fault':fault,'state':after}))
    issues=[]; observations=[]
    if not reached: issues.append('fault_not_injected' if fault.startswith('sync_') else 'cleanup_path_point_not_reached')
    if ('Nothing was changed' in text or 'as it was before this run' in text) and before != after:
        issues.append('unchanged_claim_contradicts_header')
    # The state the script printed last is the header's, read independently here. "unreadable" is
    # the script saying it could not read the header, which is no claim about it.
    said=reported_state(text)
    if said not in (None, 'unreadable') and said != after['state']: issues.append('reported_state_contradicts_header')
    # Not a finding: any script that writes the header more than once leaves a changed header that
    # is not finished when it is killed between two writes. The gate is that the next ordinary run
    # finishes it (below), and level 2 faults that run too.
    left_unfinished = after != before and finished(mode, after, ctx.tpm, spent_refused(ctx, image)) is not None
    if left_unfinished:
        observations.append('header_needs_reconciliation')
        if level == 1:
            # Distinct by what was observed AND by the bytes of both header copies: a stale secondary
            # header is a state of its own (the next load repairs it), even when it reads the same.
            with open(left, 'rb') as stream:
                raw = _header_bytes_digest(stream)
            key = json.dumps({'observed': {k: after[k] for k in ('state', 'keyslots', 'tokens', 'marks', 'priorities', 'opens_boot', 'opens_slots')},
                              'stale_secondary': raw}, sort_keys=True)
            with _guard:
                if key not in ctx.kept:
                    kept = ctx.keep_dir / ('%s-%d.img' % (mode, len(ctx.kept)))
                    shutil.copyfile(left, kept)
                    ctx.kept[key] = kept
    # The ordinary retry, with no fault: it must finish the run, with the right key.
    invoke(ctx.script,image,ctx.inputs,executable,directory)
    retried=observe(executable,image,values)
    why=finished(mode, retried, ctx.tpm, spent_refused(ctx, image))
    if why: issues.append('ordinary_retry_does_not_reconcile')
    repaired=True
    if why:
        repaired=reconcile_fixture(executable,image,values,retried,mode,ctx.reconciler)
        if not repaired: raise ValueError('explicit reconciliation failed after: %s' % why)
    left.unlink(missing_ok=True)
    return {'mode':mode,'level':level,'point':index,'fault':fault,'sync':sync,'exit_code':code,
            'calls_made':[c[:2] for c in actual] if not reached else None,
            'reported_state':said,'observations':observations,'retry_unfinished_because':why,
            'call':operation, 'primary_failure':primary, 'injection_reached':reached, 'actual_call_count':len(actual), 'state':after,
            'unlock_available':available,'ordinary_retry_clean':why is None,
            'fixture_reconciliation_clean':repaired,'findings':issues}


STRACE = shutil.which('strace')


def enumerate_run(ctx, baseline, work, writes_only, discover_cleanup):
    """The scenarios for one starting header: its calls (all, or only those that write the header)
    under each call fault, and each fsync of each header-writing call under each sync fault."""
    image = work/'trial.img'; shutil.copyfile(baseline, image)
    counts = work/'syncs.txt'; counts.unlink(missing_ok=True)
    code, _, calls, _ = invoke(ctx.script, image, ctx.inputs, ctx.executable, work, counts=counts)
    syncs = {int(i): int(n) for i, n in (line.split() for line in counts.read_text().splitlines())} if counts.exists() else {}
    table = {}
    for i, n in sorted(syncs.items()):
        if n: table.setdefault(' '.join(calls[i-1][:2]), []).append(n)
    scenarios = [(i, f, 0, calls[i-1][0], 0) for i in range(1, len(calls)+1)
                 if not writes_only or calls[i-1][0] in WRITES for f in FAULTS]
    if not writes_only: scenarios.append((0, 'closed_stderr', 0, 'stderr', 0))
    scenarios.extend((i, f, 0, calls[i-1][0], n) for i, count in sorted(syncs.items())
                     for n in range(1, count+1) for f in SYNC_FAULTS)
    if discover_cleanup:
        # Cleanup paths reached after each possible command refusal; every later command in them
        # that WRITES the header is interrupted too.
        for primary in range(1, len(calls)+1):
            shutil.copyfile(baseline, image)
            _, _, cleanup, _ = invoke(ctx.script, image, ctx.inputs, ctx.executable, work, primary, 'fail_before')
            for i in range(primary+1, len(cleanup)+1):
                if cleanup[i-1][0] in WRITES:
                    scenarios.extend((i, f, primary, cleanup[i-1][0], 0) for f in FAULTS)
    image.unlink(missing_ok=True)
    return code, calls, table, scenarios


def build_fixture(executable, directory, script, values):
    """base: the installer's passphrase (keyslot 0) and a TPM stand-in (keyslot 1, a systemd-tpm2
    token). enrolled: base, the old recovery key enrolled by the script, the installer's wiped."""
    base=directory/'base.img';base.touch();os.truncate(base,32<<20)
    fast=['--pbkdf','pbkdf2','--pbkdf-force-iterations','1000']
    cs(executable,['luksFormat','--type','luks2','--batch-mode',*fast,str(base)],values['installer'])
    with tempfile.TemporaryFile() as added:
        added.write(values['tpm'].encode()); added.seek(0)
        with tempfile.TemporaryFile() as current:
            current.write(values['installer'].encode()); current.seek(0)
            subprocess.run([executable,'luksAddKey','--batch-mode',*fast,'--new-key-slot',TPM_SLOT,'--key-file',f'/proc/self/fd/{current.fileno()}',
                            str(base),f'/proc/self/fd/{added.fileno()}'],pass_fds=(current.fileno(),added.fileno()),
                           stdin=subprocess.DEVNULL,capture_output=True,check=True,timeout=30)
    subprocess.run([executable,'token','import','--json-file','-',str(base)],input=json.dumps(TPM_TOKEN),
                   text=True,capture_output=True,check=True,timeout=30)
    enrolled=directory/'enrolled.img';shutil.copyfile(base,enrolled)
    work=directory/'baseline'; (work/'bin').mkdir(parents=True); shim=work/'bin/cryptsetup'; shim.write_text(SHIM); shim.chmod(0o700)
    code, text, _, _=invoke(script,enrolled,['enrol',values['installer'],values['old']],executable,work)
    if code: raise ValueError('baseline enrol failed: %s' % text[-500:])
    cs(executable,['luksKillSlot','--batch-mode',str(enrolled),'0'])
    return base, enrolled, work


def scenario_id(scenario):
    index, fault, primary, operation, sync = scenario
    return '%d:%s:%d:%s:%d' % (index, fault, primary, operation, sync)


def shard_of(items, shard):
    index, count = shard
    return [item for n, item in enumerate(items) if n % count == index - 1]


def run(script, output, mode='all', shard=(1, 1), reconciler=None):
    executable = shutil.which('cryptsetup', path=os.environ['PATH']+':/usr/sbin')
    if not executable or not Path('/proc/self/fd').is_dir():
        raise ValueError('Linux with real cryptsetup is required; no skipping')
    if not STRACE:
        raise ValueError('strace is required for the faults inside a call; no skipping')
    script = script.resolve()
    reconciler = reconciler.resolve() if reconciler else None
    source_sha256 = hashlib.sha256(script.read_bytes()).hexdigest()
    output.parent.mkdir(parents=True, exist_ok=True)
    report = {'schema':'regalia.recovery-crash-matrix/v2', 'status':'failed', 'production_approved':False,
              'script_sha256':source_sha256,
              'reconciler_sha256':hashlib.sha256(reconciler.read_bytes()).hexdigest() if reconciler else None,
              'cryptsetup':cs(executable, ['--version']).stdout.strip(),
              'strace':subprocess.run([STRACE,'-V'],capture_output=True,text=True).stdout.splitlines()[0],
              'shard':'%d/%d' % shard, 'cases':[], 'first_level_total':{}, 'second_level_baselines':{},
              'scope':'Level 1: every cryptsetup call from a clean header, header-writing calls after each single failure, '
                      'every fsync of every header-writing call (KILL, TERM, EIO). Level 2: the header writes and fsyncs '
                      'of the run resuming every distinct header level 1 left. Not physical power loss.'}
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix='regalia-luks-matrix-') as temp:
            directory = Path(temp)
            # The script runs from a staged copy, with recovery_state.py and a trail writer beside it (#278): the real
            # trails.py writes root's /var/log/regalia, which this harness (no root) does not touch. The stand-in
            # accepts every event; the trail itself is tested in tests/test_baremetal_recovery_key.py and the e2e.
            staged = directory/'tool'; staged.mkdir()
            shutil.copy(script, staged/script.name)
            shutil.copy(script.parent/'recovery_state.py', staged/'recovery_state.py')
            (staged/'trails.py').write_text('import sys\nsys.stdin.read()\nprint(1)\n')
            script = staged/script.name
            alphabet='cbdefghijklnrtuv'
            recovery=lambda: '-'.join(''.join(secrets.choice(alphabet) for _ in range(8)) for _ in range(8))
            values={'installer':secrets.token_hex(32), 'tpm':secrets.token_hex(32), 'old':recovery(), 'new':recovery()}
            base, enrolled, work = build_fixture(executable, directory, script, values)
            tpm = observe(executable, base, values)['tpm']
            for name in (('enrol','replace') if mode == 'all' else (mode,)):
                baseline=base if name=='enrol' else enrolled
                inputs=[name, values['installer'] if name=='enrol' else values['old'],
                        values['old'] if name=='enrol' else values['new']]
                keep_dir = directory/('level2-'+name); keep_dir.mkdir()
                ctx = Context(script, executable, name, inputs, values, tpm, reconciler, keep_dir)
                code, calls, table, scenarios = enumerate_run(ctx, baseline, work, writes_only=False, discover_cleanup=True)
                image=work/'trial.img'; shutil.copyfile(baseline,image)
                invoke(script,image,inputs,executable,work)
                why = finished(name, observe(executable,image,values), tpm, spent_refused(ctx, image))
                image.unlink()
                if code or why:
                    raise ValueError('the successful %s run does not finish with the right key: %s' % (name, why or 'exit %s' % code))
                report.setdefault('syncs',{})[name]=table
                report['first_level_total'][name]=len(scenarios)
                # Which scenarios, not only how many: merge.py checks that the shards' sets are
                # disjoint and that their union is this full list.
                ids=[scenario_id(s) for s in scenarios]
                if len(set(ids)) != len(ids): raise ValueError('two %s scenarios share an id' % name)
                report.setdefault('first_level_all_ids',{})[name]=ids
                mine = shard_of(scenarios, shard)
                report.setdefault('first_level_ids',{})[name]=[scenario_id(s) for s in mine]
                with ThreadPoolExecutor(WORKERS) as pool:
                    for case in pool.map(lambda s: trial(ctx, baseline, s, 1), mine):
                        report['cases'].append(case)
                        print(f"{name} L1 point={case['point']} sync={case['sync']} prefail={case['primary_failure']} {case['fault']}: observed, unlock preserved{' FINDINGS '+','.join(case['findings']) if case['findings'] else ''}",flush=True)
                # Level 2: every distinct unfinished header this shard's faults left, resumed under faults.
                second = []
                for key, kept in sorted(ctx.kept.items(), key=lambda kv: kv[1].name):
                    _, _, _, resumed = enumerate_run(ctx, kept, work, writes_only=True, discover_cleanup=False)
                    second.extend((kept, s) for s in resumed)
                report['second_level_baselines'][name]=len(ctx.kept)
                with ThreadPoolExecutor(WORKERS) as pool:
                    for case in pool.map(lambda ks: trial(ctx, ks[0], ks[1], 2), second):
                        report['cases'].append(case)
                        print(f"{name} L2 point={case['point']} sync={case['sync']} {case['fault']}: observed, unlock preserved{' FINDINGS '+','.join(case['findings']) if case['findings'] else ''}",flush=True)
        findings=sum(bool(c['findings']) for c in report['cases'])
        report.update(status='completed-with-findings' if findings else 'passed', finding_cases=findings,
                      cases_executed=len(report['cases']),
                      first_level_executed={n:sum(c['level']==1 and c['mode']==n for c in report['cases']) for n in report['first_level_total']},
                      second_level_executed={n:sum(c['level']==2 and c['mode']==n for c in report['cases']) for n in report['first_level_total']},
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
    parser.add_argument('--mode',choices=('all','enrol','replace'),default='all')
    parser.add_argument('--shard',default='1/1',help='i/n: run the level-1 scenarios whose position modulo n is i-1')
    parser.add_argument('--reconciler',type=Path,help='repair unfinished headers with this recovery-reconcile.py')
    args=parser.parse_args()
    index, count = (int(x) for x in args.shard.split('/'))
    if not 1 <= index <= count: parser.error('--shard i/n needs 1 <= i <= n')
    result=run(args.script, args.output, args.mode, (index, count), args.reconciler)
    print(json.dumps({k:v for k,v in result.items() if k!='cases'},indent=2))
    if result['status'] != 'passed': raise SystemExit(1)

if __name__=='__main__': main()
