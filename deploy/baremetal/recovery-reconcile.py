#!/usr/bin/env -S python3 -I
"""Inspect recovery metadata or reconcile slots explicitly selected by a custodian.

No key is generated, no unknown keyslot is guessed away, and no rollback runs.
Use from a serialized, trusted console; other header writers must be stopped.
"""
import argparse
import fcntl
import getpass
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import stat
import sys

# recovery_state.py beside this file, by its resolved path: the reader recovery-key.sh uses. Run with
# python3 -I, the script's own directory is not on sys.path, so it is added explicitly, last.
sys.path.append(str(Path(__file__).resolve().parent))
import recovery_state  # noqa: E402
import trails  # noqa: E402

CRYPTSETUP = '/usr/sbin/cryptsetup'
LOCKDIR = Path('/run/lock')
# The audit trail (#278): the registry's fixed path, root's. Tests point it elsewhere, as they do LOCKDIR.
TRAIL = trails.where('recovery-reconcile')
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C'}
KEY = re.compile(r'(?:[cbdefghijklnrtuv]{8}-){7}[cbdefghijklnrtuv]{8}')


class Refused(Exception):
    pass


def command(device, arguments, key=None):
    # An anonymous pipe supplies the secret. It is absent from argv and env.
    arguments = list(arguments)
    slot = arguments.pop() if arguments[0] == 'luksKillSlot' else None
    suffix = [str(device)] + ([slot] if slot is not None else [])
    if key is None:
        result = subprocess.run([CRYPTSETUP, *arguments, *suffix],
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=45, env=ENV)
    else:
        reader, writer = os.pipe()
        try:
            os.write(writer, key.encode()); os.close(writer); writer = None
            result = subprocess.run([CRYPTSETUP, *arguments, '--key-file', f'/proc/self/fd/{reader}', *suffix],
                                    pass_fds=(reader,), stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=45, env=ENV)
        finally:
            os.close(reader)
            if writer is not None: os.close(writer)
    return result


def cryptsetup_new_enough():
    """2.4 or newer: token import --token-replace, which the retiring mark relies on, is not in
    older ones. Refused by name, not by a failed flag."""
    result = subprocess.run([CRYPTSETUP, '--version'], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=45, env=ENV)
    found = re.match(r'cryptsetup (\d+)\.(\d+)', result.stdout or '')
    if not found: raise Refused('cannot read the cryptsetup version')
    if tuple(int(x) for x in found.groups()) < (2, 4):
        raise Refused('cryptsetup %s.%s is too old: 2.4 or newer is required (token import --token-replace)' % found.groups())


def header(device):
    result = command(device, ['luksDump', '--dump-json-metadata'])
    if result.returncode or len(result.stdout) > 2**20:
        raise Refused('cannot read bounded LUKS2 metadata')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise Refused('duplicate metadata field')
            result[key] = value
        return result
    try:
        data = json.loads(result.stdout, object_pairs_hook=unique)
        slots, tokens = data['keyslots'], data['tokens']
        if not isinstance(slots, dict) or not isinstance(tokens, dict): raise ValueError()
        if len(slots) > 32 or len(tokens) > 32: raise ValueError()
        for slot, value in slots.items():
            if not re.fullmatch(r'(?:[0-9]|[12][0-9]|3[01])', slot): raise ValueError()
            if not isinstance(value.get('kdf', {}).get('salt'), str): raise ValueError()
            priority = value.get('priority', 1)
            if type(priority) is not int or priority not in (0, 1, 2): raise ValueError()
        for token, value in tokens.items():
            if not re.fullmatch(r'(?:[0-9]|[12][0-9]|3[01])', token): raise ValueError()
            if not isinstance(value['type'], str) or not isinstance(value['keyslots'], list): raise ValueError()
            if any(type(slot) is not str or slot not in slots for slot in value['keyslots']): raise ValueError()
    except (ValueError, KeyError, TypeError, AttributeError):
        raise Refused('malformed or inconsistent LUKS2 metadata') from None
    return data


def describe(data):
    """The custodian's view; 'header_state' is recovery_state.classify, the reader recovery-key.sh uses."""
    shared = recovery_state.classify(data)
    owners = {slot: [] for slot in data['keyslots']}
    recovery = set(); orphans = []
    for token, value in data['tokens'].items():
        for slot in value['keyslots']: owners[slot].append(value['type'])
        if value['type'] == 'systemd-recovery':
            recovery.update(value['keyslots'])
            if not value['keyslots']: orphans.append(token)
    ignored = [s for s in recovery if data['keyslots'][s].get('priority', 1) == 0]
    unlabelled = [s for s, types in owners.items() if not types]
    ambiguous = [s for s, types in owners.items() if len(types) > 1]
    clean = len(recovery) == 1 and not (orphans or ignored or unlabelled or ambiguous)
    return {'state': 'clean' if clean else 'needs-review', 'header_state': shared['state'],
            'recovery_slots': sorted(recovery, key=int), 'unlabelled_slots': sorted(unlabelled, key=int),
            'ignored_recovery_slots': sorted(ignored, key=int),
            'orphan_recovery_tokens': sorted(orphans, key=int),
            'ambiguous_slots': sorted(ambiguous, key=int),
            'slots': {s: {'types': types, 'priority': data['keyslots'][s].get('priority', 1)}
                      for s, types in owners.items()}}


def proves(device, key, slot=None):
    args = ['open', '--test-passphrase']
    if slot is not None: args += ['--key-slot', slot]
    return command(device, args, key).returncode == 0


def secret(prompt):
    value = getpass.getpass(prompt) if sys.stdin.isatty() else sys.stdin.readline(4097).rstrip('\n')
    if not KEY.fullmatch(value): raise Refused('expected a correctly grouped systemd recovery key')
    return value


def reconcile(device, keep, retire, kept_key, retired_keys):
    if keep in retire or len(set(retire)) != len(retire) or len(retire) != len(retired_keys):
        raise Refused('keep and retire selections must be distinct')
    before = header(device)
    if keep not in before['keyslots']: raise Refused('selected kept slot is absent')
    for slot in [keep, *retire]:
        types = describe(before)['slots'].get(slot, {}).get('types', [])
        owned = [t for t in before['tokens'].values() if slot in t['keyslots']]
        if len(owned) > 1 or any(t['keyslots'] != [slot] for t in owned):
            raise Refused('selected slot has ambiguous token ownership')
        if any(t != 'systemd-recovery' for t in types):
            raise Refused('selected slot belongs to another device/token type')
    if not proves(device, kept_key, keep): raise Refused('kept card does not open the selected slot')
    # Prove every requested retirement before the first write. Absent slots are
    # already retired; a retry can continue without inventing an undo operation.
    # luksKillSlot wipes a slot's key material (with random bytes) BEFORE it updates
    # the metadata, so a kill between the two leaves the slot listed while its card
    # opens nothing. That is accepted only when this tool recorded, on the kept
    # slot's token and after proving the card, that it was retiring exactly that slot
    # (number and salt), and cryptsetup itself answers "no key" (exit 2) for the card.
    retiring = retiring_marks(before, keep)
    for slot, value in zip(retire, retired_keys):
        if slot in before['keyslots'] and not proves(device, value, slot):
            salt = before['keyslots'][slot].get('kdf', {}).get('salt')
            if (slot, salt) not in retiring:
                raise Refused('retired card does not open its selected slot')
            if command(device, ['open', '--test-passphrase'], value).returncode != 2:
                raise Refused('cannot prove the retired card opens nothing; inspect and repeat the selections')
    retained = {s: v for s, v in before['keyslots'].items() if s not in retire and s != keep}
    kept_salt = before['keyslots'][keep]['kdf']['salt']
    def checked_write(args, key=None, input_data=None):
        # Ignore cooperative signals only during a single child header update.
        # KILL still leaves an observable header for the next explicit retry.
        prior = {s: signal.signal(s, signal.SIG_IGN) for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
        try:
            if input_data is None:
                result = command(device, args, key)
            else:
                result = subprocess.run([CRYPTSETUP, *args, str(device)], input=input_data,
                                        capture_output=True, timeout=45, env=ENV)
        finally:
            for sig, handler in prior.items(): signal.signal(sig, handler)
        actual = header(device)
        if actual['keyslots'].get(keep, {}).get('kdf', {}).get('salt') != kept_salt:
            raise Refused('kept slot identity changed; stop concurrent header writers')
        if any(actual['keyslots'].get(s) != value for s, value in retained.items()):
            raise Refused('an unselected slot changed; stop concurrent header writers')
        if result.returncode: raise Refused('header operation refused; inspect actual state and retry selections')
        return actual
    current = before
    if current['keyslots'][keep].get('priority', 1) == 0:
        current = checked_write(['config', '--priority', 'normal', '--key-slot', keep])
    if not any(t['type'] == 'systemd-recovery' and t['keyslots'] == [keep] for t in current['tokens'].values()):
        # A token shared across multiple slots must be handled by the custodian.
        if any(keep in t['keyslots'] for t in current['tokens'].values()):
            raise Refused('kept slot has ambiguous token ownership')
        token = json.dumps({'type': 'systemd-recovery', 'keyslots': [keep]}).encode()
        current = checked_write(['token', 'import', '--json-file', '-'], input_data=token)
    if not proves(device, kept_key): raise Refused('kept card does not open the volume as a boot prompt tries it')
    for slot in retire:
        current = header(device)
        if slot not in current['keyslots']: continue
        # Slot number reuse is not authority to retire a different slot.
        if current['keyslots'][slot] != before['keyslots'][slot]:
            raise Refused('retired slot identity changed; inspect again')
        mark = (slot, current['keyslots'][slot]['kdf']['salt'])
        if mark not in retiring_marks(current, keep):
            token_id, token = kept_token(current, keep)
            marks = [list(m) for m in sorted(retiring_marks(current, keep) | {mark})]
            data = json.dumps(dict(token, regalia_retiring=marks)).encode()
            current = checked_write(['token', 'import', '--token-id', token_id, '--token-replace', '--json-file', '-'], input_data=data)
        current = checked_write(['luksKillSlot', '--batch-mode', slot], kept_key)
    for token in describe(header(device))['orphan_recovery_tokens']:
        checked_write(['token', 'remove', '--token-id', token])
    # Every retirement is done: clear the mark (one in-place token replace, measured atomic on
    # cryptsetup 2.7.5), so that a finished header holds the kept slot's token as it was before.
    current = header(device)
    # Only marks whose slot is gone are cleared; a mark for a slot still listed stays, so a later
    # retry can still finish it.
    marks = retiring_marks(current, keep)
    pending = sorted(m for m in marks if m[0] in current['keyslots'])
    if marks and len(pending) < len(marks):
        token_id, token = kept_token(current, keep)
        token = {k: v for k, v in token.items() if k != 'regalia_retiring'}
        if pending: token['regalia_retiring'] = [list(m) for m in pending]
        data = json.dumps(token).encode()
        checked_write(['token', 'import', '--token-id', token_id, '--token-replace', '--json-file', '-'], input_data=data)
    final = header(device)
    if any(s in final['keyslots'] for s in retire) or not proves(device, kept_key, keep) or not proves(device, kept_key):
        raise Refused('selected reconciliation did not finish')
    for value in retired_keys:
        if value == kept_key: continue  # explicit retirement of a redundant copy
        tested = command(device, ['open', '--test-passphrase'], value)
        if tested.returncode == 0:
            raise Refused('a retired card still opens an unselected slot; review it without deleting unknown slots')
        if tested.returncode != 2:
            raise Refused('cannot prove the retired card no longer opens; inspect and repeat the selections')
    return describe(final)


def kept_token(data, keep):
    found = [(i, t) for i, t in data['tokens'].items() if t['type'] == 'systemd-recovery' and t['keyslots'] == [keep]]
    if len(found) != 1: raise Refused('kept slot has no single recovery token')
    return found[0]


def retiring_marks(data, keep):
    """(slot, salt) pairs this tool recorded on the kept slot's token before retiring them."""
    try:
        _, token = kept_token(data, keep)
    except Refused:
        return set()
    marks = token.get('regalia_retiring')
    if not isinstance(marks, list): return set()
    return {(m[0], m[1]) for m in marks if isinstance(m, list) and len(m) == 2 and all(isinstance(x, str) for x in m)}


@contextmanager
def instance_lock(device):
    # The same lock file recovery-key.sh takes (recovery_state.lock_path): the two never interleave.
    path = recovery_state.lock_path(device, str(LOCKDIR))
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        if recovery_state.lock_unsafe(os.fstat(descriptor)):
            raise Refused('unsafe reconciliation lock')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('device', type=Path)
    parser.add_argument('--keep-slot', choices=[str(n) for n in range(32)])
    parser.add_argument('--retire-slot', action='append', choices=[str(n) for n in range(32)], default=[])
    args = parser.parse_args()
    result = 1
    try:
        # Separate lock file: locking the device inode itself deadlocks real
        # cryptsetup. Other header tools do not share this utility lock.
        cryptsetup_new_enough()
        with instance_lock(args.device):
            if args.keep_slot is None:
                if args.retire_slot: raise Refused('--retire-slot requires --keep-slot')
                result = 0 if describe(header(args.device))['state'] == 'clean' else 1
            else:
                # The custodian's choice is recorded before a card is asked for, and the run refuses if it
                # cannot be (nothing is done unrecorded); then exactly one outcome: ALLOW, DENY (the header
                # byte for byte as it was) or INCOMPLETE (it changed: repeat the same selection). Never a key.
                before = header(args.device)
                identity = recovery_state.device_id(args.device)
                event = {'event': 'recovery-reconcile', 'device': str(args.device), 'device_id': identity, 'keep': args.keep_slot,
                         'retire': list(args.retire_slot), 'state_before': describe(before)['header_state']}
                try:
                    # a run killed after its request left it unanswered: closed first, so every request on the
                    # trail has exactly one outcome
                    stale = trails.unanswered(TRAIL, event='recovery-reconcile', device_id=identity)   # whatever name it was given
                    if stale is not None:
                        trails.append(TRAIL, {'event': 'recovery-reconcile', 'device': str(args.device), 'device_id': identity, 'keep': stale.get('keep'),
                                              'retire': stale.get('retire'), 'outcome': 'INCOMPLETE', 'request': stale['seq'],
                                              'reason': 'the previous run was killed: no outcome was recorded',
                                              'state_after': describe(before)['header_state']})
                        print('the audit trail held an unanswered request (seq %d): it is closed as INCOMPLETE' % stale['seq'], file=sys.stderr)
                    request = trails.append(TRAIL, dict(event, outcome='REQUESTED', reason=''))
                except (trails.Refused, OSError) as error:
                    raise Refused('the audit trail cannot be written, nothing was done: %s' % error)
                # TERM and HUP raise, so the finally below records the outcome; from here a kill -9 is closed by the
                # next run (above)
                def stop(signum, frame):
                    raise KeyboardInterrupt('signal %d' % signum)
                for sig in (signal.SIGTERM, signal.SIGHUP):
                    signal.signal(sig, stop)
                outcome, reason = 'DENY', ''
                try:
                    kept = secret('Recovery key to KEEP, read from its card: ')
                    retired = [secret(f'Recovery key to RETIRE from slot {slot}: ') for slot in args.retire_slot]
                    reconcile(args.device, args.keep_slot, args.retire_slot, kept, retired)
                    kept = ''; retired.clear()
                    outcome = 'ALLOW'
                except BaseException as error:
                    reason = str(error)[:240] or type(error).__name__
                    raise
                finally:
                    try:
                        after = header(args.device)
                        if outcome != 'ALLOW' and after != before:
                            outcome = 'INCOMPLETE'
                        state_after = describe(after)['header_state']
                    except (Refused, OSError, subprocess.SubprocessError):
                        state_after = 'unreadable'
                        outcome = 'INCOMPLETE' if outcome != 'ALLOW' else outcome
                    try:
                        trails.append(TRAIL, dict(event, outcome=outcome, reason=reason, state_after=state_after, request=request))
                    except (trails.Refused, OSError) as error:
                        print('REFUSED: the outcome (%s) could not be written to the audit trail: %s' % (outcome, error), file=sys.stderr)
                        outcome = 'UNRECORDED'
                result = 0 if outcome == 'ALLOW' and describe(header(args.device))['state'] == 'clean' else 1
    except (Refused, OSError, subprocess.SubprocessError) as error:
        print(f'REFUSED: {error}', file=sys.stderr)
    finally:
        try: print(json.dumps(describe(header(args.device)), sort_keys=True))
        except (Refused, OSError, subprocess.SubprocessError):
            print('{"state":"unreadable"}'); result = 1
    return result


if __name__ == '__main__':
    raise SystemExit(main())
