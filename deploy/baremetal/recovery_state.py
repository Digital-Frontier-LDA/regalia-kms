"""The disk recovery key's header state (#175), shared by recovery-key.sh and recovery-reconcile.py.

One reader of a LUKS2 header's JSON metadata (cryptsetup luksDump --dump-json-metadata), so that
the two tools never disagree about what a header holds. lab/recovery/matrix.py deliberately keeps a
reader of its own, written separately, to check this one.

  clean           one recovery keyslot, every keyslot named by a token, no empty recovery token
  no-recovery     no recovery keyslot
  orphan-keyslot  one recovery keyslot, and a keyslot no token names
  added-unproven  two recovery keyslots, and the header records that one replaces the other
  orphan-token    a recovery token that names no keyslot (or only keyslots that are gone)
  unknown         anything else: two recovery keyslots no --replace made, a token naming two
                  keyslots, a keyslot named by two recovery tokens, a recovery keyslot a boot
                  prompt skips (priority ignore), more than two recovery keyslots

Two recovery keyslots are a --replace that stopped if, and only if, each is named by exactly one
recovery token naming only it, and exactly one of the two tokens says it REPLACES the other keyslot,
names THAT KEYSLOT'S SALT, and carries the other's generation plus one. The salt is the keyslot's
identity: keyslot numbers are reused, and the mark outlives a completed replace.

Also here: the lock both tools take for one device.
"""
import json
import os
import stat
import sys

LOCKDIR = '/run/lock'


def _order(slot):
    return (len(slot), slot)


def generation(token):
    value = token.get('regalia_generation', 0)
    return value if type(value) is int and 0 <= value <= 2**31 - 1 else None


def classify(meta):
    keyslots = meta.get('keyslots') or {}
    present = set(keyslots)
    tokens = sorted(((i, t) for i, t in (meta.get('tokens') or {}).items() if isinstance(t, dict)),
                    key=lambda item: _order(item[0]))
    named, owner, empty, why = set(), {}, [], []
    for token_id, token in tokens:
        listed = [str(s) for s in token.get('keyslots') or []]
        live = [s for s in listed if s in present]
        named.update(live)
        if token.get('type') != 'systemd-recovery':
            continue
        if not live:
            empty.append(token_id)
            continue
        if len(listed) != 1:
            why.append('one recovery token names more than one keyslot (token %s)' % token_id)
            continue
        if listed[0] in owner:
            why.append('keyslot %s is named by more than one recovery token' % listed[0])
            continue
        owner[listed[0]] = token
    recovery = sorted(owner, key=_order)
    unnamed = sorted((s for s in present if s not in named), key=_order)
    for slot in recovery:
        if (keyslots[slot] or {}).get('priority') == 0:
            why.append('recovery keyslot %s has priority ignore: a boot prompt would not try it '
                       '(cryptsetup config --priority normal --key-slot %s DEVICE)' % (slot, slot))

    def salt(slot):
        value = ((keyslots.get(slot) or {}).get('kdf') or {}).get('salt')
        return value if isinstance(value, str) and value else None

    pair = None
    if len(recovery) == 2 and not why:
        a, b = recovery
        newer = [(new, old) for new, old in ((a, b), (b, a))
                 if str(owner[new].get('regalia_replaces')) == old and salt(old) is not None
                 and owner[new].get('regalia_replaces_salt') == salt(old)
                 and generation(owner[new]) is not None and generation(owner[old]) is not None
                 and generation(owner[new]) == generation(owner[old]) + 1]
        if len(newer) == 1:
            pair = (newer[0][1], newer[0][0])
        else:
            why.append('two recovery keyslots (%s), and the header does not say that one replaces the other' % ' '.join(recovery))
    elif len(recovery) > 2:
        why.append('%d recovery keyslots' % len(recovery))
    if why:
        state = 'unknown'
    elif empty:
        state = 'orphan-token'
    elif not recovery:
        state = 'no-recovery'
    elif pair:
        state = 'added-unproven'
    elif unnamed:
        state = 'orphan-keyslot'
    else:
        state = 'clean'
    return {'state': state, 'recovery': recovery, 'unnamed': unnamed, 'empty': empty,
            'pair': list(pair) if pair else [], 'all': sorted(present, key=_order), 'why': why}


def lock_path(device, lockdir=LOCKDIR):
    """The lock recovery-key.sh and recovery-reconcile.py both take for one device."""
    identity = os.stat(device)
    key = 'block-%d' % identity.st_rdev if stat.S_ISBLK(identity.st_mode) else 'file-%d-%d' % (identity.st_dev, identity.st_ino)
    return os.path.join(lockdir, 'regalia-recovery-%s.lock' % key)


def lock_unsafe(info):
    """Why an open lock file may not be trusted, or None (the same checks in both tools)."""
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o077:
        return 'unsafe recovery lock (not a private regular file of this user)'
    return None


def main(argv):
    """For recovery-key.sh: `classify` (header JSON on stdin, one line out), `lock DEVICE`."""
    if argv[:1] == ['classify']:
        try:
            meta = json.load(sys.stdin)
        except ValueError:
            return 1
        c = classify(meta)
        print('|'.join([c['state'], ' '.join(c['recovery']), ' '.join(c['unnamed']), ' '.join(c['empty']),
                        ' '.join(c['pair']), ' '.join(c['all']), '; '.join(c['why'])]))
        return 0
    if argv[:1] == ['lock'] and len(argv) == 2:
        path = lock_path(argv[1])
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            reason = lock_unsafe(os.fstat(descriptor))
        finally:
            os.close(descriptor)
        if reason:
            print('%s: %s' % (path, reason), file=sys.stderr)
            return 1
        print(path)
        return 0
    return 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
