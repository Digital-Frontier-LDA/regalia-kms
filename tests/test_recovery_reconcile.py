"""Explicit operator choices must never delete unproved or unselected slots."""
import copy
import json
import os
import shutil
import subprocess
import tempfile
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('recovery_reconcile', Path(__file__).resolve().parents[1] / 'deploy/baremetal/recovery-reconcile.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
from deploy.baremetal import trails  # noqa: E402


def metadata():
    return {'keyslots': {'0': {'kdf': {'salt': 'installer'}}, '1': {'kdf': {'salt': 'old'}},
                         '2': {'kdf': {'salt': 'new'}}},
            'tokens': {'0': {'type': 'systemd-recovery', 'keyslots': ['1']},
                       '1': {'type': 'systemd-recovery', 'keyslots': ['2']}}}


class CustodianSelection(unittest.TestCase):
    def test_wrong_retirement_card_causes_no_writes(self):
        with patch.object(module, 'header', return_value=metadata()), patch.object(module, 'proves', side_effect=[True, False]), patch.object(module, 'command') as call:
            with self.assertRaisesRegex(module.Refused, 'retired card'):
                module.reconcile('/fixture', '2', ['1'], 'new', ['wrong'])
            call.assert_not_called()

    def test_never_accepts_another_token_type_or_shared_token(self):
        for token in [{'type': 'systemd-tpm2', 'keyslots': ['2']}, {'type': 'systemd-recovery', 'keyslots': ['1', '2']}]:
            data = metadata(); data['tokens'] = {'0': token}
            with patch.object(module, 'header', return_value=data), patch.object(module, 'command') as call:
                with self.assertRaises(module.Refused): module.reconcile('/fixture', '2', ['1'], 'new', ['old'])
                call.assert_not_called()

    def test_ignored_or_unlabelled_keys_and_duplicate_owners_are_not_clean(self):
        data = metadata(); del data['keyslots']['0']; del data['keyslots']['1']; del data['tokens']['0']
        self.assertEqual(module.describe(data)['state'], 'clean')
        for change in ['ignored', 'unlabelled', 'duplicate', 'orphan']:
            trial = copy.deepcopy(data)
            if change == 'ignored': trial['keyslots']['2']['priority'] = 0
            if change == 'unlabelled': trial['keyslots']['3'] = {'kdf': {'salt': 'unknown'}}
            if change == 'duplicate': trial['tokens']['4'] = trial['tokens']['1']
            if change == 'orphan': trial['tokens']['4'] = {'type': 'systemd-recovery', 'keyslots': []}
            self.assertEqual(module.describe(trial)['state'], 'needs-review')


class ReconciliationLock(unittest.TestCase):
    def test_other_instance_cannot_lock_the_same_device_alias(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(module, 'LOCKDIR', Path(temp)):
            device = Path(temp) / 'device'; device.touch()
            alias = Path(temp) / 'alias'; alias.symlink_to(device)
            with module.instance_lock(device):
                with self.assertRaises(BlockingIOError):
                    with module.instance_lock(alias): pass
            with module.instance_lock(device): pass


PATH = os.environ.get('PATH', '') + os.pathsep + '/usr/sbin' + os.pathsep + '/sbin'
CRYPTSETUP = shutil.which('cryptsetup', path=PATH)
STRACE = shutil.which('strace', path=PATH)
CRYPTENROLL = shutil.which('systemd-cryptenroll', path=PATH)
OLD = 'cbdefghi-jklnrtuv-vutrnlkj-ihgfedbc-ccddeeff-gghhiijj-kkllnnrr-ttuuvvcb'
NEW = 'vvuuttrr-nnllkkjj-iihhggff-eeddccbb-cbdefghi-jklnrtuv-bcdefghi-jklnrtuc'
# Runs main() with cryptsetup replaced by the shim and the lock directory moved into the test's own.
WORKER = '''import importlib.util,sys
p=sys.argv.pop(1); c=sys.argv.pop(1); l=sys.argv.pop(1)
s=importlib.util.spec_from_file_location('reconcile',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
m.CRYPTSETUP=c; m.LOCKDIR=m.Path(l); m.TRAIL=str(m.Path(l)/'trail.jsonl')   # the registry's path is root's: here, the test's own
raise SystemExit(m.main())
'''
# KILL at the first fsync of luksKillSlot (its key material is wiped, its metadata not yet written),
# and the reconcile process with it, as a power cut or kill -9 would.
# (reconcile runs cryptsetup with a fixed environment, so the kill is written into a shim of its own)
SHIM = '''#!/bin/bash
if [ "$1" = luksKillSlot ]; then
  "%s" -f -qq -o /dev/null -e trace=fsync -e inject=fsync:signal=KILL:when=1 "%s" "$@"
  kill -KILL "$PPID"; exit 137
fi
exec "%s" "$@"
'''


@unittest.skipUnless((CRYPTSETUP and STRACE) or os.environ.get('REGALIA_EXPECT_CRYPTSETUP') == '1', 'cryptsetup or strace is not installed')
class KilledInsideTheRetirement(unittest.TestCase):
    """d9's read of #236: luksKillSlot wipes a slot's key material before it updates the metadata.
    Killed between the two, the retired slot is still listed and its card opens nothing. The same
    selection, run again, must finish it rather than refuse "retired card does not open"."""

    def setUp(self):
        self.assertTrue(CRYPTSETUP and STRACE, 'REGALIA_EXPECT_CRYPTSETUP=1 and cryptsetup or strace is missing')
        self.dir = tempfile.mkdtemp(prefix='regalia-reconcile-kill-')
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.img = os.path.join(self.dir, 'disk.img')
        with open(self.img, 'wb') as f:
            f.truncate(32 << 20)
        fast = ['--pbkdf', 'pbkdf2', '--pbkdf-force-iterations', '1000']
        self.cs('luksFormat', '--type', 'luks2', '--batch-mode', *fast, '--key-file', self.secret('installer'), self.img)
        self.cs('luksAddKey', '--batch-mode', *fast, '--key-file', self.secret('installer'), '--new-key-slot', '1', self.img, self.secret(OLD))
        self.cs('luksAddKey', '--batch-mode', *fast, '--key-file', self.secret('installer'), '--new-key-slot', '2', self.img, self.secret(NEW))
        subprocess.run([CRYPTSETUP, 'token', 'import', '--json-file', '-', self.img], input='{"type":"systemd-recovery","keyslots":["1"]}',
                       capture_output=True, text=True, check=True, timeout=60)
        self.killing = os.path.join(self.dir, 'cryptsetup-killed-at-the-wipe')
        with open(self.killing, 'w', encoding='ascii') as f:
            f.write(SHIM % (STRACE, CRYPTSETUP, CRYPTSETUP))
        os.chmod(self.killing, 0o700)
        self.shim = CRYPTSETUP

    def secret(self, value):
        path = os.path.join(self.dir, 'secret-%d' % len(os.listdir(self.dir)))
        with open(path, 'w', encoding='ascii') as f:
            f.write(value)
        return path

    def cs(self, *args, ok=True):
        done = subprocess.run([CRYPTSETUP, *args], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
        if ok:
            self.assertEqual(done.returncode, 0, done.stderr)
        return done

    def header(self):
        return json.loads(self.cs('luksDump', '--dump-json-metadata', self.img).stdout)

    def opens(self, value, slot=None):
        return self.cs('open', '--test-passphrase', '--key-file', self.secret(value), *(['--key-slot', slot] if slot else []), self.img, ok=False).returncode

    def reconcile(self, kill=False):
        source = Path(__file__).resolve().parents[1] / 'deploy/baremetal/recovery-reconcile.py'
        return subprocess.run(['python3', '-I', '-c', WORKER, str(source), self.killing if kill else CRYPTSETUP, self.dir, self.img,
                               '--keep-slot', '2', '--retire-slot', '1'],
                              input=NEW + '\n' + OLD + '\n', capture_output=True, text=True, timeout=120)

    def test_the_same_selection_finishes_a_retirement_killed_after_the_wipe(self):
        killed = self.reconcile(kill=True)
        self.assertEqual(killed.returncode, -9, killed.stderr)
        meta = self.header()
        self.assertIn('1', meta['keyslots'], 'the premise: the retired slot is still listed')
        self.assertEqual(self.opens(OLD, '1'), 2, 'the premise: its key material is gone')
        kept = [t for t in meta['tokens'].values() if t['keyslots'] == ['2']]
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]['regalia_retiring'], [['1', meta['keyslots']['1']['kdf']['salt']]])
        done = self.reconcile()
        self.assertEqual(done.returncode, 1, done.stderr)   # 1: the installer's passphrase is still an unlabelled slot
        self.assertNotIn('REFUSED', done.stderr)
        meta = self.header()
        self.assertEqual(sorted(meta['keyslots']), ['0', '2'])
        # the mark is cleared: the kept slot's token is the plain one, as if nothing had stopped
        self.assertEqual(list(meta['tokens'].values()), [{'type': 'systemd-recovery', 'keyslots': ['2']}])
        self.assertEqual(self.opens(OLD), 2)
        self.assertEqual(self.opens(NEW), 0)
        # #278: each run recorded before a card was asked for, and its outcome after: the cut one INCOMPLETE
        with open(os.path.join(self.dir, 'trail.jsonl'), encoding='utf-8') as f:
            events = [json.loads(line) for line in f]
        # the killed run's request is closed by the rerun (INCOMPLETE, naming it) before the rerun's own
        self.assertEqual([(e['outcome'], e.get('request')) for e in events],
                         [('REQUESTED', None), ('INCOMPLETE', events[0]['seq']), ('REQUESTED', None), ('ALLOW', events[2]['seq'])])
        self.assertEqual((events[-1]['keep'], events[-1]['retire'], events[-1]['state_after']), ('2', ['1'], 'orphan-keyslot'))
        trails.verify(os.path.join(self.dir, 'trail.jsonl'))
        with open(os.path.join(self.dir, 'trail.jsonl'), encoding='utf-8') as f:
            text = f.read()
        self.assertNotIn(OLD, text)
        self.assertNotIn(NEW, text)
        self.assertNotIn(OLD[:8], text)

    def test_a_wrong_card_against_a_listed_slot_with_no_mark_is_still_refused(self):
        # the same wiped-looking answer (the card opens nothing) but no mark: refused, nothing written
        before = self.header()
        done = subprocess.run(['python3', '-I', '-c', WORKER, str(Path(__file__).resolve().parents[1] / 'deploy/baremetal/recovery-reconcile.py'),
                               self.shim, self.dir, self.img, '--keep-slot', '2', '--retire-slot', '1'],
                              input=NEW + '\n' + 'rtuvcbde-fghijkln-bcdefghi-jklnrtuv-vvttrrnn-llkkjjii-hhggffee-ddccbbcc\n',
                              capture_output=True, text=True, timeout=120)
        self.assertIn('retired card does not open its selected slot', done.stderr)
        self.assertEqual(self.header(), before)

    @unittest.skipUnless(CRYPTENROLL, 'systemd-cryptenroll is not installed')
    def test_systemd_accepts_a_marked_token(self):
        subprocess.run([CRYPTSETUP, 'token', 'import', '--token-id', '0', '--token-replace', '--json-file', '-', self.img],
                       input='{"type":"systemd-recovery","keyslots":["1"],"regalia_retiring":[["2","c2FsdA=="]]}', capture_output=True, text=True, check=True, timeout=60)
        listing = subprocess.run([CRYPTENROLL, self.img], capture_output=True, text=True, timeout=60).stdout
        self.assertRegex(listing, r'(?m)^\s*1\s+recovery\s*$')
        self.assertEqual(self.opens(OLD), 0, 'a boot prompt no longer opens with a marked token')
        subprocess.run([CRYPTENROLL, self.img, '--wipe-slot=recovery'], capture_output=True, text=True, check=True, timeout=60)
        self.assertNotIn('1', self.header()['keyslots'])
