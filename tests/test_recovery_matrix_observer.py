import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
import importlib.util
spec = importlib.util.spec_from_file_location('recovery_matrix_fixture',Path(__file__).resolve().parents[1]/'lab/recovery/matrix.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RecoveryHeaderObserver(unittest.TestCase):
    def test_a_finished_run_is_judged_by_which_key_owns_the_recovery_slot(self):
        """d9's read of #236: "clean" by shape alone passed a retry that left the USED key as the
        recovery key. A finished run needs the expected key in the one recovery keyslot."""
        finished = module.finished
        tpm = ['tpm-slot', ['tpm-token']]
        good = {'state': 'clean', 'keyslots': ['1', '2'], 'priorities': {'1': 1, '2': 1}, 'tpm': tpm,
                'tokens': {'0': {'type': 'systemd-tpm2', 'keyslots': ['1']}, '1': {'type': 'systemd-recovery', 'keyslots': ['2']}},
                'opens_boot': {'tpm': True, 'new': True, 'old': False}, 'opens_slots': {'new': ['2'], 'old': []}}
        self.assertIsNone(finished('replace', good, tpm, spent_refused=True))
        for why, bad, spent in (
            ('the used key owns the recovery slot', dict(good, opens_slots={'new': [], 'old': ['2']}), True),
            ('the used key still opens somewhere', good, False),
            ('the TPM keyslot changed', dict(good, tpm=['other', ['tpm-token']]), True),
            ('the TPM stand-in does not open', dict(good, opens_boot={'tpm': False, 'new': True, 'old': False}), True),
            ('ignored priority', dict(good, priorities={'1': 1, '2': 0}), True),
            ('not clean', dict(good, state='orphan-keyslot'), True),
        ):
            with self.subTest(why=why): self.assertIsNotNone(finished('replace', bad, tpm, spent_refused=spent))
        enrolled = dict(good, state='orphan-keyslot', keyslots=['0', '1', '2'], priorities={'0': 1, '1': 1, '2': 1},
                        opens_slots={'old': ['2'], 'new': []})
        self.assertIsNone(finished('enrol', enrolled, tpm, spent_refused=True))
        # a marked recovery slot that no card key opens is not a finished enrol
        self.assertIsNotNone(finished('enrol', dict(enrolled, opens_slots={'old': [], 'new': []}), tpm, spent_refused=True))

    @unittest.skipUnless(module.STRACE and shutil.which('cryptsetup', path=os.environ.get('PATH', '') + ':/usr/sbin'), 'cryptsetup or strace is missing')
    def test_a_script_that_ends_clean_with_the_wrong_key_fails_the_matrix(self):
        """The mutation 24 asked for: --replace that leaves the used key as the recovery key and
        prints STATE: clean. The matrix must refuse it before any scenario runs."""
        real = Path(__file__).resolve().parents[1] / 'deploy/baremetal/recovery-key.sh'
        with tempfile.TemporaryDirectory() as temp:
            mutated = Path(temp) / 'recovery-key.sh'
            text = real.read_text()
            # replace: do nothing, report the header (still the used key's), succeed
            text = text.replace('replace)\n  case "$STATE" in', 'replace)\n  end 0 "REPLACED (mutated: nothing done)"\n  case "$STATE" in', 1)
            self.assertIn('mutated: nothing done', text)
            mutated.write_text(text)
            shutil.copy(real.parent / 'recovery_state.py', Path(temp) / 'recovery_state.py')
            with self.assertRaisesRegex(ValueError, "the recovery keyslot is not the new key's"):
                module.run(mutated, Path(temp) / 'report.json', mode='replace', shard=(1, 50))

    def test_the_state_is_read_from_the_header_independently_of_the_script(self):
        header_state = module.header_state
        salt = {'kdf': {'salt': 'c2FsdC1vZi10aGUtdXNlZC1rZXlzbG90'}}
        recovery = lambda slot, **extra: dict({'type': 'systemd-recovery', 'keyslots': [slot]}, **extra)
        cases = {
            'no-recovery': {'keyslots': {'0': {}}, 'tokens': {}},
            'clean': {'keyslots': {'1': {}}, 'tokens': {'0': recovery('1')}},
            'orphan-keyslot': {'keyslots': {'0': {}, '1': {}}, 'tokens': {'0': recovery('1')}},
            'orphan-token': {'keyslots': {'1': {}}, 'tokens': {'0': recovery('1'), '1': {'type': 'systemd-recovery', 'keyslots': []}}},
            'added-unproven': {'keyslots': {'1': salt, '2': {}}, 'tokens': {
                '0': recovery('1', regalia_generation=1),
                '1': recovery('2', regalia_generation=2, regalia_replaces='1', regalia_replaces_salt=salt['kdf']['salt'])}},
            'unknown': {'keyslots': {'1': {}, '2': {}}, 'tokens': {'0': recovery('1'), '1': recovery('2')}},
        }
        for expected, meta in cases.items():
            with self.subTest(state=expected): self.assertEqual(header_state(meta), expected)
        for name, meta in {
            'ignored priority': {'keyslots': {'1': {'priority': 0}}, 'tokens': {'0': recovery('1')}},
            'a token naming two keyslots': {'keyslots': {'1': {}, '2': {}}, 'tokens': {'0': {'type': 'systemd-recovery', 'keyslots': ['1', '2']}}},
            'a mark naming the wrong salt': dict(cases['added-unproven'], keyslots={'1': {'kdf': {'salt': 'b3RoZXI='}}, '2': {}}),
        }.items():
            with self.subTest(case=name): self.assertEqual(header_state(meta), 'unknown')
        self.assertEqual(module.reported_state('x\nSTATE: clean — one\nSTATE: orphan-token — t\n'), 'orphan-token')
        self.assertIsNone(module.reported_state('killed before it printed anything'))


merge_spec = importlib.util.spec_from_file_location('recovery_matrix_merge', Path(__file__).resolve().parents[1] / 'lab/recovery/merge.py')
merge = importlib.util.module_from_spec(merge_spec)
merge_spec.loader.exec_module(merge)


class ShardMerge(unittest.TestCase):
    def reports(self, temp, changes=None):
        changes = changes or {}
        paths = []
        for mode in ('enrol', 'replace'):
            for shard in (1, 2, 3):
                report = {'shard': '%d/3' % shard, 'status': 'passed', 'cryptsetup': 'cryptsetup 2.7.0', 'script_sha256': 'abc',
                          'first_level_total': {mode: 30}, 'first_level_executed': {mode: 10},
                          'second_level_executed': {mode: 4}, 'second_level_baselines': {mode: 1},
                          'syncs': {mode: {'luksAddKey --batch-mode': [3]}}, 'finding_cases': 0,
                          'first_level_all_ids': {mode: ['%s-%d' % (mode, i) for i in range(30)]},
                          'first_level_ids': {mode: ['%s-%d' % (mode, i) for i in range(30) if i % 3 == shard - 1]}}
                report.update(changes.get((mode, shard), {}))
                path = Path(temp) / ('%s-%d.json' % (mode, shard))
                path.write_text(json.dumps(report))
                paths.append(path)
        return paths

    def test_six_complete_shards_merge(self):
        with tempfile.TemporaryDirectory() as temp:
            summary = merge.merge(self.reports(temp), 3)
        self.assertEqual(summary['status'], 'passed', summary['problems'])
        self.assertEqual(summary['modes']['replace']['level1_executed'], 30)

    def test_a_missing_short_failed_or_disagreeing_shard_fails_the_merge(self):
        for name, changes, drop in (
            ('a shard missing', {}, 'replace-3.json'),
            ('a shard ran short', {('enrol', 2): {'first_level_executed': {'enrol': 9}}}, None),
            ('a shard with findings', {('replace', 1): {'status': 'completed-with-findings'}}, None),
            ('shards on different cryptsetup', {('enrol', 1): {'cryptsetup': 'cryptsetup 2.7.5'}}, None),
            ('a header-writing call with no sync counted', {('enrol', 1): {'syncs': {'enrol': {'token import': [0]}}}}, None),
            # the counts add up, but one scenario ran twice and another never ran
            ('a scenario swapped for a duplicate', {('enrol', 1): {'first_level_ids': {'enrol': ['enrol-0', 'enrol-3', 'enrol-6', 'enrol-9', 'enrol-12',
                                                                                              'enrol-15', 'enrol-18', 'enrol-21', 'enrol-24', 'enrol-1']}}}, None),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                paths = [p for p in self.reports(temp, changes) if p.name != drop]
                self.assertEqual(merge.merge(paths, 3)['status'], 'failed')
