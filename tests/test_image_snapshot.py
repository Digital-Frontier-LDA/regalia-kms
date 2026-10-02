"""Real clear signatures and negative policy/index checks for package snapshots."""
import copy
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from deploy.images import snapshot
from deploy.images.verify import VerificationError


class PackageSnapshotPolicy(unittest.TestCase):
    def setUp(self):
        self.config=json.loads(snapshot.POLICY.read_text())
        self.now=datetime(2026,10,2,12,tzinfo=timezone.utc)

    def test_both_pinned_authorities_and_recent_timestamp_required(self):
        snapshot.policy(self.config,self.now)
        for kind in ('future','stale','signer','missing','injection','age'):
            config=copy.deepcopy(self.config)
            if kind=='future': config['timestamp']='20261003T000000Z'
            if kind=='stale': config['timestamp']='20260901T000000Z'
            if kind=='signer': config['archives']['debian']['primary_fingerprint']='0'*40
            if kind=='missing': del config['archives']['debian-security']
            if kind=='injection': config['timestamp']='20261002T000000Z\ndeb evil'
            if kind=='age': config['max_snapshot_age_days']=True
            with self.subTest(kind=kind), self.assertRaises((VerificationError,ValueError)):
                snapshot.policy(config,self.now)

    def test_installed_versions_must_appear_in_authenticated_indexes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'packages.tsv';path.write_text('openssl\t1.2.3\n')
            inventory=[{'Package':'openssl','Version':'1.2.3'}]
            self.assertEqual(snapshot.check_installed(path,inventory)['packages'],1)
            path.write_text('openssl\t9.9.9\n')
            with self.assertRaises(VerificationError): snapshot.check_installed(path,inventory)

    def test_duplicate_fields_and_unsafe_package_urls_refused(self):
        with self.assertRaises(VerificationError): snapshot.fields('Date: x\nDate: y\n')
        text='Package: test\nVersion: 1\nArchitecture: amd64\nFilename: ../evil.deb\nSHA256: '+'0'*64+'\nSize: 4\n'
        with self.assertRaises(VerificationError): snapshot.packages(text.encode())


class SnapshotSignatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='regalia-snapshot-fixture-')
        cls.home=Path(cls.temp.name)
        cls.gpg=['gpg','--no-options','--homedir',str(cls.home),'--batch','--pinentry-mode','loopback','--passphrase','']
        for name in ('snapshot','attacker'):
            subprocess.run(cls.gpg+['--quick-generate-key',name+'@example.invalid','ed25519','sign','0'],check=True,capture_output=True)
        listing=subprocess.run(cls.gpg+['--with-colons','--list-keys'],check=True,capture_output=True,text=True).stdout
        cls.pins=[x.split(':')[9] for x in listing.splitlines() if x.startswith('fpr:')]
        cls.key=cls.home/'public.asc'
        cls.key.write_bytes(subprocess.run(cls.gpg+['--export',cls.pins[0]],check=True,capture_output=True).stdout)

    @classmethod
    def tearDownClass(cls):
        subprocess.run(['gpgconf','--homedir',str(cls.home),'--kill','all'],check=True)
        cls.temp.cleanup()

    def sign(self, expiry=None, date=None, signer=0):
        now=datetime.now(timezone.utc)
        self.release=self.home/'Release.txt';self.signed=self.home/'InRelease'
        text='Origin: Debian\nCodename: trixie-security\nDate: '+format_datetime(date or now-timedelta(hours=1))+'\n'
        if expiry != 'missing': text+='Valid-Until: '+format_datetime(expiry or now+timedelta(days=1))+'\n'
        text+='SHA256:\n '+hashlib.sha256(b'fixture').hexdigest()+' 7 main/binary-amd64/Packages.xz\n'
        self.release.write_text(text)
        subprocess.run(self.gpg+['--yes','--local-user',self.pins[signer]+'!','--output',str(self.signed),'--clearsign',str(self.release)],check=True,capture_output=True)

    def verify(self):
        return snapshot.verify_release(self.signed,self.key,self.pins[0],'trixie-security')

    def test_real_signature_and_required_security_freshness(self):
        self.sign();report,sums=self.verify()
        self.assertEqual(report['primary_fingerprint'],self.pins[0])
        self.assertEqual(sums['main/binary-amd64/Packages.xz'][1],7)
        for change in ({'expiry':datetime.now(timezone.utc)-timedelta(days=1)}, {'expiry':'missing'},
                       {'date':datetime.now(timezone.utc)+timedelta(days=1)}):
            self.sign(**change)
            with self.assertRaises(VerificationError): self.verify()

    def test_wrong_signer_and_modified_signed_metadata(self):
        self.sign(signer=1)
        with self.assertRaises(VerificationError): self.verify()
        self.sign();self.signed.write_bytes(self.signed.read_bytes().replace(b'Origin: Debian',b'Origin: Evil!!'))
        with self.assertRaises(VerificationError): self.verify()

class FrozenPackageIndexes(unittest.TestCase):
    def test_index_tampering_is_refused_and_parsing_uses_verified_bytes(self):
        import lzma
        from unittest.mock import patch
        payload=('Package: fixture\nVersion: 1\nArchitecture: amd64\nFilename: pool/f/fixture/fixture_1_amd64.deb\n'
                 'SHA256: '+'0'*64+'\nSize: 1\n').encode()
        compressed=lzma.compress(payload)
        expected=(hashlib.sha256(compressed).hexdigest(),len(compressed))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for archive in snapshot.ARCHIVES:
                folder=root/archive;folder.mkdir();(folder/'Packages.xz').write_bytes(compressed)
            with patch.object(snapshot,'verify_release',return_value=({'status':'verified'},{'main/binary-amd64/Packages.xz':expected})):
                _, inventory=snapshot.validate(root)
                self.assertEqual(len(inventory),2)
                first=root/'debian/Packages.xz';first.write_bytes(compressed+b'corrupted')
                with self.assertRaises(VerificationError): snapshot.validate(root)
                first.write_bytes(compressed)
                original=snapshot.read_regular
                def replaced_after_read(path,*args):
                    data=original(path,*args)
                    if path==first: path.write_bytes(b'not an authenticated index')
                    return data
                with patch.object(snapshot,'read_regular',side_effect=replaced_after_read):
                    _, inventory=snapshot.validate(root)
                    self.assertEqual([x['Package'] for x in inventory],['fixture','fixture'])
