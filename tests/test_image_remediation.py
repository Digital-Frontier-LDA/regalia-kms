"""Signed update candidates are diagnostic; they never suppress findings."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deploy.images import remediation, triage
from deploy.images.verify import VerificationError


def package(name='libexample1', version='1:2.0-1'):
    return {'id': name, 'name': name, 'type': 'deb', 'version': version,
            'metadata': {'architecture': 'amd64', 'source': 'example'}}


class RemediationTests(unittest.TestCase):
    def test_candidates_use_debian_ordering_and_never_propose_a_downgrade(self):
        packages = [package(), {**package('consumer'), 'metadata': {
            'architecture': 'all', 'depends': ['libexample1 (>= 1) | another'],
            'preDepends': ['libexample1 (>= 1:2.0)']}}]
        indexes = [{'Package': 'libexample1', 'Architecture': 'amd64', 'Version': v}
                   for v in ['9.0-1', '1:2.0-1', '1:2.0-1+deb13u1']]
        indexes.append({'Package': 'libexample1', 'Architecture': 'arm64', 'Version': '9:99'})
        rows = remediation.package_plan(packages, indexes)
        self.assertEqual(rows['libexample1']['candidate']['Version'], '1:2.0-1+deb13u1')
        self.assertEqual(rows['libexample1']['action'], 'newer-signed-package')
        self.assertEqual(rows['libexample1']['declared_reverse_dependencies'][0]['package'], 'consumer')
        self.assertEqual({x['relation'] for x in rows['libexample1']['declared_reverse_dependencies']},
                         {'Depends', 'Pre-Depends'})
        self.assertEqual(rows['consumer']['action'], 'index-missing')
        rows = remediation.package_plan([package(version='1:3.0-1')], indexes)
        self.assertEqual(rows['libexample1']['action'], 'no-newer-signed-package')

    def test_ambiguous_binary_inventory_and_foreign_architecture_refused(self):
        for packages in ([package(), package()], [{**package(), 'metadata': {'architecture': 'arm64'}}]):
            with self.assertRaises(VerificationError): remediation.package_plan(packages, [])

    def test_split_kernel_uses_the_exact_binary_owner_not_the_image_meta_package(self):
        version='7.1.13+deb13-amd64'
        path='/boot/vmlinuz-'+version
        kernel={'id':'kernel','name':'linux-kernel','version':version,'type':'linux-kernel',
                'locations':[{'path':path}]}
        binary={**package('linux-binary-'+version,'7.1.13-1~bpo13+1'),
                'metadata':{'architecture':'amd64','source':'linux-signed-amd64',
                            'sourceVersion':'7.1.13+1~bpo13+1','files':[{'path':path}]}}
        meta={**package('linux-image-'+version,'7.1.13-1~bpo13+1'),
              'metadata':{'architecture':'amd64','source':'linux-signed-amd64','files':[]}}
        packages=[kernel,binary,meta]
        self.assertEqual(triage.source_identity(kernel,packages),
                         ('linux','7.1.13-1~bpo13+1','kernel-package-ownership-candidate'))
        self.assertEqual(remediation.finding_packages({'packages':['linux-kernel']},packages),[binary['name']])
        meta['metadata']['files']=[{'path':path}]
        self.assertEqual(triage.source_identity(kernel,packages)[2],'unmapped')
        self.assertEqual(remediation.finding_packages({'packages':['linux-kernel']},packages),[])

    def fixture(self, root):
        evidence, review = root / 'scan', root / 'review'
        evidence.mkdir(); review.mkdir()
        artifact = package()
        sbom = {'artifacts': [artifact], 'distro': {'id': 'debian', 'versionID': '13'}}
        findings = {'matches': [{'artifact': artifact, 'vulnerability': {
            'id': 'CVE-2026-10000', 'severity': 'Critical', 'fix': {'state': 'not-fixed'}}}]}
        hashes = {}
        for name, value in [('sbom.syft.json', sbom), ('vulnerabilities.json', findings)]:
            data = json.dumps(value).encode(); (evidence / name).write_bytes(data)
            hashes[name] = hashlib.sha256(data).hexdigest()
        scan_bytes = json.dumps({'schema': 'regalia.image-scan/v1', 'status': 'blocked',
                                 'rootfs_sha256': 'a'*64, 'evidence': hashes}).encode()
        (evidence / 'scan-report.json').write_bytes(scan_bytes)
        tracker = b'{}'; (review / 'debian-tracker.json').write_bytes(tracker)
        report = triage.summarize(sbom, findings, {})
        report.update(rootfs_sha256='a'*64, scan_report_sha256=hashlib.sha256(scan_bytes).hexdigest(),
                      tracker={'sha256': hashlib.sha256(tracker).hexdigest(), 'authentication': 'operator-supplied'})
        (review / 'triage.json').write_text(json.dumps(report))
        return evidence, review

    def test_newer_package_cannot_turn_a_blocked_scan_into_release_approval(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); evidence, review = self.fixture(root)
            index = [{'Package': 'libexample1', 'Architecture': 'amd64', 'Version': '1:2.0-2'}]
            with patch.object(remediation.snapshot, 'validate', return_value=({'status': 'verified'}, index)) as verify:
                result = remediation.plan(evidence, review, root / 'indexes', root / 'output')
                verify.assert_called_once_with(root / 'indexes', root / 'indexes/policy.json')
            self.assertEqual(result['newer_signed_packages'], 1)
            self.assertEqual(result['blocking_matches'], 1)
            self.assertEqual(result['findings'][0]['action'], 'rebuild-and-rescan')
            self.assertFalse(result['release_admissible']); self.assertFalse(result['production_approved'])
            self.assertEqual(result['exceptions'], [])
            self.assertEqual(json.loads((evidence / 'scan-report.json').read_text())['status'], 'blocked')

    def test_tampering_or_signature_failure_never_publishes_a_plan(self):
        for mutation in ('inventory', 'tracker', 'classification', 'scan', 'signature'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); evidence, review = self.fixture(root)
                if mutation == 'inventory': (evidence / 'sbom.syft.json').write_text('{}')
                if mutation == 'tracker': (review / 'debian-tracker.json').write_text('{"changed":true}')
                if mutation == 'classification':
                    p = review / 'triage.json'; data = json.loads(p.read_text()); data['findings'] = []; p.write_text(json.dumps(data))
                if mutation == 'scan':
                    p = evidence / 'scan-report.json'; data = json.loads(p.read_text()); data['status'] = 'failed'; p.write_text(json.dumps(data))
                with patch.object(remediation.snapshot, 'validate', side_effect=VerificationError('signature failure')):
                    with self.assertRaises(VerificationError):
                        remediation.plan(evidence, review, root / 'indexes', root / 'output')
                self.assertFalse((root / 'output').exists())


if __name__ == '__main__': unittest.main()
