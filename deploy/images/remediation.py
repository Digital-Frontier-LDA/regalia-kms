"""Plan image remediation against signed Debian indexes; never grant exceptions."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

from . import snapshot, triage
from .verify import VerificationError, read_regular, require


def package_plan(packages, indexes):
    available = defaultdict(list)
    for entry in indexes:
        if entry['Architecture'] in {'amd64', 'all'}:
            available[entry['Package']].append(entry)
    installed = [p for p in packages if p.get('type') == 'deb']
    require(len({p['name'] for p in installed}) == len(installed), 'ambiguous binary package inventory')
    result = {}
    for package in installed:
        name, version = package['name'], package['version']
        require(package.get('metadata', {}).get('architecture') in {'amd64', 'all'},
                'unsupported installed package architecture')
        candidates = available[name]
        candidate = None
        for entry in candidates:
            if candidate is None or not triage.at_least(candidate['Version'], entry['Version']):
                candidate = entry
        action = 'index-missing'
        if candidate:
            # A newer signed package is an update candidate, never proof that a
            # particular CVE was fixed. Never propose downgrades to reduce scans.
            action = ('newer-signed-package' if not triage.at_least(version, candidate['Version'])
                      else 'no-newer-signed-package')
        parents = []
        for other in installed:
            for field, relation in [('depends', 'Depends'), ('preDepends', 'Pre-Depends')]:
                for dependency in other.get('metadata', {}).get(field, []):
                    alternatives = [part.strip().split()[0].split(':')[0] for part in dependency.split('|')]
                    if name in alternatives:
                        parents.append({'package': other['name'], 'relation': relation, 'dependency': dependency})
        result[name] = {'name': name, 'installed_version': version, 'action': action,
                        'candidate': candidate, 'declared_reverse_dependencies': parents}
    return result


def finding_packages(row, packages):
    names = []
    for name in row['packages']:
        matches = [p for p in packages if p['name'] == name]
        for package in matches:
            if package['type'] == 'deb':
                names.append(name)
            elif package['type'] == 'linux-kernel':
                # Same review-only unique file-owner evidence as triage; this
                # never claims the kernel's upstream version lacks backports.
                source, _, mapping = triage.source_identity(package, packages)
                if source == 'linux' and mapping == 'kernel-package-ownership-candidate':
                    paths = {item['path'] for item in package.get('locations', [])}
                    names.extend(p['name'] for p in packages if p['type'] == 'deb'
                                 and p['name'] in {'linux-image-' + package['version'],
                                                   'linux-binary-' + package['version']}
                                 and paths.intersection(f['path'] for f in p.get('metadata', {}).get('files', [])))
    return sorted(set(names))


def plan(evidence, review, indexes, output):
    require(not output.exists() and not output.is_symlink(), 'remediation output already exists')
    scan_bytes = read_regular(evidence / 'scan-report.json')
    scan = json.loads(scan_bytes)
    require(scan.get('schema') == 'regalia.image-scan/v1' and scan.get('status') in {'blocked', 'passed'},
            'remediation requires a completed scan')
    report = json.loads(read_regular(review / 'triage.json'))
    require(report.get('scan_report_sha256') == hashlib.sha256(scan_bytes).hexdigest()
            and report.get('rootfs_sha256') == scan.get('rootfs_sha256'), 'review scan binding mismatch')
    inputs = {}
    for name in ('sbom.syft.json', 'vulnerabilities.json'):
        data = read_regular(evidence / name, triage.LIMIT)
        require(hashlib.sha256(data).hexdigest() == scan['evidence'][name], 'remediation evidence hash mismatch')
        inputs[name] = json.loads(data)
    tracker_bytes = read_regular(review / 'debian-tracker.json', triage.LIMIT)
    require(hashlib.sha256(tracker_bytes).hexdigest() == report['tracker']['sha256'], 'tracker binding mismatch')
    recomputed = triage.summarize(inputs['sbom.syft.json'], inputs['vulnerabilities.json'], json.loads(tracker_bytes))
    require(all(report.get(k) == v for k, v in recomputed.items()), 'review classification was modified')
    authenticated, inventory = snapshot.validate(indexes, indexes / 'policy.json')
    packages = inputs['sbom.syft.json']['artifacts']
    binaries = package_plan(packages, inventory)
    rows = []
    for row in recomputed['findings']:
        names = finding_packages(row, packages)
        rows.append({**row, 'binary_packages': names,
                     'update_candidates': [name for name in names if binaries[name]['action'] == 'newer-signed-package'],
                     'action': ('review-unmapped-finding' if not names else
                                'review-missing-package-index' if any(binaries[n]['action'] == 'index-missing' for n in names) else
                                'rebuild-and-rescan' if any(binaries[n]['action'] == 'newer-signed-package' for n in names) else
                                'review-backport-or-applicability' if row['classification'] in
                                {'vendor-fixed-candidate', 'vendor-not-affected-candidate'} else 'await-fix-or-reduce-surface')})
    result = {'schema': 'regalia.image-remediation/v1', 'status': 'review-required',
              'production_approved': False, 'release_admissible': False, 'exceptions': [],
              'rootfs_sha256': scan['rootfs_sha256'], 'scan_report_sha256': hashlib.sha256(scan_bytes).hexdigest(),
              'tracker': report['tracker'], 'package_snapshot': authenticated,
              'installed_packages': len(binaries),
              'newer_signed_packages': sum(p['action'] == 'newer-signed-package' for p in binaries.values()),
              'blocking_matches': recomputed['blocking_matches'], 'findings': rows,
              'packages': [binaries[name] for name in sorted(binaries)]}
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.image-remediation-', dir=output.parent))
    try:
        (staging / 'remediation.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
        actions = Counter()
        for row in rows: actions[row['action']] += row['matches']
        lines = ['# Image remediation plan', '',
                 f"{result['blocking_matches']} High/Critical matches; {result['newer_signed_packages']} installed packages have newer signed candidates.",
                 '', '| Action | Matches |', '| --- | ---: |']
        lines += [f'| {action} | {count} |' for action, count in sorted(actions.items())]
        lines += ['', '## Limits', '',
                  'Candidates come from freshly reverified, pinned Debian/security signatures and indexes. '
                  'A newer version is not a CVE fix claim. Rebuild, boot and scan the exact new filesystem. '
                  'The tracker uses HTTPS; backport/applicability results require review. '
                  'Dependency lists are diagnostic alternatives, not an APT removal plan. '
                  'No package is installed or removed; no exception or release approval is issued.', '']
        (staging / 'remediation.md').write_text('\n'.join(lines))
        require(not output.exists() and not output.is_symlink(), 'remediation output appeared during review')
        staging.rename(output)
        return result
    finally:
        if staging.exists(): shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--review', required=True, type=Path)
    parser.add_argument('--snapshot', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        report = plan(args.evidence, args.review, args.snapshot, args.output)
        print(json.dumps({k: v for k, v in report.items() if k not in {'findings', 'packages'}}, indent=2))
    except (VerificationError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f'REFUSED: {error}\n')


if __name__ == '__main__':
    main()
