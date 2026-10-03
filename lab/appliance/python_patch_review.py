"""Evaluate Debian patches against authenticated CPython; never apply or drop them."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

from deploy.images import python_source
from deploy.images.verify import VerificationError, require


def series_names(data):
    names = []
    for line in data.decode('utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        require(len(line.split()) == 1 and '/' not in line and '\\' not in line
                and line not in ('.', '..') and not line.startswith('-'),
                'unreviewed Python patch path or options')
        require(line not in names, 'duplicate Python patch')
        names.append(line)
    require(names, 'empty Python patch series')
    return names


def review(bundle, output, patch_binary="patch", *, packaging_suite="trixie"):
    require(not output.exists() and not output.is_symlink(), 'patch review output already exists')
    authenticated = python_source.validate(bundle, packaging_suite=packaging_suite)
    names = ('Python-3.13.16.tar.xz', f"python3.13_{authenticated['debian_packaging_version']}.debian.tar.xz")
    expected = {name: (authenticated['files'][name]['sha256'], authenticated['files'][name]['bytes'])
                for name in names}
    frozen = python_source.inputs(bundle, expected)
    version = subprocess.check_output([patch_binary, '--version'], text=True, timeout=10).splitlines()[0]
    require(version.startswith('GNU patch '), 'this evaluation requires GNU patch')
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.python-patch-review-', dir=output.parent))
    try:
        with tempfile.TemporaryDirectory(prefix='python-patch-inputs-') as temp:
            work = Path(temp)
            source = work / 'Python-3.13.16'
            for name, destination in zip(names, (work, source)):
                with tarfile.open(fileobj=io.BytesIO(frozen[name]), mode='r:xz') as archive:
                    archive.extractall(destination, filter='data')
            series = (source / 'debian/patches/series').read_bytes()
            rows = []
            for name in series_names(series):
                path = source / 'debian/patches' / name
                require(path.is_file() and not path.is_symlink(), 'unsafe patch input')
                row = {'patch': name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                for direction in ('forward', 'reverse'):
                    # --force prevents patch's automatic direction correction.
                    # --batch alone can silently ignore an explicit --reverse.
                    args = [patch_binary, '--dry-run', '--batch', '--force', '--fuzz=0', '-p1', '-i', str(path)]
                    if direction == 'reverse':
                        args.append('--reverse')
                    result = subprocess.run(args, cwd=source, text=True, capture_output=True, timeout=30)
                    require(result.returncode in (0, 1), 'patch failed outside an applicability verdict')
                    row[direction + '_exit'] = result.returncode
                    log = result.stdout + result.stderr
                    # Temporary directories vary; normalize only this diagnostic path.
                    log = log.replace(str(source), 'Python-3.13.16')
                    row[direction + '_log'] = log
                rows.append(row)
        report = {'schema': 'regalia.python-patch-applicability/v1', 'production_approved': False,
                  'package_admitted': False, 'source': authenticated, 'patch_version': version,
                  'recipe_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  'series_sha256': hashlib.sha256(series).hexdigest(), 'patches': rows,
                  'method': 'Each patch dry-run independently against clean authenticated upstream; fuzz=0, forced direction. Reverse success is only a review candidate, not semantic proof.',
                  'limits': ['No patch is applied, omitted or approved.',
                             'Patch interactions and security regressions require separate verification.']}
        (staging / 'patch-review.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        require(not output.exists() and not output.is_symlink(), 'patch output appeared during evaluation')
        staging.rename(output)
        return report
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--patch', default='patch', help='GNU patch executable')
    parser.add_argument('--packaging-suite', choices=('trixie', 'sid'), default='trixie')
    args = parser.parse_args()
    try:
        report = review(args.bundle, args.output, args.patch, packaging_suite=args.packaging_suite)
        print(json.dumps({'patches': len(report['patches']), 'production_approved': False,
                          'package_admitted': False}, sort_keys=True))
    except (VerificationError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'REFUSED: {error}\n')


if __name__ == '__main__':
    main()
