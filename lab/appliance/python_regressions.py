"""Run authenticated upstream security tests against installed candidate packages.

Only test fixtures enter the import path. Source-tree standard libraries never
substitute for installed modules. Passing this check grants no image admission.
"""
import argparse
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

from deploy.images import python_source
from deploy.images.verify import VerificationError, hash_regular, read_regular, require
from .python_profile import VERSION

PACKAGES = ('libpython3.13-minimal', 'libpython3.13-stdlib',
            'python3.13-minimal', 'python3.13')
CASES = {
    'CVE-2026-15308': ('test.test_htmlparser.HTMLParserTestCase.test_eof_no_quadratic_complexity',
                       'test.test_htmlparser.HTMLParserTestCase.test_incremental_no_quadratic_complexity'),
    'CVE-2026-19445': ('test.test_ssl.SSLObjectTests.test_sni_callback_context_released_and_callback_raises',
                       'test.test_ssl.SSLObjectTests.test_sni_callback_context_released_before_second_client_hello'),
    'CVE-2026-19553': ('test.test_ssl.SSLObjectTests.test_check_hostname_requires_server_hostname',),
    'CVE-2026-82049': ('test.test_tarfile.TestExtractionFilters.test_sneaky_hardlink_relocation',),
}
MARKER = 'REGALIA_PYTHON_RESULT='
WORKER = r'''
import html.parser, json, pathlib, ssl, sys, tarfile, unittest
import pyexpat, xml.etree.ElementTree
modules = (html.parser, ssl, tarfile, pyexpat, xml.etree.ElementTree)
origins = {}
for module in modules:
    path = getattr(module, '__file__', None)
    if path is not None:
        assert pathlib.Path(path).resolve().is_relative_to('/usr/lib/python3.13'), path
    else:
        assert module.__spec__.origin == 'built-in', module.__name__
    origins[module.__name__] = path or 'built-in'
assert pyexpat.version_info >= (2, 8, 0), pyexpat.EXPAT_VERSION
# This is compatibility evidence; it does not prove Expat hash-salt entropy.
assert xml.etree.ElementTree.fromstring('<root a="ok"/>').attrib == {'a': 'ok'}
sys.path.insert(0, sys.argv[1])  # Contains only authenticated test/ fixtures.
from test import support
support.use_resources = ['cpu']  # The DoS regressions must actually execute.
suite = unittest.defaultTestLoader.loadTestsFromNames(sys.argv[2:])
result = unittest.TextTestRunner(verbosity=2).run(suite)
print('REGALIA_PYTHON_RESULT=' + json.dumps({
    'tests_run': result.testsRun, 'errors': len(result.errors),
    'failures': len(result.failures), 'skipped': len(result.skipped),
    'expected_failures': len(result.expectedFailures),
    'unexpected_successes': len(result.unexpectedSuccesses),
    'installed_module_origins': origins, 'expat_version': pyexpat.EXPAT_VERSION,
    'openssl_version': ssl.OPENSSL_VERSION}), flush=True)
sys.exit(0 if result.wasSuccessful() else 1)
'''


def checked_result(text, expected):
    records = [line[len(MARKER):] for line in text.splitlines() if line.startswith(MARKER)]
    require(len(records) == 1, 'missing or ambiguous Python regression result')
    result = json.loads(records[0])
    require(isinstance(result, dict) and type(result.get('tests_run')) is int
            and result['tests_run'] == expected
            and all(type(result.get(name)) is int and result[name] == 0
                    for name in ('errors', 'failures', 'skipped', 'expected_failures', 'unexpected_successes')),
            'Python security regressions failed, skipped or did not execute')
    return result


def checked_expat_trace(text):
    require(text.splitlines().count('REGALIA_EXPAT_SALT16_ACCEPTED') == 1
            and 'REGALIA_EXPAT_LEGACY_SALT_ACCEPTED' not in text
            and 'ERROR:' not in text,
            'Expat did not accept the 16-byte salt API exclusively')
    return {'accepted_16_byte_calls': 1, 'legacy_calls': 0}


def expat_probe(parent, environment, output):
    # Interpose only in disposable test processes; record API use, never salts.
    source = Path(__file__).with_name('python_expat_probe.c')
    frozen = read_regular(source, 8192)
    candidate = parent / 'expat_probe.c'
    candidate.write_bytes(frozen)
    library = parent / 'expat_probe.so'
    subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
                    str(candidate), '-o', str(library), '-ldl'], env=environment,
                   capture_output=True, check=True, timeout=60)
    results = {}
    programs = {
        'pyexpat': 'from xml.parsers import expat; p=expat.ParserCreate(); p.Parse("<root/>", True)',
        'ElementTree': 'import xml.etree.ElementTree as E; assert E.fromstring("<root/>").tag == "root"',
    }
    for name, program in programs.items():
        log = output / ('expat-' + name + '.log')
        with log.open('wb') as stream:
            result = subprocess.run([sys.executable, '-I', '-c', program],
                                    cwd=parent, env=dict(environment, LD_PRELOAD=str(library)),
                                    stdout=stream, stderr=subprocess.STDOUT, timeout=20)
        require(result.returncode == 0, 'Expat API probe failed: ' + name)
        results[name] = {**checked_expat_trace(log.read_text()),
                         'log_sha256': hash_regular(log, 'sha256')[0]}
    return {'source_sha256': hash_regular(candidate, 'sha256')[0],
            'library_sha256': hash_regular(library, 'sha256')[0], 'results': results,
            'limits': 'API-width evidence, not a statistical claim about entropy quality.'}


def run(bundle, output):
    require(not output.exists() and not output.is_symlink(), 'Python regression output already exists')
    authenticated = python_source.validate(bundle, packaging_suite='sid')
    require(sys.flags.isolated and sys.platform == 'linux' and os.geteuid() != 0
            and sys.version_info[:3] == (3, 13, 16)
            and Path(sys.executable).resolve() == Path('/usr/bin/python3.13'),
            'run with the installed candidate interpreter, isolated, as an ordinary user')
    inventory = subprocess.check_output(['dpkg-query', '-W', '-f=${Package}\t${Version}\n', *PACKAGES],
                                        text=True, timeout=20)
    require(sorted(inventory.splitlines()) == sorted(name + '\t' + VERSION for name in PACKAGES),
            'installed Python package identities differ from the reviewed candidate')
    frozen = python_source.inputs(bundle, {'Python-3.13.16.tar.xz':
                                          python_source.UPSTREAM_FILES['Python-3.13.16.tar.xz']})
    output.mkdir(parents=True, mode=0o700)
    results = {}
    with tempfile.TemporaryDirectory(prefix='regalia-python-regressions-') as temp:
        parent = Path(temp)
        prefix = 'Python-3.13.16/Lib/'
        with tarfile.open(fileobj=io.BytesIO(frozen['Python-3.13.16.tar.xz']), mode='r:xz') as archive:
            members = [item for item in archive.getmembers() if item.name.startswith(prefix + 'test/')]
            require(members, 'authenticated upstream test fixtures missing')
            archive.extractall(parent, members=members, filter='data')
        fixtures = parent / prefix
        require({p.name for p in fixtures.iterdir()} == {'test'}, 'source standard library entered test path')
        env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': temp, 'TZ': 'UTC'}
        for advisory, names in CASES.items():
            log = output / (advisory + '.log')
            with log.open('wb') as stream:
                try:
                    result = subprocess.run([sys.executable, '-I', '-c', WORKER, str(fixtures), *names],
                                            cwd=parent, env=env, stdout=stream,
                                            stderr=subprocess.STDOUT, timeout=90)
                except subprocess.TimeoutExpired as error:
                    raise VerificationError('Python regression timed out: ' + advisory) from error
            require(result.returncode == 0, 'Python regression failed: ' + advisory + '; see ' + str(log))
            results[advisory] = {'tests': list(names), 'result': checked_result(log.read_text(), len(names)),
                                 'log_sha256': hash_regular(log, 'sha256')[0]}
        entropy = expat_probe(parent, env, output)
    report = {'schema': 'regalia.python-installed-regressions/v1', 'status': 'regressions_passed',
              'production_approved': False, 'package_admitted': False,
              'authenticated_source': authenticated, 'installed_packages': inventory.splitlines(),
              'interpreter_sha256': hash_regular(Path(sys.executable).resolve(), 'sha256')[0],
              'recipe_sha256': hash_regular(Path(__file__), 'sha256')[0], 'regressions': results,
              'expat_salt_api_probe': entropy,
              'limits': ['Expat API-width evidence must be combined with authenticated built-source and library provenance.',
                         'No compiler provenance, package repeatability, ABI, AppArmor, image boot or scan admission is granted.']}
    (output / 'regressions.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.bundle, args.output), sort_keys=True, indent=2))
    except (VerificationError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f'REFUSED: {error}\n')


if __name__ == '__main__':
    main()
