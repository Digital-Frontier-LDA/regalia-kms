"""Prepare the reviewed CPython/Debian source candidate; no package admission."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

from deploy.images.verify import read_regular, require

POLICY = Path(__file__).with_name('python-profile-policy.json')
VERSION = '3.13.16-0+regalia1'


def diff(before, after, name, destination=None):
    return ''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                      fromfile='a/' + name, tofile=destination or 'b/' + name))


def prepare(root):
    policy = json.loads(read_regular(POLICY))
    require(policy['schema'] == 'regalia.python-source-profile/v1'
            and policy['upstream'] == '3.13.16' and policy['packaging'] == '3.13.15-1',
            'unreviewed Python source profile')
    frozen = {}
    for name, digest in policy['input_sha256'].items():
        data = read_regular(root / name)
        require(hashlib.sha256(data).hexdigest() == digest, 'Python profile input differs: ' + name)
        frozen[name] = data.decode()
    edits = {}
    name = 'debian/patches/tkinter-import.diff'
    original = frozen[name]
    source = frozen['Lib/turtle.py']
    needle = 'import tkinter as TK\n'
    require(source.count(needle) == 1, 'turtle import is ambiguous')
    changed = source.replace(needle, "try:\n    import tkinter as TK\nexcept ImportError as msg:\n"
                             "    raise ImportError(str(msg) + ', please install the python3-tk package')\n")
    edits[name] = original[:original.index('--- a/Lib/turtle.py')] + diff(source, changed, 'Lib/turtle.py')
    name = 'debian/patches/test-freeze-strip-libdir.diff'
    original = frozen[name]
    source = frozen['Tools/freeze/test/freeze.py']
    needle = "    config_args = shlex.split(sysconfig.get_config_var('CONFIG_ARGS') or '')\n"
    require(source.count(needle) == 1, 'freeze configuration is ambiguous')
    changed = source.replace(needle, needle + '    config_args = [arg for arg in config_args if not arg.startswith("--libdir=/")]\n')
    edits[name] = original[:original.index('--- a/Tools/freeze/test/freeze.py')] + diff(source, changed, 'Tools/freeze/test/freeze.py')
    name = 'debian/patches/issue127330.diff'
    original = frozen[name]
    start = original.index('--- a/Modules/_ssl_data_31.h')
    end = original.index('\n--- ', start + 6)
    # Retain Debian's complete OpenSSL 3.4 metadata patch. Its old deletion
    # context predates upstream's regenerated 3.6 table. Error mapping against
    # the actual Debian runtime library remains a required qualification gate.
    edits[name] = (original[:start] + diff(frozen['Modules/_ssl_data_31.h'], '',
                                         'Modules/_ssl_data_31.h', '/dev/null') + original[end:])
    # The trixie OpenGraph extension concatenates a list with custom tags.
    # Preserve every tag while adapting upstream's tuple to that API.
    edits['Doc/conf.py'] = (frozen['Doc/conf.py']
                            + '\n# Compatibility with Debian trixie sphinxext.opengraph.\n'
                            + 'ogp_custom_meta_tags = list(ogp_custom_meta_tags)\n')
    # Debian's dependency checker still uses its legacy imp helper. Preserve
    # the old diagnostic without importing a removed private bootstrap name.
    name = 'debian/imp.py'
    original = frozen[name]
    imports = 'from importlib._bootstrap import _ERR_MSG, _exec, _load, _builtin_from_name\n'
    diagnostic = 'raise ImportError(_ERR_MSG.format(name), name=name)'
    require(original.count(imports) == original.count(diagnostic) == 1,
            'legacy Debian import helper differs')
    edits[name] = original.replace(imports, imports.replace('_ERR_MSG, ', '')).replace(
        diagnostic, 'raise ImportError(f"No module named {name!r}", name=name)')
    name = 'debian/control'
    original = frozen[name]
    maintainer = 'Maintainer: Matthias Klose <doko@debian.org>'
    require(original.count(maintainer) == 1, 'Python maintainer identity differs')
    edits[name] = original.replace(maintainer, 'Maintainer: Regalia laboratory <noreply@example.invalid>')
    edits['debian/changelog'] = (
        f'python3.13 ({VERSION}) experimental; urgency=medium\n\n'
        '  * Laboratory candidate from authenticated CPython 3.13.16 and Debian 3.13.15 packaging.\n'
        '  * Retain every downstream patch and the vendor test/build rules.\n'
        '  * Rebase turtle/freeze context and generated-table deletion for the new source.\n\n'
        ' -- Regalia laboratory <noreply@example.invalid>  Sat, 03 Oct 2026 00:00:00 +0000\n\n'
        + frozen['debian/changelog'])
    for name, text in edits.items():
        (root / name).write_text(text)
    return {'schema': 'regalia.python-source-profile-result/v1', 'production_approved': False,
            'package_admitted': False, 'version': VERSION,
            'input_sha256': policy['input_sha256'],
            'edit_sha256': {name: hashlib.sha256(text.encode()).hexdigest() for name, text in edits.items()}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
