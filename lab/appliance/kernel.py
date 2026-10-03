"""Install the reviewed Debian backports kernel without expanding its APT plan."""
import argparse
import hashlib
import json
import re
import subprocess

RELEASE = '7.1.13+deb13-amd64'
VERSION = '7.1.13-1~bpo13+1'
PACKAGES = {name: VERSION for name in (
    'linux-image-amd64', 'linux-base-amd64', 'linux-base-' + RELEASE,
    'linux-binary-' + RELEASE, 'linux-image-' + RELEASE, 'linux-modules-' + RELEASE)}
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive'}


def upgrade_plan(text):
    selected = {}
    for line in text.splitlines():
        words = line.split()
        if not words or words[0] not in {'Inst', 'Conf', 'Remv', 'Purg'}:
            continue
        if words[0] in {'Remv', 'Purg'}:
            raise ValueError('kernel upgrade must not remove packages')
        match = re.fullmatch(r'(Inst|Conf) ([^ ]+)(?: \[[^\]]+\])? \(([^ ]+) .+\)', line)
        if not match or PACKAGES.get(match[2]) != match[3]:
            raise ValueError('unreviewed kernel package/version in APT plan: ' + line[:256])
        if match[1] == 'Inst':
            if match[2] in selected: raise ValueError('duplicate package in kernel upgrade plan')
            selected[match[2]] = match[3]
    if selected != PACKAGES:
        raise ValueError('kernel upgrade plan is incomplete')
    return selected


def upgrade(apply=False):
    command = ['/usr/bin/apt-get', '--no-install-recommends', 'install', '-y',
               'linux-image-amd64=' + VERSION]
    result = subprocess.run([command[0], '--simulate', *command[1:]], env=ENV,
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise ValueError('APT refused kernel upgrade: ' + result.stderr[-4000:])
    plan = result.stdout
    selected = upgrade_plan(plan)
    if apply:
        result = subprocess.run(command, env=ENV, capture_output=True, text=True, timeout=600)
        if result.returncode:
            raise ValueError('kernel installation failed: ' + result.stdout[-3000:] + result.stderr[-1000:])
        for name, version in PACKAGES.items():
            result = subprocess.run(['/usr/bin/dpkg-query', '-W', '-f=${db:Status-Status}\t${Version}', name],
                                    env=ENV, capture_output=True, text=True, timeout=30)
            if result.returncode or result.stdout != 'installed\t' + version:
                raise ValueError('reviewed kernel package was not installed: ' + name)
    return {'schema': 'regalia.kernel-upgrade/v1', 'status': 'applied' if apply else 'planned',
            'release': RELEASE, 'packages': selected, 'plan': plan,
            'plan_sha256': hashlib.sha256(plan.encode()).hexdigest(),
            'production_approved': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    print(json.dumps(upgrade(args.apply), indent=2))
