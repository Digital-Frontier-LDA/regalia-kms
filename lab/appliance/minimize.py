"""Remove a reviewed set of installer utilities, with a bounded APT removal plan."""
import argparse
import hashlib
import json
import subprocess

CANDIDATES = ('locales', 'libc-l10n', 'util-linux-locales', 'eject', 'fdisk', 'task-english', 'tasksel', 'tasksel-data',
              'libfdisk1', 'installation-report', 'laptop-detect', 'os-prober',
              'binutils', 'binutils-common', 'binutils-x86-64-linux-gnu', 'libbinutils',
              'libctf0', 'libctf-nobfd0', 'libgprofng0', 'libsframe1',
              'libcurl3t64-gnutls', 'libcurl4t64', 'libtss2-fapi1t64',
              'perl', 'perl-modules-5.40', 'libperl5.40', 'libgdbm6t64', 'libgdbm-compat4t64',
              'bzip2', 'xz-utils')
REQUIRED = ('linux-image-amd64', 'systemd-sysv', 'cryptsetup-initramfs', 'wireguard-tools',
            'nftables', 'apparmor', 'apparmor-utils', 'tpm2-tools', 'opensc', 'pcscd',
            'python3', 'ca-certificates', 'util-linux', 'mount', 'perl-base')


def installed(name):
    result = subprocess.run(['/usr/bin/dpkg-query', '-W', '-f=${db:Status-Status}\t${Essential}', name],
                            capture_output=True, text=True, timeout=30)
    if result.returncode: return False, False
    state, _, essential = result.stdout.partition('\t')
    return state == 'installed', essential == 'yes'


def removal_plan(text, selected):
    removed = []
    for line in text.splitlines():
        words = line.split()
        if words and words[0] in ('Remv', 'Purg'):
            if len(words) < 2 or words[1] not in selected:
                raise ValueError('APT would remove an unreviewed package: ' + (words[1] if len(words)>1 else 'missing name'))
            if words[1] not in removed: removed.append(words[1])
        if words and words[0] in ('Inst', 'Conf'):
            raise ValueError('a removal plan must not install or configure packages')
    if set(removed) != set(selected): raise ValueError('APT removal plan is incomplete')
    return removed


def minimize(apply=False):
    for package in REQUIRED:
        if not installed(package)[0]: raise ValueError('required appliance package is absent: ' + package)
    selected = []
    for package in CANDIDATES:
        present, essential = installed(package)
        if present and essential: raise ValueError('candidate is Essential: ' + package)
        if present: selected.append(package)
    plan = ''
    if selected:
        result = subprocess.run(['/usr/bin/apt-get', '--simulate', 'purge', '-y', *selected],
                                capture_output=True, text=True, timeout=60,
                                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C'})
        if result.returncode:
            raise ValueError('APT rejected reviewed removal: ' + result.stderr[-4000:])
        plan = result.stdout
        removal_plan(plan, selected)
        if apply:
            subprocess.run(['/usr/bin/apt-get', 'purge', '-y', *selected], check=True, timeout=180, capture_output=True,
                           env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL':'C', 'DEBIAN_FRONTEND':'noninteractive'})
            if any(installed(p)[0] for p in selected): raise ValueError('reviewed removal did not finish')
    if any(not installed(p)[0] for p in REQUIRED): raise ValueError('required appliance package was removed')
    return {'schema':'regalia.appliance-minimization/v1', 'status':'applied' if apply else 'planned',
            'removed' if apply else 'selected':selected, 'required':list(REQUIRED),
            'plan_sha256':hashlib.sha256(plan.encode()).hexdigest(), 'plan':plan,
            'production_approved':False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    print(json.dumps(minimize(args.apply), indent=2))
