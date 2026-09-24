#!/usr/bin/env python3
"""Is this build, host and token combination the one the hardware drills qualified? (regalia#42)

regalia#42 asks that "exact hardware and middleware combinations are qualified and pinned". The
drills recorded WHICH versions they ran on, in prose; nothing refused a combination that had never
run. config/qualified-stack.json pins the combination; this checks against it.

    python3 tools/qualified_stack.py --go-mod go.mod        # CI: the Go token libraries are the pinned ones
    python3 tools/qualified_stack.py --host                 # commissioning: installed middleware + attached tokens

A component NOT in the list is UNQUALIFIED, and the exit status is 1. That does not mean it is broken.
It means no drill has run on it, and a KMS should not be the first thing that finds out. To qualify a
new version, run the drills on it and add it together with the drill record.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

STACK = Path(__file__).resolve().parents[1] / "config" / "qualified-stack.json"


def load(path=STACK):
    return json.loads(Path(path).read_text())


def go_module_versions(go_mod_text):
    """module -> version for every `require`d module (single-line and block forms)."""
    versions = {}
    for line in go_mod_text.splitlines():
        line = line.split("//")[0].strip()
        line = re.sub(r"^require\s+", "", line)
        m = re.fullmatch(r"(\S+)\s+(v\S+)", line)
        if m:
            versions[m.group(1)] = m.group(2)
    return versions


def check_go_mod(stack, go_mod_text):
    have = go_module_versions(go_mod_text)
    problems = []
    for module, pinned in stack["go_modules"].items():
        if have.get(module) != pinned:
            problems.append(f"{module} is {have.get(module, 'absent')}, the qualified version is {pinned}")
    return problems


def upstream_version(debian_version):
    """2.3.3-1 -> 2.3.3; 5.6.1+repack1-1 -> 5.6.1; 1:0.26.1-2 -> 0.26.1"""
    v = debian_version.split(":", 1)[-1]
    return re.split(r"[-+~]", v, maxsplit=1)[0]


def run(argv):
    if not shutil.which(argv[0]):
        return None
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None


def host_packages():
    out = run(["dpkg-query", "-W", "-f", "${Package} ${Version}\\n", "opensc", "pcscd", "libccid", "yubikey-manager"]) or ""
    return {name: upstream_version(ver) for name, ver in (l.split(" ", 1) for l in out.splitlines() if " " in l)}


def yubikey_firmwares(ykman_list_output):
    """`ykman list`: 'YubiKey 5 NFC (5.7.4) [OTP+FIDO+CCID] Serial: 36345471' -> [(model, fw, serial)]"""
    found = []
    for line in (ykman_list_output or "").splitlines():
        m = re.match(r"(.+?) \((\d+\.\d+\.\d+)\).*Serial: (\d+)", line)
        if m:
            found.append((m.group(1).strip(), m.group(2), m.group(3)))
    return found


def smartcard_hsm_readers(opensc_list_output):
    """PC/SC readers holding a Nitrokey HSM: [(index, serial)]"""
    found = []
    for line in (opensc_list_output or "").splitlines():
        m = re.match(r"\s*(\d+)\s+Yes\s+.*Nitrokey HSM \((DENK\d{7})", line)
        if m:
            found.append((m.group(1), m.group(2)))
    return found


def applet_version(sc_hsm_tool_output):
    m = re.search(r"^Version\s*:\s*(\d+\.\d+)", sc_hsm_tool_output or "", re.M)
    return m.group(1) if m else None


def check_host(stack):
    lines, problems = [], []
    packages = host_packages()
    for name, allowed in stack["host"].items():
        have = packages.get(name)
        ok = have in allowed
        lines.append(f"{'QUALIFIED' if ok else 'UNQUALIFIED'} host {name} {have or 'not installed'} (qualified: {', '.join(allowed)})")
        if not ok:
            problems.append(f"{name} {have or 'not installed'}")
    token = {t["backend"]: t for t in stack["tokens"]}
    for model, fw, serial in yubikey_firmwares(run(["ykman", "list"])):
        ok = model == token["yubikey-piv"]["model"] and fw in token["yubikey-piv"]["firmware"]
        lines.append(f"{'QUALIFIED' if ok else 'UNQUALIFIED'} token {model} {fw} serial {serial}")
        if not ok:
            problems.append(f"YubiKey {serial} ({model} {fw})")
    for index, serial in smartcard_hsm_readers(run(["opensc-tool", "-l"])):
        version = applet_version(run(["sc-hsm-tool", "--reader", index]))
        ok = version in token["nitrokey-pkcs11"]["applet"]
        lines.append(f"{'QUALIFIED' if ok else 'UNQUALIFIED'} token Nitrokey HSM {serial} applet {version or 'unreadable'}")
        if not ok:
            problems.append(f"Nitrokey {serial} (applet {version or 'unreadable'})")
    return lines, problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--stack", default=str(STACK))
    ap.add_argument("--go-mod", help="check this go.mod's token libraries against the pins")
    ap.add_argument("--host", action="store_true", help="check installed middleware and attached tokens")
    args = ap.parse_args(argv)
    if not args.go_mod and not args.host:
        ap.error("give --go-mod and/or --host")
    stack = load(args.stack)
    problems = []
    if args.go_mod:
        found = check_go_mod(stack, Path(args.go_mod).read_text())
        for p in found:
            print(f"UNQUALIFIED go module: {p}")
        if not found:
            print("QUALIFIED go modules: " + ", ".join(f"{m} {v}" for m, v in stack["go_modules"].items()))
        problems += found
    if args.host:
        lines, found = check_host(stack)
        print("\n".join(lines))
        problems += found
    if problems:
        print(f"UNQUALIFIED STACK: {len(problems)} component(s) no drill has run on — see config/qualified-stack.json")
        return 1
    print("QUALIFIED STACK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
