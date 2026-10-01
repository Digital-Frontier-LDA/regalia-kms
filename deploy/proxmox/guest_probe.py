#!/usr/bin/env python3
"""Measure the KMS guest's memory and credential controls from INSIDE the guest (regalia#49).

WHY THIS EXISTS. verify.py checks a signed description of the guest, and its `guest` section is a
set of booleans somebody typed: `core_dumps_disabled: true`, `swap_disabled_or_encrypted: true`.
Signing a claim does not make it true. A guest with an unencrypted swap partition passes the
verifier as long as the evidence says otherwise. This probe reads the guest itself, reports each
control it can measure with the reason for its verdict, and, given an evidence file, refuses one
that claims a control the guest does not have.

    sudo python3 deploy/proxmox/guest_probe.py                     # the measured guest section, as JSON
    sudo python3 deploy/proxmox/guest_probe.py --evidence E.json   # exit 1 if E claims what the guest lacks

WHAT IT MEASURES, AND HOW:
  core_dumps_disabled         the KMS unit's effective LimitCORE is 0, fs.suid_dumpable is 0, and a
                              core_pattern piped to systemd-coredump has Storage=none
  hibernation_disabled        no resume= on the kernel command line, and every hibernating sleep
                              target is masked, or sleep.conf forbids hibernation, hybrid sleep and
                              suspend-then-hibernate
  swap_disabled_or_encrypted  every active swap is zram (RAM) or a dm-crypt device
  kms_service_unprivileged    the unit runs as a non-root User= with NoNewPrivileges=yes
  direct_token_clients_absent no token client tool is installed on PATH, and every process connected
                              to pcscd runs the KMS binary (matched by socket inode, identified by
                              /proc/<pid>/exe, never by the name a process gives itself)

WHAT IT CANNOT MEASURE, and says so rather than guessing: runtime_credentials_excluded_from_backup
(a property of the HOST's backup jobs) and credential_tpm2_pcrs (the PCR set inside a sealed blob).
Those stay attested in the evidence and are reported as "attested, not measured".

Standard library only. It must run on a hardened guest where nothing else is installed.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "baremetal"))
from os_probe import *  # noqa: E402,F401,F403  (the OS probes now live with the supported deployment)
from os_probe import (MEASURED as _OS_MEASURED, PROBES as _OS_PROBES, TOKEN_CLIENTS,  # noqa: E402
                      pcscd_clients)

MEASURED = _OS_MEASURED + ("direct_token_clients_absent",)
UNMEASURED = ("runtime_credentials_excluded_from_backup", "credential_tpm2_pcrs")


def token_clients(host):
    installed = [t for t in TOKEN_CLIENTS if host.which(t)]
    if installed:
        return False, f"token client tools installed: {', '.join(installed)}"
    ok, why = pcscd_clients(host)
    return ok, (f"no token client tools installed; {why}" if ok else why)


PROBES = dict(_OS_PROBES, direct_token_clients_absent=token_clients)


def measure(host):
    return {name: dict(zip(("value", "why"), PROBES[name](host))) for name in MEASURED}


def compare(measured, evidence):
    """Refusals for every control the evidence claims and the guest does not have."""
    claims = evidence.get("guest", {})
    problems = []
    for name in MEASURED:
        if claims.get(name) is True and not measured[name]["value"]:
            problems.append(f"evidence claims {name}, the guest measures false: {measured[name]['why']}")
    return problems


def main(argv=None, host=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--evidence", help="signed evidence JSON whose guest section must agree with the guest")
    args = ap.parse_args(argv)
    host = host or Host()
    measured = measure(host)
    report = {"measured": measured, "attested_not_measured": list(UNMEASURED)}
    if args.evidence:
        with open(args.evidence, encoding="utf-8") as f:
            problems = compare(measured, json.load(f))
        report["disagreements"] = problems
    print(json.dumps(report, indent=2))
    if args.evidence:
        return 1 if report["disagreements"] else 0
    return 0 if all(v["value"] for v in measured.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
