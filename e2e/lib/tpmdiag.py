"""What a software-TPM run keeps, so a TPM failure is diagnosed from ONE run (regalia-zga, regalia-a0y).

Both of 2026-10-24's TPM failures needed evidence the runs did not keep: swtpm logged at its default level (nothing
per command), the QEMU boot test gave swtpm no log at all, and the tool versions were only in apt's install output.
regalia-a0y's cause took an experiment branch with --log level=20 to find. Every harness that starts a swtpm now:
  - logs it at LOG_LEVEL (each command and response, with the control channel's CMD_CANCEL_TPM_CMD and friends);
  - says which swtpm, libtpms, tpm2-tools, QEMU and kernel it ran on (versions()).
tpm2-tss is left as it is: it already logs its warnings and errors to stderr (TSS2_LOG's default, all+warning), which
the harnesses keep in their failures, and membership.run_tpm2 reads that stderr to recognise TPM_RC_SESSION_MEMORY
(0x903). Redirecting it to a file would hide what that check reads.
The CI jobs upload these on failure (.github/actions/tpm-diagnostics). Test TPMs only: no production key passes here.
"""
import os
import shutil
import subprocess

LOG_LEVEL = 20
KEEP_DIR = "/tmp/regalia-tpm-diagnostics"   # outlives a harness that removes its work directory; the CI action reads /tmp


def log_arg(path):
    """swtpm's --log value: `path` at LOG_LEVEL."""
    return "file=%s,level=%d" % (path, LOG_LEVEL)


def keep(files, label, root=KEEP_DIR, environ=None):
    """Copy {relative name: path} under root/label, so a harness that removes its work directory (the three-node
    scripts do, in their `finally`) still leaves its TPM logs for the CI action. Only in CI (RUNNER_ENVIRONMENT, which
    the jobs' sudo preserves) or with REGALIA_KEEP_TPM_LOGS=1: a laptop run leaves nothing behind. Returns what it kept."""
    environ = os.environ if environ is None else environ
    if not (environ.get("RUNNER_ENVIRONMENT") or environ.get("REGALIA_KEEP_TPM_LOGS") == "1"):
        return []
    kept = []
    for name, path in sorted(files.items()):
        if os.path.isfile(path):
            target = os.path.join(root, label, name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copyfile(path, target)
            kept.append(target)
    return kept


def _first_line(argv):
    if not shutil.which(argv[0]):
        return "absent"
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        return "<%s>" % error
    text = (done.stdout or done.stderr).strip().splitlines()
    return text[0].strip()[:160] if text else "<no output, %d>" % done.returncode


def _package(name):
    if not shutil.which("dpkg-query"):
        return "?"
    try:
        done = subprocess.run(["dpkg-query", "-W", "-f=${Version}", name], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return "?"
    return done.stdout.strip() or "absent"


def versions():
    """One line naming what the software TPM ran on: the evidence regalia-a0y had to dig out of apt's output."""
    parts = ["swtpm %s" % _first_line(["swtpm", "--version"]),
             "libtpms %s" % (_package("libtpms0") if _package("libtpms0") not in ("absent", "?") else _package("libtpms-dev")),
             "tpm2-tools %s" % _first_line(["tpm2_startup", "--version"]),
             "qemu %s" % _first_line(["qemu-system-x86_64", "--version"]),
             "kernel %s" % os.uname().release]
    return "TPM stack: " + " | ".join(parts)
