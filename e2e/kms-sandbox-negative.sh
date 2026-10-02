#!/usr/bin/env bash
# kms-sandbox-negative.sh — the KMS unit's sandbox, by behaviour (#61, PoC 1.2): a dummy service under
# the SHIPPED settings (deploy/systemd/regalia-kms.service + deploy/baremetal/regalia-kms-hardening.conf.example)
# tries to write outside its state directory, read home directories, reach the kernel, gain privilege
# and open socket families it has no use for. Every refusal has a positive control: the same dummy
# service, with none of the settings, is allowed the same action. And what the KMS needs (its state
# directory, TCP and unix sockets) must still work inside the sandbox.
#
#   REGALIA_SANDBOX_HOST_OK=1 e2e/kms-sandbox-negative.sh     (CI sets nothing: GITHUB_ACTIONS is enough)
#
# It starts two transient units AS ROOT on this machine's system manager, and the control unit really
# does create (and remove) a file in /etc, /usr/local and /var, and rewrites a kernel tunable with its
# own value. That is fine on a CI runner or a throwaway VM. It is refused anywhere else unless
# REGALIA_SANDBOX_HOST_OK=1 says the host is one of those. Never a shared or production machine.
#
# The service runs as root, not as the KMS user: what root is refused in this sandbox, the KMS user is
# too, and the control then shows the refusal comes from the sandbox and not from file permissions.
# Not applied here: User=/Group= (above), ExecStart and restart settings, and AppArmorProfile= (the
# profile confines the KMS binary's paths, not this probe; it has its own CI job).
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
UNIT="$HERE/deploy/systemd/regalia-kms.service"; DROPIN="$HERE/deploy/baremetal/regalia-kms-hardening.conf.example"
PROBE="$HERE/e2e/lib/sandbox_probe.py"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
if [ "${GITHUB_ACTIONS:-}" != true ] && [ "${REGALIA_SANDBOX_HOST_OK:-}" != 1 ]; then
  echo "kms-sandbox-negative: refused: this starts root units on this machine's system manager and its control"
  echo "  unit writes to /etc, /usr/local and /var. Run it in CI or on a throwaway VM (REGALIA_SANDBOX_HOST_OK=1)."
  exit 2
fi
for t in systemd-run python3; do command -v "$t" >/dev/null || { echo "kms-sandbox-negative: $t is required"; exit 2; }; done
sudo -n true 2>/dev/null || { echo "kms-sandbox-negative: needs sudo"; exit 2; }
echo "kms-sandbox-negative: $(systemctl --version | head -1), kernel $(uname -r)"

W="$(mktemp -d)"; tag="regalia-sandbox-marker.$$"
sudo sh -c "echo marker > /root/$tag && echo marker > /home/$tag && echo marker > /tmp/$tag" || { echo "cannot create the marker files"; exit 2; }
trap 'sudo rm -f "/root/$tag" "/home/$tag" "/tmp/$tag"; sudo rm -rf "/var/lib/regalia-sandbox-probe" "$W"' EXIT

# The shipped [Service] settings, as -p arguments. The drop-in comes second, as systemd would read it.
mapfile -t props < <(python3 - "$UNIT" "$DROPIN" <<'PY'
import sys
SKIP = {"Type", "User", "Group", "ExecStart", "Restart", "RestartSec", "StateDirectory", "StateDirectoryMode", "AppArmorProfile"}
for path in sys.argv[1:]:
    section = None
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line
        elif section == "[Service]" and line and not line.startswith(("#", ";")) and "=" in line \
                and line.split("=", 1)[0] not in SKIP:
            print(line)
PY
)
[ "${#props[@]}" -ge 20 ] || { echo "kms-sandbox-negative: only ${#props[@]} settings read from the unit and the drop-in"; exit 2; }
hardening=(); for p in "${props[@]}"; do hardening+=(-p "$p"); done

# run <unit name> <out> [-p …]: the probe goes in on stdin, since ProtectHome hides the checkout.
run(){ local name="$1" out="$2"; shift 2
  # shellcheck disable=SC2024  # the report is written by this user, on purpose: only the unit is root
  sudo systemd-run --quiet --wait --pipe --collect --unit="$name-$$" -p StateDirectory=regalia-sandbox-probe \
    -E "MARKER_ROOT=/root/$tag" -E "MARKER_HOME=/home/$tag" -E "MARKER_TMP=/tmp/$tag" "$@" \
    /usr/bin/python3 - < "$PROBE" > "$out" 2> "$out.err"; }
run regalia-sandbox-control "$W/control.json";             rc_control=$?
run regalia-sandbox-hardened "$W/hardened.json" "${hardening[@]}"; rc_hardened=$?

hdr "0  both units ran the probe"
[ "$rc_control" = 0 ] && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$W/control.json" 2>/dev/null \
  && P "the control unit (no hardening) ran it" || F "control unit: exit $rc_control: $(head -c 400 "$W/control.json.err")"
[ "$rc_hardened" = 0 ] && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$W/hardened.json" 2>/dev/null \
  && P "the hardened unit (${#props[@]} shipped settings) ran it" || F "hardened unit: exit $rc_hardened: $(head -c 400 "$W/hardened.json.err")"
if [ "$fail" != 0 ]; then echo; echo "kms-sandbox-negative: $pass passed, $fail failed"; exit 1; fi

# The verdicts: one line per check, "PASS|FAIL<TAB>text", sections as "HDR<TAB>title", and a last line
# "END<TAB><number of checks>". They are written to a file and counted, so an evaluator that dies part
# way cannot leave a short list of passes behind.
python3 - "$W/control.json" "$W/hardened.json" > "$W/verdicts" <<'PY'
import json, sys
control, hardened = (json.load(open(p)) for p in sys.argv[1:3])
REFUSED = (
    ("1  the filesystem outside the state directory", (
        ("write_etc", "create a file in /etc"), ("write_usr", "create a file in /usr/local"),
        ("write_var", "create a file in /var"), ("read_root_home", "read a file under /root"),
        ("read_home", "read a file under /home"), ("see_host_tmp", "see a file in the host's /tmp"))),
    ("2  the kernel", (
        ("write_kernel_tunable", "write a kernel tunable (/proc/sys)"), ("list_kernel_modules", "list /usr/lib/modules"),
        ("load_kernel_module", "call init_module (load a kernel module)"), ("read_kernel_log", "open the kernel log (/dev/kmsg)"))),
    ("3  privilege", (
        ("make_setuid_file", "make a file setuid"), ("use_cap_chown", "use a capability (chown a file to another user)"),
        ("change_personality", "change the execution domain (personality)"), ("new_mount_namespace", "create a mount namespace"))),
    ("4  socket families the KMS has no use for", (
        ("socket_netlink", "open an AF_NETLINK socket"), ("socket_packet", "open an AF_PACKET socket"))),
)
NEEDED = (("write_state_directory", "write in its state directory"), ("socket_inet_stream", "open a TCP socket (IPv4)"),
          ("socket_inet6_stream", "open a TCP socket (IPv6)"), ("socket_unix", "open a unix socket (pcscd)"))
for title, actions in REFUSED:
    print("HDR\t" + title)
    for name, text in actions:
        c, h = control.get(name, "missing"), hardened.get(name, "missing")
        # The control first: a refusal only counts if the same action is allowed without the sandbox.
        if c != "allowed":
            print("FAIL\t%s: the CONTROL unit was not allowed either (%s), so the refusal proves nothing" % (text, c))
        elif not h.startswith("refused"):
            print("FAIL\t%s: the hardened unit was %s" % (text, h))
        else:
            print("PASS\t%s: %s in the sandbox, allowed without it" % (text, h))
print("HDR\t5  what the KMS needs still works in the sandbox")
for name, text in NEEDED:
    c, h = control.get(name, "missing"), hardened.get(name, "missing")
    print("%s\t%s: %s in the sandbox, %s without it" % ("PASS" if c == h == "allowed" else "FAIL", text, h, c))
print("HDR\t6  the process's own state, as the kernel reports it")
cs, hs = control["state"], hardened["state"]
def check(ok, text):
    print("%s\t%s" % ("PASS" if ok else "FAIL", text))
check(cs["uid"] == hs["uid"] == 0, "both ran as root (uid %s, %s): the refusals are the sandbox's, not file permissions" % (hs["uid"], cs["uid"]))
check(int(hs["CapBnd"], 16) == 0 and int(hs["CapEff"], 16) == 0 and int(cs["CapEff"], 16) != 0,
      "no capability in the sandbox (bounding %s, effective %s); control effective %s" % (hs["CapBnd"], hs["CapEff"], cs["CapEff"]))
check(hs["NoNewPrivs"] == "1" and cs["NoNewPrivs"] == "0", "NoNewPrivs is %s in the sandbox, %s without it" % (hs["NoNewPrivs"], cs["NoNewPrivs"]))
check(hs["Seccomp"] == "2" and cs["Seccomp"] == "0", "a system-call filter is loaded in the sandbox (Seccomp %s), none without it (%s)" % (hs["Seccomp"], cs["Seccomp"]))
print("END\t%d" % (sum(len(actions) for _, actions in REFUSED) + len(NEEDED) + 4))
PY
rc_verdicts=$?; expected=""; before=$((pass+fail))
while IFS=$'\t' read -r kind text; do
  case "$kind" in HDR) hdr "$text";; PASS) P "$text";; FAIL) F "$text";; END) expected="$text";; esac
done < "$W/verdicts"
if [ "$rc_verdicts" != 0 ] || [ -z "$expected" ] || [ "$((pass+fail-before))" != "$expected" ]; then
  F "the evaluator did not finish (exit $rc_verdicts; $((pass+fail-before)) verdicts of ${expected:-an unknown number})"
fi

echo; echo "kms-sandbox-negative: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
