#!/usr/bin/env bash
# vtpm-proxy-probe.sh — regalia-afi step 2, PR 1 (#592): can a runner give each software TPM the KERNEL's resource manager,
# as a host's /dev/tpmrm0 is, before the three-node fixture is moved onto it? Proven here, on the runner, not assumed:
#
#   1  tpm_vtpm_proxy loads, and `swtpm chardev --vtpm-proxy` makes the kernel register /dev/tpmN and /dev/tpmrmN
#   2  /dev/tpmrmN answers (TPM2_GetRandom through device:/dev/tpmrmN)
#   3  THE CONTROL (#592 occurrences 1 and 2): N parallel clients, each looping a policy session, against swtpm's raw
#      socket exhaust its session slots (TPM_RC_SESSION_MEMORY, 0x903) ...
#   4  ... and the same load through /dev/tpmrmN never does: the kernel swaps sessions as it does on a host
#   5  the vTPM-proxy swtpm stops on SIGTERM (#592 occurrence 3 was a socket swtpm that did not)
#
# ONLY the kernel path counts (TEAMLEAD-grafana): there is no CUSE fallback here, and a missing module, a missing
# /dev/tpmrmN, or a session load that does not pass through it is a FAIL, never "swtpm started".
# Prints one PASS/FAIL line per check, a RESULT line, and "vtpm-proxy-probe: N passed, M failed". Root, throwaway runner only.
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "vtpm-proxy-probe: run as root (it loads a kernel module)"; exit 2; }
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || [ "${REGALIA_VTPM_PROBE_HOST_OK:-}" = "$(cat /etc/machine-id 2>/dev/null)" ] \
  || { echo "vtpm-proxy-probe: refused: it loads a kernel module and makes TPM devices; GitHub-hosted runners only"; exit 2; }
CLIENTS="${CLIENTS:-10}" ROUNDS="${ROUNDS:-15}"
# SWTPM_EXTRA: flags for a local container run only (e.g. --seccomp action=none, where docker's own seccomp refuses
# swtpm's); never set in CI, where swtpm runs as on a runner
read -r -a extra <<< "${SWTPM_EXTRA:-}"
pass=0; fail=0
ok(){ if [ "$1" = 0 ]; then pass=$((pass+1)); echo "  PASS $2"; else fail=$((fail+1)); echo "  FAIL $2${3:+: $3}"; fi; }
W="$(mktemp -d)"; trap 'kill $(cat "$W"/*.pid 2>/dev/null) 2>/dev/null; rm -rf "$W"' EXIT
echo "kernel $(uname -r); $(swtpm --version 2>&1 | head -1); $(tpm2_getrandom --version 2>&1 | head -1)"

# THE LOAD: each client loops tpm2_unseal of one PCR-policy-sealed object. One invocation is one connection that loads
# the object, starts a policy session, satisfies it and unseals: session-heavy WITHIN a connection, so it is a fair test
# of a resource manager (one that flushes a connection's sessions when it closes would fail a multi-tool session for
# that reason alone, and prove nothing). Setup once per TPM; then $CLIENTS clients x $ROUNDS unseals, counted.
load(){ # $1 TCTI, $2 tag
  local tcti="$1" tag="$2" d="$W/$2"
  mkdir -p "$d"; : > "$W/$tag.err"; : > "$W/$tag.ok"           # before anything: a failed setup still counts as read
  # with no resource manager every tool leaves its transient objects loaded (that IS #592's mechanism: the setup alone
  # filled the raw socket's object slots, Esys_Load 0x902), so the setup flushes them between steps; harmless on a RM
  clean(){ tpm2_flushcontext -T "$tcti" -t >/dev/null 2>&1; tpm2_flushcontext -T "$tcti" -s >/dev/null 2>&1; true; }
  { tpm2_createprimary -T "$tcti" -C o -c "$d/prim.ctx" -Q && clean && tpm2_pcrread -T "$tcti" -Q -o "$d/pcr.bin" sha256:0 \
    && tpm2_createpolicy -T "$tcti" -Q --policy-pcr -l sha256:0 -f "$d/pcr.bin" -L "$d/pol.dat" && clean \
    && echo -n probe-secret | tpm2_create -T "$tcti" -Q -C "$d/prim.ctx" -L "$d/pol.dat" -i- -u "$d/seal.pub" -r "$d/seal.priv" \
    && clean && tpm2_load -T "$tcti" -Q -C "$d/prim.ctx" -u "$d/seal.pub" -r "$d/seal.priv" -c "$d/seal.ctx" && clean; } \
    2> "$d/setup.log" || { echo "setup failed on $tcti: $(tail -3 "$d/setup.log" | tr '\n' ' ')" > "$d/setup.err"; return 1; }
  for _ in $(seq 1 "$CLIENTS"); do
    ( for _ in $(seq 1 "$ROUNDS"); do
        if out="$(tpm2_unseal -T "$tcti" -c "$d/seal.ctx" -p pcr:sha256:0 2>&1)" && [ "$out" = probe-secret ]; then
          echo ok >> "$W/$tag.ok"
        else
          echo "$out" | tr '\n' ' ' >> "$W/$tag.err"; echo >> "$W/$tag.err"
        fi
      done ) &
  done
  wait
}
exhausted(){ grep -cE '0x90[23]|0x0000090[23]|(OBJECT|SESSION)_MEMORY' "$1" || true; }

echo "### the control: swtpm's raw socket"
mkdir -p "$W/sock"
swtpm socket --tpm2 --server type=unixio,path="$W/sock/tpm.sock" --ctrl type=unixio,path="$W/sock/tpm.sock.ctrl" \
  --tpmstate dir="$W/sock" --flags not-need-init,startup-clear --daemon --pid file="$W/sock.pid" "${extra[@]}"
sleep 1
load "swtpm:path=$W/sock/tpm.sock" sock; ok $? "the raw socket: a PCR-policy-sealed object made" "$(cat "$W/sock/setup.err" 2>/dev/null)"
sock_mem="$(exhausted "$W/sock.err")"
ok "$([ "$sock_mem" -gt 0 ] && echo 0 || echo 1)" "the raw socket, $CLIENTS clients x $ROUNDS policy unseals: $(wc -l < "$W/sock.ok") ok, OBJECT/SESSION_MEMORY $sock_mem times (#592, reproduced)" \
  "none: the control did not reproduce #592; raise CLIENTS (now $CLIENTS) before trusting the comparison"

echo "### the kernel's resource manager: swtpm chardev --vtpm-proxy"
modprobe tpm_vtpm_proxy; rc=$?
ok "$rc" "tpm_vtpm_proxy loads" "modprobe exit $rc ($(ls "/lib/modules/$(uname -r)/kernel/drivers/char/tpm/" 2>&1 | tr '\n' ' '))"
rms(){ local d; for d in /dev/tpmrm[0-9]*; do [ -c "$d" ] && echo "${d#/dev/}"; done | sort; }
before="$(rms)"
mkdir -p "$W/vtpm"
swtpm chardev --vtpm-proxy --tpm2 --tpmstate dir="$W/vtpm" --flags not-need-init,startup-clear --daemon --pid file="$W/vtpm.pid" "${extra[@]}" \
  > "$W/vtpm.out" 2>&1
dev=""
for _ in $(seq 1 50); do
  dev="$(comm -13 <(echo "$before") <(rms) | head -1)"; [ -n "$dev" ] && break; sleep 0.2
done
ok "$([ -n "$dev" ] && echo 0 || echo 1)" "the kernel registered /dev/${dev:-?} for it ($(cat "$W/vtpm.out" | tr '\n' ' '))" "no new /dev/tpmrmN in 10 s"
if [ -n "$dev" ]; then
  r="$(tpm2_getrandom -T "device:/dev/$dev" --hex 8 2>&1)"
  ok "$([[ "$r" =~ ^[0-9a-f]{16}$ ]] && echo 0 || echo 1)" "/dev/$dev answers (TPM2_GetRandom: $r)" "$r"
  load "device:/dev/$dev" rm; ok $? "/dev/$dev: a PCR-policy-sealed object made" "$(cat "$W/rm/setup.err" 2>/dev/null)"
  rm_mem="$(exhausted "$W/rm.err")"; rm_ok="$(wc -l < "$W/rm.ok" | tr -d ' ')"
  # POSITIVE: every unseal through the kernel succeeded; an absent error alone would prove nothing
  ok "$([ "$rm_ok" = $((CLIENTS * ROUNDS)) ] && echo 0 || echo 1)" "/dev/$dev, the same load: $rm_ok of $((CLIENTS * ROUNDS)) unseals ok, OBJECT/SESSION_MEMORY $rm_mem times (the kernel swaps them)" \
     "$(head -3 "$W/rm.err" | tr '\n' ' ')"
  pid="$(cat "$W/vtpm.pid")"; kill -TERM "$pid"
  for _ in $(seq 1 50); do [ -e "/proc/$pid" ] || break; sleep 0.2; done
  ok "$([ -e "/proc/$pid" ] && echo 1 || echo 0)" "the vTPM-proxy swtpm stops on SIGTERM" "pid $pid still there after 10 s: $(grep -E '^(State|PPid)' /proc/$pid/status 2>/dev/null | tr '\n' ' ')"
fi
echo "RESULT socket_ok=$(wc -l < "$W/sock.ok" | tr -d ' ') socket_exhausted=$sock_mem rm_ok=${rm_ok:-?} rm_exhausted=${rm_mem:-?} of=$((CLIENTS * ROUNDS)) device=${dev:-none} runner=$(. /etc/os-release; echo "$VERSION_ID")"
echo "vtpm-proxy-probe: $pass passed, $fail failed"
[ "$fail" = 0 ]
