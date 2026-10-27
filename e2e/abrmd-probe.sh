#!/usr/bin/env bash
# abrmd-probe.sh — regalia-afi step 2 (#592), after #597 measured that no GitHub-hosted image has tpm_vtpm_proxy: can each
# software TPM of the three-node fixture get a USER-SPACE resource manager instead, one tpm2-abrmd per node on its own
# D-Bus name, before the fixture is moved onto it? Proven here, on the runner, not assumed:
#
#   1  a D-Bus policy lets tss own and everyone reach the per-node names (com.intel.tss2.Tabrmd.e2e3.<node>)
#   2  two tpm2-abrmd, each on its own name in front of its own swtpm socket, answer (TPM2_GetRandom through
#      tabrmd:bus_name=<name>,bus_type=system) ...
#   3  ... and each reaches ITS OWN TPM: a PCR extended through one is unchanged through the other
#   4  THE CONTROL (#592 occurrences 1 and 2): N parallel clients, each looping a policy unseal, against swtpm's raw
#      socket exhaust its slots (TPM_RC_OBJECT/SESSION_MEMORY, 0x902/0x903) ...
#   5  ... and the same load through tpm2-abrmd never does: it swaps objects and sessions as /dev/tpmrm0 does on a host
#   6  a power cycle (TPM2_Shutdown(CLEAR) through tpm2-abrmd, swtpm stopped and started on the same state), with that
#      node's tpm2-abrmd restarted after it: the node answers again, resetCount one higher, PCR 11 back at its reset value
#   7  tpm2-abrmd stops on SIGTERM
# MEASURED, not judged (the fixture's design depends on it): whether a tpm2-abrmd left running across the swtpm restart
# still answers, or exits; printed as a MEASURE line and in RESULT.
#
# Prints one PASS/FAIL line per check, a RESULT line, and "abrmd-probe: N passed, M failed". Root, throwaway runner only:
# it writes a D-Bus policy into /etc and reloads the system bus.
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "abrmd-probe: run as root (it writes a D-Bus policy and reloads the system bus)"; exit 2; }
[ "${RUNNER_ENVIRONMENT:-}" = github-hosted ] || { [ -f /.dockerenv ] && [ "${REGALIA_ABRMD_PROBE_CONTAINER:-}" = 1 ]; } \
  || { echo "abrmd-probe: refused: it changes the system bus's policy; GitHub-hosted runners or a throwaway container only"; exit 2; }
CLIENTS="${CLIENTS:-10}" ROUNDS="${ROUNDS:-15}"
# SWTPM_EXTRA: flags for a local container run only (e.g. --seccomp action=none, where docker's own seccomp refuses
# swtpm's); never set in CI, where swtpm runs as on a runner
read -r -a extra <<< "${SWTPM_EXTRA:-}"
pass=0; fail=0
ok(){ if [ "$1" = 0 ]; then pass=$((pass+1)); echo "  PASS $2"; else fail=$((fail+1)); echo "  FAIL $2${3:+: $3}"; fi; }
W="$(mktemp -d)"; chmod 0755 "$W"
POLICY=/etc/dbus-1/system.d/regalia-e2e-tabrmd.conf
trap 'kill $(cat "$W"/*.pid 2>/dev/null) 2>/dev/null; rm -f "$POLICY"; rm -rf "$W"' EXIT
echo "kernel $(uname -r); $(swtpm --version 2>&1 | head -1); $(tpm2-abrmd --version 2>&1 | head -1); $(tpm2_getrandom --version 2>&1 | head -1); $(dbus-daemon --version 2>&1 | head -1)"
# D-Bus prefixes match whole name components: the names are <prefix>.<node>, never <prefix><node>
NAME=com.intel.tss2.Tabrmd.e2e3.

# THE LOAD (as vtpm-proxy-probe.sh's): each client loops tpm2_unseal of one PCR-policy-sealed object, one connection
# each, session-heavy within it. Setup once per TPM, then $CLIENTS clients x $ROUNDS unseals, counted.
# Every TPM call here is bounded by $CALL_S: a call that does not return is counted as TIMEOUT and the processes are
# snapshotted, so a stall is evidence, never a probe that hangs the runner (it did, twice, in a local container)
CALL_S="${CALL_S:-20}"
t(){ timeout "$CALL_S" "$@"; }
snapshot(){ ps -eo pid,ppid,stat,etimes,args > "$W/$1.ps" 2>&1; }
load(){ # $1 TCTI, $2 tag
  local tcti="$1" tag="$2" d="$W/$2"
  mkdir -p "$d"; : > "$W/$tag.err"; : > "$W/$tag.ok"
  clean(){ t tpm2_flushcontext -T "$tcti" -t >/dev/null 2>&1; t tpm2_flushcontext -T "$tcti" -s >/dev/null 2>&1; true; }
  { t tpm2_createprimary -T "$tcti" -C o -c "$d/prim.ctx" -Q && clean && t tpm2_pcrread -T "$tcti" -Q -o "$d/pcr.bin" sha256:0 \
    && t tpm2_createpolicy -T "$tcti" -Q --policy-pcr -l sha256:0 -f "$d/pcr.bin" -L "$d/pol.dat" && clean \
    && echo -n probe-secret | t tpm2_create -T "$tcti" -Q -C "$d/prim.ctx" -L "$d/pol.dat" -i- -u "$d/seal.pub" -r "$d/seal.priv" \
    && clean && t tpm2_load -T "$tcti" -Q -C "$d/prim.ctx" -u "$d/seal.pub" -r "$d/seal.priv" -c "$d/seal.ctx" && clean; } \
    2> "$d/setup.log" || { echo "setup failed on $tcti: $(tail -3 "$d/setup.log" | tr '\n' ' ')" > "$d/setup.err"; return 1; }
  # the clients' pids, waited for by name: a bare `wait` also waits for the tpm2-abrmd daemons this shell started, which
  # never exit (it hung the probe until its timeout, twice)
  local clients=()
  for _ in $(seq 1 "$CLIENTS"); do
    ( for _ in $(seq 1 "$ROUNDS"); do
        out="$(t tpm2_unseal -T "$tcti" -c "$d/seal.ctx" -p pcr:sha256:0 2>&1)"; rc=$?
        if [ "$rc" = 0 ] && [ "$out" = probe-secret ]; then
          echo ok >> "$W/$tag.ok"
        elif [ "$rc" = 124 ]; then
          echo "TIMEOUT after ${CALL_S}s" >> "$W/$tag.err"; [ -f "$W/$tag.ps" ] || snapshot "$tag"
        else
          echo "$out" | tr '\n' ' ' >> "$W/$tag.err"; echo >> "$W/$tag.err"
        fi
      done ) &
    clients+=($!)
  done
  wait "${clients[@]}"
}
exhausted(){ grep -cE '0x90[23]|0x0000090[23]|(OBJECT|SESSION)_MEMORY' "$1" || true; }
timedout(){ grep -c '^TIMEOUT' "$1" || true; }
evidence(){ # $1 tag, $2 node: what a stall leaves, in full, into the log (the runner keeps nothing else)
  [ "$(timedout "$W/$1.err")" -gt 0 ] || return 0
  echo "    --- $1: processes at the first timeout"; sed 's/^/    /' "$W/$1.ps" 2>/dev/null | grep -E 'swtpm|tpm2|abrmd|PID'
  echo "    --- $2's swtpm log (tail)"; tail -20 "$W/$2.swtpm.log" 2>/dev/null | sed 's/^/    /'
  [ -f "$W/$2.abrmd.log" ] && { echo "    --- $2's tpm2-abrmd log (tail)"; tail -20 "$W/$2.abrmd.log" | sed 's/^/    /'; }
  true
}
swtpm_up(){ # $1 node: its socket, tss's 0660 as the fixture makes it
  local tss; tss="$(getent group tss | cut -d: -f3)"; mkdir -p "$W/$1"; chown tss: "$W/$1"
  swtpm socket --tpm2 --server type=unixio,path="$W/$1/tpm.sock",mode=0660,gid="$tss" \
    --ctrl type=unixio,path="$W/$1/tpm.sock.ctrl",mode=0660,gid="$tss" --tpmstate dir="$W/$1" \
    --flags not-need-init,startup-clear --daemon --pid file="$W/$1.swtpm.pid" --log file="$W/$1.swtpm.log",level=2 "${extra[@]}"
  for _ in $(seq 1 50); do [ -S "$W/$1/tpm.sock" ] && return 0; sleep 0.2; done; return 1
}
abrmd_up(){ # $1 node: tpm2-abrmd as tss (as its packaged unit runs it) on the node's own name, in front of its socket
  runuser -u tss -- tpm2-abrmd --tcti="swtpm:path=$W/$1/tpm.sock" --dbus-name="$NAME$1" > "$W/$1.abrmd.log" 2>&1 &
  echo $! > "$W/$1.abrmd.pid"
  for _ in $(seq 1 50); do
    tpm2_getrandom -T "tabrmd:bus_name=$NAME$1,bus_type=system" --hex 8 >/dev/null 2>&1 && return 0; sleep 0.2
  done; return 1
}
tc(){ echo "tabrmd:bus_name=$NAME$1,bus_type=system"; }
resets(){ tpm2_readclock -T "$1" 2>/dev/null | sed -n 's/.*reset_count: *\([0-9]*\).*/\1/p'; }

echo "### the D-Bus policy for the per-node names"
cat > "$POLICY" <<'EOF'
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="tss"><allow own_prefix="com.intel.tss2.Tabrmd.e2e3"/></policy>
  <policy context="default"><allow send_destination_prefix="com.intel.tss2.Tabrmd.e2e3"/></policy>
</busconfig>
EOF
if [ ! -S /run/dbus/system_bus_socket ]; then mkdir -p /run/dbus; dbus-daemon --system --fork; sleep 0.5; fi
reload="$(dbus-send --system --print-reply --dest=org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus.ReloadConfig 2>&1)"
ok $? "the system bus reloaded with the per-node policy" "$reload"

echo "### two nodes, each its own swtpm and its own tpm2-abrmd"
up=0
for n in a b; do
  swtpm_up "$n" && abrmd_up "$n" || { up=1; echo "    $n: $(tail -5 "$W/$n.abrmd.log" 2>/dev/null | tr '\n' ' ')"; }
done
ra="$(tpm2_getrandom -T "$(tc a)" --hex 8 2>&1)"; rb="$(tpm2_getrandom -T "$(tc b)" --hex 8 2>&1)"
ok "$([ "$up" = 0 ] && [[ "$ra" =~ ^[0-9a-f]{16}$ ]] && [[ "$rb" =~ ^[0-9a-f]{16}$ ]] && echo 0 || echo 1)" \
   "both answer through their own names (a: $ra, b: $rb)" "a: $ra | b: $rb"
pcr(){ tpm2_pcrread -T "$1" sha256:16 2>/dev/null | sed -n 's/.*16 *: *0x\([0-9A-Fa-f]*\).*/\1/p'; }
b0="$(pcr "$(tc b)")"; tpm2_pcrextend -T "$(tc a)" "16:sha256=$(printf '%064d' 1)"; a1="$(pcr "$(tc a)")"; b1="$(pcr "$(tc b)")"
ok "$([ -n "$a1" ] && [ "$a1" != "$b0" ] && [ "$b1" = "$b0" ] && echo 0 || echo 1)" \
   "each reaches its own TPM (PCR 16 extended through a: a ${a1:0:12}…, b unchanged ${b1:0:12}…)" "a=$a1 b before=$b0 after=$b1"

echo "### the control: the raw socket (node c, no resource manager)"
swtpm_up c
load "swtpm:path=$W/c/tpm.sock" sock; s=$?
sock_mem="$(exhausted "$W/sock.err")"; sock_to="$(timedout "$W/sock.err")"
ok "$([ "$s" = 0 ] && [ "$sock_mem" -gt 0 ] && echo 0 || echo 1)" "the raw socket, $CLIENTS clients x $ROUNDS policy unseals: $(wc -l < "$W/sock.ok") ok, OBJECT/SESSION_MEMORY $sock_mem times, TIMEOUT $sock_to (#592, reproduced)" \
  "setup $s, exhausted $sock_mem: the control did not reproduce #592; raise CLIENTS (now $CLIENTS) before trusting the comparison"
evidence sock c

echo "### the same load through tpm2-abrmd (node a)"
load "$(tc a)" rm; s=$?
rm_mem="$(exhausted "$W/rm.err")"; rm_ok="$(wc -l < "$W/rm.ok" | tr -d ' ')"; rm_to="$(timedout "$W/rm.err")"
# POSITIVE: every unseal through tpm2-abrmd succeeded; an absent error alone would prove nothing
ok "$([ "$s" = 0 ] && [ "$rm_ok" = $((CLIENTS * ROUNDS)) ] && echo 0 || echo 1)" \
   "tpm2-abrmd, the same load: $rm_ok of $((CLIENTS * ROUNDS)) unseals ok, OBJECT/SESSION_MEMORY $rm_mem times, TIMEOUT $rm_to" \
   "$(cat "$W/rm/setup.err" 2>/dev/null) $(head -3 "$W/rm.err" | tr '\n' ' ')"
evidence rm a

echo "### a power cycle of node b's TPM"
before="$(resets "$(tc b)")"
tpm2_shutdown -c -T "$(tc b)" 2>"$W/b.shutdown.err"; sd=$?
spid="$(cat "$W/b.swtpm.pid")"; kill -TERM "$spid"
for _ in $(seq 1 50); do [ -e "/proc/$spid" ] || break; sleep 0.2; done
swtpm_up b; sleep 1
apid="$(cat "$W/b.abrmd.pid")"
kept="$(tpm2_getrandom -T "$(tc b)" --hex 8 2>&1)"; alive="$([ -e "/proc/$apid" ] && echo yes || echo no)"
survived="$([[ "$kept" =~ ^[0-9a-f]{16}$ ]] && echo yes || echo no)"
echo "  MEASURE tpm2-abrmd left running across the swtpm restart: process alive=$alive, answers=$survived ($(echo "$kept" | tr '\n' ' ' | cut -c1-200)); its log: $(tail -3 "$W/b.abrmd.log" | tr '\n' ' ' | cut -c1-300)"
kill -TERM "$apid" 2>/dev/null; for _ in $(seq 1 50); do [ -e "/proc/$apid" ] || break; sleep 0.2; done
abrmd_up b; r=$?
after="$(resets "$(tc b)")"; p11="$(tpm2_pcrread -T "$(tc b)" sha256:11 2>/dev/null | sed -n 's/.*11 *: *0x\([0-9A-Fa-f]*\).*/\1/p')"
ok "$([ "$sd" = 0 ] && [ "$r" = 0 ] && [ -n "$before" ] && [ "$after" = $((before + 1)) ] && [ "$p11" = "$(printf '%064d' 0)" ] && echo 0 || echo 1)" \
   "after the cycle, with its tpm2-abrmd restarted: it answers, resetCount $before -> $after, PCR 11 at reset" \
   "shutdown $sd ($(tr '\n' ' ' < "$W/b.shutdown.err")), abrmd up $r, resetCount $before -> $after, PCR 11 $p11"

echo "### tpm2-abrmd stops on SIGTERM"
apid="$(cat "$W/a.abrmd.pid")"
# POSITIVE: it was running and answering before the signal; a tpm2-abrmd that never started "stops" too
was="$([ -e "/proc/$apid" ] && [[ "$(tpm2_getrandom -T "$(tc a)" --hex 8 2>&1)" =~ ^[0-9a-f]{16}$ ]] && echo yes || echo no)"
kill -TERM "$apid" 2>/dev/null
for _ in $(seq 1 50); do [ -e "/proc/$apid" ] || break; sleep 0.2; done
ok "$([ "$was" = yes ] && [ ! -e "/proc/$apid" ] && echo 0 || echo 1)" "tpm2-abrmd, running and answering, stops on SIGTERM" \
   "running and answering before: $was; pid $apid $([ -e "/proc/$apid" ] && echo "still there after 10 s" || echo gone)"

echo "RESULT socket_ok=$(wc -l < "$W/sock.ok" | tr -d ' ') socket_exhausted=$sock_mem abrmd_ok=${rm_ok:-?} abrmd_exhausted=${rm_mem:-?} socket_timeouts=${sock_to:-?} abrmd_timeouts=${rm_to:-?} of=$((CLIENTS * ROUNDS)) abrmd_survives_swtpm_restart=$survived abrmd_alive_after=$alive runner=$(. /etc/os-release; echo "$VERSION_ID")"
echo "abrmd-probe: $pass passed, $fail failed"
[ "$fail" = 0 ]
