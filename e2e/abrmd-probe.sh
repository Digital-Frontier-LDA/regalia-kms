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
# and, on a private bus per node (the fixture's design; systemd units, so the runner only):
#   8  a unit reaches its node's tpm2-abrmd over that node's bus, and each bus reaches its own TPM
#   9  THE ONE THAT COUNTS: a unit given node q's bus address, with q's directory hidden (InaccessiblePaths=, as the
#      fixture hides the other nodes'), does not reach q; its control, nothing hidden, does
#  10  NO FALLBACK: a unit with no address and /run/dbus hidden fails closed; its control, the real bus visible, reaches
#      a decoy tpm2-abrmd there under the default name (without one, "unreachable" would prove nothing)
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
  swtpm socket --tpm2 --server "type=unixio,path=$W/$1/tpm.sock,mode=0660,gid=$tss" \
    --ctrl "type=unixio,path=$W/$1/tpm.sock.ctrl,mode=0660,gid=$tss" --tpmstate dir="$W/$1" \
    --flags not-need-init,startup-clear --daemon --pid file="$W/$1.swtpm.pid" --log file="$W/$1.swtpm.log",level=2 "${extra[@]}"
  for _ in $(seq 1 50); do [ -S "$W/$1/tpm.sock" ] && return 0; sleep 0.2; done; return 1
}
abrmd_up(){ # $1 node: tpm2-abrmd as tss (as its packaged unit runs it) on the node's own name, in front of its socket
  runuser -u tss -- tpm2-abrmd --tcti="swtpm:path=$W/$1/tpm.sock" --dbus-name="$NAME$1" > "$W/$1.abrmd.log" 2>&1 &
  echo $! > "$W/$1.abrmd.pid"
  for _ in $(seq 1 50); do
    timeout 5 tpm2_getrandom -T "tabrmd:bus_name=$NAME$1,bus_type=system" --hex 8 >/dev/null 2>&1 && return 0; sleep 0.2
  done; return 1
}
tc(){ echo "tabrmd:bus_name=$NAME$1,bus_type=system"; }
resets(){ t tpm2_readclock -T "$1" 2>/dev/null | sed -n 's/.*reset_count: *\([0-9]*\).*/\1/p'; }

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
ra="$(t tpm2_getrandom -T "$(tc a)" --hex 8 2>&1)"; rb="$(t tpm2_getrandom -T "$(tc b)" --hex 8 2>&1)"
ok "$([ "$up" = 0 ] && [[ "$ra" =~ ^[0-9a-f]{16}$ ]] && [[ "$rb" =~ ^[0-9a-f]{16}$ ]] && echo 0 || echo 1)" \
   "both answer through their own names (a: $ra, b: $rb)" "a: $ra | b: $rb"
pcr(){ t tpm2_pcrread -T "$1" sha256:16 2>/dev/null | sed -n 's/.*16 *: *0x\([0-9A-Fa-f]*\).*/\1/p'; }
b0="$(pcr "$(tc b)")"; t tpm2_pcrextend -T "$(tc a)" "16:sha256=$(printf '%064d' 1)"; a1="$(pcr "$(tc a)")"; b1="$(pcr "$(tc b)")"
ok "$([ -n "$a1" ] && [ "$a1" != "$b0" ] && [ "$b1" = "$b0" ] && echo 0 || echo 1)" \
   "each reaches its own TPM (PCR 16 extended through a: a ${a1:0:12}…, b unchanged ${b1:0:12}…)" "a=$a1 b before=$b0 after=$b1"

# MEASURED, not judged: while node a's tpm2-abrmd holds its connection, does swtpm's socket serve a SECOND, raw client
# (the fixture's Go unlock client speaks only unix:<socket>, never tabrmd)? If it waits, the fixture runs tpm2-abrmd
# only while a node's services run (start() to stop()), and its initrd steps reach the socket with no daemon on it
raw="$(timeout 5 tpm2_getrandom -T "swtpm:path=$W/a/tpm.sock" --hex 8 2>&1)"; rrc=$?
shared="$([ "$rrc" = 0 ] && [[ "$raw" =~ ^[0-9a-f]{16}$ ]] && echo yes || { [ "$rrc" = 124 ] && echo waits || echo refused; })"
echo "  MEASURE a raw client on a's socket while a's tpm2-abrmd holds it: $shared (rc $rrc: $(echo "$raw" | tr '\n' ' ' | cut -c1-200))"
after_raw="$(t tpm2_getrandom -T "$(tc a)" --hex 8 2>&1)"
echo "  MEASURE a's tpm2-abrmd after that raw client: $([[ "$after_raw" =~ ^[0-9a-f]{16}$ ]] && echo answers || echo "fails: $(echo "$after_raw" | tr '\n' ' ' | cut -c1-200)")"

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
t tpm2_shutdown -c -T "$(tc b)" 2>"$W/b.shutdown.err"; sd=$?
spid="$(cat "$W/b.swtpm.pid")"; kill -TERM "$spid"
for _ in $(seq 1 50); do [ -e "/proc/$spid" ] || break; sleep 0.2; done
swtpm_up b; sleep 1
apid="$(cat "$W/b.abrmd.pid")"
kept="$(t tpm2_getrandom -T "$(tc b)" --hex 8 2>&1)"; alive="$([ -e "/proc/$apid" ] && echo yes || echo no)"
survived="$([[ "$kept" =~ ^[0-9a-f]{16}$ ]] && echo yes || echo no)"
echo "  MEASURE tpm2-abrmd left running across the swtpm restart: process alive=$alive, answers=$survived ($(echo "$kept" | tr '\n' ' ' | cut -c1-200)); its log: $(tail -3 "$W/b.abrmd.log" | tr '\n' ' ' | cut -c1-300)"
kill -TERM "$apid" 2>/dev/null; for _ in $(seq 1 50); do [ -e "/proc/$apid" ] || break; sleep 0.2; done
abrmd_up b; r=$?
after="$(resets "$(tc b)")"; p11="$(t tpm2_pcrread -T "$(tc b)" sha256:11 2>/dev/null | sed -n 's/.*11 *: *0x\([0-9A-Fa-f]*\).*/\1/p')"
ok "$([ "$sd" = 0 ] && [ "$r" = 0 ] && [ -n "$before" ] && [ "$after" = $((before + 1)) ] && [ "$p11" = "$(printf '%064d' 0)" ] && echo 0 || echo 1)" \
   "after the cycle, with its tpm2-abrmd restarted: it answers, resetCount $before -> $after, PCR 11 at reset" \
   "shutdown $sd ($(tr '\n' ' ' < "$W/b.shutdown.err")), abrmd up $r, resetCount $before -> $after, PCR 11 $p11"

echo "### tpm2-abrmd stops on SIGTERM"
apid="$(cat "$W/a.abrmd.pid")"
# POSITIVE: it was running and answering before the signal; a tpm2-abrmd that never started "stops" too
was="$([ -e "/proc/$apid" ] && [[ "$(t tpm2_getrandom -T "$(tc a)" --hex 8 2>&1)" =~ ^[0-9a-f]{16}$ ]] && echo yes || echo no)"
kill -TERM "$apid" 2>/dev/null
for _ in $(seq 1 50); do [ -e "/proc/$apid" ] || break; sleep 0.2; done
ok "$([ "$was" = yes ] && [ ! -e "/proc/$apid" ] && echo 0 || echo 1)" "tpm2-abrmd, running and answering, stops on SIGTERM" \
   "running and answering before: $was; pid $apid $([ -e "/proc/$apid" ] && echo "still there after 10 s" || echo gone)"

echo "### a private bus per node (the fixture's design: the other nodes' buses hidden as their sockets are)"
# Each node: its own dbus-daemon, a system-style bus listening under the node's directory, and its tpm2-abrmd on it under
# the DEFAULT name. Clients reach it by DBUS_SYSTEM_BUS_ADDRESS (GDBus honours it for bus_type=system), so every node's
# tcti is the same "tabrmd:bus_type=system", and InaccessiblePaths= on the node's directory hides its bus with its socket.
# Each negative check counts only beside its positive control: the same unit, the same route, nothing hidden, reaches it.
# Every call below is bounded and each step leaves a breadcrumb: its first run hung here, silently, for 18 minutes
step(){ echo "    $(date -u +%H:%M:%S) $*"; }
sysstate="$(timeout 10 systemctl is-system-running 2>&1)"
if ! command -v systemd-run >/dev/null || ! [[ "$sysstate" =~ ^(running|degraded)$ ]]; then
  if [ "${REGALIA_ABRMD_PROBE_CONTAINER:-}" = 1 ]; then
    echo "  SKIP no systemd here (a container): the private-bus checks run on the runner only"; private=skipped
  else
    ok 1 "systemd runs here, for the private-bus checks' units" "$sysstate"; private=no
  fi
else
  private=run
fi
PRIV=com.intel.tss2.Tabrmd
bus_up(){ # $1 node: its private system-style bus, under its own directory
  mkdir -p "$W/$1/dbus"; chmod 0755 "$W/$1" "$W/$1/dbus"
  cat > "$W/$1/bus.conf" <<EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:path=$W/$1/dbus/system_bus_socket</listen>
  <auth>EXTERNAL</auth>
  <!-- the stock system bus's default policy (dbus's system.conf), plus tpm2-abrmd's name: a type=system bus with no
       receive rules denies receives, the bus's own replies included ("Rejected receive message, 0 matched rules"), and
       then every client hangs on its first call (#605, run 40449316347) -->
  <policy context="default">
    <allow user="*"/>
    <deny own="*"/>
    <deny send_type="method_call"/>
    <allow send_type="signal"/>
    <allow send_requested_reply="true" send_type="method_return"/>
    <allow send_requested_reply="true" send_type="error"/>
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus"/>
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus.Introspectable"/>
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus.Properties"/>
    <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus.Peer"/>
    <allow send_destination="$PRIV"/>
  </policy>
  <policy user="tss"><allow own="$PRIV"/></policy>
</busconfig>
EOF
  step "$1: its dbus-daemon"
  # in the foreground, backgrounded: with --fork it closes its stderr, and its refusals are the evidence wanted here
  dbus-daemon --config-file="$W/$1/bus.conf" --nofork --nopidfile --print-pid > "$W/$1.bus.pid" 2> "$W/$1.bus.log" &
  for _ in $(seq 1 25); do [ -S "$W/$1/dbus/system_bus_socket" ] && chmod 0666 "$W/$1/dbus/system_bus_socket" && return 0; sleep 0.2; done
  return 1
}
priv_abrmd_up(){ # $1 node: its tpm2-abrmd on its own bus, under the default name
  step "$1: its tpm2-abrmd on its bus"
  local a="unix:path=$W/$1/dbus/system_bus_socket"
  runuser -u tss -- env DBUS_SYSTEM_BUS_ADDRESS="$a" G_MESSAGES_DEBUG=all \
    tpm2-abrmd --tcti="swtpm:path=$W/$1/tpm.sock" > "$W/$1.abrmd.log" 2>&1 &
  echo $! > "$W/$1.abrmd.pid"
  for _ in $(seq 1 10); do
    DBUS_SYSTEM_BUS_ADDRESS="$a" timeout 3 tpm2_getrandom -T tabrmd:bus_type=system --hex 8 >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  # NOT up: what a stall leaves, in full, into the log (the runner keeps nothing else)
  step "$1: NOT up; the evidence"
  echo "    --- names on $1's bus:"; timeout 5 busctl --address="$a" list --no-pager 2>&1 | head -20 | sed 's/^/    /'
  echo "    --- one client attempt, GLib debug on:"
  DBUS_SYSTEM_BUS_ADDRESS="$a" G_MESSAGES_DEBUG=all timeout 5 tpm2_getrandom -T tabrmd:bus_type=system --hex 8 2>&1 | tail -15 | sed 's/^/    /'
  echo "    --- its tpm2-abrmd (pid $(cat "$W/$1.abrmd.pid"), $([ -e "/proc/$(cat "$W/$1.abrmd.pid")" ] && echo alive || echo gone)):"
  tail -25 "$W/$1.abrmd.log" | sed 's/^/    /'
  echo "    --- its dbus-daemon:"; tail -15 "$W/$1.bus.log" | sed 's/^/    /'
  echo "    --- the processes:"; ps -eo pid,user,stat,args | grep -E 'dbus-daemon|tpm2-abrmd|swtpm' | grep -v grep | sed 's/^/    /'
  return 1
}
unit(){ # a transient unit, as the fixture's are, running tpm2_getrandom over tabrmd:bus_type=system with properties "$@"
  # tpm2_getrandom itself, not the probe's `t` (a shell function: systemd-run runs executables); bounded by the timeout
  timeout 30 systemd-run --quiet --wait --pipe --collect "$@" tpm2_getrandom -T tabrmd:bus_type=system --hex 8 2>&1
}
hexok(){ [[ "$1" =~ ^[0-9a-f]{16}$ ]]; }
if [ "$private" = run ]; then
  pu=0; for n in p q; do swtpm_up "$n" && bus_up "$n" && priv_abrmd_up "$n" || { pu=1; echo "    $n: $(tail -3 "$W/$n.bus.log" "$W/$n.abrmd.log" 2>/dev/null | tr '\n' ' ')"; }; done
  addr(){ echo "DBUS_SYSTEM_BUS_ADDRESS=unix:path=$W/$1/dbus/system_bus_socket"; }
  step "a unit on p's bus"
  pp="$(unit -p "Environment=$(addr p)")"
  timeout 5 tpm2_pcrextend -T "swtpm:path=$W/q/tpm.sock" "16:sha256=$(printf '%064d' 2)" >/dev/null 2>&1   # q's own mark, raw, before
  step "PCR 16 through each bus"
  p16="$(env "$(addr p)" timeout 5 tpm2_pcrread -T tabrmd:bus_type=system sha256:16 2>/dev/null | sed -n 's/.*16 *: *0x\([0-9A-Fa-f]*\).*/\1/p')"
  q16="$(env "$(addr q)" timeout 5 tpm2_pcrread -T tabrmd:bus_type=system sha256:16 2>/dev/null | sed -n 's/.*16 *: *0x\([0-9A-Fa-f]*\).*/\1/p')"
  ok "$([ "$pu" = 0 ] && hexok "$pp" && [ -n "$p16" ] && [ -n "$q16" ] && [ "$p16" != "$q16" ] && echo 0 || echo 1)" \
     "a unit reaches its node's tpm2-abrmd over that node's private bus, and each bus reaches its own TPM (PCR 16: p ${p16:0:12}…, q ${q16:0:12}…)" \
     "up $pu, unit: $(echo "$pp" | tr '\n' ' ' | cut -c1-200), p16=$p16 q16=$q16"
  # THE ONE THAT COUNTS (TEAMLEAD-grafana): a unit given q's bus address but with q's directory hidden, as the fixture hides
  # the other nodes' directories, does not reach q. Beside its control: the same unit, nothing hidden, does
  step "q's bus: control, then hidden"
  qc="$(unit -p "Environment=$(addr q)")"
  qh="$(unit -p "Environment=$(addr q)" -p "InaccessiblePaths=$W/q")"
  ok "$(hexok "$qc" && ! hexok "$qh" && echo 0 || echo 1)" \
     "node q's bus, its directory hidden: refused ($(echo "$qh" | tr '\n' ' ' | cut -c1-120)); control, nothing hidden: reached" \
     "control: $(echo "$qc" | tr '\n' ' ' | cut -c1-150) | hidden: $(echo "$qh" | tr '\n' ' ' | cut -c1-150)"
  # NO FALLBACK: a unit whose address is missing must not land on the runner's real system bus. A DECOY there under the
  # default name makes it falsifiable: the control, the real bus visible, reaches the decoy; hidden, it fails closed
  swtpm_up d
  runuser -u tss -- tpm2-abrmd --tcti="swtpm:path=$W/d/tpm.sock" > "$W/d.abrmd.log" 2>&1 &
  echo $! > "$W/d.abrmd.pid"
  step "the decoy on the real system bus"
  for _ in $(seq 1 50); do timeout 5 tpm2_getrandom -T tabrmd:bus_type=system --hex 8 >/dev/null 2>&1 && break; sleep 0.2; done
  step "no address: control, then the real bus hidden"
  dc="$(unit -p "UnsetEnvironment=DBUS_SYSTEM_BUS_ADDRESS")"
  dh="$(unit -p "UnsetEnvironment=DBUS_SYSTEM_BUS_ADDRESS" -p "InaccessiblePaths=/run/dbus")"
  ok "$(hexok "$dc" && ! hexok "$dh" && echo 0 || echo 1)" \
     "no address and the real system bus hidden: fails closed ($(echo "$dh" | tr '\n' ' ' | cut -c1-120)); control, the real bus visible: the decoy answered" \
     "control: $(echo "$dc" | tr '\n' ' ' | cut -c1-150) | hidden: $(echo "$dh" | tr '\n' ' ' | cut -c1-150) | decoy: $(tail -2 "$W/d.abrmd.log" | tr '\n' ' ')"
  # NOT ON THE SHARED BUS (TEAMLEAD-grafana): the nodes' tpm2-abrmd own nothing on the runner's real system bus, so a unit
  # that reaches that bus still cannot reach a node's TPM through it. Its control: the decoy's own name IS there, owned
  step "who owns what on the real system bus"
  owners="$(timeout 10 busctl --system list --no-pager 2>&1)"
  dpid="$(cat "$W/d.abrmd.pid")"; ppid_="$(cat "$W/p.abrmd.pid" 2>/dev/null)"; qpid="$(cat "$W/q.abrmd.pid" 2>/dev/null)"
  # the abrmd pids are runuser's: the daemon is its child (runuser -u tss forks it), so match the children too
  kids(){ [ -n "$1" ] && { echo "$1"; pgrep -P "$1"; }; }
  decoy_owns="$(for k in $(kids "$dpid"); do echo "$owners" | awk -v k="$k" '$1 ~ /^com\.intel\.tss2\.Tabrmd/ && $2 == k'; done)"
  node_owns="$(for k in $(kids "$ppid_") $(kids "$qpid"); do echo "$owners" | awk -v k="$k" '$2 == k'; done)"
  ok "$([ -n "$decoy_owns" ] && [ -z "$node_owns" ] && [ -n "$ppid_" ] && [ -n "$qpid" ] && echo 0 || echo 1)" \
     "on the real system bus the nodes' tpm2-abrmd own nothing; control: the decoy owns $(echo "$decoy_owns" | awk '{print $1}' | head -1)" \
     "decoy owns: [$decoy_owns] | p/q own: [$node_owns] | p pid $ppid_, q pid $qpid | $(echo "$owners" | grep -i tabrmd | head -5 | tr '\n' ' ')"
  kill -TERM "$dpid" 2>/dev/null
fi

echo "RESULT private_bus=$private socket_ok=$(wc -l < "$W/sock.ok" | tr -d ' ') socket_exhausted=$sock_mem abrmd_ok=${rm_ok:-?} abrmd_exhausted=${rm_mem:-?} socket_timeouts=${sock_to:-?} abrmd_timeouts=${rm_to:-?} of=$((CLIENTS * ROUNDS)) abrmd_survives_swtpm_restart=$survived abrmd_alive_after=$alive raw_beside_abrmd=${shared:-?} runner=$(. /etc/os-release; echo "$VERSION_ID")"
echo "abrmd-probe: $pass passed, $fail failed"
[ "$fail" = 0 ]
