#!/usr/bin/env bash
# tpm-lockout-swtpm.sh — the TPM's dictionary-attack settings and power cuts (#57), against software
# TPMs (swtpm). A "power cut" is the swtpm killed with no TPM2_Shutdown.
#
#   sudo -v && e2e/tpm-lockout-swtpm.sh
#
#   1  deploy/baremetal/tpm-lockout.sh: --status fails on a fresh TPM; --set puts the policy and a
#      lockout authorization; a second --set asks for nothing and changes nothing; a weak
#      authorization is refused before the TPM is touched
#   2  host_probe's tpm_lockout_policy reads the same TPM: true after --set; false, with the reason,
#      on a fresh TPM, when a setting drifts, and when the TPM is in lockout
#   3  drift is repaired by --set with the authorization; a wrong authorization is refused, and then
#      the lockout hierarchy refuses the right one too (its recovery time: ask once, from the escrow)
#   4  the PIN import key that seal-hsm-pin.sh --init-import-key creates is used and the power cut,
#      four times: no try is counted. Control: a key with the template before #57 counts every cut
#   5  what the settings are for: unsealing a PIN credential, then a power cut, counts one try each
#      time; the PIN is still released after four cuts under the policy; --clear forgives them; and they heal
#      on their own (shown with a short healing time, since 600 s is too long for a test)
set -uo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"; LOCKOUT="$HERE/deploy/baremetal/tpm-lockout.sh"; SEAL="$HERE/deploy/seal-hsm-pin.sh"
pass=0; fail=0
P(){ printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
F(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
hdr(){ printf '\n\033[1m### %s\033[0m\n' "$1"; }
for t in swtpm tpm2_getcap tpm2_dictionarylockout tpm2_changeauth tpm2_rsadecrypt openssl systemd-creds python3; do
  command -v "$t" >/dev/null || { echo "tpm-lockout-swtpm: $t is required (swtpm, tpm2-tools, openssl, systemd)"; exit 2; }
done
sudo -n true 2>/dev/null || { echo "tpm-lockout-swtpm: needs sudo"; exit 2; }
echo "tpm-lockout-swtpm: $(systemd-creds --version | head -1), swtpm $(swtpm --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
W="$(mktemp -d)"; cd "$W" || exit 2
stop_all(){ local p; for p in "$W"/*.pid; do [ -f "$p" ] && kill -9 "$(cat "$p")" 2>/dev/null; done; }
trap 'stop_all; sudo rm -rf "$W"' EXIT
D=""; cur=""
# up <name>: start (or restart) that TPM; PCR 7 extended as a boot would. A unix socket in this run's own directory.
up(){ cur="$1"; mkdir -p "$W/$1"
  swtpm socket --tpm2 --tpmstate "dir=$W/$1" --server "type=unixio,path=$W/$1.sock" --ctrl "type=unixio,path=$W/$1.sock.ctrl" \
    --flags not-need-init,startup-clear --daemon --pid "file=$W/$1.pid"
  D="swtpm:path=$W/$1.sock"; export TPM2TOOLS_TCTI="$D"
  for _ in 1 2 3 4 5 6 7 8 9 10; do tpm2_pcrread sha256:7 >/dev/null 2>&1 && break; sleep 0.3; done
  tpm2_pcrextend "7:sha256=$(printf secure-boot | sha256sum | cut -d' ' -f1)" >/dev/null; }
cut_power(){ kill -9 "$(cat "$W/$cur.pid")" 2>/dev/null; sleep 0.3; rm -f "$W/$cur.pid"; up "$cur"; }
down(){ tpm2_shutdown -c >/dev/null 2>&1; kill "$(cat "$W/$cur.pid")" 2>/dev/null; sleep 0.3; rm -f "$W/$cur.pid"; }
# get <property>: in decimal (tpm2_getcap prints hexadecimal, which awk's %d reads as 0).
get(){ local v; v="$(tpm2_getcap properties-variable 2>/dev/null | awk -v n="$1:" '$1==n{print $2; exit}')"; [ -n "$v" ] && printf '%d' "$v"; }
lockout(){ sudo env TPM2TOOLS_TCTI="$D" "$LOCKOUT" "$@" 2>&1; }
probe(){ PYTHONPATH="$HERE" python3 -c 'from deploy.baremetal import host_probe
ok, why = host_probe.lockout_policy(host_probe.Host())
print(("true" if ok else "false") + "\t" + why)'; }
AUTH="lockout-auth-for-this-test-0001"

hdr "1  tpm-lockout.sh sets the policy and a lockout authorization"
up a
out="$(lockout --status)"; rc=$?
[ "$rc" = 1 ] && grep -q 'lockout authorization set   : NO' <<< "$out" && P "--status on a fresh TPM: exit 1, no authorization, swtpm's defaults ($(get TPM2_PT_MAX_AUTH_FAIL) tries, $(get TPM2_PT_LOCKOUT_INTERVAL) s)" || F "--status on a fresh TPM (exit $rc): $out"
out="$(printf 'short\n' | lockout --set)"; rc=$?
[ "$rc" != 0 ] && grep -q '16-32 printable characters' <<< "$out" && [ "$(get lockoutAuthSet)" = 0 ] && [ "$(get TPM2_PT_MAX_AUTH_FAIL)" != 32 ] \
  && P "a 5-character authorization is refused, and the TPM is untouched (exit $rc)" || F "weak authorization: $out"
out="$(printf '%s\n' "$AUTH" | lockout --set)"; rc=$?
[ "$rc" = 0 ] && [ "$(get TPM2_PT_MAX_AUTH_FAIL)" = 32 ] && [ "$(get TPM2_PT_LOCKOUT_INTERVAL)" = 600 ] && [ "$(get TPM2_PT_LOCKOUT_RECOVERY)" = 86400 ] \
  && [ "$(get lockoutAuthSet)" = 1 ] && P "--set: 32 tries, 600 s to heal, 86400 s lockout recovery, authorization set" || F "--set (exit $rc): $out"
grep -qF "$AUTH" <<< "$out" && F "the authorization appeared in the output" || P "the authorization never appears in the output"
out="$(lockout --status)"; rc=$?
[ "$rc" = 0 ] && P "--status now exits 0" || F "--status after --set (exit $rc): $out"
out="$(lockout --set < /dev/null)"; rc=$?
[ "$rc" = 0 ] && grep -q 'nothing to do' <<< "$out" && P "a second --set asks for nothing and changes nothing" || F "second --set (exit $rc): $out"

hdr "2  host_probe measures the same TPM"
IFS=$'\t' read -r value why < <(probe)
[ "$value" = true ] && P "tpm_lockout_policy: $why" || F "tpm_lockout_policy is $value: $why"
down; up fresh
IFS=$'\t' read -r value why < <(probe)
[ "$value" = false ] && grep -q 'TPM2_PT_MAX_AUTH_FAIL is 3, not 32' <<< "$why" && P "a TPM nobody commissioned: false ($why)" || F "fresh TPM: $value: $why"
tpm2_dictionarylockout -Q -s -n 32 -t 600 -l 86400 >/dev/null 2>&1
IFS=$'\t' read -r value why < <(probe)
[ "$value" = false ] && grep -q 'no authorization value' <<< "$why" && P "the settings right but no lockout authorization: false" || F "no authorization: $value: $why"
down; up a

hdr "3  drift, and the authorization"
printf '%s' "$AUTH" | tpm2_dictionarylockout -Q -s -n 5 -t 600 -l 86400 -p file:- >/dev/null 2>&1 || F "could not make the settings drift"
IFS=$'\t' read -r value why < <(probe)
[ "$value" = false ] && grep -q 'TPM2_PT_MAX_AUTH_FAIL is 5, not 32' <<< "$why" && P "one drifted setting: false ($why)" || F "drift: $value: $why"
# The right value copied in groups, as one does from paper: a different value to the TPM, and there a
# wrong attempt. The script refuses it itself; that it spent no attempt is shown by the next step,
# where the right value is accepted at once.
out="$(printf '%s\n' "${AUTH:0:8} ${AUTH:8:8} ${AUTH:16}" | lockout --set)"; rc=$?
[ "$rc" != 0 ] && grep -q 'Nothing was tried on the TPM' <<< "$out" && [ "$(get TPM2_PT_MAX_AUTH_FAIL)" = 5 ] \
  && P "the authorization typed in groups (with spaces) is refused by the script, before the TPM hears it (exit $rc)" || F "spaced authorization (exit $rc): $out"
out="$(printf '%s\n' "$AUTH" | lockout --set)"; rc=$?
[ "$rc" = 0 ] && [ "$(get TPM2_PT_MAX_AUTH_FAIL)" = 32 ] && P "--set with the authorization repairs it (so the refusal above cost no attempt)" || F "repair (exit $rc): $out"
# At a TERMINAL the value is typed twice and compared before the TPM hears anything.
# tty_set <first entry> <second entry>: tpm-lockout.sh --set on a pseudo-terminal, each hidden prompt answered in turn.
tty_set(){ python3 - "$D" "$LOCKOUT" "$1" "$2" <<'PY'
import os, pty, select, sys, time
tcti, script, first, second = sys.argv[1:5]
pid, fd = pty.fork()
if pid == 0:
    os.execvp("sudo", ["sudo", "env", "TPM2TOOLS_TCTI=" + tcti, script, "--set"])
out, pending, answers, deadline = "", "", [first, second], time.time() + 60
while time.time() < deadline:
    ready, _, _ = select.select([fd], [], [], 1)
    if not ready:
        continue
    try:
        chunk = os.read(fd, 4096).decode(errors="replace")
    except OSError:
        break
    if not chunk:
        break
    out += chunk
    pending += chunk
    # Answer only a prompt that has just been printed: typed between two prompts, before the next
    # read has switched echo off, a value would be echoed by the terminal itself.
    if pending.rstrip(" ").endswith("(hidden):") and answers:
        os.write(fd, (answers.pop(0) + "\n").encode())
        pending = ""
_, status = os.waitpid(pid, 0)
print(out.replace("\r", ""))
print("RC=%d" % os.waitstatus_to_exitcode(status))
PY
}
printf '%s' "$AUTH" | tpm2_dictionarylockout -Q -s -n 5 -t 600 -l 86400 -p file:- >/dev/null 2>&1 || F "could not make the settings drift again"
out="$(tty_set "$AUTH" "${AUTH%?}X")"
grep -q 'RC=1' <<< "$out" && grep -q 'the two entries differ; nothing was tried on the TPM' <<< "$out" && [ "$(get TPM2_PT_MAX_AUTH_FAIL)" = 5 ] \
  && P "at a terminal: two entries that differ are refused before the TPM hears anything" || F "terminal, differing entries: $out"
grep -q 'the TPM gets ONE attempt' <<< "$out" && grep -q 'type it twice here' <<< "$out" && P "the prompt says the TPM gets one attempt and that the value is typed twice here" || F "terminal prompt: $out"
out="$(tty_set "$AUTH" "$AUTH")"
grep -q 'RC=0' <<< "$out" && [ "$(get TPM2_PT_MAX_AUTH_FAIL)" = 32 ] && P "at a terminal: the same value twice repairs the settings (so the refusal above cost no attempt)" || F "terminal, matching entries: $out"
grep -qF "$AUTH" <<< "$out" && F "the authorization was echoed on the terminal" || P "the authorization is never echoed on the terminal"
printf '%s' "$AUTH" | tpm2_dictionarylockout -Q -s -n 5 -t 600 -l 86400 -p file:- >/dev/null 2>&1
out="$(printf 'not-the-authorization-0000\n' | lockout --set)"; rc=$?
[ "$rc" != 0 ] && grep -q 'the TPM refused' <<< "$out" && [ "$(get TPM2_PT_MAX_AUTH_FAIL)" = 5 ] && P "a wrong authorization changes nothing (exit $rc)" || F "wrong authorization (exit $rc): $out"
out="$(printf '%s\n' "$AUTH" | lockout --set)"; rc=$?
[ "$rc" != 0 ] && [ "$(get TPM2_PT_MAX_AUTH_FAIL)" = 5 ] && P "and after it the RIGHT one is refused too: the lockout hierarchy is blocked for its recovery time" \
  || F "the right authorization straight after a wrong one was accepted (exit $rc): the hierarchy does not protect itself"
down

hdr "4  the PIN import key is not subject to the counter"
up b
out="$(sudo env TPM2TOOLS_TCTI="$D" "$SEAL" --init-import-key --import-pub "$W/import.pem" 2>&1)" && grep -q 'IMPORT KEY CREATED' <<< "$out" || F "--init-import-key failed: $out"
attrs="$(tpm2_readpublic -c 0x81000101 2>/dev/null | awk '/^attributes:/{getline; print $2}')"
grep -q noda <<< "$attrs" && P "the key seal-hsm-pin.sh creates carries noda ($attrs)" || F "import key attributes: $attrs"
printf 7310048261 | openssl pkeyutl -encrypt -pubin -inkey "$W/import.pem" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -out "$W/pin.blob"
cut_power; base="$(get TPM2_PT_LOCKOUT_COUNTER)"
[ "$base" = 0 ] && P "creating it, then a power cut: 0 tries counted" || F "creating the key and cutting the power counted $base"
ok=1; for _ in 1 2 3 4; do
  [ "$(tpm2_rsadecrypt -c 0x81000101 -s oaep -o /dev/stdout "$W/pin.blob" 2>/dev/null | tr -d '\0')" = 7310048261 ] || ok=0; cut_power; done
[ "$ok" = 1 ] && [ "$(get TPM2_PT_LOCKOUT_COUNTER)" = 0 ] && P "used, then the power cut, four times: it still decrypts and 0 tries are counted" \
  || F "import key after 4 cuts: decrypts=$ok, counter $(get TPM2_PT_LOCKOUT_COUNTER)"
down; up c
tpm2_createprimary -Q -C o -g sha256 -G ecc256:aes128cfb -c "$W/p.ctx"
tpm2_create -Q -C "$W/p.ctx" -G rsa3072 -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt' -u "$W/k.pub" -r "$W/k.priv"; tpm2_flushcontext -t
tpm2_load -Q -C "$W/p.ctx" -u "$W/k.pub" -r "$W/k.priv" -c "$W/k.ctx"; tpm2_evictcontrol -Q -C o -c "$W/k.ctx" 0x81000101 >/dev/null; tpm2_flushcontext -t
tpm2_readpublic -Q -c 0x81000101 -f pem -o "$W/old.pem"
printf 7310048261 | openssl pkeyutl -encrypt -pubin -inkey "$W/old.pem" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -out "$W/old.blob"
down; up c
tpm2_rsadecrypt -c 0x81000101 -s oaep -o /dev/null "$W/old.blob" 2>/dev/null; cut_power
tpm2_rsadecrypt -c 0x81000101 -s oaep -o /dev/null "$W/old.blob" 2>/dev/null; cut_power
[ "$(get TPM2_PT_LOCKOUT_COUNTER)" = 2 ] && P "control: the template before #57 (no noda), used and cut twice: 2 tries counted" \
  || F "control: the old template counted $(get TPM2_PT_LOCKOUT_COUNTER) after 2 cuts, so the check above proves nothing"
down

hdr "5  a PIN credential, power cuts, and healing"
up d
printf '%s\n' "$AUTH" | lockout --set >/dev/null || F "--set on TPM d failed"
printf 7310048261 | sudo systemd-creds encrypt --with-key=tpm2 --tpm2-device="$D" --tpm2-pcrs=7 --name=t.pin - "$W/pin.cred" 2>/dev/null || F "cannot seal the credential"
down; up d
open(){ sudo systemd-creds decrypt --tpm2-device="$D" --name=t.pin "$W/pin.cred" - 2>/dev/null; }
ok=1; for _ in 1 2 3 4; do [ "$(open)" = 7310048261 ] || ok=0; cut_power; done
counted="$(get TPM2_PT_LOCKOUT_COUNTER)"
[ "$ok" = 1 ] && [ "$counted" = 4 ] && P "unsealed, then the power cut, four times: 4 tries counted (one per cut)" || F "after 4 cuts: unsealed=$ok, counter $counted"
[ "$(open)" = 7310048261 ] && [ "$(get inLockout)" = 0 ] && P "under the policy (32 tries) the PIN is still released" || F "the PIN is not released after 4 cuts under the policy"
# The manual way back, for an operator who cannot wait for the tries to heal.
out="$(printf '%s\n' "$AUTH" | lockout --clear)"; rc=$?
[ "$rc" = 0 ] && [ "$(get TPM2_PT_LOCKOUT_COUNTER)" = 0 ] && P "--clear with the authorization forgives the counted tries (4 -> 0)" || F "--clear (exit $rc, counter $(get TPM2_PT_LOCKOUT_COUNTER)): $out"
out="$(lockout --clear < /dev/null)"; rc=$?
[ "$rc" = 0 ] && grep -q 'nothing to clear' <<< "$out" && P "--clear with nothing counted asks for nothing" || F "--clear with nothing counted (exit $rc): $out"
down; up e
tpm2_dictionarylockout -Q -s -n 32 -t 2 -l 86400 >/dev/null 2>&1      # a 2 s healing time, to watch it happen
printf 7310048261 | sudo systemd-creds encrypt --with-key=tpm2 --tpm2-device="$D" --tpm2-pcrs=7 --name=t.pin - "$W/pin.cred" 2>/dev/null
down; up e
for _ in 1 2 3; do open >/dev/null; cut_power; done
before="$(get TPM2_PT_LOCKOUT_COUNTER)"; sleep 9; after="$(get TPM2_PT_LOCKOUT_COUNTER)"
[ "$before" -ge 2 ] && [ "$after" = 0 ] && P "the tries heal on their own: $before counted after 3 cuts, $after after 9 s at 2 s per try" || F "healing: $before before, $after after 9 s"
down; up f
printf 7310048261 | sudo systemd-creds encrypt --with-key=tpm2 --tpm2-device="$D" --tpm2-pcrs=7 --name=t.pin - "$W/pin.cred" 2>/dev/null
down; up f
for _ in 1 2 3; do open >/dev/null; cut_power; done
o="$(open)"
[ -z "$o" ] && [ "$(get inLockout)" = 1 ] && P "control: at swtpm's default limit of 3, three cuts and the PIN is NOT released" || F "control: default limit: opened='$o', inLockout $(get inLockout)"
IFS=$'\t' read -r value why < <(probe)
[ "$value" = false ] && P "and tpm_lockout_policy is false on that TPM ($why)" || F "probe on a locked-out TPM: $value: $why"

echo; echo "tpm-lockout-swtpm: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
