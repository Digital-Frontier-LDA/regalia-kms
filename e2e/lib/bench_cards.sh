# shellcheck shell=bash
# bench_cards.sh — a drill that uses real cards sees only those cards, and presents a PIN only to the
# card it names (regalia-kms#174). Sourced by the e2e drills; it defines functions and sets nothing until
# bench_isolate is called.
#
# WHY. OpenSC enumerates every reader on the bench. That probes the other cards (an SLE-4442 in the
# ACR40U cost ~15 s a call), leaves a YubiKey's PIV applet selected (three PIV PIN tries were spent that
# way elsewhere on 2026-10-02), and numbers slots over all readers: when one reader disappears the
# others are renumbered, and a login "on the same slot" can reach another card (DENK0404380 slid into
# DENK0404144's slot 0x4, measured). So:
#
#   bench_isolate <conf> <module> <serial>…   writes <conf> so that OpenSC shows ONLY the readers of
#                                            these tokens (e2e/lib/opensc_isolate.py), exports
#                                            OPENSC_CONF=<conf>, and checks that exactly these tokens,
#                                            one slot each, are what PKCS#11 now sees
#   bench_slot <serial>                      the slot that holds this serial now (empty if not exactly one)
#   bench_gate <serial> [slot]               0 only if exactly the isolated set of slots is visible, the
#                                            serial is in exactly one of them (and in <slot>, if given):
#                                            call it before EVERY command that presents a PIN
#
# Under sudo the configuration must be carried explicitly (sudo env OPENSC_CONF=…; systemd-run
# --setenv / -E): sudo drops the environment, and an OpenSC with its defaults enumerates every reader.
# A process running as ANOTHER user must be able to read the file: put <conf> in a directory that user
# can enter (the file itself is written 0644). An unreadable configuration is the same as none.
#
# What isolation cannot do: two readers with the same name (two Pico HSMs: "Pol Henarejos Pico Key
# CCID Interface") cannot be told apart by name; opensc_isolate.py refuses, and such a pair cannot be
# isolated from each other.
#
# Readers that are off the bus when bench_isolate runs (a YubiKey replugged later) are not in the
# snapshot; HSM_IGNORE_READERS (comma-separated, default "Yubico") is always ignored as well.
#
# The isolated configuration keeps OpenSC's PKCS#11 slot limits raised (32 virtual slots, 4 per card):
# with the default 16, a fifth reader gets no slot at all (measured 2026-09-24).

BENCH_CARDS=()

bench_slot(){ # <serial>
  timeout 30 pkcs11-tool --module "$BENCH_MODULE" -L 2>/dev/null | python3 -I -c '
import re, sys
serial, slot, hits = sys.argv[1], None, []
for line in sys.stdin:
    m = re.match(r"Slot \d+ \((0x[0-9a-f]+)\)", line)
    if m:
        slot = m.group(1)
    elif "serial num" in line and line.split(":", 1)[1].strip() == serial:
        hits.append(slot)
print(hits[0] if len(hits) == 1 else "")' "$1"; }

bench_gate(){ # <serial> [slot]
  [ "${#BENCH_CARDS[@]}" -gt 0 ] || { echo "bench_gate: bench_isolate was not called: no PIN" >&2; return 97; }
  timeout 30 pkcs11-tool --module "$BENCH_MODULE" -L 2>/dev/null | python3 -I -c '
import re, sys
serial, want_slot, expected = sys.argv[1], sys.argv[2], int(sys.argv[3])
cur, slots, hits = None, 0, []
for line in sys.stdin:
    m = re.match(r"Slot \d+ \((0x[0-9a-f]+)\)", line)
    if m:
        cur = m.group(1); slots += 1
    elif "serial num" in line and line.split(":", 1)[1].strip() == serial:
        hits.append(cur)
# A slot id given in decimal (the ceremony helpers print 0) or in hex (pkcs11-tool -L prints 0x0).
ok = len(hits) == 1 and slots == expected and (not want_slot or int(hits[0], 0) == int(want_slot, 0))
if not ok:
    print("bench_gate: %s is in %s of %d visible slot(s), expected one slot of %d%s: no PIN"
          % (serial, hits or "none", slots, expected, " (slot %s)" % want_slot if want_slot else ""), file=sys.stderr)
sys.exit(0 if ok else 97)' "$1" "${2:-}" "${#BENCH_CARDS[@]}"; }

bench_isolate(){ # <conf> <module> <serial>…
  local conf="$1" module="$2"; shift 2
  local serial slot slots="" here
  BENCH_MODULE="$module"
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # Resolve the slots with OpenSC's slot limits raised and the caller's ignore list (default: every
  # YubiKey) already applied: even this first look must not open a YubiKey.
  local first
  first="$(python3 -I -c 'import sys; print(", ".join("\"%s\"" % n.strip().replace("\"", "") for n in sys.argv[1].split(",") if n.strip()) or "\"__none__\"")' "${HSM_IGNORE_READERS:-Yubico}")"
  printf 'app default {\n  ignored_readers = %s;\n}\napp opensc-pkcs11 {\n\tpkcs11 {\n\t\tmax_virtual_slots = 32;\n\t\tslots_per_card = 4;\n\t}\n}\n' "$first" > "$conf"
  chmod 0644 "$conf"
  export OPENSC_CONF="$conf"
  for serial in "$@"; do
    slot="$(bench_slot "$serial")"
    [ -n "$slot" ] || { echo "bench_isolate: no single PKCS#11 slot holds $serial" >&2; return 1; }
    slots="${slots:+$slots,}$slot"
  done
  HSM_IGNORE_READERS="${HSM_IGNORE_READERS:-Yubico}" python3 -Es "$here/opensc_isolate.py" "$slots" "$conf.ignore" "$module" >/dev/null \
    || { echo "bench_isolate: cannot isolate the readers of $*" >&2; return 1; }
  local ignored; ignored="$(grep -o 'ignored_readers = .*;' "$conf.ignore")"; rm -f "$conf.ignore"
  [ -n "$ignored" ] || { echo "bench_isolate: the isolation wrote no ignored_readers line" >&2; return 1; }
  printf 'app default {\n  %s\n}\napp opensc-pkcs11 {\n\tpkcs11 {\n\t\tmax_virtual_slots = 32;\n\t\tslots_per_card = 4;\n\t}\n}\n' "$ignored" > "$conf"
  chmod 0644 "$conf"
  BENCH_CARDS=("$@")
  for serial in "$@"; do
    bench_gate "$serial" || { echo "bench_isolate: after isolation the visible slots are not exactly $*" >&2; return 1; }
  done; }

