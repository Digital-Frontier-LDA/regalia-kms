#!/usr/bin/env bash
# heartbeat-swtpm.sh — deploy/baremetal/heartbeat.py's TPM half on a software TPM (swtpm): the
# heartbeat sequence in a TPM NV counter of its own, and the TPM clock behind the time floor.
# regalia-kms#69 (Phase 9). No hardware, no root, a private unix socket; it runs in CI.
#
#   e2e/heartbeat-swtpm.sh
#
#   1  the sequence counter is a second NV index, independent of membership's epoch counter; a
#      replayed sequence is refused, and a disk rolled back to an older heartbeat is refused by the
#      counter although that heartbeat is still signed and unexpired
#   2  the counter survives a TPM restart; deleted and re-created, it will not count from below
#   3  the TPM clock runs forward; an authenticated clock that goes backwards, and an unreachable
#      TPM, are refusals
#
# These are the three tests of tests/test_baremetal_heartbeat.py's OnSwtpm class, run where the TPM
# tools must be present: a skip here is a failure. Everything that needs no TPM (expiry, the manifest
# binding, unauthenticated time, the signer) is in the same file and runs with the Python guards.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
for t in swtpm tpm2_nvdefine tpm2_nvincrement tpm2_readclock python3; do
  command -v "$t" >/dev/null || { echo "heartbeat-swtpm: $t is required (swtpm, tpm2-tools, python3)"; exit 2; }
done
out="$(REGALIA_EXPECT_SWTPM=1 python3 -BEs -m unittest -v tests.test_baremetal_heartbeat.OnSwtpm 2>&1)"; rc=$?
printf '%s\n' "$out"
[ "$rc" = 0 ] || { echo "heartbeat-swtpm: FAILED"; exit 1; }
# all three ran, and none was skipped
grep -q '^Ran 3 tests' <<< "$out" && ! grep -qi 'skipped' <<< "$out" || { echo "heartbeat-swtpm: the three TPM tests did not all run"; exit 1; }
echo "heartbeat-swtpm: 3 passed, 0 failed"
