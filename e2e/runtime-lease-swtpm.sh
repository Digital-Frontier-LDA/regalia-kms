#!/usr/bin/env bash
# runtime-lease-swtpm.sh — deploy/baremetal/lease.py on two software TPMs (swtpm): node a and peer b.
# regalia-kms#74 (Phase 14). No hardware, no root, private unix sockets; it runs in CI.
#
#   e2e/runtime-lease-swtpm.sh
#
#   1  PoC 14.1: a re-attests to b (attest.py: EK-bound AK, a quote over its boot session); b, holding
#      a live heartbeat, signs a 5-minute lease with a TPM2_Quote by its own AK; a installs it. A
#      replayed lease, an altered one, and one a signed for itself are refused. a renews.
#   2  PoC 14.3: a is revoked. b, with the new manifest and a heartbeat for it, refuses to renew; the
#      held lease is refused under that manifest at once, and expires under the old one.
#   3  a reboots (its TPM restarts): the old boot session cannot be re-attested, a request from the old
#      boot is refused, and a new attested session gets a new lease.
#   4  D32 (#483): signing and checking leases writes nothing to either TPM's NV (swtpm's tpm2-00.permall
#      is unchanged).
#
# These are the three tests of tests/test_baremetal_lease.py's OnSwtpm class, run where the TPM tools must
# be present: a skip here is a failure. The rules that need no TPM (every binding of the signed lease,
# who may issue, partition, time) are in the same file and run with the Python guards.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
for t in swtpm tpm2_createek tpm2_createak tpm2_quote tpm2_nvdefine tpm2_readclock openssl python3; do
  command -v "$t" >/dev/null || { echo "runtime-lease-swtpm: $t is required (swtpm, tpm2-tools, openssl, python3)"; exit 2; }
done
out="$(REGALIA_EXPECT_SWTPM=1 python3 -BEs -m unittest -v tests.test_baremetal_lease.OnSwtpm 2>&1)"; rc=$?
printf '%s\n' "$out"
[ "$rc" = 0 ] || { echo "runtime-lease-swtpm: FAILED"; exit 1; }
# all three ran, and none was skipped
grep -q '^Ran 3 tests' <<< "$out" && ! grep -qi 'skipped' <<< "$out" || { echo "runtime-lease-swtpm: the three TPM tests did not all run"; exit 1; }
echo "runtime-lease-swtpm: 3 passed, 0 failed"
