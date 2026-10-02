#!/usr/bin/env bash
# node-replacement-swtpm.sh — replacing a node on three software TPMs (swtpm): the old node a, its
# replacement a2, and peer b. regalia-kms#76 (Phase 16). No hardware, no root; it runs in CI.
#
#   e2e/node-replacement-swtpm.sh
#
#   1  before: a is enrolled with b (EK-bound AK), is unlocked, and holds a lease signed by b's TPM
#   2  PoC 16.1-16.4: one root-signed manifest retires a and enrolls a2, a different TPM; b rebuilds its
#      attestation policy from that manifest
#   3  PoC 16.3: a2 enrolls its AK under its EK, is unlocked, and holds a lease
#   4  PoC 16.5: old a, hardware intact: not attested as itself (unknown node) nor as a2 (wrong EK; cannot
#      open a credential for a2's EK; its quote does not verify); not unlocked; no lease issued; the lease
#      it held is refused; a lease its TPM signs, as itself or as b, is refused
#   5  recycling: the retired EK or AK under a new node ID, the tombstone dropped, the node revived: each
#      refused, with the real TPM Names
#
# This is the test of tests/test_baremetal_replacement.py's OnSwtpm class, run where the TPM tools must be
# present: a skip here is a failure. The rules that need no TPM run with the Python guards.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
for t in swtpm tpm2_createek tpm2_createak tpm2_makecredential tpm2_quote tpm2_nvdefine tpm2_readclock openssl python3; do
  command -v "$t" >/dev/null || { echo "node-replacement-swtpm: $t is required (swtpm, tpm2-tools, openssl, python3)"; exit 2; }
done
out="$(REGALIA_EXPECT_SWTPM=1 python3 -m unittest -v tests.test_baremetal_replacement.OnSwtpm 2>&1)"; rc=$?
printf '%s\n' "$out"
[ "$rc" = 0 ] || { echo "node-replacement-swtpm: FAILED"; exit 1; }
grep -q '^Ran 1 test' <<< "$out" && ! grep -qi 'skipped' <<< "$out" || { echo "node-replacement-swtpm: the TPM test did not run"; exit 1; }
echo "node-replacement-swtpm: 1 passed, 0 failed"
