#!/usr/bin/env bash
# convergence-swtpm.sh — deploy/baremetal/convergence.py on two software TPMs (swtpm): peers b and c,
# each with its epoch anchor and its heartbeat counter in real TPM NV counters. regalia-kms#69
# (Phase 9, PoC 9.4). No hardware, no root; it runs in CI.
#
#   e2e/convergence-swtpm.sh
#
#   1  node a is revoked as stolen in two revocation-signed manifests; b takes them and the heartbeat as
#      one bundle and refuses a at once
#   2  c is partitioned: it still helps a for the life left in its heartbeat, and cannot take the new
#      heartbeat without the manifests
#   3  c reconnects: one exchange with b brings both epochs through the chain, c's own TPM counter moves
#      to epoch 3, and c refuses a at once
#   4  c's disk is put back to before the revocation: its TPM refuses it; it recovers by fetching the chain
#
# This is the test of tests/test_baremetal_convergence.py's OnSwtpm class, run where the TPM tools must be
# present: a skip here is a failure. The decisions that need no TPM run with the Python guards.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
for t in swtpm tpm2_nvdefine tpm2_nvincrement tpm2_readclock python3; do
  command -v "$t" >/dev/null || { echo "convergence-swtpm: $t is required (swtpm, tpm2-tools, python3)"; exit 2; }
done
out="$(REGALIA_EXPECT_SWTPM=1 python3 -BEs -m unittest -v tests.test_baremetal_convergence.OnSwtpm 2>&1)"; rc=$?
printf '%s\n' "$out"
[ "$rc" = 0 ] || { echo "convergence-swtpm: FAILED"; exit 1; }
grep -q '^Ran 1 test' <<< "$out" && ! grep -qi 'skipped' <<< "$out" || { echo "convergence-swtpm: the TPM test did not run"; exit 1; }
echo "convergence-swtpm: 1 passed, 0 failed"
