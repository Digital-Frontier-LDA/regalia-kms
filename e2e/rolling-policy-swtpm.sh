#!/usr/bin/env bash
# rolling-policy-swtpm.sh — a kernel update rolled through three nodes on three software TPMs (swtpm).
# regalia-kms#75 (Phase 15). No hardware, no root; it runs in CI.
#
#   e2e/rolling-policy-swtpm.sh
#
# Each TPM is a node that boots an image (PCR 7 and PCR 11 extended at each restart) and a peer that
# judges the other two: its own membership store anchored in its TPM's NV counter, its own heartbeat
# counter, its own attestation verifier, and leases signed by its TPM. PCR 11 moves with the boot as it
# does on a UKI host: the image, then "enter-initrd" (the node asks for its disk), then "leave-initrd",
# "sysinit", "ready" (the node asks for leases). One image, two PCR 11 values.
#
#   15.1  CURRENT: every node is enrolled with both peers and unlocked on image-1; a node that boots
#         image-2 before the root approved it is refused, and comes back on image-1
#         a node still in its initrd is refused a lease; a booted node is refused a disk key (#156)
#   15.3  the root approves CURRENT and NEXT in one manifest (the document it commits to lists both)
#   15.4  one node at a time, in order: asked at the same moment, only a may reboot; b and c wait
#   15.5  a, on image-2, is unlocked by its peers and vouches for them while they are still on image-1
#   15.6  b goes when it has itself seen a back on NEXT and both peers vouch; a new image that fails
#         falls back to CURRENT and is still unlocked; then c
#   15.7  CURRENT is retired only once every node was seen on NEXT by a peer
#   15.8  the old image, booted again, is refused by both peers: no unlock, no lease; the older document
#         is refused under the newer manifest; a peer whose disk is restored to the manifest that still
#         approved the old image refuses to load it (the TPM high-water)
#
# This is tests/test_baremetal_rollout.py's OnSwtpm class, run where the TPM tools must be present: a
# skip here is a failure. The rules that need no TPM run with the Python guards.
#
# NOT HERE: real UKIs (the PCR 11 values here are extended by hand, in the order systemd uses; that a
# real image measures what its build record predicts is #57), systemd-boot's boot counting and automatic fallback, the reboot
# itself, a TPM firmware update, and the local seal (e2e/pcr-signed-policy-swtpm.sh shows that the PIN
# sealed once opens on both images, and that the TPM alone never retires one).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
for t in swtpm tpm2_createek tpm2_createak tpm2_makecredential tpm2_quote tpm2_nvdefine tpm2_readclock tpm2_pcrextend openssl python3; do
  command -v "$t" >/dev/null || { echo "rolling-policy-swtpm: $t is required (swtpm, tpm2-tools, openssl, python3)"; exit 2; }
done
out="$(REGALIA_EXPECT_SWTPM=1 python3 -Es -m unittest -v tests.test_baremetal_rollout.OnSwtpm 2>&1)"; rc=$?
printf '%s\n' "$out"
[ "$rc" = 0 ] || { echo "rolling-policy-swtpm: FAILED"; exit 1; }
grep -q '^Ran 1 test' <<< "$out" && ! grep -qi 'skipped' <<< "$out" || { echo "rolling-policy-swtpm: the TPM test did not run"; exit 1; }
echo "rolling-policy-swtpm: 1 passed, 0 failed"
