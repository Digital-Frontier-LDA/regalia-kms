#!/usr/bin/env bash
# peer-unlock-swtpm.sh — a KMS host's disk opens with its TPM and one peer, never the TPM alone
# (regalia-kms#67, Phase 7; closes the software half of #135). Three software TPMs (target a, peers b and
# c), systemd-creds, and a REAL dm-crypt volume on a loop device; root; it runs in CI.
#
#   sudo e2e/peer-unlock-swtpm.sh
#
#   1  enrolment: the local half sealed to a's TPM by systemd-creds (PCRs 7 and 11 of the approved image),
#      one contribution minted by each peer and carried under a one-time key, one LUKS2 keyslot and one
#      token per peer; the header is judged as host_probe will judge it
#   2  PoC 7.1: a reboots on the approved image; b verifies its fresh quote and gives its contribution,
#      signed by b's TPM; the volume is mapped by dm-crypt, its filesystem mounts and the marker reads back
#   3  PoC 7.2-7.4: with b down, c restores a through its own keyslot; with no peer the disk stays locked
#   4  #135: a boots a retired image. Its TPM refuses the local half; and with that half in hand (what a
#      signed PCR policy would release for every image ever signed), both peers refuse the quote
#   5  PoC 7.8, 7.9: the disk behind another TPM that claims to be a: no local half, and no contribution
#   6  a is reported stolen (the revocation key alone): both peers refuse and drop their halves; the
#      recovery key still opens the volume
#
# This is tests/test_baremetal_unlock.py's OnSwtpm class, run where everything it needs must be present:
# a skip here is a failure. The decisions that need no TPM and no root (every binding of the exchange,
# the store, enrolment, rotation, the header's judgement) run with the Python guards and are run here too.
#
# NOT covered: the transport (WG-BOOT, #66), the initramfs, a real boot, and any physical TPM or DL360.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
export LC_ALL=C PATH="$PATH:/usr/sbin:/sbin"
[ "$(id -u)" = 0 ] || { echo "peer-unlock-swtpm: run as root (systemd-creds seals to a TPM only as root; it makes a loop device and a dm-crypt mapping)"; exit 2; }
for t in swtpm tpm2_createek tpm2_createak tpm2_makecredential tpm2_quote tpm2_nvdefine tpm2_pcrextend tpm2_readclock openssl systemd-creds \
         cryptsetup losetup mkfs.ext4 mount umount python3; do
  command -v "$t" >/dev/null || { echo "peer-unlock-swtpm: $t is required (swtpm, tpm2-tools, openssl, systemd, cryptsetup-bin, util-linux, e2fsprogs, python3)"; exit 2; }
done
echo "peer-unlock-swtpm: $(systemd-creds --version | head -1), $(cryptsetup --version), swtpm $(swtpm --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"

W="$(mktemp -d)"; LOOP=""
cleanup(){ [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null; rm -rf -- "$W"; }
trap cleanup EXIT
truncate -s 64M "$W/disk.img"
LOOP="$(losetup --find --show "$W/disk.img")" || { echo "peer-unlock-swtpm: no loop device"; exit 2; }

out="$(REGALIA_EXPECT_SWTPM=1 REGALIA_EXPECT_CRYPTSETUP=1 REGALIA_UNLOCK_DEVICE="$LOOP" python3 -m unittest -v tests.test_baremetal_unlock </dev/null 2>&1)"; rc=$?
printf '%s\n' "$out"
[ "$rc" = 0 ] || { echo "peer-unlock-swtpm: FAILED"; exit 1; }
ran="$(grep -oE '^Ran [0-9]+ tests?' <<< "$out" | grep -oE '[0-9]+')"
if ! grep -q '^test_tpm_plus_one_peer_opens_the_disk.*ok$' <<< "$out" || grep -qi 'skipped' <<< "$out"; then
  echo "peer-unlock-swtpm: the TPM test did not run, or a test was skipped"; exit 1
fi
echo "peer-unlock-swtpm: $ran passed, 0 failed"
