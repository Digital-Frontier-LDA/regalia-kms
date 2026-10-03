#!/usr/bin/env bash
# peer-unlock-swtpm.sh — a KMS host's disk opens with its TPM and one peer, never the TPM alone
# (regalia-kms#67, Phase 7; closes the software half of #135). Three software TPMs (target a, peers b and
# c), systemd-creds, and a REAL dm-crypt volume on a loop device; root; it runs in CI.
#
#   sudo e2e/peer-unlock-swtpm.sh
#
#   1  enrolment: the local half sealed to a's TPM by systemd-creds (PCR 7, which no boot image changes),
#      one contribution minted by each peer and carried under a one-time key, one LUKS2 keyslot and one
#      token per peer; the header is judged as host_probe will judge it
#   2  PoC 7.1: a reboots on the approved image; b verifies its fresh quote and gives its contribution,
#      signed by b's TPM; the volume is mapped by dm-crypt, its filesystem mounts and the marker reads back
#   3  PoC 7.2-7.4: with b down, c restores a through its own keyslot; with no peer the disk stays locked
#   4  #135: a boots a retired image. Its TPM releases the local half all the same; both peers refuse
#      the quote, and the disk stays locked
#   5  PoC 7.8, 7.9: the disk behind another TPM that claims to be a: no local half, and no contribution
#   6  a is reported stolen (the revocation key alone): both peers refuse and drop their halves; the
#      recovery key still opens the volume
#
# Each step is made twice: with cmd/regalia-unlock, the native pre-root client (its TPM2_Quote, its reading
# of the LUKS2 header, the key it gives over the socket systemd-cryptsetup would read), against the peers
# served over TCP; and with the reference client in unlock.py. The test stands in for systemd: it unseals
# the local half as LoadCredentialEncrypted= would, passes the socket, and opens the volume with the key.
#
# This is tests/test_baremetal_unlock.py's OnSwtpm class, run where everything it needs must be present:
# a skip here is a failure. The decisions that need no TPM and no root (every binding of the exchange,
# the store, enrolment, rotation, the header's judgement) run with the Python guards and are run here too.
#
#   7  with a running systemd: the shipped units (deploy/baremetal/initrd/) are installed, the real
#      systemd-cryptsetup is given the socket as its key file, and the volume is mapped; with no peer it
#      gets no key, gives up, and the socket goes on listening; a retired image gets nothing
#
# NOT covered: the units inside an initrd, the TPM unsealing done by systemd itself (it can use only the
# machine's own TPM: the test unseals and passes the credential plain), the prompt for the recovery key
# at a console, WG-BOOT under the TCP transport (e2e/wg-boot-netns.sh has the network), a real boot, and
# any physical TPM or DL360.
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

# The native pre-root client: built by the caller (CI builds it before sudo, where the Go toolchain is), or here.
if [ -z "${REGALIA_UNLOCK_BIN:-}" ]; then
  command -v go >/dev/null || { echo "peer-unlock-swtpm: set REGALIA_UNLOCK_BIN to a built cmd/regalia-unlock, or have go on PATH"; exit 2; }
  REGALIA_UNLOCK_BIN="$W/regalia-unlock"
  go build -o "$REGALIA_UNLOCK_BIN" ./cmd/regalia-unlock || { echo "peer-unlock-swtpm: cmd/regalia-unlock did not build"; exit 2; }
fi
[ -x "$REGALIA_UNLOCK_BIN" ] || { echo "peer-unlock-swtpm: $REGALIA_UNLOCK_BIN is not an executable"; exit 2; }
export REGALIA_UNLOCK_BIN

# With a running systemd and systemd-cryptsetup, the shipped units are started for real and
# systemd-cryptsetup itself asks for the key (deploy/baremetal/initrd/). CI has both; a container may not.
SYSTEMD=0
if [ "$(systemctl is-system-running 2>/dev/null)" != offline ] && [ -d /run/systemd/system ] && { [ -x /usr/lib/systemd/systemd-cryptsetup ] || command -v systemd-cryptsetup >/dev/null; }; then SYSTEMD=1; fi
[ "$SYSTEMD" = 1 ] || [ "${REGALIA_EXPECT_SYSTEMD:-0}" != 1 ] || { echo "peer-unlock-swtpm: a running systemd with systemd-cryptsetup is expected here"; exit 2; }

out="$(REGALIA_EXPECT_SWTPM=1 REGALIA_EXPECT_CRYPTSETUP=1 REGALIA_UNLOCK_SYSTEMD="$SYSTEMD" REGALIA_UNLOCK_DEVICE="$LOOP" python3 -BEs -m unittest -v tests.test_baremetal_unlock </dev/null 2>&1)"; rc=$?
printf '%s\n' "$out"
[ "$rc" = 0 ] || { echo "peer-unlock-swtpm: FAILED"; exit 1; }
ran="$(grep -oE '^Ran [0-9]+ tests?' <<< "$out" | grep -oE '[0-9]+')"
skips="$(grep -c 'skipped' <<< "$out")"
if ! grep -q '^test_tpm_plus_one_peer_opens_the_disk.*ok$' <<< "$out" || { [ "$SYSTEMD" = 1 ] && [ "$skips" != 0 ]; } || [ "$skips" -gt 1 ]; then
  echo "peer-unlock-swtpm: the TPM test did not run, or a test was skipped that should have run"; exit 1
fi
[ "$SYSTEMD" = 1 ] || echo "peer-unlock-swtpm: NOTE: no running systemd here, the units were not started (one test skipped)"
echo "peer-unlock-swtpm: $ran passed, 0 failed"
