#!/bin/bash
# dracut module: the pre-root disk unlock of a KMS host (regalia-kms#66, #67).
#
# What it puts in the initrd: the unlock client and its socket-activated unit, the boot mesh unit and
# its script, and the three tools the script runs (ip, wg, nft). The files that differ per host and per
# manifest are under /etc/regalia: the boot configuration, the two TPM-sealed credentials, the
# WireGuard configuration, the ruleset and boot.env. They are taken when present.
#
# Not included by default: add it with `dracut --add regalia-unlock` (or add_dracutmodules+=).

check() {
    require_binaries regalia-unlock wg nft ip || return 1
    return 255
}

depends() {
    # kernel-network-modules: the network card's driver. Nothing else here asks for the network, and
    # without it the initrd has no interface to put the boot mesh on.
    echo systemd systemd-cryptsetup tpm2-tss kernel-network-modules
}

installkernel() {
    hostonly='' instmods wireguard nf_tables nft_ct nf_conntrack tpm_tis tpm_crb
}

install() {
    inst_multiple regalia-unlock wg nft ip sed cat sleep
    inst_simple /usr/lib/regalia/wg-boot
    for unit in regalia-unlock.socket regalia-unlock.service regalia-wg-boot.service; do
        inst_simple "$systemdsystemunitdir/$unit"
    done
    inst_multiple -o /etc/regalia/unlock.json /etc/regalia/unlock-local.cred /etc/regalia/wg-boot.cred \
        /etc/regalia/wg-boot.conf /etc/regalia/boot.nft /etc/regalia/boot.env /etc/crypttab
    $SYSTEMCTL -q --root "$initdir" enable regalia-unlock.socket
}
