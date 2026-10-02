#!/bin/bash
# dracut module: the pre-root disk unlock of a KMS host (regalia-kms#66, #67).
#
# What it puts in the initrd: the unlock client and its socket-activated unit, the boot mesh unit and
# its script, and the three tools the script runs (ip, wg, nft). The files that differ per host and per
# manifest are under /etc/regalia: the boot configuration, the two TPM-sealed credentials, the
# WireGuard configuration, the ruleset and boot.env. They are taken when present.
#
# Not included by default: add it with `dracut --add regalia-unlock` (or add_dracutmodules+=).
#
# dracut sources this file and provides $initdir, $systemdsystemunitdir, $SYSTEMCTL and the inst_*
# functions. They are used as ${name:?}: sourced by anything that does not provide them, the module
# stops instead of installing into nowhere.

check() {
    require_binaries regalia-unlock wg nft ip || return 1
    # systemd unseals the two credentials through this library, and its package only suggests it: without
    # it the image builds, and no boot can unseal anything
    local library found=
    for library in /usr/lib/*/libtss2-tcti-device.so.0 /usr/lib64/libtss2-tcti-device.so.0 /usr/lib/libtss2-tcti-device.so.0; do
        [ -e "$library" ] && found=yes
    done
    if [ -z "$found" ]; then
        derror "regalia-unlock: libtss2-tcti-device is not installed: systemd could not unseal the boot credentials"
        return 1
    fi
    return 255
}

depends() {
    echo systemd systemd-cryptsetup tpm2-tss
}

installkernel() {
    hostonly='' instmods wireguard nf_tables nft_ct nf_conntrack tpm_tis tpm_crb
    # The network card's driver. Nothing else in the initrd asks for the network, so nothing else brings
    # it; dracut's own kernel-network-modules is in a separate package (dracut-network) on Debian.
    hostonly='' instmods virtio_net '=drivers/net/ethernet' '=drivers/net/phy' '=drivers/net/mdio'

}

install() {
    inst_multiple regalia-unlock wg nft ip sed cat sleep grep
    inst_simple /usr/lib/regalia/wg-boot
    # The client and its unit come from the host separately: a client that records the boot session, run
    # by a unit that gives it nowhere to write, would boot with its leases refused.
    if ! grep -q '^RuntimeDirectory=regalia$' "${systemdsystemunitdir:?}/regalia-unlock.service"; then
        dfatal "regalia-unlock: the installed regalia-unlock.service is older than the client (no RuntimeDirectory=regalia)"
        return 1
    fi
    for unit in regalia-unlock.socket regalia-unlock.service regalia-wg-boot.service; do
        inst_simple "${systemdsystemunitdir:?}/$unit"
    done
    # Taken when present, and said when not: an image without them builds, and every boot of it ends at
    # the recovery-key prompt.
    for file in /etc/regalia/unlock.json /etc/regalia/unlock-local.cred /etc/regalia/wg-boot.cred \
        /etc/regalia/wg-boot.conf /etc/regalia/boot.nft /etc/regalia/boot.env /etc/crypttab; do
        if [ -e "$file" ]; then
            inst_simple "$file"
        else
            dwarn "regalia-unlock: $file is not there: this image cannot unlock the root volume unattended"
        fi
    done
    "${SYSTEMCTL:?}" -q --root "${initdir:?}" enable regalia-unlock.socket
}
