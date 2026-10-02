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
    # (under --sysroot, in the tree the image is built from)
    for library in "${dracutsysrootdir-}"/usr/lib/*/libtss2-tcti-device.so.0 "${dracutsysrootdir-}"/usr/lib64/libtss2-tcti-device.so.0 \
        "${dracutsysrootdir-}"/usr/lib/libtss2-tcti-device.so.0; do
        [ -e "$library" ] && found=yes
    done
    if [ -z "$found" ]; then
        derror "regalia-unlock: libtss2-tcti-device is not installed: systemd could not unseal the boot credentials"
        return 1
    fi
    # The client and its unit come from the host separately. The client stays for the whole initrd phase
    # and records the boot session: under a unit that gives it nowhere to write, or does not stop it before
    # the root filesystem takes over, the host would boot with its leases refused or the client left behind.
    # Checked here and not in install(): dracut stops for a requested module whose check fails, and goes
    # on after an install() that fails.
    local line
    for line in 'RuntimeDirectory=regalia' 'RuntimeDirectoryPreserve=yes' 'Conflicts=initrd-switch-root.target shutdown.target'; do
        if ! grep -qxF "$line" "${dracutsysrootdir-}${systemdsystemunitdir:?}/regalia-unlock.service" 2>/dev/null; then
            derror "regalia-unlock: the installed regalia-unlock.service is not the one of this client (no '$line')"
            return 1
        fi
    done
    return 255
}

depends() {
    # systemd-pcrphase: the unit that extends PCR 11 with "enter-initrd". It is not in dracut's default set
    # (its check() returns 0, not 255), and without it no credential sealed to the image's initrd-phase
    # signature opens: the units here are ordered After= it, which does nothing for a unit that is absent.
    echo systemd systemd-cryptsetup systemd-pcrphase tpm2-tss
}

installkernel() {
    hostonly='' instmods wireguard nf_tables nft_ct nf_conntrack tpm_tis tpm_crb
    # The network card's driver. Nothing else in the initrd asks for the network, so nothing else brings
    # it; dracut's own kernel-network-modules is in a separate package (dracut-network) on Debian.
    hostonly='' instmods virtio_net '=drivers/net/ethernet' '=drivers/net/phy' '=drivers/net/mdio'

}

install() {
    inst_multiple regalia-unlock wg nft ip sed cat sleep
    inst_simple /usr/lib/regalia/wg-boot
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
