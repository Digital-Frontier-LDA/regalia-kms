#!/bin/bash
# dracut module: the pre-root disk unlock of a KMS host (regalia-kms#66, #67).
#
# What it puts in the initrd: the unlock client and its socket-activated unit, the boot mesh unit and
# its script, the three tools the script runs (ip, wg, nft), and one crypttab line. The image is the
# same for every host: what differs per host and per manifest (the boot configuration, the two
# TPM-sealed credentials, the WireGuard configuration, the ruleset, boot.env) comes at boot as system
# credentials, from the ESP through systemd-stub.
#
# Not included by default: add it with `dracut --add regalia-unlock` (or add_dracutmodules+=).
#
# dracut sources this file and provides $initdir, $systemdsystemunitdir, $SYSTEMCTL and the inst_*
# functions. They are used as ${name:?}: sourced by anything that does not provide them, the module
# stops instead of installing into nowhere.

check() {
    require_binaries regalia-unlock wg nft ip || return 1
    # One image for every host: in hostonly mode dracut copies the build machine's identity and crypt
    # settings into the image (machine-id, rd.luks.uuid in cmdline.d, its crypttab). Build with
    # --no-hostonly --no-hostonly-cmdline.
    if [ -n "${hostonly-}" ]; then
        derror "regalia-unlock: dracut runs in hostonly mode: build the image with --no-hostonly --no-hostonly-cmdline"
        return 1
    fi
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
    # The module is two files: without its crypttab line the image would build and open nothing.
    if [ ! -s "${moddir:?}/crypttab" ]; then
        derror "regalia-unlock: $moddir/crypttab is missing: install the whole module directory"
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
    for unit in regalia-unlock.socket regalia-unlock-relay.service regalia-unlock-core.socket regalia-unlock.service \
        regalia-wg-boot.service; do
        inst_simple "${systemdsystemunitdir:?}/$unit"
    done
    # The one crypttab line, the same on every host: the root partition is found by its GPT label. Nothing
    # per host is taken from the machine that builds the image (not /etc/regalia, not its /etc/crypttab):
    # what differs per host comes as system credentials at boot (the units say which).
    # (in place of any other: dracut's crypt modules copy the build machine's in hostonly mode)
    rm -f -- "${initdir:?}/etc/crypttab"
    inst_simple "${moddir:?}/crypttab" /etc/crypttab
    # Nothing in the initrd acts on a credential by name. The image's command line already stops systemd
    # importing any (systemd.import_credentials=no); this is the second layer, for an image built without
    # it: no unit or drop-in from a credential (the generator that makes them is left out), and the tmpfiles
    # and sysctl services import none.
    rm -f -- "${initdir:?}${systemdutildir:?}/system-generators/systemd-debug-generator"
    local service
    for service in systemd-tmpfiles-setup.service systemd-tmpfiles-setup-dev-early.service systemd-tmpfiles-setup-dev.service \
        systemd-sysctl.service; do
        mkdir -p "${initdir:?}${systemdsystemunitdir:?}/$service.d"
        printf '[Service]\nImportCredential=\n' > "${initdir:?}${systemdsystemunitdir:?}/$service.d/50-regalia-no-credentials.conf"
    done
    "${SYSTEMCTL:?}" -q --root "${initdir:?}" enable regalia-unlock.socket regalia-unlock-core.socket
}
