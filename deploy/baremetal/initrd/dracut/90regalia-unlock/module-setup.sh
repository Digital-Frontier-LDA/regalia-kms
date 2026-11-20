#!/bin/bash
# dracut module: the pre-root disk unlock of a KMS host (regalia-kms#66, #67, #70).
#
# What it pulls in (depends): systemd's cryptsetup, pcrphase and veritysetup modules, the last of which opens the
# image's /usr from the UKI's usrhash= (#61).
# What it puts in the initrd: the unlock client (a password agent, enabled beside systemd-cryptsetup) and
# its unit, the unit that renders the boot configuration from the signed membership chain (the same
# binary, -render; #66 B3), the boot mesh unit and its script, the three tools the script runs (ip, wg,
# nft), the FAT driver the ESP is read with, one crypttab line, and the membership root it trusts
# (/usr/lib/regalia/root-key.json, a build input: deploy/baremetal/initrd/build-initrd.sh --root-key, #156).
# The image is the same for every host: what differs per host comes at boot from the ESP: the measured
# site document and the two TPM-sealed credentials as system credentials through systemd-stub, and the
# signed membership chain, verified here.
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
    if [ ! -s "${dracutsysrootdir-}/usr/lib/regalia/root-key.json" ]; then
        derror "regalia-unlock: /usr/lib/regalia/root-key.json is missing: the image would trust no membership root"
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
    # systemd-veritysetup (#61, the dm-verity design): systemd-veritysetup-generator opens /usr from the UKI's usrhash=,
    # and veritysetup.target. Its check() returns 255, so dracut adds it only when a module names it; named here, not
    # left to a --add on the command line, so an image built without it cannot boot to a missing /usr in silence: its
    # check() needs systemd-veritysetup and the generator (package systemd-cryptsetup), and without them the module
    # fails and dracut stops the build.
    echo systemd systemd-cryptsetup systemd-pcrphase systemd-veritysetup tpm2-tss
}

installkernel() {
    hostonly='' instmods wireguard nf_tables nft_ct nf_conntrack tpm_tis tpm_crb
    # the ESP, mounted read-only to read the membership chain (#66 B3): FAT, and the code pages its names use
    hostonly='' instmods vfat nls_cp437 nls_ascii nls_utf8 nls_iso8859-1
    # The network card's driver. Nothing else in the initrd asks for the network, so nothing else brings
    # it; dracut's own kernel-network-modules is in a separate package (dracut-network) on Debian.
    hostonly='' instmods virtio_net '=drivers/net/ethernet' '=drivers/net/phy' '=drivers/net/mdio'

}

install() {
    inst_multiple regalia-unlock wg nft ip sed cat sleep
    inst_simple /usr/lib/regalia/wg-boot
    inst_simple /usr/lib/regalia/root-key.json
    for unit in regalia-boot-render.service regalia-unlock.service regalia-wg-boot.service; do
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
    # it: no unit or drop-in from a credential (the generator that makes them is left out), and no unit
    # imports or loads one by name (below). fstab-generator (which mounts the root), the network
    # generator and PID 1 itself still read some: the first layer covers those.
    rm -f -- "${initdir:?}${systemdutildir:?}/system-generators/systemd-debug-generator"
    # Every unit already in the image that takes credentials by name, found rather than listed, and
    # systemd-cryptsetup's (its generator writes ImportCredential=cryptsetup.* into units made at boot):
    # all three settings reset. The boot test checks the finished image for any unit left out.
    local unit
    for unit in "${initdir:?}${systemdsystemunitdir:?}"/*.service systemd-cryptsetup@.service; do
        unit="${unit##*/}"
        case "$unit" in regalia-*) continue ;; esac
        # (the unit file and its vendor drop-ins; the reset is named to sort last, so it wins over them)
        # (grep over the files themselves, not a pipe: under pipefail a missing drop-in directory would fail
        # the pipe even on a match; -q exits 0 on a match whatever else it could not read)
        if [ "$unit" != systemd-cryptsetup@.service ] \
            && ! grep -qsE '^(ImportCredential|LoadCredential|LoadCredentialEncrypted)=' \
                "${initdir:?}${systemdsystemunitdir:?}/$unit" "${initdir:?}${systemdsystemunitdir:?}/$unit.d/"*.conf; then
            continue
        fi
        mkdir -p "${initdir:?}${systemdsystemunitdir:?}/$unit.d"
        printf '[Service]\nImportCredential=\nLoadCredential=\nLoadCredentialEncrypted=\n' \
            > "${initdir:?}${systemdsystemunitdir:?}/$unit.d/99-regalia-no-credentials.conf"
    done
    # The firewall's modules, loaded on every boot by systemd-modules-load here (regalia-kms-r1s.15): the image's
    # /usr holds no kernel modules, so the host's ruleset loads after switch-root only with what is loaded already.
    # Exactly these bytes: deploy/baremetal/uki.py FIREWALL_MODULES_LOAD pins them.
    mkdir -p "${initdir:?}/usr/lib/modules-load.d"
    printf 'nf_tables\nnft_ct\nnf_conntrack\n' > "${initdir:?}/usr/lib/modules-load.d/regalia-firewall.conf"
    # The ESP must also mount after switch-root, including a recovery boot before genesis (r1s.19).
    # Carrying .ko files is insufficient: the module-free verity /usr cannot autoload them later.
    # vfat pulls in fat; preload its runtime codepages too. binfmt_misc has the same cause (r1s.18).
    # Exactly these bytes: uki.py FILESYSTEM_MODULES_LOAD and the initrd inventory pin them.
    # MUTANT DROP_VFAT_PRELOAD: expected inventory refusal; revert after CI proof.
    printf 'nls_cp437\nnls_ascii\nnls_iso8859-1\nnls_utf8\nbinfmt_misc\n' \
        > "${initdir:?}/usr/lib/modules-load.d/regalia-filesystems.conf"
    # The client answers systemd-cryptsetup's request beside the console; nothing orders one after the other,
    # so a client that never starts leaves the prompt as it is (#70).
    "${SYSTEMCTL:?}" -q --root "${initdir:?}" enable regalia-unlock.service
}
