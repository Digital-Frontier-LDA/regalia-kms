# Bare-metal KMS host commissioning (HPE ProLiant DL360 Gen9)

ADR-0002 D21: the KMS runs on **dedicated bare metal with a discrete TPM 2.0**, not as a Proxmox
guest. Three DL360 Gen9 with the HPE TPM 2.0 module: Lisbon, Porto, and a spare (regalia#46).

Commissioning has two halves:
- **Firmware and hardware** (below): BIOS/RBSU and iLO settings the operating system cannot read.
  They are done at the console and **attested** in the signed evidence.
- **The running host:** `sudo python3 deploy/baremetal/host_probe.py --import-key-sha256 <hex> --evidence E.json`
  **measures** the platform, TPM and OS controls. It exits 1 unless every measured control is true AND
  the evidence agrees (evidence never lowers the bar).

## 1. Intake of a used server (before trusting it)

1. Update the **System ROM** and **iLO 4** firmware from HPE's signed packages (the Service Pack for
   ProLiant, or the individual signed components). TPM 2.0 on Gen9 needs a System ROM that supports
   it, and the updates carry the Spectre-class microcode fixes.
2. In RBSU (F9): **Restore Default System Settings**, then **clear the TPM**.
3. Replace the disks, or securely erase them.
4. Record the server serial, the ROM and iLO versions, and the TPM's EK certificate presence
   (`tpm2_getekcertificate`) in the evidence: `used_hardware_intake`.

## 2. Firmware settings (RBSU / iLO)

| Setting | Value | Evidence field |
|---|---|---|
| Boot mode | **UEFI** (TPM 2.0 needs it; not Legacy BIOS) | measured: `uefi_boot` |
| Secure Boot | **Enabled** (Debian 13's shim is signed by Microsoft's UEFI CA) | measured: `secure_boot_enabled` |
| TPM | **TPM 2.0 visible and enabled**; SHA-256 PCR bank active | measured: `tpm2_present`, `tpm_sha256_bank` |
| TPM module | **never moved**: the HPE module is bound to its system board | — |
| AC power recovery ("Automatic Power-On") | **Restore last state / always on** | attested: `ac_power_recovery` |
| Power supplies | both fitted, on **A and B feeds** where the datacenter offers them | attested |
| Chassis intrusion | the detection kit **fitted and armed** (it is optional on Gen9: check) | attested: `chassis_intrusion_armed` |
| iLO 4 | default password changed; on an **isolated management network**, or disabled | attested: `ilo_isolated_or_disabled` |
| Internal USB port | the **Nitrokey HSM 2** goes here, inside the chassis | measured: `hsm_token_attached` (USB 20a0:4230 in sysfs; path pinned in the evidence) |

## 3. Operating system (Debian 13)

- **Full-disk encryption** (LUKS2), enrolled to the TPM:
  `systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 <root partition>`, with
  `tpm2-device=auto` in `/etc/crypttab`. Keep a recovery passphrase in the escrow. Measured:
  `root_disk_tpm_unlocked`.
- **IMA** policy measuring executables (`measure func=BPRM_CHECK mask=MAY_EXEC`, as in `ima_policy=tcb`),
  so the regalia-kms binary is in the PCR the PIN is sealed to. Measured: `ima_policy_loaded`, which
  also requires `/usr/local/sbin/regalia-kms` in the IMA measurement log (start the service first).
- **Signed PCR policies** (systemd-measure / systemd-pcrlock), so a signed kernel or KMS update doesn't
  strand the sealed PIN.
- The regalia-kms host role (unprivileged service, no core dumps, no hibernation, swap off or
  encrypted): measured by the same probes as the Proxmox guest.
- **Token clients root-only.** Unlike the guest, this host seals and re-seals its own PINs, so
  `seal-hsm-pin.sh` needs `opensc-tool` and `pkcs11-tool` here. They must be `root:root`, mode `0700`
  (`chown root:root … && chmod 0700 …`), so the KMS user cannot run them, and every process
  connected to pcscd must be the KMS binary. Measured: `token_clients_root_only`. A KMS user that
  brings its own client is caught by the pcscd check only while it is connected; restricting pcscd
  access with a polkit rule (root and the KMS user only) is recommended on top.

## 4. TPM provisioning

1. **PIN import key:** `sudo deploy/seal-hsm-pin.sh --init-import-key`. Copy the printed fingerprint
   **by hand** at the console (the ceremony checks it) and record it in the evidence as
   `host.pin_import_key_sha256`. Measured: `pin_import_key_present`, which compares the key at the
   handle with that recorded value and checks its template (RSA-3072, fixedtpm, fixedparent,
   sensitivedataorigin, decrypt, no sign). Any other key at the handle fails.
2. **PINs:** `sudo deploy/seal-hsm-pin.sh --id … --serial <Nitrokey> --pcrs 7+… --from-blob
   pin-hsm_<x>.blob`, and `--yubikey <serial> … --from-blob pin-yubikey_<x>.blob` for the KMS YubiKey
   (PIN-CUSTODY.md). Without a blob, the PIN is typed from the PIN card.
3. Then: the mTLS server key in the TPM, certified by an EK-bound attestation key; the fencing epoch in
   a TPM monotonic counter; audit checkpoints in an NV extend index (ADR-0002 D21).

## 5. Pass criteria

`host_probe.py --import-key-sha256 <recorded> --evidence E.json` exits 0 (every measured control
true, and the evidence agrees with it), and an unattended
**reboot** brings the KMS back with no one present (the disk and the PIN both unseal from the TPM).
