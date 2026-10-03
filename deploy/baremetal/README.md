# Bare-metal KMS host commissioning (HPE ProLiant DL360 Gen9)

ADR-0002 D21: the KMS runs on **dedicated bare metal with a discrete TPM 2.0**, not as a Proxmox
guest. Three DL360 Gen9 with the HPE TPM 2.0 module: Lisbon, Porto, and a spare (regalia#46).

Commissioning has two halves:
- **Firmware and hardware** (below): BIOS/RBSU and iLO settings the operating system cannot read.
  They are done at the console and **attested** in the signed evidence.
- **The running host:** `host_probe.py` **measures** the platform, TPM and OS controls, and checks
  the signed evidence (`deploy/baremetal/evidence.py`: exact schema, every firmware setting attested,
  signed by the commissioning evidence key, which is trusted only by its recorded SHA-256). It exits 1
  unless every measured control is true AND the evidence is valid and agrees (section 5).

> **Every Python command in this document is written `python3 -Es …`, and is meant to be typed that
> way.** `-E` ignores the `PYTHON*` variables of the shell it is typed in and `-s` ignores the user's
> own site-packages, so nothing left in root's environment or under `~/.local` runs inside a tool that
> signs commissioning evidence or renders the firewall. Run them from the checkout's top directory.

## 1. Intake of a used server (before trusting it)

1. Update the **System ROM** and **iLO 4** firmware from HPE's signed packages (the Service Pack for
   ProLiant, or the individual signed components). TPM 2.0 on Gen9 needs a System ROM that supports
   it, and the updates carry the Spectre-class microcode fixes.
2. In RBSU (F9): **Restore Default System Settings**, then **clear the TPM**.
3. Replace the disks, or securely erase them.
4. Record them in the evidence: the server serial (`host_serial`), `system_rom_version`,
   `ilo_firmware_version`, `tpm_ek_certificate_present` (`tpm2_getekcertificate`), and
   `used_hardware_intake: true` once steps 1-3 are done.

## 2. Firmware settings (RBSU / iLO)

| Setting | Value | Evidence field |
|---|---|---|
| Boot mode | **UEFI** (TPM 2.0 needs it; not Legacy BIOS) | measured: `uefi_boot` |
| Secure Boot | **Enabled** (Debian 13's shim is signed by Microsoft's UEFI CA) | measured: `secure_boot_enabled` |
| TPM | **TPM 2.0 visible and enabled**; SHA-256 PCR bank active | measured: `tpm2_present`, `tpm_sha256_bank` |
| TPM module | **never moved**: the HPE module is bound to its system board | — |
| AC power recovery ("Automatic Power-On") | **Restore last state / always on** | attested: `ac_power_recovery` |
| Power supplies | both fitted, on **A and B feeds** where the datacenter offers them | attested: `redundant_power_supplies` |
| Chassis intrusion | the detection kit **fitted and armed** (it is optional on Gen9: check) | attested: `chassis_intrusion_armed` |
| iLO 4 | default password changed; on an **isolated management network**, or disabled | attested: `ilo_isolated_or_disabled` |
| Internal USB port | the **Nitrokey HSM 2** goes here, inside the chassis | measured: `hsm_token_attached` (USB 20a0:4230 in sysfs; path pinned in the evidence) |

## 3. Operating system (Debian 13)

- **Full-disk encryption** (LUKS2), enrolled to the TPM:
  `systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 <root partition>`, with
  `tpm2-device=auto` in `/etc/crypttab`. Measured: `root_disk_tpm_unlocked`.
  - **A disk enrolled this way FAILS `root_disk_unlock_revocable`, and `host_probe.py` exits 1. That is
    intended (#135): it is the known blocker for production.** PCR 7 does not change with the kernel, so
    an old signed kernel image unlocks this disk, reads the host key and opens the HSM PIN. The probe
    passes only when the unlock can retire an image: a peer's contribution (#67: `regalia-peer-unlock`
    tokens and no `systemd-tpm2` token, judged with `--node-id <this node> --unlock-peer <peer>` for each
    peer that holds a path, and a crypttab entry whose key file is the unlock client's socket,
    `/run/regalia-unlock/key.sock`, with only options known to leave the unlock alone (`luks`, `x-initrd.attach`,
    `discard`, `tries=`, `timeout=`, …: no `header=`, no `headless`, no other token device) and no `rd.luks.*` on the
    kernel command line. The probe reads `/etc/crypttab`, which is what the initrd was built from, not necessarily
    what the initrd holds: rebuild the initrd after every edit. The enrolment exists in
    `deploy/baremetal/unlock.py`, its boot-time client
    does not yet), or an
    NV-backed policy (`systemd-cryptenroll --tpm2-pcrlock`: it does retire an image on a software TPM,
    `e2e/pcrlock-luks-swtpm.sh`, and is unproven on a real boot). There is no option to skip the probe.
    A host that is otherwise commissioned shows this as its only failing control. Signed evidence
    (section 5) records every measured control as true, so no evidence can be signed for such a host:
    with `--evidence` the run says the evidence is refused; run it without, to see the one control.
  - The probe judges every dm-crypt volume under `/`, under the host key and under the credstore, and
    every token that names a keyslot on them: a second volume, a `clevis` token or a stale token fails
    it, and so does a keyslot that no token names (a passphrase, or a key file) on any of them. For an
    NV-backed token it also requires `/var/lib/systemd/pcrlock.json` to bind PCR 7 and a PCR that tells
    boot images apart, with measured values: `systemd-pcrlock` leaves out a PCR it cannot predict, and a
    PCR nothing was measured into is all zeros for every image. PCR 11 qualifies on a UKI boot
    (systemd-stub measures the image into it); PCR 4 qualifies when the kernel is started as an EFI
    image, as a UKI is, and not when GRUB loads the kernel itself. It
    does not measure that the NV index holds that policy, nor that a retired image is refused on the
    host; that is the #65 checklist, section D.
- **The recovery key**: a second keyslot, independent of the TPM and of every peer, that opens this
  host's disk by itself after a total outage (#77; PIN-CUSTODY.md, "The disk recovery key"). It is a
  ceremony secret, one per host, written on the KMS host recovery card and carried in every escrow;
  it is never stored on a host. In this order:
  1. `sudo deploy/baremetal/recovery-key.sh --enrol <root partition>`: asks for the installer's
     passphrase, then for the recovery key twice. Then `--check`, with the key read from the **card**.
  2. Enrol the TPM (above) and reboot once to see the disk unlock unattended.
  3. Only then wipe the installer's passphrase: `systemd-cryptenroll --wipe-slot=password <root partition>`.

  The key is 8 groups of 8 lower-case letters with a dash between groups. **The dashes are part of
  the key**; typed without them, or in capitals, it does not open the disk. Measured:
  `root_disk_recovery_keyslot` (exactly one recovery keyslot, of its own, and no keyslot left that no
  token names, such as the installer's passphrase). The probe reads the LUKS2 header only and never
  asks for the key. After **any** use of the key, a rehearsal included: `recovery-key.sh --replace`
  with a new key printed by the ceremony disc's `pin-escrow.sh --new-recovery-key` (never invented by hand); escrow it only after `--replace` and `--check` have succeeded.
- **IMA** policy measuring executables (`measure func=BPRM_CHECK mask=MAY_EXEC`, as in `ima_policy=tcb`).
  This is for **attestation**: TPM quotes over PCR 10 and the IMA log let another host or an
  appraiser (Keylime) check that the running regalia-kms is the expected binary. Measured:
  `ima_policy_loaded`, which also requires the newest IMA entry for `/usr/local/sbin/regalia-kms` to
  carry the digest of the binary there now (start the service first).
- **The PIN and the disk are sealed to PCR 7** (Secure Boot state and the keys it trusts), as
  `systemd-cryptenroll` does by default. A kernel or KMS update does not change PCR 7, so nothing is
  stranded; turning Secure Boot off, or enrolling other keys, does change it.
  - **The PIN is sealed to the host key as well** (`/var/lib/systemd/credential.secret`, on the
    encrypted root disk): key type `host+tpm2`. A TPM policy alone cannot retire an image, so the PIN
    must also need the unlocked root disk (PIN-CUSTODY.md, "Why the host key is in the seal"). Losing
    the root disk therefore means resealing the PIN from the PIN card.
  - **Not PCR 10 (IMA).** systemd decrypts `LoadCredentialEncrypted` before it executes regalia-kms, so
    a policy expecting that binary's measurement could never unseal at an unattended start; PCR 10
    also depends on the order everything else ran in.
  - **Not PCR 11 directly.** It measures the kernel image, which changes at every update, so
    `seal-hsm-pin.sh` refuses `--pcrs` with 10 or 11. PCR 11 is bound only through a *signed* PCR
    policy: `seal-hsm-pin.sh --pcrs 7 --tpm2-public-key FILE --tpm2-public-key-pcrs 11`
    (PIN-CUSTODY.md, "Binding the kernel as well"). That is proven on a software TPM only; the
    PCR-signing key's custody, signed UKIs and the root disk are not provisioned yet (#57), so
    production binds PCR 7 alone until they are. The evidence records the two separately:
    `credential_tpm2_pcrs` (bound directly) and `credential_tpm2_signed_pcrs` with
    `credential_tpm2_pcr_key_pkfp` (the signed policy and its key; both `""` without one).
    It also records `node_id` and `unlock_peers` (#67): which node of the membership manifest this
    host is and which peers hold an unlock path for its root disk (`[]` when none). The probe judges a
    peer-enrolled root disk against that signed record; `--node-id`/`--unlock-peer` given beside the
    evidence must agree with it.
  The binary itself is covered by IMA attestation (above) and by the package signature.
- The regalia-kms host role (unprivileged service, no core dumps, no hibernation, swap off or
  encrypted): measured by `deploy/baremetal/os_probe.py`.
- **The service's sandbox.** Install `deploy/baremetal/regalia-kms-hardening.conf.example` as
  `/etc/systemd/system/regalia-kms.service.d/hardening.conf`. Measured, with the service running:
  `kms_service_sandboxed` (ProtectSystem=strict, ProtectHome, PrivateTmp, ProtectKernelTunables/
  Modules/Logs, ProtectControlGroups, RestrictSUIDSGID, LockPersonality), `kms_capabilities_minimal`
  (no capability in the unit's bounding or ambient set, nor in the running process's) and
  `kms_apparmor_enforced` (the running process is confined by a profile in enforce mode; the
  profile and how to load it are under **AppArmor** below). All three are required in the evidence.
- **Token clients root-only.** This host seals and re-seals its own PINs, so
  `seal-hsm-pin.sh` needs `opensc-tool` and `pkcs11-tool` here. They must be `root:root`, mode `0700`
  (`chown root:root … && chmod 0700 …`), so the KMS user cannot run them, and every process
  connected to pcscd must be the KMS binary. Measured: `token_clients_root_only`. A KMS user that
  brings its own client is caught by the pcscd check only while it is connected.
- **pcscd admits the KMS user and root, and nobody else.** Install
  `deploy/polkit/50-regalia-kms-pcscd.rules` as `/etc/polkit-1/rules.d/50-regalia-kms-pcscd.rules`,
  byte for byte, `root:root`, mode `0644` (polkitd reads it as its own user: a file only root can
  read is silently not loaded). **It is required, not an extra:** Debian's pcscd asks polkit, and its
  policy lets in only a user with an active local session. The daemon's user has none, so without the
  rule pcscd refuses it and the daemon reaches neither the HSM nor the YubiKey: it starts, is never
  ready, and every key is unavailable (measured with pcscd 2.3.3 under the shipped unit,
  `e2e/kms-two-token-systemd.sh`). The same rule is written to refuse every other user, an operator
  at the console included, because whoever can talk to pcscd can present PINs and spend retry
  counters; that refusal follows from the rule and from no other rules file deciding first, and has
  been observed only for users without a session. polkit runs every rules file in one shared
  JavaScript context, in name order, and the first answer wins: any other rules file could grant
  first or rewrite polkit under the KMS rule. **So a KMS host carries no polkit rules file but the
  distribution's own and this one.** Measured: `kms_pcscd_access_rule` (the file is the shipped one
  byte for byte, root's, readable by polkitd; every other rules file in the four polkit directories
  is one of the distribution's, by path and sha256 as measured on Debian 13, and each of those
  directories that exists, and its parent, is root's alone to change; and `pkcheck` says polkit admits the running daemon to both of pcscd's actions). A
  distribution update that changes one of those files fails the control until its digest is renewed
  in `os_probe.KNOWN_RULES_FILES`.
- **AppArmor.** The unit asks for the profile by name (`AppArmorProfile=regalia-kms` in
  `regalia-kms-hardening.conf.example`) and does not start without it. Deny by default: no
  capability, no execution, no datagram socket, so `audit_sink_url` must be an IP address or a name
  in `/etc/hosts`. The profile is parser-checked only, so load it in complain mode first, correct it
  from the kernel log, and only then enforce (the full sequence is in the file's header):
  ```sh
  sudo install -m 0644 deploy/baremetal/apparmor/usr.local.sbin.regalia-kms /etc/apparmor.d/
  sudo apparmor_parser -r -C /etc/apparmor.d/usr.local.sbin.regalia-kms   # complain: logs, refuses nothing
  sudo apparmor_parser -r /etc/apparmor.d/usr.local.sbin.regalia-kms      # enforce, once the log is clean
  ```
  Restart regalia-kms after each load. Measured: `kms_apparmor_enforced` (enforce mode only).
- **Runtime admission.** A production configuration states `"runtime_admission": "required"` with
  `runtime_admission_path`, `node_id` and `boot_session_path` (`config/daemon.example.json`); with a
  token configured the daemon refuses to start if the setting is left out, and `"disabled-for-lab"` is
  for lab and CI hosts only. The daemon then serves key operations only while the root lease service
  (`deploy/baremetal/admission.py`) reports that this node holds a runtime lease: without one,
  `/v1/health/ready` is 503 and every key operation is a 503 `DEPENDENCY_UNAVAILABLE`, audited as
  `not-admitted`. `/run/regalia` must be root's, mode 0755, and the two files in it root's, mode 0644.
  `python3 -Es -m deploy.baremetal.admission` shows what the daemon currently reads. The call from the
  lease service to a peer is not shipped yet (#80). Where admission is required, a token that was
  absent (removed and returned, or the daemon restarted) serves again only once the node holds a lease
  it asked for after the token was back (after the daemon's own start, for a restart): until then that
  binding is unavailable and the daemon is not ready. The lease service sees the daemon's start and asks
  at once; a token's return it does not see, and that waits for the next scheduled renewal. A token
  pulled while an operation is in flight is seen too (it stops answering for its identity); a request the
  token merely refuses, or one whose caller hung up, is not an absence. A token pulled during the PIN
  login also leaves the PIN latch set: after its return it needs the fresh lease **and** an operator's
  PIN-block reset, as any failed login does. This holds for every key the daemon serves: the HSM's, a
  YubiKey's PIV slots and its OpenPGP applet; the daemon refuses to start with a provider that cannot wait. Measured: `kms_runtime_admission_required` (the
  configuration the unit starts the daemon with says `"required"`; `"disabled-for-lab"` fails it).
- **Authenticated time (`authtime.py`; the unit is NOT BUILT yet, #80).** Every expiry here (a
  heartbeat's, a lease's) is judged against the clock, so the clock itself must be vouched for. It counts
  as authenticated only while chrony is synchronised to **NTS** sources, **at least two of which agree**
  (declare servers of independent operators, so that no single operator can move the clock; with
  exactly two, one operator's outage stops the nodes, so declare **three**), with no source that was not
  declared or is not NTS, an update within the last hour, and no correction pending. `authtime.conf()`
  renders the **whole** `chrony.conf`: no `pool`, no `sourcedir` (the distribution's default takes
  servers from DHCP that way), no `refclock`; and chronyd must be the only thing on the host that sets
  the clock (no systemd-timesyncd beside it). A host whose RTC is far off never authenticates, because
  NTS checks certificates against the clock: set the RTC by hand; `nocerttimecheck` is not used. A small root
  service asks chrony every 15 s and publishes the answer in `/run/regalia/authtime.json`; the other
  services believe it for 60 s.
  **If time is not authenticated, nothing is served:** peers authorize no unlock and issue no lease, a
  node's own lease is not renewed, and within the lease bound (300 s) the KMS daemon stops. That is
  intended. So NTS must get out of each site: TCP 4460 to each server for the key exchange and UDP 123
  for the time itself; an outage of the NTS servers, or of that path, longer than those bounds stops the
  nodes. Proven against live chrony daemons in `e2e/authtime-chrony-nts.py`.

### OpenSC leaves the YubiKey to the PIV backend

A host whose daemon serves both an HSM (PKCS#11, through OpenSC) and YubiKey PIV keys needs OpenSC
told to ignore the YubiKey's reader. The PIV backend opens the card for itself alone, and OpenSC
keeps a connection to every card it is not told to ignore: with OpenSC's defaults the daemon's own
PKCS#11 module locks its PIV backend out (measured, regalia#541).

- Install `deploy/opensc/ignore-yubikey.conf` as `/etc/regalia-kms/opensc.conf` (`root:root`, `0644`).
  The shipped unit starts the daemon with `OPENSC_CONF` naming that path, and the AppArmor profile
  already allows reading it.
- **The daemon then reads that file and not `/etc/opensc/opensc.conf`.** Anything a host had put in
  the system file for the daemon (a `card_atr` block for the OpenPGP applet, a slot limit) must move
  to `/etc/regalia-kms/opensc.conf`, or it stops applying when the new unit is installed.
- On an HSM-only host install the same file: ignoring a reader that is not there changes nothing.
  If the file is missing, OpenSC uses its defaults (measured): the HSM is served as before, and a
  host that also has PIV cards is refused at startup as described next.
- **The daemon checks the effect at startup.** After its module has looked at the readers, every
  configured PIV card must still open. A card that cannot be opened **while another connection
  holds a YubiKey's reader** stops the daemon, with a message naming this setting: that is this
  misconfiguration, or another process using the card, and neither heals by waiting. (The HSM's
  reader does not count: the module holds it by design.) A card that is simply **not attached**
  is a warning and the daemon starts, as it does with an HSM unplugged: the HSM's keys must not
  go down for a missing YubiKey.
- **What the startup check cannot see** is a YubiKey attached later to a daemon that started
  without the setting. Its requests then fail, and the daemon logs the cause (an error, once a
  minute at most, naming every configured card that is missing: a held reader cannot be asked
  which card is in it) instead of leaving a bare "unavailable"; it does not stop. The host probe
  below is what catches that host before the card is ever attached.
- One host's YubiKeys then serve PIV only, not the OpenPGP applet through OpenSC
  (`deploy/opensc/yubikey-openpgp.conf` asks OpenSC to drive the card; this asks it not to).

Measured: `kms_opensc_leaves_piv_cards` (when the configuration the unit starts the daemon with names
both a PKCS#11 module and YubiKey PIV devices, the unit's `Environment=` carries `OPENSC_CONF`, and
in that file the block `opensc-pkcs11.so` reads, `app opensc-pkcs11` if there is one and else
`app default`, has an `ignored_readers` entry naming a YubiKey's reader). The block and the statement
are chosen as OpenSC chooses them, and a file that is not well formed (braces that do not balance,
a list not ended by `;`) fails the control rather than being guessed at. An `EnvironmentFile=` on
the unit fails it too: what it sets is not seen.

### Host firewall (default deny, both directions)

The site config (`site.example.json`, validated by `sitecfg.py`; `"boot_mesh": null` and `"service_mesh": null` for a single-site
host, section 7 otherwise) declares the host's address, the
KMS and SSH ports, the zones allowed to reach each, and the only destinations the host may reach
(the audit and NTP sinks at least). From it:

```sh
install -d -m 0755 /etc/nftables.d
# Render to a name the *.nft include never matches, validate, load, and only then replace the fragment:
# a bad config or a failed render leaves the previous, working ruleset in place at the next boot.
tmp="$(mktemp /etc/nftables.d/.regalia-kms.XXXXXX)"
if python3 -Es deploy/baremetal/firewall.py site.json > "$tmp" && nft -c -f "$tmp" && nft -f "$tmp"; then
  chmod 0644 "$tmp" && mv -f "$tmp" /etc/nftables.d/regalia-kms.nft
else
  rm -f "$tmp"; echo "firewall NOT installed: the previous ruleset stays" >&2
fi
```

It must also survive a reboot, and the KMS must never start without it:
- **Load it at boot:** in `/etc/nftables.conf`, keep Debian's `flush ruleset` first, then add
  `include "/etc/nftables.d/*.nft"`, and `systemctl enable nftables.service`.
- **Order the KMS after it**, with a drop-in `/etc/systemd/system/regalia-kms.service.d/firewall.conf`:
  ```ini
  [Unit]
  Requires=nftables.service
  After=nftables.service
  ```
  If the ruleset fails to load, nftables.service fails and the KMS does not start.
- **Check again after the reboot** (section 5): `firewall_default_deny` is measured on the running
  host, so a ruleset that loaded once but not at boot fails commissioning.

Measured: `firewall_default_deny` (the table is loaded, with input, output and forward on policy
drop). Checked by behaviour from each zone after commissioning:

```sh
python3 -Es deploy/baremetal/network_probe.py site.json --role client --source-ip <a client address>
```

(`monitoring`, `admin`, `unauthorized` likewise). `e2e/baremetal-firewall-netns.sh` runs the whole
matrix in network namespaces in CI. Never load the ruleset on a workstation: it is default-deny.

## 4. TPM provisioning

0. **Lockout settings, first:** `sudo deploy/baremetal/tpm-lockout.sh --set`. It sets the TPM's
   dictionary-attack policy (32 failed tries before lockout, one try forgiven every 600 s, 86400 s of
   lockout-hierarchy recovery) and the **lockout authorization**, a ceremony secret typed from the
   escrow (16-32 characters) and never stored on the host. Why it matters here: a power cut after
   the PIN was unsealed counts as one failed try, and at the limit the TPM releases no PIN, so the
   KMS would not come back unattended. With this policy a host survives 31 cuts in a row and forgets
   one every 10 minutes. A **wrong** lockout authorization blocks the lockout hierarchy for a day:
   read it from the escrow, never guess. Measured: `tpm_lockout_policy` (the three settings, an
   authorization set, not in lockout; the tries counted are reported). Proven on software TPMs only
   (`e2e/tpm-lockout-swtpm.sh`); the DL360's own behaviour under real power cuts is a PoC still to
   run (#57).
1. **PIN import key:** `sudo deploy/seal-hsm-pin.sh --init-import-key`. Copy the printed fingerprint
   **by hand** at the console (the ceremony checks it) and record it in the evidence as
   `host.pin_import_key_sha256`. Measured: `pin_import_key_present`, which compares the key at the
   handle with that recorded value and checks its template: RSA-3072 with exactly
   fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|noda. Any other key at the handle fails.
   `noda`: the key has no authorization value to guess, so the TPM's dictionary-attack counter
   protects nothing there, and without it every power cut after the key was used would count a try.
2. **PINs:** `sudo deploy/seal-hsm-pin.sh --id … --serial <Nitrokey> --pcrs 7 --from-blob
   pin-hsm_<x>.blob`, and `--yubikey <serial> … --from-blob pin-yubikey_<x>.blob` for the KMS YubiKey
   (PIN-CUSTODY.md). Without a blob, the PIN is typed from the PIN card. Record the binding in the
   evidence (`host.credential_tpm2_pcrs`, and the signed policy's two fields). Measured:
   `pin_credentials_sealed_as_recorded` reads the header of every
   `/etc/credstore.encrypted/regalia-kms-*.pin` and fails unless each is sealed to the host key and
   the TPM together (not the TPM alone, which is what `seal-hsm-pin.sh` made before #75: reseal those
   with `--replace`; not the host key alone) with exactly the recorded PCRs (of the SHA-256 bank) and
   signing key, and opens on this boot under the name the unit loads it by; and unless the host key
   is root's, mode 0400, on a filesystem with dm-crypt beneath it. Without evidence, give the record on
   the command line: `--credential-pcrs 7 [--credential-signed-pcrs 11 --credential-pcr-key-pkfp HEX]`.
3. Then: the mTLS server key in the TPM, certified by an EK-bound attestation key; the fencing epoch in
   a TPM monotonic counter; audit checkpoints in an NV extend index (ADR-0002 D21).
4. **Attestation key (three-site, #65):** `python3 -Es deploy/baremetal/attest.py node-init --out DIR`
   creates the EK and a restricted AK and exports their public areas; a peer enrolls the AK with
   `challenge` / `node-activate` / `enroll` and then verifies quotes with `nonce` / `node-quote` /
   `verify`. Proven on a software TPM (`e2e/tpm-attest-swtpm.sh`); the PCRs to expect and the EK
   certificate check are set on the DL360s (#65 PoC 5.2/5.3).

## 4a. Updating the kernel on three nodes without locking the cluster out (#75)

**The whole procedure, step by step, with what can and cannot be run today: `KERNEL-UPDATE.md`** (gaps:
#156). This section explains the mechanism.

A peer unlocks a node only if its quote matches the reference values the peer holds. Those values are
a **measurement document** (`deploy/baremetal/measurements.py`) that the signed membership manifest
commits to: the manifest's `policy_version` is a digest of the document (174 bits of its SHA-256), so a
peer accepts exactly the document the root approved, and an older one is refused by the manifest the peer holds now (which a
restored disk cannot roll back: the epoch is anchored in the TPM).

Each node has one accepted set, or two while an update is under way.

**One image, two PCR 11 values.** On a host that boots a unified kernel image, systemd extends PCR 11
as the boot passes its phases. So the same image measures one PCR 11 in the initrd, where the node asks
a peer for its disk, and another once booted, where it asks for a runtime lease. A set therefore gives
PCR 11 **per phase** (`"phases": {"initrd": {"11": …}, "system": {"11": …}}`, both values from the
image's build record), and a peer accepts each request from its own phase only: **an unlock from the
initrd, a lease from the booted system.** A booted system that asks for a disk key is refused, on an
approved image too. A set with one value per PCR (a host that does not boot a UKI) is judged the same in
both. The peer's record of a node says in which phase it last saw it, and **"back on the new image"
means seen up**: a node verified only in its initrd has asked for its disk and may never have come up,
so it does not let the next node reboot and does not count towards retiring the old image.
Until this was added, a set held one PCR 11 value and a real UKI host would have been refused at
one of the two requests; the software-TPM tests extended PCR 11 once and did not show it.

An update is three documents:

| Step | Document | The root signs | What works |
|---|---|---|---|
| before | CURRENT | manifest N | the running image |
| approve | CURRENT + NEXT | manifest N+1 | both; nodes reboot into NEXT one at a time |
| retire | NEXT | manifest N+2 | NEXT only; the old image is refused by every peer |

1. **Build and predict.** Build the new UKI, predict its PCR 11 (`systemd-measure calculate`), sign it
   with the PCR-signing key (so the PIN and the disk unseal under it with no reseal), and write the
   CURRENT + NEXT document. `measurements.transition(old, new)` must say `approve`.
2. **Approve.** The root's operator computes `measurements.version(document)` from the file in hand, at
   signing time, and the root signs manifest N+1 with that as `policy_version`. Distribute the manifest
   and the document to all three nodes.
3. **One node at a time.** On each node, in the order of the node IDs, `rollout.may_reboot(...)` must
   pass before the reboot: an update is approved for this node and it is not yet on NEXT; every node
   before it has been seen back on NEXT by this node's own verifier; and every peer that will have to
   unlock it holds the new manifest and has vouched for it, in its current boot, in the last five
   minutes (a runtime lease for this boot session). With every record current, one node can pass at
   a time: the first, in order, that is not on NEXT. **The limit:** a node judges "the one before me is
   back" from its own last re-attestation of that node, which it repeats only at the next lease
   renewal. If the earlier node falls back or goes down just after, the next node may still pass for up
   to the lease lifetime (five minutes), and two nodes can then be down together. Three cannot. So
   wait for a node to be back and serving before starting the next, and do not treat `may_reboot` alone
   as the interlock. A node that is down
   and must not hold the others up is taken out by a signed manifest (QUARANTINED); there is no
   unsigned way to skip it.
4. **If the new image fails**, the node boots CURRENT again and is unlocked as before: both sets are
   accepted until the retirement. That is the fallback, at every step up to step 5.
5. **Retire.** When `rollout.retire_ready(...)` passes (given the state of every node that may
   authorize: under manifest N+1, every peer that has seen a node last saw it on NEXT, for every node), and `transition` says `retire` (not `abandon`, which is
   the document that gives NEXT up instead), the root signs manifest N+2 for the NEXT-only document.
   From then on a node booted
   into the old image gets no unlock and no lease. A lease issued just before the retirement runs out
   within five minutes.

Both manifests can be signed in one root-key session and the second released later; if a revocation
is published in between, the second no longer chains and is signed again.

**The image itself** (#57) is built and signed by `deploy/baremetal/uki.py`: `build` gives the same bytes
on any machine and a record of what the image will measure in each phase; `sign` rebuilds it on the
signing machine, signs PCR 11 with one key per phase and the file for Secure Boot with a third, keys in
a PKCS#11 token; `verify` is the check before an image is installed; `set` prints the image's
measurement set for one host. `e2e/uki-build.sh` runs it with Debian 13's ukify, systemd-measure and
sbsign and test keys, and replays the image on a software TPM: PCR 11 reaches the record's two values,
and a secret sealed to each phase's key opens with the image's own signature in that phase only.
**Not done:** no image has booted; the real initrd, the pinned inputs, the keys and their ceremony do
not exist yet.

**Replacing a node during all this** (#76) changes the document too, since the new node needs an entry:
`measurements.check_replacement(...)` requires the manifest to replace the node and the document to
differ by that node's and the new node's entries, and nothing else.

**An emergency** (the current image is compromised) skips the overlap: `transition(..., emergency=True)`
accepts a document that drops CURRENT at once, on every node. Every node still on it is then locked out until it boots
the new image; that is the intent.

Proven on three software TPMs, with real quotes, NV counters and TPM-signed leases
(`e2e/rolling-policy-swtpm.sh`); the rules themselves in `tests/test_baremetal_rollout.py`. **Not done:**
nothing here is wired into a service or reboots a machine; `may_reboot` is a check an operator or a
script must call, and it does not stop a reboot it was not asked about. Real UKIs, systemd-boot's boot
counting and automatic fallback, a TPM firmware update (staged the same way, as a second set) and the
timing of three reboots are for the DL360s (#65). And retirement by the peers protects what needs a peer:
see PIN-CUSTODY.md, "Why the host key is in the seal", for the local seal and what is still open there.

## 5. Pass criteria

Sign the evidence with the commissioning evidence key (`openssl dgst -sha256 -sign key.pem -out
E.json.sig E.json`), then:

```sh
sudo python3 -Es deploy/baremetal/host_probe.py --evidence E.json --signature E.json.sig \
  --evidence-key commissioning-p256.pem --evidence-key-sha256 <recorded fingerprint>
```

It must exit 0: every measured control true; the evidence at most 24 hours old (the firmware settings
are not re-measured, so sign fresh evidence for each run), complete, signed by the recorded key,
attesting every firmware setting, and agreeing with every measurement (including the import key's
fingerprint). Then an unattended
**reboot** brings the KMS back with no one present (the disk unseals from the TPM; the PIN from the
TPM and the host key on that disk).

## 6. Backups: the control-plane export, never an image

A KMS host is never backed up, snapshotted, replicated or restored as a disk or machine image. An
image carries memory-resident credentials and runtime state out of the custody boundary, and
restoring one restores operational authority with it.

What a rebuilt site cannot reconstruct on its own (the audit journal, the policy reservation state,
the fencing epoch history) is exported separately, as encrypted, integrity-protected application
data sealed to the custody authority's public key. Runtime credentials, the TPM-sealed PIN blobs,
memory, swap, core dumps, PINs, plaintext outputs and token state are excluded. A rebuilt host gets
its credentials back through the witnessed custody procedure, never from the export.

- `regalia-kms --export-control-plane` on the host;
- `--inspect-export` and `--scan-tree`, offline, from the ceremony checkout;
- `--restore-export F --authority-key-pem K --expect-site S --restore-root /` on the rebuilt host:
  verified first, all or nothing, never over existing state, each journal with its mark.

`internal/controlplane` implements this contract. The evidence attests it
(`runtime_credentials_excluded_from_backup`); nothing measures it. The export, wipe, restore and
serve sequence passed on the bench with the real daemon and a real Nitrokey (2026-09-24). Carrying
an export out of a real site and restoring it on a rebuilt host has not been done (regalia#46).

## 7. Peer-assisted disk unlock (three-site, #67): not commissioned yet

Section 3's TPM-only disk unlock is the single-site baseline. It cannot retire a boot image: the TPM
releases the disk key to every image its policy ever accepted (#135). The three-site design replaces
it: the disk needs the host's TPM **and** one peer, and a peer helps only a node its current manifest
lets be unlocked, on an image the manifest's measurements still list.

Proven on software TPMs and a real dm-crypt volume (`e2e/peer-unlock-swtpm.sh`):

- **The credential** of each peer path is derived from two halves: one sealed in this host's TPM, one
  kept on the peer's encrypted disk. Each peer has a LUKS2 keyslot and a `regalia-peer-unlock` token of
  its own, so either peer restores the host and each path is rotated alone.
- **The peer** (`deploy/baremetal/unlock.py`, on a booted host): the host sends a fresh TPM quote for
  this boot; the peer decides with `replacement.may_unlock`, and answers with its half encrypted to
  this boot's one-time key and signed by its own TPM. A captured exchange is useless in another boot.
- **The pre-root client** (`cmd/regalia-unlock`, a static Go binary that talks to the TPM through
  `go-tpm`, the standard Go library for it; `unlock.py` also holds a
  reference client that the tests use and that is not shipped). It holds no manifest and makes no
  membership decision. It runs no other program and writes no secret anywhere:
  - systemd unseals the local half with the TPM and passes it as the unit's credential
    `regalia-unlock-local` (`LoadCredentialEncrypted=`);
  - the client reads the LUKS2 header for the peer paths, asks the peers of its boot configuration in
    turn (`unlock.boot_config`: node ID, disk, PCRs to quote, and each peer's address and TPM key
    names), for a bounded number of rounds;
  - it gives the derived key to systemd-cryptsetup over the socket that crypttab names as the key
    file (`/run/regalia-unlock/key.sock`). If no peer helps, it gives nothing.
- **The relay** (`regalia-unlock-relay.service`): it makes the key socket crypttab names, holds no
  credential, no TPM and no network, and needs nothing that can fail. It asks the real client on its
  own socket (`regalia-unlock-core.socket`) and passes on exactly one whole key, or gives nothing after
  any failure or after 330 s (the real client ends its own attempt within 240 s, so its answer comes
  first; a client that hangs yields the prompt). With nothing, systemd-cryptsetup asks for the
  recovery key. It makes the socket ITSELF, with no `.socket` unit, because systemd-cryptsetup asks for
  the recovery key when the key file does not exist, and fails without asking when a connection is
  refused or reset (systemd 257): so if the relay cannot start, or is gone, there is no socket, and the
  console asks. It is restarted without limit; its runtime directory, the socket in it, goes when it
  stops; systemd-cryptsetup is ordered after it, weakly. Before it, a real client that could not start
  (a sealed credential that did not decrypt) left systemd-cryptsetup with a reset connection, and it
  failed without asking (#66). Shown with the real systemd and systemd-cryptsetup: a client that hangs,
  one that crashes mid-answer, an undecryptable credential, an absent one, and the relay unable to
  start each end with no key and the prompt's path.
- **The real client's units** (`deploy/baremetal/initrd/regalia-unlock-core.socket` and `regalia-unlock.service`): the relay's
  connection to the socket starts the client, sandboxed (no capability, no write anywhere but its own
  `/run/regalia`, no device but the TPM and the disks, read-only). Shown with a running systemd and
  the real systemd-cryptsetup: the volume is mapped with the key from the socket; with no peer,
  systemd-cryptsetup gets no key, gives up within a second and maps nothing, and the client goes on
  answering the next attempt.
  **One boot carries one attested session.** The client is one process for the whole initrd phase and
  makes one boot session; a retry in the same boot (a lost reply, peers that came back) is asked under
  the same session and is answered. One valid response is used per boot: the key made from it is kept
  in memory and given to each later connection on the socket. For the running system it leaves, in
  `/run/regalia`, `boot-session` and `boot-session.pub` (the session's ID and public key, written
  before the session's first quote is taken: the runtime leases of this boot are asked for under them)
  and `key-given-through` (the peer and keyslot). None is secret. systemd stops the process before
  switch-root; it zeroes the local half and the key (the session's private key ends with the process:
  Go keeps a copy of it that a program cannot reach). **If the client is
  started a second time in one boot** (it crashed, or was restarted by hand) it finds the first one's
  session on record and asks no peer, because a peer that recorded the first session refuses any
  other: that boot ends at the recovery-key prompt, and a reboot is a new boot with a new session.
  **A kexec is not a new boot for the TPM** (its counters and PCRs are not reset), so the peers refuse
  the new initrd's session and a kexec always ends at the recovery-key prompt; reboot instead.
  `systemctl soft-reboot` does not run the initrd again and keeps `/run/regalia`. **What remains
  open:** if `/run/regalia` cannot be written when the first quote is taken (a full `/run`) and the
  client then restarts in the same boot, the record can name a session one peer does not hold; that
  peer refuses this boot's leases until the next reboot. The client says so in the journal; it does
  not leave the disk locked for it.
- **The initrd** is built with dracut and the module `deploy/baremetal/initrd/dracut/90regalia-unlock`
  (`dracut --add regalia-unlock`): the client, the two units above, `regalia-wg-boot.service` with its
  script (the initrd ruleset first, then the declared address, then WireGuard with the WG-BOOT key
  systemd unsealed), `ip`, `wg`, `nft`, the network drivers, and one crypttab line, the same on every
  host: `root PARTLABEL=regalia-root /run/regalia-unlock/key.sock luks,x-initrd.attach` (the root
  volume is the GPT partition labelled `regalia-root`). **The image holds nothing per host**, so one
  image has one PCR 11 for every host. What differs per host and per manifest comes at boot as
  **system credentials**, which systemd-stub passes from the ESP (`loader/credentials/<name>.cred`,
  each measured into PCR 12):
  | credential | what | sealed |
  |---|---|---|
  | `regalia.unlock-local` | the local half | to the TPM (`unlock.seal_local`) |
  | `regalia.wg-boot-key` | the WG-BOOT private key | to the TPM |
  | `regalia.unlock-config` | `unlock.boot_config` | no |
  | `regalia.wg-boot-conf` | `bootnet.boot_wg_conf` | no |
  | `regalia.boot-nft` | `bootnet.boot_ruleset` | no |
  | `regalia.boot-env` | `BOOT_NIC`, `BOOT_ADDRESS`, `BOOT_GATEWAY`, `BOOT_TUNNEL` (read as data) | no |

  **Nothing in the initrd acts on a credential by name.** The image's command line (signed, in PCR 11)
  carries `systemd.import_credentials=no`: systemd imports no credential from any source, not the ESP,
  not SMBIOS type 11 or QEMU's fw_cfg (which nothing the peers attest measures), not the command line.
  The stub still unpacks the ESP's files into the initrd at `/.extra/global_credentials/`, and the two
  units read exactly their six by fixed paths there: the two sealed ones decrypted by systemd (a plain
  one is refused), the four others as data. A missing file keeps its unit from starting, and the
  console asks for the recovery key (within seconds in the boot test). Second layer, for an image built
  without that switch: the dracut module leaves out systemd-debug-generator (which makes units and
  drop-ins from credentials) and resets `ImportCredential=` for the tmpfiles, sysctl, journald,
  sysusers, udev rule-credential and systemd-cryptsetup services (the last imports `cryptsetup.*`: a
  planted passphrase would be tried before the key socket). It is partial: fstab-generator
  (`fstab.extra`; it mounts the root), the network generator and PID 1 itself are covered by the
  first layer only. A PE addon on the ESP could add a command line (systemd-stub appends it, and only
  PCR 12 changes); with Secure Boot on, the stub loads only addons signed by a key in db, and the
  peers refuse any changed PCR 12, so it gains no contribution. Enforcement of the switch in
  `uki.py build` is d9's follow-up. The boot test reads systemd's own message ("systemd.import_credentials=no
  is set") from the booted journal, and passes an extra unit through SMBIOS that is never started.
  The machine that builds the image needs no `/etc/regalia`, and the module takes nothing from it.

  **The ESP is a channel into the initrd, and PCR 12 is what judges it.** Whoever can write the
  ESP can add credentials of their own, and systemd in the initrd consumes some by name: a unit or a
  drop-in (`systemd.extra-unit.*`, `systemd.unit-dropin.*`), tmpfiles, sysctl and fstab lines. Sealed to
  this machine's TPM with an empty PCR policy, which needs only the TPM's public storage key, such a
  credential decrypts, and a drop-in on the unit that opens the disk could print the volume key, while
  PCR 11 is unchanged and the peers answer. This is systemd-stub's behaviour with or without the files
  here. What catches it is PCR 12: every credential is measured into it, so **the peers must attest PCR
  12 in the initrd phase**, against the value the node's credentials give: `espcreds.pcr12(files)`,
  the stub's own computation (one extend with the SHA-256 of a cpio archive of the files, sorted by
  name), shown equal to a real boot's. The boot test's peers do; a planted credential is refused.
  **Not every credential channel is measured**: SMBIOS type 11 strings and QEMU's fw_cfg reach PCR 1
  at most, through the firmware, which no peer attests. That is why systemd imports none (above); the
  boot test passes a unit drop-in through SMBIOS and it is not acted on.
  OPEN for production: the measurement set's PCR 12 per node, computed by a tool from the node's
  credentials (#66, d9), and the split decided on #66 (membership-derived data signed and verified in
  the initrd, B3).
  The image must be built with `dracut --no-hostonly --no-hostonly-cmdline` (the module refuses
  hostonly mode, which copies the build machine's identity and crypt settings into the image). The
  ruleset credential may hold only `table inet regalia_boot` and include no file; `down` flushes every
  table.
- **Shown on a real boot** (`e2e/unlock-boot-qemu.sh`: a Debian 13 guest in QEMU under UEFI (OVMF)
  with a software TPM, MEASURED BOOT of a unified kernel image built and signed by
  `deploy/baremetal/uki.py` with test keys, its disk an ESP and the LUKS2 partition, the peers reached
  over WireGuard):
  - enrolment: with no credential on the ESP the client gives nothing, the console asks "Please enter
    recovery key for disk regalia-root (root)", and the key opens the volume; the running guest seals
    the two boot credentials to its own TPM, to PCR 7 and to the image's initrd-phase signature of PCR
    11; its PCR 11 is the build record's booted-phase value, and its PCR 12 is zero;
  - unattended: systemd-stub passes the six credentials from the ESP, systemd unseals the two sealed
    ones in the initrd, the boot mesh comes up, a peer verifies the guest's quote of PCR 7, PCR 11
    (the record's initrd-phase value) and PCR 12, gives its half, and the root volume opens with
    nobody typing anything (about five seconds after the kernel started, in the runs so far); the
    booted PCR 12 is exactly what `deploy/baremetal/espcreds.py` computes from the ESP's files, and
    nothing moves it after the initrd; after switch-root the boot interface, its ruleset and its
    addresses are gone and the link is down;
  - a planted credential: one more file on the ESP (a unit drop-in for the unlock client, an extra
    unit, a tmpfiles line) changes PCR 12, and both peers refuse the quote, so the console asks;
  - no peer: the client gives nothing after its five rounds, and the console asks for the passphrase
    or recovery key, which opens the volume.
  NOT shown: Secure Boot (OVMF runs with no enrolled keys, so nothing checks the image's signature
  and PCR 7 says so), the membership-derived parts of the configuration verified in the initrd
  instead of passed as credentials (B3 on #66), a network card that udev renames in the initrd (the
  guest's is `eth0`), and any physical machine.
- **Reviewing an image.** What opens the root volume is decided inside the initrd, and the running host
  keeps no record of it: after switch-root the unit that opened the volume is no longer loaded (seen
  in the boot test). `/etc/crypttab` on the root is only what the initrd was built from, if it was
  rebuilt since the last edit. So it is checked on the image, before the image is approved:
  ```sh
  lsinitrd IMAGE | grep -E 'regalia|etc/crypttab|etc/cmdline\.d|usr/bin/(wg|nft)$'   # what it holds
  lsinitrd -f etc/crypttab IMAGE          # one entry: root PARTLABEL=regalia-root /run/regalia-unlock/key.sock luks,x-initrd.attach
  ```
  No file under `etc/cmdline.d` may configure LUKS (`rd.luks.*`), no other crypttab entry may name
  the root volume, and nothing may be under `etc/regalia`.
- **Enrolment** is an operator step between two running hosts; the recovery key authorizes adding the
  keyslot. Order: enrol the recovery key, enrol both peer paths, reboot once and see a peer unlock the
  disk, and only then wipe the TPM-only keyslot (`systemd-cryptenroll --wipe-slot=tpm2`).
- **`unlock.judge_tokens`** judges the LUKS2 header for the probe: one path per expected peer, each with
  a keyslot of its own, and no `systemd-tpm2` token left.

**A dependency this adds.** A peer helps only while it holds a live heartbeat from the revocation
authority (#69). If the authority is unreachable for longer than a heartbeat lives, a host that
reboots stays locked until someone types its recovery key. Where the authority runs and who is alerted
when heartbeats stop are decided before commissioning.

**The boot mesh (#66).** Unlock requests travel over WireGuard, and the network decides who can reach
a peer's unlock port at all (`deploy/baremetal/bootnet.py`, proven in network namespaces by
`e2e/wg-boot-netns.sh`):

- The site config's `boot_mesh` says where the nodes are (their addresses outside and inside the
  tunnel, the two ports). Which keys are WireGuard peers comes from the signed manifest only: a node
  that may no longer be unlocked leaves every peer's list with the manifest that says so.
- The booting node, in its initrd: interface `wg-boot` with its WG-BOOT key, and a default-deny ruleset
  that lets out WireGuard to the peers' declared addresses and the unlock port inside the tunnel.
- The running peer: interface `wg-unlock` with its WG-SERVICE key. The host firewall of section 3
  gains two openings: WireGuard from the peers' declared addresses only, and the unlock port inside the
  tunnel only. There is no SSH and no KMS port inside the tunnel.
- A valid key at an undeclared address gets no answer: that is the stolen server powered on elsewhere.
- **WG-BOOT is a transport identity, never an authorization.** Its key is sealed like the local half
  (PCR 7 and the signed PCR 11 policy), so a retired but signed image still brings the tunnel up. It is
  refused at attestation, by the peer, against current measurements.
- A WireGuard configuration is applied with its private key added in memory (`bootnet.with_key`),
  never without it: `wg syncconf` with a file that has no key unsets the interface's key.

**The service mesh (#80).** The running services of the three nodes talk over a second WireGuard
interface, `wg-svc` (the site config's `service_mesh`; it needs a `boot_mesh`, whose node ID and
underlay addresses it uses). Inside it every address is derived from a node's WireGuard key, in one
fixed prefix (`sitecfg.SERVICE_PREFIX`), so the site config names none of them. The host firewall gains,
and only with a `service_mesh`:

- WireGuard (its UDP port) with the peers' declared addresses, and the revocation authority's if one is
  configured;
- the sync port inside the tunnel, only between addresses of that prefix, in both directions;
- **nothing else on that interface**, IPv4 or IPv6, in or out: the rule that drops the rest of the
  interface comes before every zone rule, so a zone's address inside the tunnel opens nothing.

It is the only IPv6 the host carries. Proven by behaviour, with real WireGuard, in section 5 of
`e2e/baremetal-firewall-netns.sh`: a source outside the prefix, another port, the sync port on the
wire, a client-zone address inside the tunnel, and a valid key at an undeclared address each get
nothing.

Not there yet, so **nothing here is to be run on a KMS host**: measured boot with a unified kernel
image (a changed or retired initrd refused on a real boot), the commands an operator types to enrol a
host and to write the ESP credentials after each manifest, the long-running peer process, and every run on
a physical TPM, a DL360 (#65) or the real datacenter networks. Sections 3 to 5 above still describe
the single-site baseline (initramfs-tools, TPM-only crypttab); they change when this is commissioned.

## 8. The node's running services (three-site, #80): not commissioned yet

Four systemd units in `deploy/baremetal/units/`, all run from one configuration, `/etc/regalia/node.json`
(`deploy/baremetal/node.py`; schema `regalia.node/v1`, every field required):

| Unit | Runs as | Privilege | Does |
|---|---|---|---|
| `regalia-authtime` | root | none, no network | asks chrony every 15 s whether time is authenticated; writes `/run/regalia/authtime.json` |
| `regalia-wg-apply` (+ `.path`) | root | `CAP_NET_ADMIN` | makes `wg-svc` and `wg-unlock` what the current manifest says, reads them back, brings them up only then; re-run whenever the published chain changes |
| `regalia-admission` | root | none; IPv6 to the tunnel prefix only | holds the runtime lease, asking peers over the tunnel; writes `/run/regalia/admission.json` |
| `regalia-sync` | `regalia-sync` | none; the TPM through `tss` | answers peers and booting nodes, pulls manifests and heartbeats, keeps the membership store, runs the heartbeat watch |

- **One writer of the membership chain.** `regalia-sync` owns the store and publishes the verified chain
  (`/var/lib/regalia-sync/chain.json`, 0644). The root services verify that copy themselves against the
  root key and the TPM anchor: a `regalia-sync` that withholds or rolls back makes them refuse, so the node
  stops serving rather than serving under an old manifest.
- **The boot session** comes from the unlock client (`/run/regalia/boot-session` and `.pub`, #67); on a
  boot that opened the disk with the recovery key, `regalia-admission` makes one and writes the pair.
  Edge cases from the unlock side: an unwritable `/run` at the first quote followed by a client restart in
  the same boot can leave a record one peer does not hold until the next boot; a kexec always ends at the
  recovery prompt.
- `/run/regalia` is created by `regalia.tmpfiles.conf` when the unlock client did not run, and is never
  any unit's `RuntimeDirectory=` (systemd would remove it, boot session included, when that unit stops).
- Each unit's sandbox is pinned by `tests/test_baremetal_units.py`, including systemd's own
  `systemd-analyze verify` and an offline exposure score of at most 3.0.

**NOT BUILT: provisioning a node (#190).** Nothing writes a node's trust anchors yet. Until the enrolment
command exists they are placed by hand, as the end-to-end test does: the membership store's first
manifest (`/var/lib/regalia-sync/membership.json`, through `membership.Store.commit`, which also defines
and advances the TPM anchor), the heartbeat counter's NV index, the measurements document the manifest
commits to, each peer's AK in the attestation state (`attest.Verifier`), the WG-SERVICE private key
(`/etc/regalia/wg-service.key`, 0600), the site configuration with `boot_mesh` and `service_mesh`, and
`chrony.conf` as `authtime.conf()` renders it (the whole file).

**NOT BUILT: the revocation authority (#199).** Nothing signs heartbeats yet: a cluster run with these
units stops authorizing within the heartbeat lifetime, by design, until the authority exists.
