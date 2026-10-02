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
    peer that holds a path; the enrolment exists in `deploy/baremetal/unlock.py`, its boot-time client
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
  with a new key from a new escrow.
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
  brings its own client is caught by the pcscd check only while it is connected; restricting pcscd
  access with a polkit rule (root and the KMS user only) is recommended on top.
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
  `python3 -m deploy.baremetal.admission` shows what the daemon currently reads. The call from the
  lease service to a peer is not shipped yet (#80). Where admission is required, a token that was
  absent (removed and returned, or the daemon restarted) serves again only once the node holds a lease
  it asked for after the token was back: until the lease service's next renewal that binding is
  unavailable and the daemon is not ready. Measured: `kms_runtime_admission_required` (the
  configuration the unit starts the daemon with says `"required"`; `"disabled-for-lab"` fails it).

### Host firewall (default deny, both directions)

The site config (`site.example.json`, validated by `sitecfg.py`) declares the host's address, the
KMS and SSH ports, the zones allowed to reach each, and the only destinations the host may reach
(the audit and NTP sinks at least). From it:

```sh
install -d -m 0755 /etc/nftables.d
# Render to a name the *.nft include never matches, validate, load, and only then replace the fragment:
# a bad config or a failed render leaves the previous, working ruleset in place at the next boot.
tmp="$(mktemp /etc/nftables.d/.regalia-kms.XXXXXX)"
if python3 deploy/baremetal/firewall.py site.json > "$tmp" && nft -c -f "$tmp" && nft -f "$tmp"; then
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
python3 deploy/baremetal/network_probe.py site.json --role client --source-ip <a client address>
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
4. **Attestation key (three-site, #65):** `python3 deploy/baremetal/attest.py node-init --out DIR`
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

Each node has one accepted set, or two while an update is under way. An update is three documents:

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
sudo python3 deploy/baremetal/host_probe.py --evidence E.json --signature E.json.sig \
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
- **The pre-root client** (`cmd/regalia-unlock`, a static Go binary; `unlock.py` also holds a
  reference client that the tests use and that is not shipped). It holds no manifest and makes no
  membership decision. It runs no other program and writes no file:
  - systemd unseals the local half with the TPM and passes it as the unit's credential
    `regalia-unlock-local` (`LoadCredentialEncrypted=`);
  - the client reads the LUKS2 header for the peer paths, asks the peers of its boot configuration in
    turn (`unlock.boot_config`: node ID, disk, PCRs to quote, and each peer's address and TPM key
    names), for a bounded number of rounds;
  - it gives the derived key to systemd-cryptsetup over the socket that crypttab names as the key
    file. If no peer helps, it gives nothing and the console asks for the recovery key (section 3).
- **Enrolment** is an operator step between two running hosts; the recovery key authorizes adding the
  keyslot. Order: enrol the recovery key, enrol both peer paths, reboot once and see a peer unlock the
  disk, and only then wipe the TPM-only keyslot (`systemd-cryptenroll --wipe-slot=tpm2`).
- **`unlock.judge_tokens`** judges the LUKS2 header for the probe: one path per expected peer, each with
  a keyslot of its own, and no `systemd-tpm2` token left.

**A dependency this adds.** A peer helps only while it holds a live heartbeat from the revocation
authority (#69). If the authority is unreachable for longer than a heartbeat lives, a host that
reboots stays locked until someone types its recovery key. Where the authority runs and who is alerted
when heartbeats stop are decided before commissioning.

Not there yet, so **nothing here is to be run on a KMS host**: WireGuard before root under the TCP
transport (#66), the systemd units and the initramfs that start the client, the operator commands, and
every run on a physical TPM or a DL360 (#65).
