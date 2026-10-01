# Unattended device PIN custody

**Status: mechanism selected, built and drilled on both device kinds; the production posture is
decided.** The mechanism below was selected on #20 (2026-09-03) and is what the daemon implements.
**ADR-0002 D2** decided the posture: the PIN is unattended and TPM-sealed, and no operator enters a
PIN at boot (`doc/REQUIREMENTS.md` said both; it now says this). One item stays open:

- **Threat-model approval.** ADR-0001 requires the unattended YubiKey PIN bootstrap to be "approved
  by the threat model before production". `doc/HSM-THREAT-MODEL.md` does not yet evaluate it.

Every rule below says which tier verifies it. A rule no tier verifies says so.

## Which devices hold a static PIN at all

**Nitrokey (SmartCard-HSM).** A static user PIN, through the mechanism below, **is the production
design.** The 2026-08-01 ratification of 2-of-3 public-key authentication (B8) was reversed by
**ADR-0002 D4**: no PKA at runtime; the quorum stays on restore and the ceremony. What bounds a stolen
card is therefore the user-PIN retry counter, and that bound holds only if the SO-PIN cannot reset the
user PIN: a card initialised with `sc-hsm-tool --initialize` lets the SO-PIN alone set a new user PIN
and use every key (measured on a Nitrokey, DENK0404144, 2026-09-29, regalia#11), so production cards
are initialised with `hsm-init-hardened.sh --rrc off`. *Verified by:* the Nitrokey drill below.

**YubiKey PIV.** PKA does not apply. PIV has no public-key authentication that authorizes use of a
private key. The PIV library this repository uses, piv-go v2.6.0, authorizes a private-key operation
through `KeyAuth` in exactly these ways:
- a static PIN, or an interactive PIN prompt;
- biometric verification under the `Match*` PIN policies (YubiKey Bio), which needs a finger and
  therefore a person;
- `pin_policy: never`, meaning no authorization at all, which the device supports and
  `registry.validateBinding` deliberately refuses.

Its other authentication paths — the management key's challenge-response, PUK unblock — authorize
administration, not key use. So for the unattended YubiKey the PIN is the only admissible credential,
so for both device kinds the static PIN is the credential this document protects. That conclusion
comes from the library's surface, not from the PIV specification or a card.

## Decision

The KMS guest uses systemd encrypted service credentials sealed to the guest TPM2. The encrypted
credential blobs live outside the repository under `/etc/credstore.encrypted/`; systemd decrypts
them only while starting `regalia-kms` and exposes them to that service under its private
`/run/credentials/regalia-kms.service/` directory. The daemon accepts only absolute credential
paths. It never accepts PIN values in JSON, environment variables, command arguments or logs.

`internal/pin.LockedFileSource` opens credentials with `O_NOFOLLOW|O_CLOEXEC`, verifies the opened
object is a root- or service-owned regular file with no group/world permission, bounds it to 64
printable bytes, locks its pages with `mlock`, and returns a fresh buffer for one operation. Both
providers zero and `munlock` that buffer through `Release` immediately after login and operation.
Failure to lock or release memory fails the operation closed. *Verified by:* unit tests in
`internal/pin` (`TestLockedFileSourceRejectsUnknownLooseSymlinkedAndMalformedCredentials`,
`TestTheCredentialMustBeBetweenSixAndSixtyFourBytes`,
`TestACredentialThatIsNotARegularFileIsRefused`). Two of its refusals need an environment only CI
provides, and CI sets a variable that turns a skip there into a failure.
`TestACredentialWhosePagesCannotBeLockedIsRefused` needs Linux, where a lowered `RLIMIT_MEMLOCK` makes
`mlock` fail; it runs in the ordinary test step. `TestACredentialOwnedByAThirdUserIsRefused` also needs
root, to create a file owned by a third user, and runs in a separate step under `sudo`.

The encrypted credential is created interactively on the target guest with
`deploy/seal-hsm-pin.sh`, which **names the PCR set explicitly** and **names the credential**:

```sh
sudo deploy/seal-hsm-pin.sh --id hsm-site-a --serial DENK0404144 --pcrs "$KMS_CREDENTIAL_PCRS"   # --retries 10 is the default
```

It checks the card (attached, that serial, its FULL counter: `--retries`, default 10, the production
posture of a 10-digit PIN with a 10-try counter, regalia `PLAN.md` 1.3), takes the PIN hidden from the paper PIN
card, tests it on the card before sealing, reports the counter the card actually shows on a refusal,
decrypts the blob back before installing it, and keeps a replaced credential. Underneath it runs:

```sh
systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs="$KMS_CREDENTIAL_PCRS" --name=hsm-site-a.pin \
  - /etc/credstore.encrypted/regalia-kms-hsm-site-a.pin
```

**`--name` is not optional.** systemd embeds a name in the blob and checks it against the
`LoadCredentialEncrypted=` ID. The command this document used to show named nothing, so the name
defaulted to the file name (`regalia-kms-hsm-site-a.pin`), which does not match the ID
`hsm-site-a.pin` in `deploy/systemd/regalia-kms-credentials.conf.example`, and the service died with
`243/CREDENTIALS` (measured, systemd 257, 2026-09-29). *Verified by:* the bench run of
`deploy/seal-hsm-pin.sh` recorded on regalia#20 (host key; a TPM guest is #46's).

`$KMS_CREDENTIAL_PCRS` is the set chosen at commissioning and recorded, signed, as
`guest.credential_tpm2_pcrs` in the Proxmox evidence (see below). The earlier version of this command
passed no `--tpm2-pcrs` at all, so the binding it produced was whatever the tool defaulted to, not a
recorded policy — while the text below it required binding to measured-boot PCRs. Do not pass the PIN
as an argument or environment variable to `systemd-creds`; it reads the credential from standard
input. Install the provided service drop-in only after its credential IDs match the non-secret device
IDs in the custody manifest. *Verified by:* `hsm-host-role/files/verify-deployment.py`, which requires
every `LoadCredentialEncrypted=` source to sit under `/etc/credstore.encrypted/regalia-kms-`.

## Delivering the PIN to the host's TPM without typing it (TPM import)

The ceremony runs on an air-gapped laptop; the PIN must reach each KMS host's TPM. Instead of typing
it at the site, it travels **encrypted to a key that lives only in that host's TPM**:

1. **Commissioning, on the host:** `sudo deploy/seal-hsm-pin.sh --init-import-key` creates an
   RSA-3072 decryption key inside the TPM (`fixedTPM`, `fixedParent`, `sensitiveDataOrigin`: made
   there, never leaves), persists it (default handle `0x81000101`) and writes its public key and
   SHA-256 fingerprint. Copy the fingerprint by hand from the console.
2. **Ceremony, on the laptop:** step 0 checks the public key against that fingerprint and encrypts
   the site's PIN to it (RSA-OAEP, SHA-256). The blob is safe on any medium.
3. **On the host:** `sudo deploy/seal-hsm-pin.sh --id … --serial … --pcrs … --from-blob pin-<site>.blob`.
   The TPM decrypts it; then every check of the typed path runs (card serial, full counter, PIN tested
   on the card, sealed, read back). A blob for another TPM, or altered, fails to decrypt **before PIN
   verification**: the card's serial and counter are read, but no PIN try is spent.

Typing the PIN from the PIN card stays as the fallback (re-sealing later, a host commissioned after
the ceremony). Proven on DENK0404144 with two software TPMs as the two hosts:
`e2e/nitrokey-pin-import-drill.sh` (14/0, 2026-10-01).

## Retry circuit breaker

Both providers refuse to present a PIN when the card reports one or zero remaining attempts, latch the
device on any login error, and have no time-based reset. An operator must inspect the physical device
and credential version independently, then explicitly reset the in-process latch or restart after
correcting the credential. This stops a stale or wrong sealed credential from exhausting the token by
automatic restart or retry. *Verified by:* unit tests in both providers, including
`TestPINFailureAndLowRetryCountPreventRepeatedLogin`.

**How the retry count is read differs by device, for a reason in the protocol:**

- **YubiKey PIV (#405, #407, #442).** The count is read with an empty VERIFY (piv-go `ykPINRetries`:
  `INS 0x20, P2 0x80`, no data), which spends no attempt. Once *this* provider has logged in, the card
  answers that query with success instead of a count, so the count becomes **illegible — not zero**.
  The provider therefore asks the card first and falls back to its last legible reading only when the
  card cannot answer. A failed read never overwrites that reading, a device with no reading is refused
  with no PIN presented, and a rejected login forgets the reading rather than decrementing it.
  *Verified by:* `TestALegibleNearLockoutCountOverridesAStaleCachedReading` (the card wins over a stale
  reading) and `TestRepeatedOperationsUseTheLastSuccessfulPreLoginRetryReading` (the fallback keeps
  repeated operations working). Each is the sole failure under the mutation that reverts it.
  **The verified state also outlives the connection** (measured 2026-09-23 on 5.7.4). A PC/SC
  disconnect leaves the card as it was, so the NEXT connection, from any process, inherits the
  verification. It reads no count, and it can use a PIN-policy-ONCE key without the PIN. The driver
  therefore clears the PIV security status (an applet switch) when it opens a session, refusing the
  session if it cannot, and again when it closes one. *Verified by:*
  `TestPIVPhysicalSessionNeitherInheritsNorLeavesPINVerification` (physical, `piv` tag), which failed
  on the driver before the fix.
- **Nitrokey (PKCS#11 token flags).** The provider reads the count on every operation and refuses when
  the read fails, with no fallback. On the staging bench's SmartCard-HSM code path, the token flags
  stayed legible after login across repeated operations (measured 2026-09-14). Under D1 that is a measurement of the code
  path on a Pico, **not of the Nitrokey device**.

**One card, one PIN presenter.** Any other process that presents a PIN to the same card — a CI
battery run, `ykman`, a second daemon — inherits both behaviours above. Its rejected VERIFY
de-authenticates the card and can spend attempts this provider did not spend; that is how #442
happened. Production requires that no other token client exists on the guest. *Verified by:* the
Proxmox evidence tier (`direct_token_clients_absent`), which checks a signed description of the
guest, not the guest itself. The staging bench does not meet this rule, by design: the CI battery and
bench tooling share its cards.

## Proxmox and recovery limits

A virtual TPM narrows offline disk theft; it does not protect a running guest from Proxmox root,
which can inspect guest memory or roll back VM and vTPM state. Therefore:

- **Exclude the encrypted PIN blobs and vTPM state from ordinary Proxmox backup/snapshot jobs.**
  *Verified by:* the evidence tier — `deploy/proxmox/verify.py` refuses VM snapshots, any backup
  job including the VMID, and `runtime_credentials_excluded_from_backup` not proven.
- **Disable live migration and suspend/hibernate for the KMS VM.** *Verified by:* the evidence tier
  (`live_migration_allowed`, `hibernation_disabled`).
- **Seal credentials to an explicit PCR set and record that set during commissioning.** The *record*
  is verified: evidence schema v4 requires `guest.credential_tpm2_pcrs` as a non-empty list of distinct
  PCR indices 0–23, signed with the rest of the evidence. **Not verified by any tier here: that the
  blob installed on the guest is actually sealed to the recorded set.** That is a property of a file
  inside the guest, which neither the evidence verifier nor the host role inspects. Choosing the set is
  a per-site commissioning decision; this document does not choose it.
- **Rollback detection — narrower than it looks.** This rule used to say "alert off-host on VM/vTPM
  rollback". No alert rule for rollback exists, and the word overstated what the repository does. What
  exists is a **refusal at the next start**: `audit.ReconcileContinuity` compares the local journal
  with the off-host collector's committed head, and refuses a host holding less history than it
  already shipped. A whole-guest restore rolls the journal and its marks back together — the case every
  on-host check passes — and is caught that way.
  *Verified by:* `TestReconcileRefusesAJournalHoldingLessThanTheCollectorRemembers`.
  Two limits:
  - It holds **only when an audit sink is configured**. A journal-only host has nothing to reconcile
    against, and `README.md` records that no production off-host sink is configured today.
  - A rollback of **vTPM state alone**, without the disk, is not detectable by anything in this
    repository. It is mitigated by the snapshot and backup prohibitions above, not detected.
- **Keep a separately sealed encrypted credential export in the k-of-n recovery kit (4-of-6 by default)** so a rebuilt
  guest can reseal it to a replacement TPM without requiring the failed primary HSM. *Verified by:*
  nothing — prose only.
- **Never use the Nitrokey to wrap the YubiKey fallback PIN**, which would make fallback depend on the
  failed primary. *Verified by:* nothing — prose only.

Rotation is create-new-blob, verify retry metadata, stop KMS, atomically install the encrypted blob,
start, perform one bounded health/sign test, and retain the previous blob only in the witnessed
recovery package.

**Host rebuild, token replacement, HSM outage, rotation and total-loss drills (#20 AC4) were run on
the staging bench on 2026-09-23** (`e2e/yubikey-pin-custody-drill.sh`, daemon half
`TestYubiKeyPINCustodyDrill` run as a transient systemd service with `LoadCredentialEncrypted=`, on
YubiKeys 36345471 and 36344616; record in regalia `doc/drills/`).
- A stale credential after a card-PIN rotation spent **exactly one** retry and latched.
- A credential whose host key is gone makes systemd refuse the service (exit 243) **before any PIN
  is presented**.
- The recovery kit reseals on a new host.
- With the Nitrokey de-authorised, YubiKey custody still serves.
- An absent token is refused with no PIN presented.
- The replacement token serves with its own credential.

**The same drill on a Nitrokey passed on 2026-09-29** (`e2e/nitrokey-pin-custody-drill.sh`, daemon
half `TestNitrokeyPINCustodyDrill` through the production driver `NewPKCS11DriverWithProbes`, as a
transient systemd service with `LoadCredentialEncrypted=`, on DENK0404144 initialised with
`hsm-init-hardened.sh --rrc off`; record on regalia#20):
- R: a stale credential after a card-PIN rotation spent **exactly one** retry (3 → 2) and latched; the
  rotated credential served and a correct PIN restored the counter to 3.
- H: with the host key gone, systemd refused the service (exit 243) before any PIN was presented; the
  recovery kit resealed on the "new host" and served.
- O: the card de-authorised on USB was absent and refused with no PIN presented; back, it served.
- T: total loss (host key gone, recovery kit and break-glass only) resealed and served.
- The card's own PIN was put back and the drill key removed; the transcript holds no PIN.
- Run twice: at 3 tries with a 6-digit PIN, and at the **production posture** (10-digit PIN, 10
  tries): there the stale credential took the counter 10 → 9, and the correct PIN restored 10.
- A rotated PIN must keep the card's PIN length: the 10-digit card refused an 8-digit new PIN with
  `CKR_DATA_INVALID`, spending nothing. The drill rotates to a same-length PIN.
- The counter is the low nibble of `63Cx` **in hex** (a 10-try card answers `63CA`); both the drill
  and `seal-hsm-pin.sh` decode it to decimal and compare it with the card's full count, never with 3.
- Not run: **Y** (replacement), which needs a second card attached (`… <primary> <replacement>`).

**Bench substitute:** the qube has no TPM2, so both drills seal with systemd's host key. The TPM
binding, and the PCR set in particular, is still #46's to prove on the target guest.

Before these, the only credential drill recorded was `doc/drills/2026-08-01-so-pin-reset.md`, on a Pico.
Its central finding (the SO-PIN alone resets the user PIN on a default-initialised card) was
re-measured on a Nitrokey on 2026-09-29 and holds there too (regalia#11). Software and emulator
results are not physical evidence.

## Which tier verifies each rule

| Rule | Tier |
|---|---|
| paths only, `O_NOFOLLOW`, regular file, owner/mode, ≤64 printable, `mlock`/`munlock` | unit (`internal/pin`) |
| mlock refusal | CI, Linux |
| third-uid owner refusal | CI, Linux, as root |
| refuse at ≤1, latch on login failure, no timed reset | unit, both providers |
| YubiKey: card-first retry read, legible reading as fallback | unit, falsified per ordering |
| credential drop-in sources under `/etc/credstore.encrypted/regalia-kms-` | host (`hsm-host-role/files/verify-deployment.py`) |
| no snapshots/backups/live migration/hibernation; credentials excluded from backup; no other token client | evidence (signed JSON, not the VM) |
| PCR set chosen and recorded | evidence (schema v4) |
| **blob actually sealed to the recorded PCR set** | **none** |
| whole-guest rollback refused at next start | unit — **only with an audit sink configured** |
| **vTPM-only rollback** | **none** (mitigated, not detected) |
| sealed export in the recovery kit; no Nitrokey-wrapped YubiKey PIN | **none** (prose) |
| AC4 drills | **not performed** |
| Nitrokey token flags legible after login | staging SC-HSM code path only (D1: not the Nitrokey) |
