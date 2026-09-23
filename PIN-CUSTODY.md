# Unattended device PIN custody

**Status: mechanism selected and built; production posture NOT decided.** The mechanism below was
selected on #20 (2026-09-03) and is what the daemon implements. Two things it does not yet have, both
recorded on #20 as decisions for the project owner:

- **The production posture.** `doc/REQUIREMENTS.md`, which wins conflicts, currently says both
  that each site's PIN is "TPM-sealed" and that production "already chose — an operator enters the
  PIN at boot rather than sealing it for unattended use".
- **Threat-model approval.** ADR-0001 requires the unattended YubiKey PIN bootstrap to be "approved
  by the threat model before production". `doc/HSM-THREAT-MODEL.md` does not yet evaluate it.

Every rule below says which tier verifies it. A rule no tier verifies says so.

## Which devices hold a static PIN at all

**Nitrokey (SmartCard-HSM).** The 2026-08-01 ratification of 2-of-3 public-key authentication
(decision D2 / requirement B8; `doc/HSM-THREAT-MODEL.md`, `doc/HSM-KMS-DEPLOYMENT.md`) **replaces the
static user PIN at both production sites.** It is ratified, not built: nothing in `internal` or
`cmd` implements it. Until it is, the daemon gives the Nitrokey a static PIN through the mechanism
below, and that is an interim, not the production design.

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
and this document's question survives PKA **for the YubiKey only**. That conclusion comes from the
library's surface, not from the PIV specification or a card.

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

The encrypted credential must be created interactively on the target guest, **naming the PCR set
explicitly**:

```sh
sudo systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs="$KMS_CREDENTIAL_PCRS" \
  - /etc/credstore.encrypted/regalia-kms-hsm-sitea.pin
```

`$KMS_CREDENTIAL_PCRS` is the set chosen at commissioning and recorded, signed, as
`guest.credential_tpm2_pcrs` in the Proxmox evidence (see below). The earlier version of this command
passed no `--tpm2-pcrs` at all, so the binding it produced was whatever the tool defaulted to, not a
recorded policy — while the text below it required binding to measured-boot PCRs. Do not pass the PIN
as an argument or environment variable to `systemd-creds`; it reads the credential from standard
input. Install the provided service drop-in only after its credential IDs match the non-secret device
IDs in the custody manifest. *Verified by:* `hsm-host-role/files/verify-deployment.py`, which requires
every `LoadCredentialEncrypted=` source to sit under `/etc/credstore.encrypted/regalia-kms-`.

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
- **Keep a separately sealed encrypted credential export in the 4-of-6 recovery kit** so a rebuilt
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

**Bench substitute:** the qube has no TPM2, so the drill seals with systemd's host key. The TPM
binding, and the PCR set in particular, is still #46's to prove on the target guest.

Before that, the only credential drill recorded was `doc/drills/2026-08-01-so-pin-reset.md`. It ran on a Pico
and says itself that its firmware conclusion does not transfer; under D1 it informs no production
decision. Software and emulator results are not physical evidence.

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
