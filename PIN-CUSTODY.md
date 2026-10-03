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

The KMS host uses systemd encrypted service credentials sealed to its TPM 2.0 **and** to systemd's
host key on the encrypted root disk, together (see "Why the host key is in the seal" below). The encrypted
credential blobs live outside the repository under `/etc/credstore.encrypted/`; systemd decrypts
them only while starting `regalia-kms` and exposes them to that service under its private
`/run/credentials/regalia-kms.service/` directory. The daemon accepts only absolute credential
paths. It never accepts PIN values in JSON, environment variables, command arguments or logs.

`internal/pin.LockedFileSource` opens credentials with `O_NOFOLLOW|O_CLOEXEC`, verifies the opened
object is a root- or service-owned regular file with no group/world permission (the one POSIX ACL it
accepts is systemd's own: read for the service's user and nothing for anyone else, which is how
`LoadCredential`/`LoadCredentialEncrypted` deliver a credential to a unit with `User=`; that file
reads as mode 0440, and was refused until `e2e/kms-hardened-serve.sh` ran the daemon under the
shipped unit), bounds it to 64
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

The encrypted credential is created interactively on the target host with
`deploy/seal-hsm-pin.sh`, which **names the PCR set explicitly** and **names the credential**:

```sh
sudo deploy/seal-hsm-pin.sh --id hsm-site-a --serial DENK0404144 --pcrs "$KMS_CREDENTIAL_PCRS"   # --retries 10 is the default
```

It checks the card (attached, that serial, its FULL counter: `--retries`, default 10, the production
posture of a 10-digit PIN with a 10-try counter, regalia `PLAN.md` 1.3), takes the PIN hidden from the paper PIN
card, tests it on the card before sealing, reports the counter the card actually shows on a refusal,
decrypts the blob back before installing it, and keeps a replaced credential. Underneath it runs:

```sh
systemd-creds encrypt --with-key=host+tpm2 --tpm2-pcrs="$KMS_CREDENTIAL_PCRS" --name=hsm-site-a.pin \
  - /etc/credstore.encrypted/regalia-kms-hsm-site-a.pin
```

**`--name` is not optional.** systemd embeds a name in the blob and checks it against the
`LoadCredentialEncrypted=` ID. The command this document used to show named nothing, so the name
defaulted to the file name (`regalia-kms-hsm-site-a.pin`), which does not match the ID
`hsm-site-a.pin` in `deploy/systemd/regalia-kms-credentials.conf.example`, and the service died with
`243/CREDENTIALS` (measured, systemd 257, 2026-09-29). *Verified by:* the bench run of
`deploy/seal-hsm-pin.sh` recorded on regalia#20 (host key; a real TPM is #46's).

`$KMS_CREDENTIAL_PCRS` is the set chosen at commissioning and recorded, signed, as
`host.credential_tpm2_pcrs` in the commissioning evidence (`deploy/baremetal/evidence.py`; see below). The earlier version of this command
passed no `--tpm2-pcrs` at all, so the binding it produced was whatever the tool defaulted to, not a
recorded policy — while the text below it required binding to measured-boot PCRs. Do not pass the PIN
as an argument or environment variable to `systemd-creds`; it reads the credential from standard
input. Install the provided service drop-in only after its credential IDs match the non-secret device
IDs in the custody manifest. *Verified by:* `hsm-host-role/files/verify-deployment.py`, which requires
every `LoadCredentialEncrypted=` source to sit under `/etc/credstore.encrypted/regalia-kms-`.

## Binding the kernel as well: a signed PCR 11 policy

PCR 7 says which Secure Boot keys the firmware trusted, not which kernel and initrd ran. PCR 11 does,
for a Unified Kernel Image: systemd-stub measures each UKI section into it, and systemd-pcrphase the
boot phases. Bound **directly**, PCR 11 would strand the PIN at every kernel update, so
`seal-hsm-pin.sh` refuses it in `--pcrs`. It binds PCR 11 through a **signed** policy instead: the
TPM releases the PIN when PCR 11 holds *any* value signed by one PCR-signing key.

```sh
sudo deploy/seal-hsm-pin.sh --id hsm-site-a --serial DENK0404144 --pcrs 7 \
  --tpm2-public-key /run/systemd/tpm2-pcr-public-key.pem --tpm2-public-key-pcrs 11
```

- Each UKI is signed once, at build time, for its expected PCR 11 (`systemd-measure sign`, or
  `ukify build --pcr-private-key=…`, which embeds the signature); systemd-stub hands it to the
  running system as `/run/systemd/tpm2-pcr-signature.json`. A kernel update signed by the same key
  opens the same blob: nothing is re-sealed. A kernel nobody signed, one signed by another key, a
  changed PCR 7, or a boot phase the signature does not cover (the initrd, shutdown) does not.
- The key is RSA: the TPM policy systemd builds takes nothing else. The record prints its `pkfp`
  (SHA-256 of the PKCS#1 DER public key), the same fingerprint each signature file carries.
- Underneath, the key type is **`--with-key=host+tpm2-with-public-key`**. `--with-key=tpm2` and
  `--with-key=host+tpm2` accept `--tpm2-public-key` and `--tpm2-public-key-pcrs`, say nothing, and
  bind PCR 7 alone (measured, systemd 257, 2026-10-01 and 2026-10-02). So the script proves the
  binding by behaviour before it installs anything: the blob must open with the running boot's
  signature and must **not** open with a signature file that holds none.

### Why the host key is in the seal (#75)

A signed PCR policy has **no counter and no expiry**. The TPM checks that the current PCR 11 value
carries a signature by the PCR-signing key, and nothing else: every image that key ever signed
satisfies it for ever, including an old one with a known hole. systemd documents no revocation for
it; `systemd-creds` cannot use an NV-backed (`systemd-pcrlock`) policy at all, and where pcrlock can
be used (the LUKS token) it cannot be combined with a signed policy (systemd 257; sources read at
v255, v257, v258 and main). So a PIN sealed to the TPM alone can be opened on a stolen server booted
into any image that was ever signed.

The PIN is therefore sealed to the TPM **and** to systemd's host key
(`/var/lib/systemd/credential.secret`), which lives on the encrypted root disk. To open the PIN an
image must satisfy the TPM policy and also unlock the root disk. Retiring an image is then the root
disk's to enforce, in one place.

- A kernel update still needs no reseal: the host key does not change.
- The credential file copied onto another disk, in front of the same TPM, does not open.
- `seal-hsm-pin.sh` tries the sealed blob with the host key out of reach and installs nothing if it
  opens. `host_probe.py` fails a credential sealed to the TPM alone, and fails a host key that is not
  root's, mode 0400, on a filesystem with dm-crypt beneath it.
- **Losing the root disk loses the host key.** The PIN is then resealed from the PIN card, like after
  a TPM reset or a replaced board. The card is kept for this.
- The host key is a runtime credential: it is never in a backup or an export
  (`runtime_credentials_excluded_from_backup`).

*Verified by:* `e2e/pcr-signed-policy-swtpm.sh` section 8 (software TPM): the same blob opens on the
image it was sealed on and on an updated one; with another disk's host key, or none, it does not
open on either; and a TPM-only credential opens with no host key at all.

**BLOCKING FOR PRODUCTION, not done:** this moves the question to the root disk, and today the root
disk is unlocked by the local TPM alone, bound to PCR 7 (`root_disk_tpm_unlocked`). An old signed
image with the same Secure Boot state unlocks it, reaches the host key, and opens the PIN. The seal
is only as revocable as the disk unlock. The disk must need something a retired image cannot get: a
peer's contribution, given only to an image the membership manifest currently accepts (#66, #67), or
an NV-backed local policy. Until then a retired image is retired in name only. Tracked as #135, and
measured on every host: `host_probe.py` (`root_disk_unlock_revocable`) fails while a keyslot of the
root volume is released by a TPM token bound to PCR values or to a signed policy, and it cannot be
skipped.

### Migrating a credential sealed before this change

Every credential made by an earlier `seal-hsm-pin.sh` is sealed to the TPM alone, and
`pin_credentials_sealed_as_recorded` now reports it as a failure. There is no conversion: reseal.

1. Who: the operator who holds the sealed PIN card for that site, at the host's console, as root.
2. When: at commissioning (ceremony day, the step that seals each site's PIN), or, for a host already
   commissioned, at the next attended visit and before the host is counted as production.
3. How: `sudo deploy/seal-hsm-pin.sh --id <id> --serial <serial> --pcrs 7 [signed-policy options]
   --replace`, typing the PIN from the card (or `--from-blob`, if the ceremony's import blob for that
   host's TPM was kept). The script tests the PIN on the card first, keeps the old credential as
   `<file>.prev-<UTC time>`, and installs the new one in a single rename.
4. Then: `host_probe.py` must report `pin_credentials_sealed_as_recorded` true. Remove the `.prev-`
   file once it does: it is a TPM-only credential and opens without the host key.

The recorded binding (`host.credential_tpm2_pcrs` and the signed policy's two fields) does not change.

*Verified by:* `e2e/pcr-signed-policy-swtpm.sh` in CI (a software TPM, real `systemd-creds` and
`systemd-measure`, a stub card). **Not done yet (#57):** the PCR-signing key's custody (its private
half offline or in the HSM under the ceremony roots, ADR-0002 D19), signing the real UKIs, the same
policy for the root disk (`systemd-cryptenroll --tpm2-public-key=… --tpm2-public-key-pcrs=11`), and
measuring that policy on the disk. Until those land, production binds PCR 7 alone. The evidence
schema records the signed PCRs and the key's `pkfp` beside the directly bound PCRs, and
`host_probe.py` checks every installed PIN blob against that record
(`pin_credentials_sealed_as_recorded`).

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
   on the card, sealed, read back). A blob for another TPM, or altered, fails to decrypt **before any
   card is touched**: nothing is read from or tried on the card.

Typing the PIN from the PIN card stays as the fallback (re-sealing later, a host commissioned after
the ceremony). Proven on DENK0404144 with two software TPMs as the two hosts:
`e2e/nitrokey-pin-import-drill.sh` (14/0, 2026-10-01).

## Power cuts and the TPM's own lockout

The TPM has a retry counter of its own, separate from the card's: its dictionary-attack counter. A
power cut feeds it. When a key subject to that protection was used since the last start and the TPM
then loses power with no `TPM2_Shutdown`, it adds one failed try at the next start; at its limit it
refuses every protected key until tries heal. A KMS host uses such a key at every boot: systemd
unseals the PIN credential through a primary key it creates each time (the sealed object itself is
exempt; the primary is not, and `systemd-creds` has no option for it). So a run of power cuts ends
with the PIN not released, and the KMS not back, with nobody having typed anything wrong.

Decisions (#57, 2026-10-02):

- **The settings are commissioned, not left to the vendor's defaults:** 32 failed tries before
  lockout, one try forgiven every 600 s, 86400 s of lockout-hierarchy recovery
  (`deploy/baremetal/tpm-lockout.sh --set`). 31 cuts in a row are survived; counted tries heal on
  their own, one every 10 minutes.
- **The lockout authorization is set, and is a ceremony secret.** It is what changes these settings
  or clears the counter. Empty, anyone on the host can. It is generated and escrowed with the other
  ceremony secrets and typed at the console; it is never stored on the host. A wrong one blocks the
  lockout hierarchy for a day, which is the TPM protecting it.
- **The PIN import key and its parent are created `noda`.** The key has no authorization value to
  guess (anyone on the host may ask it to decrypt; its protection is that only this TPM can), so the
  counter guards nothing there and would only add a way to lock the host out.

*Verified by:* `e2e/tpm-lockout-swtpm.sh` in CI (software TPMs: the settings, drift, a wrong
authorization, the `noda` key across four power cuts with a control, one try counted per cut after
an unseal, healing, and the PIN refused at swtpm's default limit of 3); `host_probe.py`
(`tpm_lockout_policy`, `pin_import_key_present`) on the host. **Not verified: any physical TPM.** The
DL360's defaults, and whether its firmware counts a real power cut the same way, are a PoC still to
run (#57).

## The disk recovery key

Each KMS host's encrypted root has one keyslot that needs neither its TPM nor a peer: the **recovery
key** (#77, Phase 17). It exists for the cases the unattended paths cannot cover: a total outage of
all three sites (threat model A3), a host whose TPM or measured-boot policy no longer releases the
disk, or a node with no healthy peer.

Decisions (#77, 2026-10-02; regalia-kms-24 under the owner's delegation):

- **It adds a disk-only recovery secret. It does not change the 4-of-6 ceremony recovery.** The k-of-n
  shares still guard the HSM keys and the payload; the recovery key opens one host's disk and nothing
  else. A 2-of-3 scheme is a later experiment that needs its own approval (17.4).
- **What it opens, and what it does not.** With the disk open the host can boot. The HSM keys are
  still in the HSM, the HSM PIN is still sealed to the TPM (or typed from the PIN card), membership
  still decides whether peers accept the node, and serving still needs a lease. The recovery key
  restores a disk; it is not signing authority, membership authority or an HSM credential.
- **One per host**, so one envelope reaches one host. It is generated at the ceremony (step 0), in
  systemd's recovery-key format: 256 bits as 8 groups of 8 letters from `cbdefghijklnrtuv`, with a
  dash between groups. Those letters sit on the same keys of the common keyboard layouts, which
  matters at a boot prompt. The dashes are part of the key and it is lower case.
- **Custody.** On paper, on the KMS host recovery card, in its own sealed tamper-evident envelope
  in the Owner's safe: apart from every site and apart from the servers, because unlike everything
  else on a host this one secret is enough for its disk. It is also in the tier-0 payload and in
  every PIN escrow, so a lost card is recovered through k shares. It is never stored on a host and
  never typed anywhere but that host's console.
- **When it is used.** By the Owner, at the host's console, when no unattended path can unlock it.
  Every use is recorded as an incident (who, when, which host, why).
- **Using it spends it.** A key that was typed at a console has been seen. After any use, a
  rehearsal included, a new key is generated and escrowed, and `recovery-key.sh --replace` enrols it
  and destroys the used keyslot. A broken envelope seal is treated the same way.
- **Nothing weaker stays beside it.** Commissioning wipes the installer's passphrase once the TPM
  and the recovery key are proven; `root_disk_recovery_keyslot` fails while a keyslot that no token
  names remains.

*Verified by:* `tests/test_baremetal_recovery_key.py` (a real LUKS2 header in a file: enrolment, the
refusals, replacement, no secret on a command line), `lab/recovery/matrix.py` (every cryptsetup call
and every header sync inside it under KILL, TERM and a failing write: a key on a card always opens,
the state printed is the header's, and the same command finishes the run) and `e2e/luks-recovery-key.sh` in CI (a real
dm-crypt volume on a loop device: every other keyslot destroyed, the recovery key alone opens and
mounts it; a wrong key, one wrong letter, no dashes, other grouping and capitals do not);
`host_probe.py` (`root_disk_recovery_keyslot`) on the host. **Not verified: any KMS host, a real boot
prompt, or the physical custody procedure.** The rehearsal with the envelope, the safe and a
witness (PoC 17.1 proper) is the Owner's to run.

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
happened. Production requires that the KMS is the only PIN presenter on the host. *Verified by:*
the host tier, in part (`token_clients_root_only` in `deploy/baremetal/host_probe.py`). It measures
two things: every token client tool on `PATH` is `root:root` and not executable by anyone else, so
the KMS user cannot run one; and every process connected to pcscd **when the probe runs** is the KMS
binary. It does not exclude root, who seals PINs with these tools (`seal-hsm-pin.sh`), and it does
not watch pcscd between measurements. The staging bench does not meet this rule, by design: the CI battery and
bench tooling share its cards.

## Recovery and rollback limits

A discrete TPM 2.0 keeps the sealed PIN from anyone who takes the disks. It does not protect a
running host from its own root, who can read the daemon's memory, and it travels with the machine:
whoever has the whole server has the TPM too. Therefore:

- **Never back up, snapshot or image the host; the encrypted PIN blobs stay on it.** The only thing
  carried off a host is the control-plane export, which excludes them
  (`deploy/baremetal/README.md`, Backups). *Verified by:* the evidence tier —
  `runtime_credentials_excluded_from_backup` is attested in the signed commissioning evidence. It is
  not measured.
- **Disable suspend and hibernation.** *Verified by:* the host tier (`hibernation_disabled`,
  `deploy/baremetal/os_probe.py`).
- **Seal credentials to an explicit PCR set and record that set during commissioning.** *Verified
  by:* the evidence tier for the record (`host.credential_tpm2_pcrs`, and the signed policy's two
  fields, signed with the rest of the evidence), and the host tier for the blob:
  `pin_credentials_sealed_as_recorded` reads the header of every installed PIN blob and fails unless
  it carries exactly the recorded binding.
- **Rollback detection — narrower than it looks.** This rule used to say "alert off-host on
  rollback". No alert rule for rollback exists, and the word overstated what the repository does. What
  exists is a **refusal at the next start**: `audit.ReconcileContinuity` compares the local journal
  with the off-host collector's committed head, and refuses a host holding less history than it
  already shipped. A whole-disk restore rolls the journal and its marks back together — the case every
  on-host check passes — and is caught that way.
  *Verified by:* `TestReconcileRefusesAJournalHoldingLessThanTheCollectorRemembers`.
  Two limits:
  - It holds **only when an audit sink is configured**. A journal-only host has nothing to reconcile
    against, and `README.md` records that no production off-host sink is configured today.
  - It does not use the TPM. The fencing epoch in a TPM monotonic counter and audit checkpoints in
    an NV index (ADR-0002 D21) are not built, so a restored disk is caught by the collector or not
    at all.
- **Keep a separately sealed encrypted credential export in the k-of-n recovery kit (4-of-6 by default)** so a rebuilt
  host can reseal it to a replacement TPM without requiring the failed primary HSM. *Verified by:*
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
binding, and the PCR set in particular, is still #46's to prove on the target host.

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
| the host is never imaged; credentials excluded from the control-plane export | evidence (`runtime_credentials_excluded_from_backup`, attested, not measured) |
| no hibernation, no core dumps, swap off or encrypted | host (`deploy/baremetal/os_probe.py`) |
| the KMS is the only PIN presenter | host, in part (`token_clients_root_only`): token client tools are root-only and pcscd's clients are the KMS **at measurement time**; root is not excluded, and nothing watches between measurements |
| PCR set chosen and recorded | evidence (`host.credential_tpm2_pcrs` and the signed policy's two fields) |
| blob actually sealed to the recorded PCR set, signed policy and key; to the host key AND the TPM, never either alone; the host key root's, 0400, on dm-crypt | host (`host_probe.py`, `pin_credentials_sealed_as_recorded`, read from each blob's header) |
| the PIN does not open without the host key (another disk, or none), on the sealed image or an updated one | CI, software TPM (`e2e/pcr-signed-policy-swtpm.sh`, section 8); **no real host yet** |
| a retired image cannot unlock the root disk, so cannot reach the host key | host (`host_probe.py`, `root_disk_unlock_revocable`: **fails on every host enrolled with `--tpm2-pcrs=7`**, by design, #135). The mechanism is not built; an NV-backed policy retires an image on a software TPM (`e2e/pcrlock-luks-swtpm.sh`) |
| signed PCR 11 policy: opens across a signed kernel update, refused otherwise | CI, software TPM (`e2e/pcr-signed-policy-swtpm.sh`); **no real host yet** |
| whole-disk rollback refused at next start | unit — **only with an audit sink configured** |
| rollback counters in the TPM (fencing epoch, audit checkpoints; ADR-0002 D21) | **none** (not built) |
| sealed export in the recovery kit; no Nitrokey-wrapped YubiKey PIN | **none** (prose) |
| AC4 drills | **not performed** |
| Nitrokey token flags legible after login | staging SC-HSM code path only (D1: not the Nitrokey) |
