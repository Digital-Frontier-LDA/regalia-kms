# Limited OpenPGP compatibility

## Decision

ADR-0001 §4 allocates the YubiKey OpenPGP applet to **unavoidable legacy card integration** and to
nothing else. This document states what that allows, and `internal/backend/openpgp` enforces
it. Where the two disagree, the package is right and this file is stale — every limit below is
asserted by a test, and the tests are named beside each rule so a reader can check rather than
trust.

The applet is not the default abstraction and is not eligible to become one. Its key roles are
fixed in the card, its PIN behaviour differs from PIV in a way a custody manifest cannot express,
and every capability it has except one is also available on a supported backend. A new consumer
belongs on the Nitrokey HSM 2 or on YubiKey PIV.

## What the adapter admits

Two operations, each on the one applet key that can perform it:

| Operation | Applet key | Why it is here |
|---|---|---|
| `unwrap` | decryption key (`dec`) | reading legacy `sops-pgp` material, which is the migration path |
| `sign` | signature key (`sig`) | legacy signature consumers, and only with a recorded exception |

The authentication key (`aut`) exists on the card and **no operation reaches it**. Human
administrator authentication is outside the cryptographic-operation surface (ADR-0001 §4, API.md)
and `/v1/operations` has no route to reach it through. Pinned by
`TestNoOperationReachesTheAuthenticationSlot`.

## What it refuses, and why

Every operation `/v1/operations` serves that is not in the table above is refused by name, with the
reason recorded next to the refusal in `operationsNotOnThisApplet`. The set is held equal to the
router's own set by `TestEveryServedOperationIsAdmittedOrRefusedWithAReason`, so an operation added
to the API cannot default into either answer.

The refusals that are policy rather than capability are worth stating here, because for several of
them the card is perfectly able:

- **`wrap` and `seal-envelope` create material.** This backend exists to retire legacy material,
  not to accumulate more of it. An envelope wrapped to an OpenPGP decryption key can be opened only
  by the applet being removed, which would make the removal criteria below unreachable by
  construction.
- **`certificate-sign`** is a Nitrokey or PIV role. A CA key reached through a compatibility
  adapter is a *new* dependency on the thing being removed.
- **`key-agreement`** hands a shared secret back to a caller. That is a new capability, not the
  ability to read something already encrypted.
- **`release-secret`** names a wrapping key by `kek_algorithm`, and #75 puts symmetric KEK custody
  on `nitrokey-pkcs11` alone.

`unwrap` additionally accepts the `sops-pgp` format only. `regalia-envelope-v2` is what
`/v1/operations/wrap` produces, this adapter refuses `wrap`, and therefore no regalia envelope can
have been created against this applet — one presented here is either a manifest error or an attempt
to move new material onto the card being retired.

## New use cases default to PIV or Nitrokey

An `(algorithm, operation)` pair that **any supported backend can also do** requires a recorded,
time-bounded exception. A pair that **no other backend can do** does not, because there is no
alternative for anybody to have approved instead.

The split is computed from `registry.Capabilities()` rather than written down here, so it moves
when the capability matrix moves. Read it with `openpgp.PairsRequiringAnException()` and
`openpgp.PairsNeedingNoException()`; a hand-copied list in this file would keep saying "no
alternative exists" after one appeared, which is the permissive direction to be wrong in.

At the time of writing exactly one pair needs no approval — `cv25519/unwrap`, which neither the
Nitrokey nor PIV offers. That expectation is pinned in
`TestOnlyPairsNoSupportedBackendServesAreAdmittedWithoutAnApproval` so that a pair entering the set
arrives as a review rather than as a passing test.

## The exception record

Five required fields, refused at construction if any is missing or blank:

| Field | Why it is required |
|---|---|
| `ObjectID` | an approval that names no object approves everything or nothing |
| `Reason` | why the supported backend is not usable for this object yet |
| `ApprovedBy` | who accepted that reason |
| `RemovalCriteria` | what must become true for the object to move; **a carve-out nobody can close is a permanent bypass** |
| `Expires` | compared at every admission, not once at load |

The first three and the expiry match the custody manifest's `exception` object
(`tools/custody_manifest.py`), so an operator writing one is writing something they have seen
before. `RemovalCriteria` has no counterpart there and is the field most likely to be left out,
which is why it is required rather than encouraged.

These are **not read from the custody manifest today**. The manifest's `exception` record is bound
to custody mode `exception`, which means "deliberately single-homed"; overloading it to also mean
"deliberately on the legacy backend" would make one field answer two unrelated questions. The
consumer inventory below found no consumer, so no production artifact carries an exception yet;
which one should is decided when the first consumer is recorded, not in advance of one.

## Removal criteria for legacy use

An object leaves this backend when its consumer reads its data key from `/v1/operations/unwrap` on
`nitrokey-pkcs11`, and the object's binding is moved with the ordinary rotation path. Until then
its exception must be re-approved before each expiry; an expired approval refuses the route it once
admitted, which is the mechanism that makes "time-bounded" mean something rather than decorate a
record.

The backend itself is removable when `PairsRequiringAnException()` covers every advertised pair and
no object holds an exception — at which point the only remaining justification is `cv25519/unwrap`,
and removing that is a capability-matrix decision rather than a code one.

## Unattended operation, and the one limit the manifest cannot express

`pin_policy` and `touch_policy` on a binding record what the operator *intended*, and
`registry.validateBinding` enforces that the intention is a legal one: YubiKey backends require
`touch_policy: never` and a PIN policy of `once` or `always`. Whether the card in the slot behaves
that way is a different claim, and on this applet the two come apart in a way they do not on PIV.

**PW1 is not PIV's PIN.** It has two verification states that do not satisfy each other — `0x81`
authorises `PSO:CDS`, `0x82` authorises everything else — and the `PSO:CDS` state is reset after a
*single* signature unless the card's PW1 status byte says otherwise. So a binding may honestly say
`pin_policy: once`, validate, route, and run against a card that demands the PIN for every
signature. The adapter therefore requires the card to agree:

- `pin_policy: once` on the **signature** key needs a card whose PW1 is valid for several
  signatures. `pin_policy: always` makes no such claim and is admitted either way.
- The **decryption** key is unaffected by that state, so the same card that cannot sign unattended
  can still open legacy material. The check is per slot for exactly this reason.
- The applet's User Interaction Flag (touch) is set per key. It refuses the slot it guards and only
  that slot.

Pinned by `TestAPinOnceBindingIsRefusedOnACardThatResetsPW1AfterOneSignature` and
`TestTouchOnTheCardRefusesTheSlotItGuardsAndNotTheOther`.

## What has been performed, and what has only been modelled

**The Go driver has run against one OpenPGP card, and the qualification is partial.** On
2026-09-14 the bench YubiKey 5C NFC (serial 25923902, firmware 5.4.3, OpenPGP 3.4, macOS PC/SC
framework) had its OpenPGP applet reset. It was given an on-card Ed25519 signature key and an X25519
decryption key (yubikit `OpenPgpSession.generate_ec_key`), with touch off and PW1 valid for several
signatures; the PIV applet was untouched. The driver's command bytes were first sent from a PC/SC
script, then run for real through `openpgp/pcsc` in `TestOpenPGPPhysicalQualification` (`-tags
piv`). Together they found three defects the scripted transports could not, because the fixtures
encoded the same assumptions as the code:

| Probe | What the driver sent or parsed | What the card said | Fixed |
|---|---|---|---|
| GET DATA 4F (AID) | serial bytes read as a big-endian integer | `… 00 06 25 92 39 02 …`: Yubico's serial is **BCD**, so the driver reported 630339842 for card 25923902 | decoded as BCD for manufacturer 0006 only; any other manufacturer is refused by name |
| PSO:DEC, X25519 | `7F49 22 86 20 <key>` | **6A80**. `A6 24 7F49 22 86 20 <key>` answered 9000 with the X25519 shared secret computed off-card | A6 cipher DO added |
| GET DATA C4 / D6 / D7 | as written | `01 7F 7F 7F 03 00 03` (PW1 valid for several signatures) / `00 20` / `00 20` (touch off) | parsed correctly |
| VERIFY 81, PSO:CDS Ed25519 | as written | 9000, and the 64-byte signature verified against the card's public key. A second PSO:CDS without re-VERIFY also answered 9000, as C4 byte 0 promises | correct |
| VERIFY 81 with a wrong PW1 | mapped only `63 Cx` to "tries left" | **6982**, and the try was spent (C4 byte 4: 3 → 2) | 6982 reads C4 back and names the tries left, or the block |

`TestOpenPGPPhysicalQualification` then passed on the card. It checked that:
- the card is found by serial, and serial `1` finds nothing;
- Status reads `25923902`, PW1-once and touch off;
- two Ed25519 signatures present PW1 81 **once** and both verify;
- X25519 decipher presents PW1 82 once and returns the shared secret computed off-card;
- a wrong PW1 is refused naming "2 tries left", and the right PW1 restores 3;
- a second connection to the card is refused while the driver holds it. Falsified on the card:
  opening in shared mode lets the second connection through, and the test fails.

`TestOpenPGPPhysicalRecoveryFromABlockedPW1` then blocked PW1 with wrong tries. The driver named the
block. The Admin PIN reset the retry counter (VERIFY 83, RESET RETRY COUNTER 2C 02 81), PW1 read 3
tries, and the card signed again. Admin PIN tries stayed at 3.

Each of the three driver fixes was reverted in turn, and each revert failed this test on the card,
naming its defect.

| Arm | Status |
|---|---|
| Admission rules: slots, refusals, matrix conformance, exception and expiry, format | **PERFORMED** — real code, run in CI |
| Ordering: a refused route never opens a card | **PERFORMED** |
| Driver protocol: APDU construction, response parsing, PW1 discipline, status-word mapping | **PERFORMED at the wire** — `openpgp/driver` against scripted transports (`driver_test.go`) |
| Card behaviour above the protocol: what a REAL applet answers | **MEASURED for the commands above**, on one YubiKey 5C NFC, with the bytes sent from a PC/SC script. The wire fixtures for the AID and X25519 PSO:DEC now carry the card's answer. |
| `Driver` / `Card` against real hardware | **PARTLY QUALIFIED** for (YubiKey 5C NFC, fw 5.4.3, macOS PC/SC, `openpgp/pcsc`). **Recorded:** positive operations; negative controls; immutable policy metadata (PW1 mode, UIF); concurrency, as a second connection refused while the driver holds the card; recovery, as a PW1 blocked by wrong tries being refused as blocked, reset with the Admin PIN, then signing again (`TestOpenPGPPhysicalRecoveryFromABlockedPW1`). **Not recorded:** removal behaviour (needs the card pulled by a person), and recovery onto a replacement card. |

`openpgp/driver` is the protocol half of the production driver: SELECT AID, GET DATA for the AID /
PW status bytes / User Interaction Flags, VERIFY with the two PW1 roles, PSO:CDS and PSO:DEC (RSA
padding indicator and the X25519 A6/7F49/86 form), short-APDU chaining, 61 xx continuation, and the
status-word mapping (63 Cx names the low-nibble tries; a YubiKey's 69 82 names the tries C4 reports; 69 83 names blocking; 68 81/82 names
interaction-required). Its one hardware boundary is the `Transport` interface, and every behaviour
is tested by a scripted transport asserting the EXACT command bytes — a seam one level deeper than
the Card doubles the admission layer used, which paid for itself twice in its first hours: the
wire scripts caught a tries-left parse that read 0xC2 as 194 and a chained-APDU Le that sat before
the data, both of which a Card-level double would have modelled as correct.

What is NOT there yet: the daemon wiring, and the qualification arms above that have no
record. The PC/SC binding is `openpgp/pcsc`, and it is built only with `-tags piv`. It opens only
readers whose name contains "Yubico", the one manufacturer whose AID encoding has been measured.
It holds the chosen card exclusively, because PW1's verification state belongs to the connection.
ADR-0001 §4 still holds: a datasheet, a script that encodes one, and a protocol probe from a script
are not proof of compatibility. A (model, firmware, middleware, adapter) tuple becomes eligible only
after a physical test records positive operations, negative controls, immutable policy metadata,
concurrency, removal behaviour and recovery. Until then the daemon constructs nothing from this
package and `internal/reachability_test.go` keeps recording that.

## The consumer inventory (AC1), measured 2026-09-13

The question "which legacy GPG integrations justify this carve-out?" has a measured answer:
**none was found** — in this repository, and in the one consumer repository its own documents
name.

- `gnupg` is *installed* — `qubes/salt/vault-tools.sls`, the offline bundle's tool
  manifest, and the preflight presence checks all list `gpg` — but installation is not dependency.
- No script in the repository *invokes* `gpg` for any operation: zero occurrences of `gpg --…`
  anywhere in `ceremony/`, ``, or CI. The emulator *stubs* it (`simulate-ceremony.sh`
  manufactures a mock `gpg`), and `hsm-import-key.sh` mentions it only in an error message
  explaining why a key without its certificate would be invisible to future GPG/SSH consumers.
- This repository contains no `.sops.yaml`; the SOPS configurations are in the repositories that
  consume the adapter. `doc/SOPS-HSM-RECIPIENT-PREP.md` names one of them as the consumer: example-service.
  **Observed 2026-09-14:** its `.sops.yaml` has three creation rules, all `age`, with no `pgp`
  recipient, and adding a card-backed PGP recipient there is deferred by that document. That is a
  dated observation of another repository, not a property this one can check — the event that would
  change it is a `pgp` recipient appearing there. SOPS's YubiKey integration is `age-plugin-yubikey`
  against the **PIV** applet.
- Ceremony key operations run through `sc-hsm-tool` / `pkcs11-tool` against the SmartCard-HSM and
  through `age` — never through the OpenPGP applet.

The list of **consumers** is therefore empty. The list of **admitted uses** is not, and the two
must not be read as the same claim. The admission layer admits `sign` and `unwrap` on their fixed
slots and refuses the other five operations by name. Of the admitted pairs, every one a supported
backend also offers is refused unless an exception is recorded — but `cv25519/unwrap` is admitted
**with no exception at all**, because neither the Nitrokey nor PIV offers it
(`PairsNeedingNoException()`; pinned by
`TestOnlyPairsNoSupportedBackendServesAreAdmittedWithoutAnApproval`). With zero exceptions recorded,
`Admit` returns the decryption slot for it, measured on `main` 2026-09-14. That default is
deliberate — it is the unavoidable legacy case this backend exists for — and it is also the one use
that needs no approval, so it is the first thing to revisit if the backend is ever removed.

When a legacy GPG consumer actually appears, this section is where it is recorded, alongside the
exception record that admits anything beyond that one default.

## The client contract does not name any of this

ADR-0001 §1: the API is purpose-shaped, and a caller cannot select a reader, slot, backend or
mechanism. `TestNoClientContractNamesTheOpenPGPApplet` holds that no exported identifier or
operation path in `internal/api`, `internal/operations` or `internal/policy` names the applet. The
`sops-pgp` format name is allowed and is not an exception to this: it names the *material* a client
presents, not the device that opens it, and which card opens it is what routing decides.
