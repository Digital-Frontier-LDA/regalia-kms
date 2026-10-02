# Supported hardware configurations

## Decision (owner, 2026-10-02)

Regalia KMS supports three token configurations:

| # | Configuration | Key-holding HSM | YubiKey |
|---|---|---|---|
| 1 | **Pico HSM alone** | Pico HSM | none |
| 2 | **Pico HSM + YubiKey** | Pico HSM | PIV and OpenPGP applets |
| 3 | **Nitrokey HSM 2 + YubiKey** | Nitrokey HSM 2 | PIV and OpenPGP applets |

**Configuration 3 comes first** (owner, 2026-10-02): it is the one Digital Frontier runs, and work
that serves it is done before work that serves only the Pico.

A configuration names the token *types* a deployment uses, not a device count. The registry still
requires two hardware bindings for a production object (or custody `exception`), so "Pico HSM alone"
means at least two Picos for such an object, and one only where the manifest declares the exception.

"Supported" means the product accepts the configuration, documents what it can do, and tests it.
It is not the same as "qualified": a token and middleware combination is qualified only when it is
listed in [`config/qualified-stack.json`](config/qualified-stack.json) with a hardware drill behind
it. The status of each configuration is [below](#status).

Whether an operator puts production keys on a Pico is that operator's trust decision: the Pico is a
microcontroller with no secure element and no security certification. This document does not change
the rule Digital Frontier applies to its own fleet (requirement D1: its production keys live on
Nitrokeys), and it does not qualify anything: no Pico stack is qualified ([status](#status)), and in
the three-site program a Pico host stays a lab profile until #62 to #64 are done.

### How an interface or an algorithm is chosen

Owner, 2026-10-02: the most standard interface and the most secure method, where open-source code
that has been independently validated counts as more secure than code written here. In practice:

- **Tokens are reached through standard interfaces and reviewed open-source middleware.** That is
  PKCS#11 through OpenSC for the HSM, and PIV (NIST SP 800-73) for the YubiKey.
- **The same rule gives Ed25519 a standard home.** OpenSC's own OpenPGP card driver presents the
  YubiKey's OpenPGP applet as a PKCS#11 token that signs with `CKM_EDDSA`, and the daemon serves it
  with the driver it already uses for the HSM, for signing only
  ([`OPENPGP-COMPATIBILITY.md`](OPENPGP-COMPATIBILITY.md)). The hand-written driver in
  `internal/backend/openpgp` is the part this rule argues against, not the applet; it stays unserved.
- **Signature formats come from maintained open-source libraries**, not from encoders written here.
  One recorded exception: for an Ed25519 OpenPGP signature, `regalia-sign` has the library build the
  packet and then replaces the two signature integers itself, because the library accepts no
  external Ed25519 signer ([`adapters/gpgsign/README.md`](adapters/gpgsign/README.md)). It ends
  when the library does.

### Relation to the three-site device profiles

[`THREE-SITE-THREAT-MODEL.md`](THREE-SITE-THREAT-MODEL.md) defines device profiles by host and
token together. On a TPM host, configuration 3 is profile A and configuration 1 is profile B.
Configuration 2 is profile B with a YubiKey added; it has no letter there yet. Profiles C and D (no
TPM) are a different question, about where an unattended PIN can live, and are not decided here.

## What each token provides

Both HSMs are SmartCard-HSMs reached through the OpenSC `sc-hsm` driver, and both are served by the
one `nitrokey-pkcs11` backend. Through that driver the two offer the same mechanisms: the Pico's
extra algorithms are not reachable. The capability matrix
([`config/backend-capabilities.json`](config/backend-capabilities.json)) is per backend, and it
promises more than either token delivers; the daemon asks each token for its own mechanism list
before relying on it:

| Token | Backend | What it offers | Evidence |
|---|---|---|---|
| Nitrokey HSM 2 | `nitrokey-pkcs11` | ECDSA and ECDH on curves of 192 to 521 bits (P-256, P-384, secp256k1); RSA 1024 to 4096 with PKCS#1 v1.5, PSS and OAEP. **No EdDSA mechanism and no AES mechanism.** | `C_GetMechanismList`, DENK0404144, applet 4.1, OpenSC 0.26.1, 2026-10-02 |
| Pico HSM | `nitrokey-pkcs11` | The same list as the Nitrokey, mechanism for mechanism. **No EdDSA and no AES**: Ed25519 key generation is refused (`mechanism 1055 not supported`). Whether the firmware does Ed25519 by another path is unmeasured. | `C_GetMechanismList` and a key-generation attempt without login, Pico Key 8625B32841D722E2, firmware 6.6, OpenSC 0.26.1, 2026-10-02 |
| YubiKey, PIV applet | `yubikey-piv` | P-256 and P-384 sign and certificate-sign; RSA-2048 sign, wrap, unwrap, certificate-sign; **Ed25519 sign** (firmware 5.7 and later). Twenty-four key slots: 9a, 9c, 9d, 9e and twenty retired slots. PIN and touch policy are read from the card. | qualified on YubiKey 5 NFC, firmware 5.7.4 (`config/qualified-stack.json`) for P-256; built only with `-tags piv`. Ed25519, on 35718625, 2026-10-02: with the pinned `piv-go` v2.6.0, 64-byte signatures over 32 to 3000 bytes verify, about 85 ms each, 4096 bytes refused by the card, and the slot is attested; through this backend's session with a PIN-once key, and through the daemon's construction path beside a Nitrokey, signatures verify. |
| YubiKey, OpenPGP applet through OpenSC | `yubikey-openpgp` | Served: `sign` with Ed25519 (`CKM_EDDSA`). Also listed by the token and not served: ECDH derive from 255 bits, ECDSA 256 to 521, RSA 2048 to 4096. | YubiKey 5 NFC 35718625, firmware 5.7.4, applet 3.4, OpenSC 0.26.1, 2026-10-02: the driver, the daemon's construction path and `regalia-sign` end to end ([`e2e/YUBIKEY-OPENPGP-PKCS11.md`](e2e/YUBIKEY-OPENPGP-PKCS11.md)). Not qualified: removal and recovery are not recorded. |

## What each configuration can serve

"HSM" is the Pico in configurations 1 and 2 and the Nitrokey in configuration 3.

| Need | 1: Pico alone | 2: Pico + YubiKey | 3: Nitrokey + YubiKey |
|---|---|---|---|
| ECDSA P-256 / P-384: sign, CA, key agreement | HSM | HSM; PIV for sign and CA, in a `-tags piv` build only | HSM; PIV for sign and CA, in a `-tags piv` build only |
| RSA 2048 to 4096: sign, wrap, unwrap, CA | HSM | HSM | HSM |
| secp256k1 sign (Cosmos) | HSM | HSM | HSM |
| Opaque secrets under an RSA KEK | HSM | HSM | HSM |
| Ed25519 sign | **none** | YubiKey: PIV slot, or OpenPGP applet | YubiKey: PIV slot, or OpenPGP applet |
| X25519 unwrap (legacy `sops-pgp`) | none | not served | not served |

Neither HSM can hold an Ed25519 key through this backend, so in configurations 2 and 3 it lives on
the YubiKey, and configuration 1 has none. The YubiKey offers two homes. **PIV** is the one to
prefer for a card that also holds PIV keys: it is the applet and middleware the KMS already uses, it
has twenty-four slots where the OpenPGP applet has one signing slot, and the card reports each
slot's PIN and touch policy. The **OpenPGP applet** through OpenSC is served too, but not on the same
card: see below.

### One YubiKey: PIV, with OpenSC told to leave it alone

Measured on one YubiKey 5 NFC (firmware 5.7.4) and a Nitrokey HSM 2 in one daemon, 2026-10-02:

- **The PIV backend and OpenSC cannot both hold the card.** The PIV backend opens the YubiKey for
  exclusive use, and `opensc-pkcs11.so` keeps a connection to every card it finds. With OpenSC's
  defaults the daemon's own PKCS#11 module locks the PIV backend out: every PIV operation fails
  ("the smart card cannot be accessed because of other connections outstanding"). This applies to
  configuration 3 as soon as both backends run in one daemon.
- **[`deploy/opensc/ignore-yubikey.conf`](deploy/opensc/ignore-yubikey.conf) fixes it**: OpenSC
  ignores the YubiKey's reader and still serves the HSM. With it, one YubiKey served a P-256 key
  (slot 9c) and an Ed25519 key (a retired slot) through PIV: 12 alternating and 12 simultaneous
  signatures, all verified, while the HSM answered through PKCS#11 in the same process.
- **So one card serves PIV or the OpenPGP applet, not both.** The applet path needs OpenSC to drive
  the YubiKey; the PIV path needs it not to. A deployment that wants one YubiKey uses PIV for
  everything, Ed25519 included. The applet path is for a card dedicated to it.
- **Requests for one card are queued.** The card takes one connection at a time; simultaneous
  requests used to fail as unavailable (nine of twelve on the bench) and now wait their turn. Ubuntu, Apple and Microsoft do not
require Ed25519; OpenPGP, SSH and git users commonly expect it.

## Signing software for a platform

The platform rules below are the platforms' own and are stated as understood on 2026-10-02. Confirm
the Microsoft row with the certificate authority before buying hardware.

| Target | What the platform demands | 1: Pico alone | 2: Pico + YubiKey | 3: Nitrokey + YubiKey |
|---|---|---|---|---|
| **Ubuntu** (APT repository, source uploads): OpenPGP | A signature the target `apt` accepts. RSA 3072 or 4096 and Ed25519 are the safe choices; check ECDSA against the oldest release served. No hardware rule. | [`regalia-sign`](adapters/gpgsign/README.md) with a P-256, P-384 or RSA key on the HSM | as 1 | as 1 |
| **Apple** (Developer ID, notarization) | An RSA-2048 key and a certificate Apple issues from a CSR. No hardware rule. | RSA-2048 on the HSM; **no CSR tool and no `codesign` adapter yet** | as 1 | as 1 |
| **Microsoft** (Authenticode, publicly trusted) | The key on hardware certified FIPS 140-2 Level 2 or Common Criteria EAL4+, proven to the CA. RSA 3072 or larger, or P-256 / P-384. | **Not possible.** The Pico has no certification. | Only with a FIPS-series YubiKey on PIV (P-384), if the CA accepts its attestation. The qualified YubiKey 5 NFC is not the FIPS series. | As 2 for the YubiKey. Whether a CA accepts the Nitrokey HSM 2 is unknown. |

Authenticode under an operator's own CA, trusted only where that root is installed, has no hardware
rule and works in every configuration once a `signtool` adapter exists.

## Status

| Configuration | Token stack qualified | What is open |
|---|---|---|
| 3: Nitrokey HSM 2 + YubiKey | Nitrokey HSM 2 applet 4.1 and YubiKey 5 NFC firmware 5.7.4 on PIV are in `config/qualified-stack.json` | Nitrokey production qualification ([`e2e/NITROKEY-QUALIFICATION.md`](e2e/NITROKEY-QUALIFICATION.md)); the OpenPGP applet (#73) |
| 1: Pico HSM alone | **No.** The Pico is not in `config/qualified-stack.json` and `tools/qualified_stack.py` does not recognise it. | PKCS#11 parity, authentication and DKEK portability (#62, #63, #64); the firmware disclosure GHSA-wq3w-g2fj-q2jq is open |
| 2: Pico HSM + YubiKey | **No**, for the same reason; the YubiKey half is as in 3 | as 1, and the OpenPGP applet (#73) |

## Gaps this decision opens

1. **The capability matrix promises what neither HSM offers, and the token is now asked.**
   `ed25519/sign` and `aes-256/unwrap` are advertised for `nitrokey-pkcs11`, and neither HSM lists
   an EdDSA or AES mechanism. The matrix is one answer per backend, so it stays; the token's own
   mechanism list decides. At startup the daemon opens each attached token once and asks it about
   the binding each object is routed to at this site; it refuses a registry that binds such a key,
   naming the object and the token (measured on Nitrokeys DENK0404144 and DENK0404380), and logs
   the tokens it could not ask. A token that is absent then is not a refusal, so the provider also
   asks before every private operation and refuses before the PIN is fetched. In that case the
   caller still sees a retryable "unavailable" that names nothing.
2. **Ed25519 is served from the YubiKey only, and that stack is not qualified.** The daemon signs
   Ed25519 on the OpenPGP applet through OpenSC, and `regalia-sign` frames it as an OpenPGP
   signature GnuPG accepts. Removal of the card, recovery onto a replacement and the daemon under
   its systemd unit are not recorded, so it is not in `config/qualified-stack.json`. Configuration 1
   has no Ed25519.
3. **The served applet is checked less than the hand-written adapter would check it.** PKCS#11
   does not expose the card's PIN-status byte or its touch flags, so a key that requires touch is
   found out when a signature fails, not when the daemon starts. The path has not run under the
   systemd unit and its AppArmor profile.
4. **The Pico is not qualified, and two on one host may not be told apart.** `config/qualified-stack.json`
   and `tools/qualified_stack.py` do not know it, and `deploy/seal-hsm-pin.sh` accepts its serial but
   labels it staging. Nothing refuses a Pico in a manifest. The attached Pico reports the token
   serial `ESPICOHSMTR`, not a per-device one. Only that one unit was measured. If a second reports
   the same, the driver, which requires a serial to name exactly one slot, cannot serve two of them
   on one host; Picos on separate hosts are unaffected.
5. **Apple and Microsoft have no client adapter.** Only SOPS and OpenPGP have one.
