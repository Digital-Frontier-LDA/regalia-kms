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
  YubiKey's OpenPGP applet as a PKCS#11 token, and that token lists `EDDSA` (255 bits, in hardware).
  The driver the KMS already uses for the HSM could serve it, with no card protocol written here.
  The hand-written driver in `internal/backend/openpgp` is the part this rule argues against, not the
  applet. Proven on a card, with the KMS's own driver and provider: an Ed25519 key generated on the applet
  signs through `CKM_EDDSA` and the signature verifies. **Proposed, not decided**: the KMS does not serve it yet (gap 3).
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
promises more than either token delivers:

| Token | Backend | What it offers | Evidence |
|---|---|---|---|
| Nitrokey HSM 2 | `nitrokey-pkcs11` | ECDSA and ECDH on curves of 192 to 521 bits (P-256, P-384, secp256k1); RSA 1024 to 4096 with PKCS#1 v1.5, PSS and OAEP. **No EdDSA mechanism and no AES mechanism.** | `C_GetMechanismList`, DENK0404144, applet 4.1, OpenSC 0.26.1, 2026-10-02 |
| Pico HSM | `nitrokey-pkcs11` | The same list as the Nitrokey, mechanism for mechanism. **No EdDSA and no AES**: Ed25519 key generation is refused (`mechanism 1055 not supported`). Whether the firmware does Ed25519 by another path is unmeasured. | `C_GetMechanismList` and a key-generation attempt without login, Pico Key 8625B32841D722E2, firmware 6.6, OpenSC 0.26.1, 2026-10-02 |
| YubiKey, PIV applet | `yubikey-piv` | P-256 and P-384 sign and certificate-sign; RSA-2048 sign, wrap, unwrap, certificate-sign. Firmware 5.7 and the pinned `piv-go` v2.6.0 also know Ed25519; the backend does not offer it and it is unmeasured. | qualified on YubiKey 5 NFC, firmware 5.7.4 (`config/qualified-stack.json`); built only with `-tags piv` |
| YubiKey, OpenPGP applet | `yubikey-openpgp` | Ed25519 sign; X25519 unwrap; RSA 2048 to 4096 sign and unwrap | partly qualified on one YubiKey 5C NFC, firmware 5.4.3 ([`OPENPGP-COMPATIBILITY.md`](OPENPGP-COMPATIBILITY.md)); **the daemon constructs no provider for it** |
| YubiKey, OpenPGP applet through OpenSC | none yet | `EDDSA` sign (255 bits), ECDH derive from 255 bits, ECDSA 256 to 521, RSA 2048 to 4096 | `C_GetMechanismList` with OpenSC's `openpgp` driver, YubiKey 5 NFC 35718625, firmware 5.7.4, applet 3.4, OpenSC 0.26.1, 2026-10-02. With an Ed25519 key generated on the applet, `CKM_EDDSA` over 32, 48 and 64 bytes returns a 64-byte signature that verifies as pure Ed25519; `CKA_EC_PARAMS` is OID 1.3.101.112. |

## What each configuration can serve

"HSM" is the Pico in configurations 1 and 2 and the Nitrokey in configuration 3.

| Need | 1: Pico alone | 2: Pico + YubiKey | 3: Nitrokey + YubiKey |
|---|---|---|---|
| ECDSA P-256 / P-384: sign, CA, key agreement | HSM | HSM; PIV for sign and CA, in a `-tags piv` build only | HSM; PIV for sign and CA, in a `-tags piv` build only |
| RSA 2048 to 4096: sign, wrap, unwrap, CA | HSM | HSM | HSM |
| secp256k1 sign (Cosmos) | HSM | HSM | HSM |
| Opaque secrets under an RSA KEK | HSM | HSM | HSM |
| Ed25519 sign | **none** | YubiKey OpenPGP applet, not wired | YubiKey OpenPGP applet, not wired |
| X25519 unwrap (legacy `sops-pgp`) | none | OpenPGP applet, not wired | OpenPGP applet, not wired |

Neither HSM can hold an Ed25519 key through this backend, so in configurations 2 and 3 it lives on
the YubiKey's OpenPGP applet, and configuration 1 has none. Ubuntu, Apple and Microsoft do not
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

1. **The capability matrix promises what neither HSM offers.** `ed25519/sign` and `aes-256/unwrap`
   are advertised for `nitrokey-pkcs11`, and neither token lists an EdDSA or AES mechanism. A
   manifest that binds such a key validates, the daemon starts, and every operation fails as
   unavailable. The token's own mechanism list should be checked against its bindings at startup.
2. **Ed25519 has no served home yet.** It is not reachable on either HSM, the OpenPGP applet is not
   wired, and the PIV backend does not offer it. `regalia-sign` accepts an Ed25519 key, so the
   missing piece is a served token, not the client: today such a key works end to end on SoftHSM only.
3. **The OpenPGP applet is not served.** The admission rules treat it as legacy only (ADR-0001 §4),
   and the only driver wired for it is hand-written. Through OpenSC and PKCS#11 the driver, its
   probes and the provider already sign Ed25519 on the applet (regalia-kms#119: OpenSC presents the
   applet as two tokens under one serial, so the binding names the token by `token_label`). What is
   left before the daemon serves it: which backend name it runs under, what stands in for
   SmartCard-HSM secure messaging on this token, and a recorded change to the legacy-only rule. The
   OpenSC driver choice is a `card_atr` block in `opensc.conf` naming `driver = "openpgp"` for the
   YubiKey's ATR; it leaves the Nitrokey on its own driver in the same module.
4. **The Pico is not qualified, and two on one host may not be told apart.** `config/qualified-stack.json`
   and `tools/qualified_stack.py` do not know it, and `deploy/seal-hsm-pin.sh` accepts its serial but
   labels it staging. Nothing refuses a Pico in a manifest. The attached Pico reports the token
   serial `ESPICOHSMTR`, not a per-device one. Only that one unit was measured. If a second reports
   the same, the driver, which requires a serial to name exactly one slot, cannot serve two of them
   on one host; Picos on separate hosts are unaffected.
5. **Apple and Microsoft have no client adapter.** Only SOPS and OpenPGP have one.
