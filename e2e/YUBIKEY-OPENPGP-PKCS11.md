# Ed25519 on a YubiKey's OpenPGP applet, through OpenSC and PKCS#11

The record of what was run on hardware for the `yubikey-openpgp` backend as the daemon serves it
(decision and limits: [`../OPENPGP-COMPATIBILITY.md`](../OPENPGP-COMPATIBILITY.md)), and how to run
it again.

## What is on the host

- `opensc-pkcs11.so` with the `card_atr` block of
  [`deploy/opensc/yubikey-openpgp.conf`](../deploy/opensc/yubikey-openpgp.conf) in
  `/etc/opensc/opensc.conf`, or that file named by `OPENSC_CONF` as the commands below do.
- An Ed25519 signature key on the applet, generated on the card, **with its creation time and
  fingerprint set**. OpenSC lists no key object for a slot whose fingerprint is all zeros.
- PIN policy "once" for signatures and touch off: the daemon signs unattended.

## The three tests

```sh
export OPENSC_CONF=$PWD/deploy/opensc/yubikey-openpgp.conf
export REGALIA_OPENPGP_PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
export REGALIA_OPENPGP_PKCS11_SERIAL=000635718625     # as the token reports it: 0006 + the serial
export REGALIA_OPENPGP_PKCS11_PIN=...                 # PW1, from the environment only
go test -count=1 -run '^TestEd25519OnAYubiKeyOpenPGPAppletThroughOpenSC$' ./internal/backend/nitrokey
go test -count=1 -run '^TestBuildHardwareServesTheOpenPGPAppletOverLocalTokenEvidence$' ./cmd/regalia-kms
REGALIA_EXPECT_GPG=1 go test -count=1 -run '^TestRegaliaSignEd25519OnAYubiKeyOpenPGPApplet$' ./internal/integration
```

Each skips without the environment and fails if the serial is set and the PIN is not.

## Recorded run, 2026-10-02

YubiKey 5 NFC, serial 35718625, firmware 5.7.4, OpenPGP applet 3.4. OpenSC 0.26.1, pcscd 2.3.3,
GnuPG 2.4.7. A Nitrokey HSM 2 and a memory-card reader were attached to the same host.

| Test | What ran | Result |
|---|---|---|
| Driver, probes, provider | Serial alone refused (two tokens). With the signature token's label: Ed25519 over 32 and 64 bytes, verified as pure Ed25519. A binding pinned to another public key quarantined the device. | PASS, 22 s |
| `buildHardware` | The daemon's construction path from an evidence file, a PIN credential file and a registry: signature through the backend manager verified. No `local-usb` evidence: backend not served. Binding with no `token_label`: refused at startup. | PASS, 31 s |
| `regalia-sign` end to end | The built executable over mTLS, RBAC, purpose policy and audit: detached and cleartext OpenPGP signatures accepted by GnuPG, a changed file rejected, six audit events for three signatures. Attestation expired: no signature, device latched. | PASS, 23 s |

Also measured with `pkcs11-tool`: `CKM_EDDSA` signs inputs of 200 to 1024 bytes; 4096 bytes failed
(possibly the tool's multi-part path). `CKA_EC_PARAMS` is the OID 1.3.101.112. The user PIN counter
stayed at 3 throughout.

## What this is not

Not a qualification under ADR-0001 §4. Recorded: positive operations, negative controls. Not
recorded: removal of the card during an operation, recovery onto a replacement card, a blocked PIN,
concurrency with the PIV backend on the same card, and the daemon binary under its systemd unit.
The `yubikey-openpgp` stack is therefore not in `config/qualified-stack.json`.
