# Cosmos hardware qualification

This run is destructive only in the sense that it consumes one PKCS#11 login. Use a staging
PicoHSM2 (or a scratch Nitrokey HSM 2), never a production token, and stop if the token reports
one or fewer PIN retries. Do not put the PIN in this file, shell history, or CI logs.

## PicoHSM2 / Nitrokey-compatible secp256k1 path

Record the module path, token label, token serial, object ID, and the fixture SHA-256 in the
ceremony evidence store. Then run from the repository root with the PIN supplied by the approved
secret mechanism:

```sh
REGALIA_COSMOS_PKCS11_MODULE=/absolute/path/to/pkcs11.so \
REGALIA_COSMOS_PKCS11_SERIAL=ESP41D722E2 \
REGALIA_COSMOS_PKCS11_OBJECT_ID=01 \
REGALIA_COSMOS_PKCS11_PIN="$STAGING_PIN" \
e2e/run.sh --mode cosmos-hardware
```

With OpenSC's module (`opensc-pkcs11.so`) the card is chosen by its serial and nothing else:
`REGALIA_COSMOS_PKCS11_SERIAL` is required, the label and slot are ignored, OpenSC is shown only that
card (`e2e/lib/bench_cards.sh`), and the PIN is presented only while that serial is the one card
visible (regalia-kms#174). A label is shared by every token left at its default (both PicoHSM2 tokens
are `Pico-HSM`), and a slot index moves when another reader comes or goes. Other modules (SoftHSM)
still take the label or the slot.

The command first runs the normal software battery, then hashes
`internal/policy/testdata/signdoc-akashnet2-msgsend.hex`, signs that digest through the token, and
verifies the raw ECDSA result against the public key read from the same object. A successful run
must preserve the command output and token identity alongside the ceremony record.

## YubiKey-compatible boundary

YubiKey PIV supports P-256/P-384/RSA operations in this repository, not Cosmos secp256k1. Its
qualification therefore remains the separate dual-device PIV test:

```sh
cd kms && REGALIA_PIV_SERIAL=... REGALIA_PIV_EMPTY_SERIAL=... REGALIA_PIV_PIN=... \
go test -tags piv ./internal/integration -run 'TestTwoPhysicalYubiKeys'
```

That test proves the compatible KMS hardware path, PIN-only operation, and active/passive failover;
it must not be reported as Cosmos transaction signing. A Cosmos wallet assigned to a YubiKey is
refused by the manifest/policy capability checks until a supported secp256k1 implementation exists.
