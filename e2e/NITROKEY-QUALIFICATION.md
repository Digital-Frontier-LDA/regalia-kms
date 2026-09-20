# Nitrokey HSM 2 qualification

`TestNitrokeyHSM2Qualification` (`internal/backend/nitrokey`) measures, through the same probes
and guards the daemon uses, the two open questions gating the production Nitrokey backend:

- **#448** — does the token expose its device-authentication certificate as a PKCS#11
  `CKO_CERTIFICATE`? `TokenProbes.Fingerprint` hashes exactly one such object. On the staging Pico
  through OpenSC it found none, so the daemon's identity probe refuses the card before login.
- **#447** — does a key **generated on the token** report `CKA_LOCAL` true on its public half?
  `AssertKEKGeneratedOnToken` reads that attribute logged out. On the Pico through OpenSC it was
  false for every key, so the wrap guard refuses every KEK.

Under D1 (`doc/REQUIREMENTS.md`) only a measurement on the production hardware — the Nitrokey HSM 2 —
answers these; the Pico result decides nothing.

## The instrument is verified in CI

`e2e/softhsm-pkcs11.sh` runs the test in **control** mode against a SoftHSM token it provisions:
a generated key (id 01) must read LOCAL, an imported key (id 07) must be refused, and there is no
device certificate. That proves the instrument reads what it claims. A wrong reading fails the run.

## Running it against a real Nitrokey (read-only, no PIN spent)

```sh
cd kms
REGALIA_QUAL_MODULE=/path/to/opensc-pkcs11.so \
REGALIA_QUAL_SERIAL=<token serial> \
REGALIA_QUAL_GENERATED_ID=<hex id of a key generated on the card, if any> \
REGALIA_QUAL_IMPORTED_ID=<hex id of a host-imported key, if any> \
  go test -count=1 -v -run '^TestNitrokeyHSM2Qualification$' ./internal/backend/nitrokey
```

Without `REGALIA_QUAL_CONTROL=1` it **records** the answers (`#448 …`, `#447 …` log lines) rather than
asserting them — the answers for the Nitrokey are not yet known, which is the point.

A factory-fresh Nitrokey has no keys, so `#447` needs a key generated on the card first. Provision one
under the bench lock with the staging tools (`sc-hsm-tool --initialize`, `pkcs11-tool --keypairgen`),
then pass its id as `REGALIA_QUAL_GENERATED_ID`. Destructive provisioning on the two future-production
units is authorized as staging (owner, 2026-09-15); restore posture and never exhaust a retry counter.

## Known host issue (2026-09-15)

Both Nitrokey HSM 2 units, on this macOS host through a USB-C→USB-A adapter, return a valid
SmartCard-HSM ATR on a direct reset but fail every data-protocol connect (T1 "unresponsive", T0
"protocol mismatch", PKCS#11 `CKR_DEVICE_ERROR`). No tool can reach the applet in that state. It is a
reader/CCID-layer failure, not the token: re-seat, use a direct port or a powered reader rather than
the adapter, or try one device at a time.
