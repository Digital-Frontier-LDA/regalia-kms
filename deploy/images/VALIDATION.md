# Image verification evidence — 2026-10-02

This records workstation verification, not production appliance qualification.
Downloaded media and reports are retained locally under ignored `.artifacts/`.
Repeat the verification at use time; this document is not an authorization token.

## Debian installer

The complete 792,723,456-byte `debian-13.7.0-amd64-netinst.iso` was downloaded by
the Debian media fetcher. GnuPG 2.5.18 verified Debian's `SHA512SUMS.sign`, using only the
approved primary key `DF9B9C49EAA9298432589D76DA87E80D6294BE9B` in a temporary keyring.
The SHA-512 matched the authenticated manifest and a separate `shasum -a 512` run:

```text
ef04d0276850d70e4aaec0b55003628660e9631b26e35215a70ab3c8c707294a4b12731bc73c75a932902f703a7c278310ca99df28d6b36fb06d5618d8d0f678
```

The image was checked again after download. This authenticates installer media;
the custom minimal KMS appliance disk is still to be built and commissioned.

## OCI verification

Cosign 3.0.6 verified this public signed test fixture without running its contents:

```text
gcr.io/distroless/static-debian13@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
identity: keyless@distroless.iam.gserviceaccount.com
issuer: https://accounts.google.com
```

The same image with `attacker@example.invalid` as the required identity was refused.
Default claims, certificate and transparency checks remained enabled. This fixture
tests Cosign interoperability; it is not the selected appliance or lab base.
Identity source: [the publisher's verification instructions](https://github.com/GoogleContainerTools/distroless#how-do-i-verify-distroless-images).

## Regression gate

21 automated tests passed, including real GPG valid/invalid signatures, wrong key
pins, weak hashes, expired keys, signing subkeys, multiple signatures, tampered
images/manifests, duplicate/unsafe entries, absent proof, symlink rejection,
failed-download cleanup, atomic verified publication, OCI command/claim handling
and new/unreviewed image detection. OCI regression tests use a mocked Cosign
process; the two live OCI checks above used the actual Cosign executable.

The full Python guard suite passed all 211 tests. The updated Docker lab entry
point also passed its 121 TPM/LUKS/bootstrap checks after writing the inventory.
Shell syntax, Python compilation, whitespace checks and staged secret scanning passed.

CI runs the automated suite and repository inventory. Lab runners write an explicit
development-only inventory before Docker builds. New inputs require reviewed policy;
the production inventory invocation fails while existing lab signatures remain
unverified. Custody of the release signer, package vulnerability review, authenticated build
provenance and hardware boot-integrity acceptance remain outstanding.
