# regalia-sign: OpenPGP signatures from a key the KMS holds

`regalia-sign` signs release artifacts, commits and tags with a key that stays on the token. It
holds the **public** key only. Each signature is one `POST /v1/operations/sign` to the KMS over
mTLS; the answer is checked against the pinned public key and framed as an OpenPGP packet by
[ProtonMail/go-crypto](https://github.com/ProtonMail/go-crypto). Anyone verifies with stock GnuPG.

This is an isolated Go module, like `adapters/sops`: its one dependency beyond the standard library
and `golang.org/x/sys` does not enter the daemon's build.

```sh
regalia-sign --config /etc/regalia-sign/config.json --detach SHA256SUMS   # writes SHA256SUMS.asc
gpg --verify SHA256SUMS.asc SHA256SUMS                                    # on any machine

regalia-sign --config /etc/regalia-sign/config.json --clearsign Release --output InRelease   # an apt repository
```

| Command | What it does | KMS operations |
|---|---|---|
| `--detach FILE` | writes `FILE.asc`, an armored detached signature (`--binary`: `FILE.sig`; `--output`: elsewhere; `-` reads stdin, writes stdout). Never replaces an existing file. | 1 |
| `--clearsign FILE` | writes `FILE.asc` (or `--output`), the text followed by a signature over it: what `gpg --clearsign` makes, and what apt reads as `InRelease`. Never replaces an existing file. | 1 |
| `--export-key` | prints the armored public key verifiers import | 1 |
| `--fingerprint` | prints the key's fingerprint | 0 |
| `--prepare PENDING` + one of the three above | under a policy that requires approval: writes the pending record an approver signs ([below](#signing-under-a-policy-that-requires-approval)) | 0 |
| `--complete PENDING --approval FILE` + the same | sends the prepared request with the approval and writes the result | 1 |
| `--status-fd=2 -bsau KEY` | git's form: signs stdin to stdout | 1 |
| `--verify …` | hands the whole line to the real `gpg` (or `REGALIA_SIGN_GPG`) | 0 |

The configuration is `--config`, or the file named by `REGALIA_SIGN_CONFIG`.

## Supported keys

Generated **on the token** and never imported:

| Key | KMS algorithm | Digest signed | Policy `max_payload_bytes` |
|---|---|---|---|
| ECDSA P-384 | `p384` | SHA-384 | 48 |
| ECDSA P-256 | `p256` | SHA-256 | 32 |
| RSA-3072 (also 2048, 4096) | `rsa3072` | SHA-256, sent as DigestInfo | 51 |
| Ed25519 | `ed25519` | SHA-256 | 32 |

One key signs with one digest: `regalia-sign` refuses any other, so the policy's payload size can be
exact.

**Ed25519 needs a token that has it.** Neither the Nitrokey HSM 2 nor the Pico HSM offers EdDSA
through OpenSC. The YubiKey's OpenPGP applet does (measured through PKCS#11, regalia#541), but the
KMS cannot open that applet yet. Today an Ed25519 release key works end to end on SoftHSM only.

## Setting up a release key

1. **Generate the key on the token** and read its public half off it, as PEM (`PUBLIC KEY`). That
   file is `public_key_path`. It is the pin: a signature it does not verify is never written, so a
   KMS object routed to another key cannot sign a release.
2. **Register the object** in the custody manifest with `operations: ["sign"]`, and give it a purpose
   policy that allows exactly the digest:

   ```json
   {
     "id": "release-signing", "object_id": "release-signing-key",
     "purpose": "release-artifact", "environment": "production",
     "operation": "sign", "algorithm": "p384",
     "content_types": ["application/vnd.regalia.digest"],
     "max_payload_bytes": 48, "max_future_seconds": 120
   }
   ```

   Grant `sign` on that object to the release job's SPIFFE identity and to nothing else.
3. **Fix the key's identity** in the configuration (`config.example.json`):
   - `key_created` is hashed into the OpenPGP fingerprint. Write it once and never change it; with
     another value every verifier sees another key.
   - `user_id` is what GnuPG shows, for example `Example Releases <releases@example.com>`.
4. **Publish the public key once**: `regalia-sign --export-key > release-key.asc`. Record
   `regalia-sign --fingerprint` where verifiers can find it out of band.

The configuration, the CA, the certificate and the pinned public key must not be writable by anyone
but their owner (root or the user running the tool), and the workload private key must be readable
by its owner alone. None may be a symbolic link. The tool refuses otherwise, before it contacts the
KMS.

## Signing commits and tags

```sh
git config gpg.program regalia-sign
git config user.signingkey "$(regalia-sign --config /etc/regalia-sign/config.json --fingerprint)"
export REGALIA_SIGN_CONFIG=/etc/regalia-sign/config.json
git tag -s v1.0.0 -m "release 1.0.0"
git verify-tag v1.0.0        # runs the real gpg, through regalia-sign --verify
```

The key git names (`user.signingkey`, or the committer identity) must be the configured key: its
fingerprint, its key ID, or part of its user ID. Otherwise nothing is signed.

## Signing an apt repository

```sh
regalia-sign --clearsign dists/stable/Release --output dists/stable/InRelease
regalia-sign --detach    dists/stable/Release --output dists/stable/Release.gpg   # for older clients
regalia-sign --export-key > regalia-release.asc    # users: /etc/apt/keyrings/, then signed-by=
```

A cleartext signature covers the text with line endings canonicalised and trailing blanks on each
line removed, and the final line ending is a separator, not content. That is the framework's rule
(RFC 9580 §7), the same for `gpg --clearsign`. A `Release` file with LF line endings, no trailing
blanks and a final newline comes back byte for byte. One with CRLF line endings does not: the
signature still verifies, but verifiers return the text with their own line endings. Anything that
must be reproduced exactly belongs under `--detach`.

The signature armor carries its CRC-24 line. go-crypto leaves it out by default, and GnuPG 2.4
(`gpg` and `gpgv`, so every apt before 3.0) then exits 2 on a signature whose base64 needs no
padding, while printing "Good signature": every RSA-3072 signature, measured here.

## From GitHub Actions

The KMS is never exposed to the internet. The release workflow runs on a **self-hosted runner inside
the network**, which holds the workload certificate for the release identity. The policy above is
what limits that runner to signing digests with this one key; the KMS audit journal records every
signature, and the request's `subject` carries the SHA-256 of the file that was signed
(`openpgp-detached sha256:…`), so a signature can be matched to an artifact.

## Signing under a policy that requires approval

The example production policy requires one approval for a release signature (ADR-0002 D25): the
release identity alone cannot sign. The approver signs, with their own Ed25519 key, a binding of the
exact request: object, purpose, environment, nonce, expiry and the SHA-256 of the payload (API.md).
The payload of an OpenPGP signature includes the signature's creation time, so the signature is
prepared first, approved, and completed unchanged.

```sh
# 1. On the runner. Contacts nobody; writes a pending record and prints the file's SHA-256.
regalia-sign --prepare SHA256SUMS.pending --detach SHA256SUMS

# 2. On the approver's machine, with the approver's OWN copy of the file and their hardware key.
regalia-approve --pending SHA256SUMS.pending --file SHA256SUMS      # writes SHA256SUMS.pending.approval

# 3. On the runner, before the record expires (5 minutes by default; --valid-for at step 1).
regalia-sign --complete SHA256SUMS.pending --approval SHA256SUMS.pending.approval --detach SHA256SUMS
```

`--clearsign` and `--export-key` work the same way. The key export is a signature too (the key's
self-certification), so it needs its own approval, once.

What each step checks:

- **Prepare** fixes the signature's creation time, the request's nonce and its expiry, and records
  the SHA-256 of the file and of the payload. Nothing in the pending record is secret.
- **Approve** does not sign an opaque digest. `regalia-approve` pins the release public key, object,
  purpose and environment in its own configuration ([approve.example.json](approve.example.json)),
  recomputes the payload from the approver's copy of the file, and refuses unless it is the payload
  in the record. It also requires the record's file hash to be that of the approver's copy, byte for
  byte: a cleartext signature's payload ignores trailing whitespace and the form of line endings
  (RFC 4880, 7.1), so the payload alone would not tell two such files apart. A record for another
  key or target, an expired one, or one that expires more than an hour from now, is refused.
  **Nothing is approved unseen**: there is no option to approve without the file, because the
  record's own account of what its digest is (which file, what kind of signature, what date) is only
  the preparer's word until the approver's side recomputes it. A key export signs no file and is
  checked against the pinned key and its date.
- **What a cleartext signature cannot pin.** The file hash is checked by the approver and by
  `--complete`; it is not in the binding the KMS verifies, and it could not usefully be. Whoever
  holds a finished cleartext signature can attach it to any text with the same canonical form, with
  or without this tool: that is the format's definition, and every verifier accepts it. The checks
  make an honest run exact. For bytes that must not vary at all, use `--detach`.
- **The signature cannot be backdated.** Its creation time is part of what is signed, and it is the
  preparer's claim. A record whose creation time is not within one window (at most an hour) before
  its expiry is refused by `regalia-approve` and by `--complete`, and the approver is shown the date.
- **The approver key** is Ed25519, on a token reached through OpenSC's `pkcs11-tool`
  (`CKM_EDDSA`). The PIN is typed into `pkcs11-tool`, not into `regalia-approve`. The token is
  named by serial and label together, and exactly one attached token must match before any PIN is
  asked for: every OpenPGP card has the same label, and one YubiKey presents two tokens under one
  serial. The tool and the module are named by absolute path and are refused unless they are owned
  by root or the approver and writable by nobody else, in directories where nobody else can replace
  them. What the token
  returns is verified against the pinned approver public key before an approval is written, so a
  device that cannot make a plain Ed25519 signature is refused here and not found out as a denial
  at the KMS. `key_file` instead of `pkcs11` is a software approver, for tests and staging.
- **Complete** rebuilds the signature and refuses, without contacting the KMS, if the file is not
  byte for byte the prepared one, if the payload differs (the key changed), if the record expired,
  or if an approval is for another request. The KMS then verifies the approval against its own approver keys; evidence it
  does not count is a plain `DENIED`.
- **An approval is spent with its request.** The nonce is the idempotency key, so completing the
  same record twice signs once.

The approval window is at most the policy's `max_future_seconds` (300 in the example): the KMS
denies a request that expires later than that from the moment it arrives, so keep `--valid-for`
within it.

## What it does not do

- **The KMS signs a digest it cannot interpret.** It knows who asked, for which key and purpose, and
  when. It does not see the file. What may be signed is decided by who holds the release identity.
- **No approval in one step.** `--detach`, `--clearsign`, `--export-key` and git's form send no
  approval evidence, so a policy with `required_approvals` denies them. Under such a policy use
  [prepare, approve, complete](#signing-under-a-policy-that-requires-approval). Signing a commit or
  tag from git cannot be approved this way: git runs one command and expects the signature back.
- **No encryption, no inline (binary) signed messages, no subkeys, no expiry.** The key is a single
  version-4 signing key.

## How it is tested

- `go test ./...` here signs through a stand-in KMS that behaves as the token does (ECDSA over the
  digest returning r‖s; RSA padding the DigestInfo it is given). GnuPG and go-crypto must both accept
  each signature against the exported key and reject it over a changed file, for P-256, P-384 and
  RSA-3072. A real `git commit -S` and `git tag -s` are made with the built binary and checked with
  `git verify-commit` and `git verify-tag`.
- Cleartext signatures are checked the same way, and also with apt's own verifiers: `gpgv`, and
  `sqv` where it is installed. `TestAptAcceptsARepositoryWhoseInReleaseWasSignedThroughTheKMS` runs
  `apt-get update` against a flat repository with the exported key as its only trust anchor, and
  requires it to refuse the repository once the signed text changes or the key is absent.
- `TestDeployedRegaliaSignExecutableThroughMTLS` in the parent module (run by
  `e2e/softhsm-pkcs11.sh`) uses no stand-in: the built binary reaches the daemon's policy stack over
  mTLS and the signature is made by the PKCS#11 driver on keys generated inside a SoftHSM token.
- The approval flow is tested at both levels. Here, the stand-in KMS verifies approvals against the
  binding of the request that arrived, and a stand-in token (the test binary, run as `pkcs11-tool`
  would be) signs honestly, with another key, over something derived from the binding, or returns a
  short result; only the first yields an approval. `TestTheBindingIsTheBytesAPIMdPublishes` holds
  this module's copy of the binding to the vector API.md publishes.
  `TestAReleaseSignatureNeedsAHardwareKeyApprovalAtTheRealDaemon` in the parent module uses no
  stand-in: the daemon's own approval verifier and policy decide, and the approver key is an Ed25519
  key on the SoftHSM token, signed with by the real `pkcs11-tool`.
- With `REGALIA_EXPECT_GPG=1` a missing `gpg` or `git` fails these tests instead of skipping them.
  CI sets it.

Evidence class: **emulated**. No release has been signed on a Nitrokey through this path yet, and
no approval has been made on a YubiKey with `regalia-approve`. Measured separately on a YubiKey 5
(firmware 5.7.4, OpenPGP applet, through OpenSC): `CKM_EDDSA` signs inputs of 200 to 1024 bytes as
plain Ed25519, which covers the binding (about 200 bytes). A key with touch required has not been
measured.

## Ed25519: signing twice (a recorded deviation)

go-crypto lets an external signer make RSA and ECDSA signatures. For EdDSA it accepts only its own
private-key type, so a KMS-held Ed25519 key cannot be plugged in. Until the library takes one,
`eddsa.go` does this instead (decided on regalia#530, 2026-10-02):

1. go-crypto builds the complete signature packet once, signing with a **throwaway** Ed25519 key.
   The public key, issuer fingerprint and issuer key ID in the packet are the KMS key's; only the
   private half is a dummy.
2. The hash object is ours, so the digest being signed is observed.
3. The KMS signs that digest (pure Ed25519 over the 32 bytes), checked against the pinned key.
4. The throwaway signature's two integers, R and S, are replaced with the KMS's.
5. The finished packet is parsed back and verified against the KMS public key before one byte is
   written. This step now runs for every key type.

What this adapter encodes itself is exactly the two integers of step 4. The project's rule is that
the library does the encoding, so this is a deviation, and it goes away when go-crypto accepts a
`crypto.Signer` for EdDSA.

Tests: the same GnuPG, `gpgv`, `sqv`, git and apt checks as the other key types;
`TestTheThrowawayEd25519SignatureCanNeverLeave` skips step 4 and requires every output path to refuse
and write nothing; `TestAnEd25519SignatureAndKeyNameTheKMSKeyAndNothingOfTheThrowawayKey` parses the
output; a signature whose R or S begins with a zero byte is held to GnuPG.

## A note on go-crypto v1.5.2

In `packet.Signature.Sign`, the RSA arm declares a new `err`, so an error from an external RSA signer
is lost and surfaces later as "need to call Sign before Serialize". `regalia-sign` keeps the signer's
own error and returns that (see `bound` in `signer.go`), so a KMS refusal reads as one for RSA and
ECDSA alike. `TestASignatureThePinnedKeyDoesNotVerifyIsNeverEmitted` fails if that is removed.
