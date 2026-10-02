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
```

| Command | What it does | KMS operations |
|---|---|---|
| `--detach FILE` | writes `FILE.asc`, an armored detached signature (`--binary`: `FILE.sig`; `--output`: elsewhere; `-` reads stdin, writes stdout). Never replaces an existing file. | 1 |
| `--export-key` | prints the armored public key verifiers import | 1 |
| `--fingerprint` | prints the key's fingerprint | 0 |
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

The Nitrokey HSM 2 has no Ed25519. One key signs with one digest: `regalia-sign` refuses any other,
so the policy's payload size can be exact.

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

## From GitHub Actions

The KMS is never exposed to the internet. The release workflow runs on a **self-hosted runner inside
the network**, which holds the workload certificate for the release identity. The policy above is
what limits that runner to signing digests with this one key; the KMS audit journal records every
signature, and the request's `subject` carries the SHA-256 of the file that was signed
(`openpgp-detached sha256:…`), so a signature can be matched to an artifact.

## What it does not do

- **The KMS signs a digest it cannot interpret.** It knows who asked, for which key and purpose, and
  when. It does not see the file. What may be signed is decided by who holds the release identity.
- **No approvals.** A policy with `required_approvals` needs evidence over the exact payload, which
  here is a digest that includes the signature's own creation time. `regalia-sign` sends none, so
  such a policy denies it.
- **No encryption, no clear-signed or inline signatures, no subkeys, no expiry.** The key is a
  single version-4 signing key.

## How it is tested

- `go test ./...` here signs through a stand-in KMS that behaves as the token does (ECDSA over the
  digest returning r‖s; RSA padding the DigestInfo it is given). GnuPG and go-crypto must both accept
  each signature against the exported key and reject it over a changed file, for P-256, P-384 and
  RSA-3072. A real `git commit -S` and `git tag -s` are made with the built binary and checked with
  `git verify-commit` and `git verify-tag`.
- `TestDeployedRegaliaSignExecutableThroughMTLS` in the parent module (run by
  `e2e/softhsm-pkcs11.sh`) uses no stand-in: the built binary reaches the daemon's policy stack over
  mTLS and the signature is made by the PKCS#11 driver on keys generated inside a SoftHSM token.
- With `REGALIA_EXPECT_GPG=1` a missing `gpg` or `git` fails these tests instead of skipping them.
  CI sets it.

Evidence class: **emulated**. No release has been signed on a Nitrokey through this path yet.

## A note on go-crypto v1.5.2

In `packet.Signature.Sign`, the RSA arm declares a new `err`, so an error from an external RSA signer
is lost and surfaces later as "need to call Sign before Serialize". `regalia-sign` keeps the signer's
own error and returns that (see `bound` in `signer.go`), so a KMS refusal reads as one for RSA and
ECDSA alike. `TestASignatureThePinnedKeyDoesNotVerifyIsNeverEmitted` fails if that is removed.
