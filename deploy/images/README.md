# Image verification contract

Every appliance download and release must pass authenticity and integrity checks
before extraction, installation or boot. A tag, TLS connection, checksum obtained
beside an image, or a successful vulnerability scan does not establish its signer.

## Implementation order

1. Authenticate Debian 13 installer media using its detached GPG signature, the
   reviewed full Debian CD signing-key fingerprint, and SHA-512. Reject missing,
   corrupt, ambiguous, expired or untrusted evidence before consuming an image.
2. Verify OCI images by digest with Cosign and an exact approved certificate
   identity/issuer or a pinned public key. Keep claims and transparency verification
   enabled. Reject unsigned images; never silently fall back to checksum-only use.
3. Apply the same GPG manifest gate to exported appliance disks, kernel, initramfs
   and recovery media, signed by a separately commissioned release authority.
4. Build and boot an uncommissioned minimal Debian appliance from verified inputs.
   Add package inventory, vulnerability assessment, reproducible build provenance
   and boot-integrity checks before production acceptance.

The current Docker bootstrap experiments are development fixtures. Their Debian
base is digest-pinned; publisher signature verification has not been demonstrated.
They are **not approved appliance images**. The inventory check reports this gap
and prevents additional unauthenticated external image references being introduced
without an explicit policy change. The deprecated Proxmox importer is also
checksum-only and is not an approved deployment path.

## Structure and commands

- `verify.py`: standard-library Python orchestrates GnuPG/Cosign; no custom crypto.
- `debian-policy.json`: reviewed release, architecture, URLs and full signer pin.
- `fetch_debian.py`: fetch, authenticate and atomically publish installer media.
- `inventory.py`: enumerate repository image inputs and report trust gaps.
- `tests/test_image_verification.py`: real GPG adversarial integration tests.

Run tests with `python3 -m unittest discover -s tests -p 'test_image_*.py'`.
From the repository root, fetch verified Debian media with
`python3 -m deploy.images.fetch_debian OUTPUT_DIR`.
Dependencies: Python 3.11+, GnuPG; Cosign for OCI verification and PyYAML 6.0.3
for the inventory (already pinned in the lab harness requirements). Tests create and
destroy disposable signing keys and never access personal GPG keyrings.

Repeat a downloaded or exported disk check immediately before use:

```sh
python3 deploy/images/verify.py gpg \
  --image OUTPUT_DIR/debian-13.7.0-amd64-netinst.iso \
  --manifest OUTPUT_DIR/SHA512SUMS --signature OUTPUT_DIR/SHA512SUMS.sign \
  --key OUTPUT_DIR/debian-cd.pub \
  --fingerprint DF9B9C49EAA9298432589D76DA87E80D6294BE9B
```

For OCI inputs, pass a digest and the exact approved signer:

```sh
python3 deploy/images/verify.py oci REGISTRY/IMAGE@sha256:DIGEST \
  --identity APPROVED_IDENTITY --issuer https://APPROVED_OIDC_ISSUER
```

For public-key signing, substitute `--key approved.pub --key-sha256 APPROVED_KEY_HASH`.
There is no insecure-registry, wildcard-identity or unsigned-fallback option.
`inventory.py --production` currently exits nonzero because lab inputs lack
publisher-authentication evidence; its ordinary success permits development only.

## Trust and limits

Policy/key updates require code review. Never learn a trusted fingerprint from the
signature under verification. A release key signs our artifacts, not Debian's
publisher provenance. A test key only tests the gate and grants no production trust.
Verification reports are evidence, not transferable permission: repeat checks at
each consumption boundary in directories writable only by the operator. Prevent
concurrent writes while checking and consuming artifacts. Signing does not prove
the build is benign or boot measurements cover its contents.

Use APT's signed Release metadata and package hashes during installation; prohibit
`trusted=yes`, insecure repositories and disabling signature/expiry checks. Assess
vulnerabilities and retain an SBOM/package list separately from signature checks.
UEFI/UKI signatures and actual TPM PCR coverage remain independent acceptance gates.

Sources: [Debian image verification](https://www.debian.org/CD/verify),
[Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/),
[Docker Content Trust retirement](https://www.docker.com/blog/docker-content-trust-retirement-and-migration-guidance/).

## Security Findings

Existing Docker lab images have no established publisher-signature chain. Block
production promotion until verified inputs and an approved release signer exist.

## Checks Performed

The verification suite uses real signatures to exercise successful verification,
wrong signers, tampering, missing proof and ambiguous checksum input. Live Debian
verification produces a sanitized JSON report containing hashes and signer identity.

## Residual Risk

The build host, trusted tools, key custody, repository policy and time must remain
trusted. Image verification does not qualify DL360 firmware or hardware devices.

## Recommendation

Use this gate for new appliance inputs. Preserve the distinction between development
fixtures and production approval until every image input has authenticated provenance.
