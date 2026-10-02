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

## Authenticated tools, filesystem scanning and release consumption

The prototype pipeline in `lab/appliance/` starts with our GPG-verified Debian
installer. It does not inherit Debian Docker Official Image publisher trust.
The scanner policy pins Syft 1.54.0 and Grype 0.119.0, their archive SHA-256
values, exact Anchore release-workflow identities and the GitHub OIDC issuer.
The local Cosign installation is a trusted verifier prerequisite. CI bootstraps
Cosign 3.0.6 from a separately reviewed binary hash in `bootstrap-cosign.sh`.
That initial pin, repository policy and build machine are trust anchors.

```sh
python3 -m deploy.images.tools deploy/images/.artifacts/scanners
python3 -m deploy.images.scan FINAL_ROOTFS.tar.gz \
  --tools deploy/images/.artifacts/scanners --output SCAN_OUTPUT
```

The scan catalogs regular files from the **final** root filesystem, generating
Syft JSON, SPDX JSON and CycloneDX JSON. A private projection skips archive links
and special files; no image executable or archive link is executed. This limits
link-only metadata coverage. Traversal, duplicate regular files and oversized
archives fail. Grype validates database freshness (maximum 120 hours); database
metadata/downloads remain dependent on Anchore's HTTPS distribution. Scanner
configuration and environment are isolated from local ignore policies. High and
Critical findings block release even when a scanner erroneously returns success.
Tool errors, empty SBOMs, wrong distro and invalid/stale databases also block.
`wont-fix` findings are retained. There is no automatic waiver or exception path.

A release consists of `release.json`, its signatures/attestations, and a flat
`payload/` with the exact artifacts named in the manifest. Preparation requires
passing boot and scan evidence bound to the disk, filesystem and executable.
The verifier checks signatures before parsing release claims or reading artifact
contents for consumption; it never executes the artifact to discover its version.
Expected repository, workflow, issuer, source ref and commit are caller policy.

```sh
python3 -m deploy.images.release verify RELEASE/payload \
  --manifest RELEASE/release.json --bundle RELEASE/release.sigstore.json \
  --commit FULL_APPROVED_COMMIT --ref refs/heads/main \
  --identity 'https://github.com/Digital-Frontier-LDA/regalia-kms/.github/workflows/appliance.yml@refs/heads/main' \
  --issuer https://token.actions.githubusercontent.com
python3 -m deploy.images.release verify-attestation RELEASE/release.json \
  --bundle RELEASE/provenance.jsonl --commit FULL_APPROVED_COMMIT --ref refs/heads/main
python3 -m deploy.images.release verify-attestation RELEASE/payload/regalia-debian13-amd64.qcow2 \
  --bundle RELEASE/sbom-attestation.jsonl --sbom RELEASE/payload/sbom.attestation.spdx.json \
  --commit FULL_APPROVED_COMMIT --ref refs/heads/main
```

Offline approval can use an independently provisioned GPG release signer. On
its offline signing workstation, create a SHA-512 checksum of `release.json`
and detach-sign that checksum file. Production private keys are never imported
into GitHub Actions. Consumers obtain the public key and full fingerprint through
an independent trusted channel, then run:

```sh
python3 -m deploy.images.release verify-offline RELEASE/payload \
  --manifest RELEASE/release.json --checksums SHA512SUMS --signature SHA512SUMS.sign \
  --key OFFLINE_RELEASE_PUBLIC_KEY --fingerprint FULL_APPROVED_FINGERPRINT \
  --commit FULL_APPROVED_COMMIT --ref refs/heads/main
```

CI identity and offline approval are separate authorities. A keyless CI signature
does not establish physical recovery authority or production approval. The manual
`Debian appliance prototype` workflow builds only from `main`; signing defaults
to off. **Before enabling signing**, configure the `appliance-signing` GitHub
environment with required reviewers and a `main` deployment restriction. The
workflow uploads signed prototype artifacts; it does not publish a production
registry image or GitHub Release. Configure protected branches separately.

## Repeatability

```sh
python3 -m deploy.images.rebuild --commit FULL_COMMIT --output REBUILD_OUTPUT
python3 -m deploy.images.release compare FIRST_ARTIFACT_DIRECTORY SECOND_ARTIFACT_DIRECTORY
```

The executable check uses two source directories and independent compiler caches
on the same host/toolchain, then requires every artifact name and byte to match.
It establishes repeatability within that environment. It does not claim independent
builder verification or disk-image reproducibility: package snapshots, filesystem
UUIDs, firmware variable stores and boot/install timestamps still need a design.

The full SBOMs retain file inventory. `sbom.attestation.spdx.json` retains every package and package relationship, removes file nodes/edges and marks `filesAnalyzed: false`. This package inventory fits the pinned GitHub action's 16 MiB SBOM limit. Both documents are hash-bound in the release manifest; consumers compare the attested predicate against the exact released package document.
# Debian vulnerability review

After a completed scan, create a diagnostic report against the current
[Debian security tracker](https://security-tracker.debian.org/tracker):

```sh
python3 -m deploy.images.triage SCAN_EVIDENCE --output NEW_REVIEW_DIRECTORY
```

This requires `dpkg` for Debian version ordering. The tool verifies inventory and
finding hashes against the scan report, joins binary packages to their source
versions and records every High/Critical finding. Kernel findings map to a unique
Debian package owning the cataloged kernel path; that association needs review.
The report groups repeated matches and identifies vendor-fixed/not-affected
**candidates**, open issues and installed versions older than recorded fixes.
It grants no waiver and never modifies the scan verdict or release policy.

The HTTPS tracker snapshot, timestamp and hash are retained beside the report.
It has no detached publisher signature. `--tracker FILE` permits an explicitly
operator-supplied snapshot, which is recorded without claiming HTTPS freshness.
Candidate findings still require patch/changelog and applicability review.
