# Debian appliance validation — 2026-10-02

## Security Findings

The cleaned, boot-verified prototype's final filesystem scan reported **38 Critical,
307 High, 467 Medium, 41 Low and 723 Negligible matches**. These are scanner
matches, often repeated across packages/modules; they are not unique CVEs or
confirmed exploitability. No exceptions were introduced. The scan returned exit 1
and `status: blocked`; collecting a release was refused before copying artifacts.
No production image or release signature was issued.

The first filesystem inventory revealed Go's automatically downloaded compiler
and modules left in `/go`: Debian's installer had set an unexpected home path.
The build now explicitly sets disposable GOPATH/GOCACHE/GOMODCACHE directories.
The repaired image removes the old cache and obsolete installer kernel; acceptance
checks both cache absence and exactly one installed versioned kernel.

## Checks Performed

- Actual Debian 13.7.0 amd64 installer authenticated using its GPG-signed SHA-512
  manifest and approved Debian CD fingerprint before kernel/initramfs extraction.
- Unattended UEFI installation under native QEMU 10.2.2 on Apple Silicon, with
  authenticated Debian packages and Go 1.26.6 toolchain/checksum-database checks.
- Real CGO Linux/amd64 KMS executable built from source commit
  `4dd517748e0d73e886e3c342d25da3ba00763417`, 11,991,232 bytes;
  SHA-256 `3d251b71af496357b7f19128edd0a77ab21288c38296a535dc530ea177162309`.
- Guest acceptance checks: Debian 13/systemd, no commissioned configuration or
  node identity, locked root, dedicated nologin user, absent compiler/cache,
  single current kernel, inactive commissioning-gated KMS service, strict unit
  settings, empty capabilities, active default-deny nftables, no TCP listeners,
  enabled AppArmor and restrictive sysctls, no swap or forbidden service packages.
- First acceptance hit a serial-console/getty conflict. The getty is now masked
  in the build recipe. Acceptance and archive export then completed with a fixed
  `REGALIA_ACCEPTANCE_PASS` marker and clean shutdown.
- The installed image was repaired using recorded initramfs hooks to apply the
  getty/cache/kernel fixes. Original logs and repair scripts/hashes are retained.
  This was a repair of a real installation; a fresh uninterrupted run of the
  final complete recipe remains to be exercised by the main-branch workflow.
- Final normal UEFI boot tested in a disposable overlay: `multi-user.target`
  reached in 20.62 seconds; verification did not rerun; clean ACPI shutdown.
  The reusable base image hash did not change during this probe.
- `qemu-img check` found no disk errors. Eight GiB virtual qcow2, approximately
  3.0 GiB allocated because deleted build-time data remains in free blocks.
  Reusable filesystem archive: 411,132,520 bytes (about 392 MiB).
- Clean disk SHA-256:
  `7b57b24087f2b3ef08961426c88d03dcdf04ba50b0bd524518eead06bd6a8c0b`.
  Filesystem archive SHA-256:
  `a70e12dda501378dcd9fda02ac8f2cd888d8556df3e107e491cca3ae250832dd`.
- Final Linux filesystem inventory: 22,531 archive members; 836,266,571 regular
  bytes; 1,560 links skipped; 4,515 cataloged artifacts including individual
  kernel modules. Host-package inventory contains 277 installed packages.
- Full Syft/SPDX/CycloneDX reports retained. Compact SPDX retains all 4,516 SPDX
  package entries (including the document source package), 9,884,599 bytes,
  fitting GitHub's 16 MiB attestation limit. File inventory stays in the full SBOM.
- Linux scanner archives authenticated on the host before execution in a pinned
  local development Docker image. TLS uses the host system CA store; the image
  being scanned cannot provide trusted roots. No TLS/transparency checks disabled.
- 231 Python guards, including 41 image tests, pass. Actionlint, shell syntax,
  Python compilation and diff checks pass. Prior provenance commit CI passed all
  24 jobs, including real scanner signatures and Linux executable repeatability.

Local artifacts and reports are ignored under:

```text
lab/appliance/.artifacts/debian13-prototype-clean/
lab/appliance/.artifacts/docker-scan-clean/evidence/
```

## Residual Risk

The prototype is unencrypted and uncommissioned, without hardware/service/recovery
credentials. Production still requires per-node LUKS2/TPM+peer provisioning,
measured/signed boot qualification on DL360 hardware, physical HSM tests and
recovery signer custody. AppArmor is enabled; a KMS-specific profile is not installed by this prototype,
and hardware access exceptions still need implementation and qualification. Unit settings were inspected
while the KMS service was deliberately unavailable, rather than a production HSM
session being exercised. Package repositories are authenticated but not snapshot
pinned. Reproducible disks and independently reproduced builds are not claimed.
The local Docker scan runner lacks publisher authentication and remains
*development-only*. Native Linux CI is the intended release scanner environment.
Scanner warnings about schema compatibility and module-level Go matching remain
visible; findings require authoritative review.

## Recommendation

Keep the image as a development prototype and the PR draft. Review all blocking
findings before release approval. Run the final automated recipe after review;
configure the protected signing environment before exercising GitHub OIDC
signatures and attestations. No production authority private key belongs in CI.
