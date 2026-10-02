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

## Follow-up: fresh baseline and enforcing daemon

This section supersedes the earlier AppArmor and fresh-execution limitations for
these specifically identified builds; it does not qualify production hardware.

- A fresh, uninterrupted build of recipe/application commit
  `f73f6dda6159f6d25823ca41e1df58a8b5a7c975` passed installation, guest acceptance,
  export, normal UEFI boot and disk integrity checks in 1,835 seconds. Disk
  SHA-256 `629d8b6f221b441194cb38737e95a2a1541cbb4a5a43e680f552a97df983c2cf`;
  filesystem SHA-256 `f888b22728ce465dfba03c70187b8ead127352f62f0060b00722d34dda797b94`.
  Evidence: `.artifacts/debian13-fresh-f73f6dd/`. This predates the new enforcing
  daemon test and package updates.
- The updated recipe upgrades authenticated Debian packages before compiling,
  removes unnecessary editors, disables the installer-only CD APT entry, and
  explicitly sets public executable/unit permissions and private configuration
  group access. Setup errors retain bounded public diagnostics and terminate the
  exact installer child instead of waiting on an interactive prompt.
- The updated installed guest was repaired using retained, hash-recorded hooks.
  Its real daemon passed AppArmor `regalia-kms (enforce)`, zero effective
  capabilities, `NoNewPrivs: 1` and `Seccomp: 2` checks. Liveness returned 200;
  readiness remained 503 without credentials. A valid public custody fixture
  passed configuration preflight under the profile; the same daemon was refused
  access to a DAC-readable file outside the permitted configuration directory.
  Temporary configuration, manifest and commissioning marker were removed before
  export, and the unit again stayed inactive without commissioning.
- This repaired build has application source
  `538d86dc88b96f12579370a8b7315e7956a94bf6`, 274 installed packages, and PCRE2
  `10.46-1~deb13u3`. Its normal UEFI boot reached multi-user in 79.51 seconds
  while scanning ran concurrently, without rerunning acceptance or changing the
  base disk. Disk SHA-256
  `b2e2d35999a63ed7e83bcda8bfc30028c6bb71f1045b3cd0f247b59b23d357d0`;
  filesystem SHA-256
  `79d586efc2effe57a52183d319f06e578bc7508a9b014aa966c67cf039bb23cb`.
  Evidence: `.artifacts/.appliance-enforce-retry-public-fixture/`. This is
  explicitly repaired evidence, not a fresh run of the latest recipe.
- PR CI now builds the complete authenticated appliance on Linux, requires both
  enforcing-daemon and acceptance markers, and probes normal UEFI disk boot.
  Recipe, application, configuration, dependencies, systemd and AppArmor changes
  trigger this gate. Failed build/boot diagnostics are retained, including hidden
  staging directories. This gate neither signs images nor bypasses scanning.
- All 54 image verification tests pass locally; shell syntax, Actionlint, diff
  checks and new-commit secret scans pass. A merged macOS stat-mode-width compile
  regression was fixed; command-package tests and public-fixture preflight pass
  there. Linux-specific PIN ACL tests still require Linux and fail on this macOS
  filesystem; no macOS hardware-credential runtime qualification is claimed.

The enforcing test covers daemon startup, health, configuration and process
restrictions. PKCS#11 access under this profile still needs physical-device
qualification. The image remains unencrypted, uncommissioned and development
only; blocking scan findings, signing custody and real measured boot remain gates.

### Updated filesystem scan

The repaired enforcing build's final filesystem rescan reports **38 Critical,
258 High, 438 Medium, 41 Low and 711 Negligible matches**. PCRE2's authenticated
update and editor removal eliminated 49 High matches relative to the earlier
cleaned image; no finding was suppressed. The scan still returns `blocked` and
release collection refuses it before creating any output. The full 307.6 MiB
filesystem archive, inventories and scan hashes are retained under
`.artifacts/docker-scan-enforced/evidence/`. The export contains no temporary
acceptance configuration, custody manifest or commissioning marker. No image was
signed or published.
