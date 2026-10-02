# Debian appliance prototype and release pipeline

## Objective

Build an uncommissioned Debian 13 amd64 disk using the authenticated installer,
boot it under QEMU, inventory and scan its contents, and produce verifiable release
artifacts. Reuse the signing/attestation/SBOM patterns from
`redoubt-cysec/provenance-template` at commit
`90544029e6c4793c3bc7046aa50a47b18853731b`, with exact signer identities,
authenticated tools, fail-closed scans and exact artifact rebuild comparisons.

## Ordered slices

1. Verified installer -> unattended UEFI Debian installation -> hardened OS and
   KMS executable -> QEMU acceptance evidence. The image is uncommissioned: no
   node identity, PIN, disk key, recovery secret or service configuration.
2. Authenticated, version-pinned Syft/Grype -> final filesystem SBOM and scan ->
   hash-bound provenance and release manifest. Tool or scanner failures block
   release. Findings require explicit review, never an implicit pass.
3. Exact signer verification for blobs and GitHub attestations, signed release
   workflow, tampering drills and deterministic artifact rebuild checks.

## Boundaries

QEMU receives only a disposable image file and verified installer. No host block
devices, hardware credentials, Docker socket or management ports are exposed.
Use an operator-owned artifact directory. The installer/build guest can reach
Debian and Go repositories; the resulting uncommissioned image has default-deny
networking, locked accounts and a gated KMS service.

The reusable template disk is unencrypted and contains no commissioned secrets.
Per-node LUKS2/TPM+peer provisioning is a separate ceremony. Never deploy this
prototype before disk commissioning, signed boot measurements, hardware tests and
release approval. A CI signature identifies our builder; Debian publisher trust
comes from the verified installer and authenticated APT metadata/package hashes.
The QEMU binary, build host and repository policy are trusted build infrastructure.

## Commands and structure

From the repository root:

```sh
mkdir -p deploy/images/.artifacts
python3 -m deploy.images.fetch_debian deploy/images/.artifacts/debian
python3 -m deploy.images.snapshot deploy/images/.artifacts/package-snapshot
python3 -m lab.appliance.build --media deploy/images/.artifacts/debian
```

The builder requires QEMU x86, xorriso, cpio, gzip, GnuPG and Python 3.11+.
`preseed.cfg`, `finish.sh` and `acceptance.sh` are the guest build/verification
inputs; `build.py` is the host orchestrator. Artifacts go under ignored `.artifacts/`.
Python verification uses unittest and real external signing tools where available.
Build inputs are frozen before guest launch. The installer uses the reviewed
Debian and security snapshot timestamp from `package-snapshot-policy.json`, and
the builder checks every final installed package version against those signed
indexes. Disk reproducibility is not yet claimed.

Snapshot capture requires the exact Debian 13 archive/security primary
fingerprints, valid clear signatures, matching SHA-256 package indexes and a
recent policy timestamp. Security Release expiry stays enabled; after expiry,
review and capture a newer snapshot. There is no automatic rolling-mirror
fallback or historical-expiry bypass. HTTP during Debian installation retains
APT signature, package hash and expiry checks; host capture uses HTTPS.
The authenticated ISO remains a separate fixed input.

Independent CI jobs build the same exact Git archive on two Linux runner
instances with separate source/module/compiler caches. The comparison checks
distinct boot IDs, equal source/toolchain inputs and identical executable bytes.
Both runners belong to the same CI provider; this is repeatability evidence, not
independent builder trust or a reproducible full disk.

## Security Findings

The appliance is a prototype until independently authenticated provenance,
vulnerability review, release signer custody and hardware commissioning are complete.

## Checks Performed

Build and boot evidence records source hashes, installer verification, packages,
toolchain, service/network restrictions and absence of commissioned configuration.

## Residual Risk

Emulation does not qualify physical TPM measurements, firmware, HSM adapters,
secret zeroization or theft resistance. Build provenance does not prove a benign build.

## Recommendation

Keep release consumption fail-closed. Use disposable signing keys only for negative
tests; production trusts an explicitly approved workflow or offline release signer.

### Linux and macOS builders

The default firmware paths select Debian/Ubuntu OVMF on Linux or Homebrew EDK2
on macOS. Explicit `--firmware` and `--variables` overrides must refer to a
compatible reviewed pair. `--acceleration kvm` is selected only when `/dev/kvm`
is accessible; otherwise the local builder uses TCG. Hosted CI requires KVM and
runs the builder with the ephemeral runner user and the KVM group. A QMP
preflight must confirm an initialized CPU and a paused diskless/networkless
machine before quitting; no world permissions are added. This avoids an observed
QEMU 8.2 TCG crash during early guest boot. The x86 TCG guest is slower on Apple
Silicon. Linux CI allows 150 minutes for installation/build; acceptance has its
own ten-minute timeout. A failed guest leaves diagnostic files and a failed
report under `.artifacts/.appliance-build-*`, never a passing output directory.
Build inputs are copied into private staging before QEMU starts and their exact
hashes appear in the report.

```sh
python3 -m deploy.images.scan lab/appliance/.artifacts/debian13-prototype/export/rootfs.tar.gz \
  --tools deploy/images/.artifacts/scanners --output lab/appliance/.artifacts/scan
python3 -m lab.appliance.collect --build lab/appliance/.artifacts/debian13-prototype \
  --scan lab/appliance/.artifacts/scan --output lab/appliance/.artifacts/release \
  --commit FULL_SOURCE_COMMIT --ref refs/heads/main
```

The collection step refuses failed scans and copies only regular files into a
flat payload. See `deploy/images/README.md` for signer setup, consumption checks
and the distinction between repeatable binaries and reproducible disks.

### Case-sensitive scans on macOS

Linux kernel packages contain filenames differing only by case. macOS's default
filesystem cannot faithfully project these names. On this development machine use:

```sh
python3 -m lab.appliance.scan_docker lab/appliance/.artifacts/debian13-prototype/export/rootfs.tar.gz \
  --tools deploy/images/.artifacts/scanners-linux --output lab/appliance/.artifacts/docker-scan
```

The helper authenticates Linux scanner archives on the host before running them
in a case-sensitive Docker overlay. It pins the local development runner by its
image ID, uses `--pull=never`, drops capabilities, enables `no-new-privileges`,
runs as the host UID, and mounts only scanner code/binaries, the input archive and
one output directory. No Docker socket or hardware devices are mounted. HTTPS
uses the trusted **host** root CA store, never certificates from the scanned
image. TLS verification remains enabled. Runner metadata records the image ID
and CA-store hash. The existing runner has no publisher authentication and remains
development-only; production CI scans natively on its trusted Linux builder.

`lab.appliance.probe` checks a normal UEFI boot in a disposable disk overlay,
without mutating the reusable base image. It requires `multi-user.target`, verifies
that the export test does not rerun, and requests a clean ACPI shutdown. This
check also runs at the end of new builds. Private temporary monitor sockets use
short paths because macOS limits Unix socket path lengths.

## Rebuild status

The recipe includes fixes discovered by live installation and scanning: masked
serial getty, explicit disposable Go cache paths, and removal of obsolete installer
kernels. The earlier baseline passed a fresh uninterrupted build; the updated
AppArmor recipe has separate repaired evidence and a continuous fresh-build gate.
See `VALIDATION.md` for exact source versions and limits. A successful boot does
not issue production approval.

### Package update and minimization policy

Before compiling, the recipe refreshes authenticated APT metadata and upgrades the
complete installed package set. This covers base packages copied from older
installer media, including fixes subsequently published in `trixie-security`.
Signature, hash and expiry checks stay enabled. Installed versions are recorded;
there is no claim of immutable repository snapshots. The recipe removes the
build compiler and interactive editors (`vim-tiny`, `vim-common`, `nano`) and
acceptance refuses images retaining them. These changes address an observed PCRE2
update gap and unnecessary parser packages; a new scan still decides release status.

### Enforced daemon acceptance

The recipe installs the bare-metal AppArmor profile and hardening drop-in already
shipped in this repository. Guest acceptance temporarily starts the real daemon
with the shipped public custody fixture and no credentials, then measures the
running process: enforcing profile,
zero effective capabilities, no-new-privileges and seccomp filtering. Liveness
must succeed while readiness remains 503 without credentials. The daemon's
configuration check must accept the permitted path and specifically report
permission denied for an otherwise readable configuration outside the profile.
All temporary configuration/commissioning markers are removed before export;
service startup must again be blocked and no TCP listener may remain. This checks
startup and OS confinement; it does not qualify token operations or a physical HSM.

### Continuous recipe validation

The `appliance-build` CI job runs the authenticated installation, acceptance and
normal UEFI boot when recipes, daemon code, dependencies, configuration, service
units, AppArmor policy or their workflows change. It
retains only public build/boot diagnostics, including failed private staging
directories. This job checks boot behavior and does not issue release approval,
signatures or image publication. The separate manual appliance workflow retains
the complete final filesystem scan and signing gate.


### Exact build scan gate

PR CI authenticates Syft/Grype and scans the exact filesystem exported by its
fresh passing build. `python3 -m lab.appliance.scan_build` first binds both rootfs
and executable bytes to the expected full source commit and passing report.
Its `build-binding.json` records the scan report and build report hashes. High
or Critical findings fail this CI gate and keep `release_admissible: false`;
public SBOMs, findings, binding, and Debian-tracker triage are retained even when
blocked. These diagnostics do not waive the scan or commission the image.
