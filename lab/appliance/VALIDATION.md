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

### Linux CI infrastructure failure and KVM preflight

[CI run 37038540866](https://github.com/Digital-Frontier-LDA/regalia-kms/actions/runs/37038540866)
passed all 29 regular jobs, CodeQL and secret scanning. The authenticated appliance
installation completed, but QEMU 8.2.2 under TCG terminated with SIGSEGV during
kernel/PCI startup, before the acceptance script began. This run is **failed**;
no image acceptance or release approval is inferred. Its source is GitHub's
synthetic PR merge `8190a14f3273d35f001bb4d161d5143e91c920c0`, not the branch head.
Retained installer/acceptance logs and report are under `.artifacts/ci-7ae5f60/`.

The first KVM attempt, [CI run 37045119166](https://github.com/Digital-Frontier-LDA/regalia-kms/actions/runs/37045119166),
also failed: the original preflight exited successfully but the installer could
not open `/dev/kvm`. Its report and stderr are retained under
`.artifacts/ci-0142be6/`. The network jobs separately failed while assigning static
addresses on an automatically configured Docker bridge.

Hosted CI now runs both preflight and the builder as the ephemeral runner user
with the KVM group. Preflight uses QMP to verify an initialized CPU, active KVM,
and a paused diskless/networkless machine before quitting. It rejects an early
zero exit; six simulated QMP cases in four tests verify success, failure and
child cleanup, without claiming actual hardware qualification. CI passes
`--acceleration kvm` explicitly; missing or unsupported KVM fails preflight
rather than silently selecting TCG. Local macOS builds retain TCG support.
Failed reports record acceleration and retain QEMU stderr. A fresh complete
Linux installation and acceptance run is still required.

The network fixture now reads Docker-assigned bridge addresses instead of
requesting static addresses. The local three-node run passes all 276 checks,
including encrypted UDP controls, confirmed underlay packet arrival and refusal
on both WireGuard planes, followed by 36 seeded chaos steps and cleanup. This
uses the recorded development source override on the cached native image; it
is not publisher authentication or a full TCP CVE exploit.


### Fresh KVM installation and acknowledged shutdown

[CI run 37047653264](https://github.com/Digital-Frontier-LDA/regalia-kms/actions/runs/37047653264)
passed all 29 regular jobs, CodeQL and secret scanning. The fresh KVM image
installation completed in about 219 seconds; enforcing-daemon acceptance and
export completed in about 41 seconds. The serial log confirms the actual daemon
in AppArmor enforce, zero effective capabilities, NoNewPrivs 1 and Seccomp 2.
Normal UEFI boot reached multi-user.target in about 12 seconds, but the monitor's
shutdown request did not result in a clean exit within 120 seconds. The complete
image job remains **failed**. Public evidence is under `.artifacts/ci-6740613/`;
source is synthetic PR merge `7d2ec66bfeb81d7f13ebb6c2d55088606b04f1da`.

The normal-boot probe now negotiates QMP capabilities, requires command
acknowledgement and keeps its socket open while waiting for guest shutdown.
Unsolicited events and QMP errors cannot count as acknowledgements. It clears
retained serial output before startup, and preserves normal-boot stderr on
failure. This removes the fire-and-close HMP request; the exact cause of the
previous lost shutdown is not established. Another fresh complete run must pass.

Release collection now includes both public boot logs. The signed artifact set
requires ordered, unique acceptance/enforcing-daemon markers without failure,
and normal UEFI evidence bound to the report's hash without a verification flag
or rerun. Legacy generic passing reports and incomplete collections are rejected.
The original vulnerability verdict remains blocked; boot evidence does not waive it.


The revised QMP probe also passed against the retained local enforcing-daemon
image: normal UEFI multi-user startup in 30.60 seconds followed by clean ACPI
shutdown. The base disk hash remained
`b2e2d35999a63ed7e83bcda8bfc30028c6bb71f1045b3cd0f247b59b23d357d0`.
Separate `normal-boot-qmp.log` and `.stderr` retain this check without replacing
the earlier normal-boot evidence; log SHA-256 is
`5c9a209bb51309767e43a498c2c8c91de30a6cc4735c68b2e7cfe9902a13d0f3`.
All 64 image verification tests pass locally. This local check is not a fresh
latest-source installation or physical hardware qualification.


### Complete fresh Linux build passes

[CI run 37048926494](https://github.com/Digital-Frontier-LDA/regalia-kms/actions/runs/37048926494)
passed the complete appliance job at branch code `a18ddb7`. Its actual source is
synthetic PR merge `bb0a2200f4fdd9f370af3763000f9af1af658644`. KVM installation,
enforcing-daemon acceptance/export, normal UEFI boot with acknowledged ACPI
shutdown, and disk integrity checks completed in 276 seconds. Normal multi-user
startup took 12.03 seconds and did not rerun verification. The retrieved public
logs also pass the stronger release boot-evidence validator and contain the
actual AppArmor enforce, CapEff zero, NoNewPrivs 1 and Seccomp 2 process checks.

Exact reported hashes:

| Artifact | SHA-256 |
|---|---|
| Disk | `b6e6d9a3031ed10767b7071c643aacab4a0aeabfc0f13c92b8835ffaccea8672` |
| Root filesystem export | `c984650f698c5a46eab55ce52173edceedf87494ef7027d45415eb01e5ce6e08` |
| Executable | `30fbd76f9362b8c80e204cbd1dc07c377ee6acec8534d14c38d75484e098b9d9` |
| Build report | `171f4961d98f80ff54f3da153ab10daf26258ec4807b1fa664a8773d1cc28264` |
| Acceptance log | `259cab859db1b45f404d866ca35c3350801ba3cf9e801eaca6e3edea7ef57968` |
| Normal boot log | `32d604baf8a75156cbe31a962ddaff9ed736948b239644f9328233b5c74015ad` |

Retained reports/logs are under `.artifacts/ci-a18ddb7/`. The GitHub job records
disk/rootfs/executable hashes but uploads only public diagnostics, not the image.
Those three hashes are build claims; the downloadable report and log hashes were
independently checked locally. This is passing fresh recipe evidence, not a signed
release or a scan of this new image. The last local image scan remains blocked
with 296 High/Critical matches, and release collection still requires a passing
scan of the exact candidate filesystem. Physical hardware commissioning,
independent disk reproducibility and protected signing remain outstanding.

The same run's binary repeatability evidence compares independent source paths
and compiler caches on one Linux host with Go 1.26.6. Both binaries are identical
at `745d8445f3c9e5b6c3f62daccf4449eb75cf34b0d020894eef82c26096523c4f`.
That repeatability test uses its own build parameters; this hash is not the
appliance executable hash above. All 64 image verification tests pass locally.


## Authenticated package snapshot and fresh exact scan — 2026-10-02

[CI run 37056356186](https://github.com/Digital-Frontier-LDA/regalia-kms/actions/runs/37056356186)
built and normally booted a fresh appliance from authenticated Debian package
snapshots at `20261002T000000Z`. Actual source is synthetic merge
`31358c6d86428570d147eb7fcf57345f30b2d733`. The enforcing-daemon checks passed;
normal UEFI startup took 10.82 seconds with no verification rerun. Every one of
274 installed package/version pairs was found in the authenticated snapshot
indexes. This is version-membership evidence, not independent file integrity.

The same job scanned the exact final exported root filesystem with authenticated
Syft/Grype tools, retaining SBOM, findings and Debian triage. It remains **blocked**:
38 Critical + 258 High matches. No waiver, release signature or publication was
issued. Earlier fresh build/boot success does not override this scan verdict.

| Artifact | SHA-256 |
|---|---|
| Disk (runner claim) | `d55c7a7a692aa2532c2d19035727e2381d7bfa3f1cfd2cefe673073578031463` |
| Root filesystem export (runner claim) | `b8084aa6c9f7ad54830491df5d10b62eafca653269b135970263e71362fbb932` |
| Executable (runner claim) | `82a416be0015f5c367a18bd08111f049a41bea7e2f54ff6062572164d5e24d8c` |
| Package inventory | `dedb5d503ea9c51ed22e413d8652e4ac8171c708eb20abfa13364f7ce218b2ab` |
| Build report | `7e806042794e10198e249b54f30eabbf8bb2cb3cda5d63cc41cd33099055236c` |
| Normal boot log | `13480c74d2614b710942f9d4d4a210731912a3243885551e2cf0ecb1efb6dc07` |
| Scan report | `190e116375c666225cd0991430405fbe81ab64a6f74e675ebc249d2619ec8602` |

Public reports/logs were downloaded and their hashes checked locally under
`lab/appliance/.artifacts/ci-4d97bee/`. Images/rootfs/binaries are not uploaded;
their hashes remain CI build claims. Snapshot verification pins exact Debian 13
primary fingerprints, validates signed Release identity/date/expiry and compressed
index hashes, and maps final installed versions to those indexes. No rolling
repository fallback or signature/expiry bypass is configured. The security
Release expires **2026-10-08 18:36:23 UTC**; refresh the reviewed policy/bundle
before expiry. The recipe remains an uncommissioned, unencrypted reusable template
without node keys; physical TPM/LUKS/HSM commissioning is separate.

### Separate ephemeral runner comparison

[CI run 37055124230](https://github.com/Digital-Frontier-LDA/regalia-kms/actions/runs/37055124230)
compared binaries built on two distinct Linux runner boots with private source,
module and compiler caches. Exact executable bytes matched at
`1e74f22536d47956f7d1046ec88e96f2596887d3337d896678f43a1a78ee1ff7`
(12,117,384 bytes), source `6bc1a4f777dbb636ca646f509aeb26928dd4ce1e`.
Runner boot identifiers were `1c549c3a-7f0a-40a2-bf4a-f1235cf3a910` and
`64320d57-a1c5-42ad-8205-a6d50355b17f`. Retained comparison:
`lab/appliance/.artifacts/ci-5594a00-independent/independent-comparison.json`.
Both builders use the same CI provider/toolchain trust; this proves binary
repeatability across runners, not independent trust authorities or disk-image
reproducibility. This binary comparison has its own fixed flags and is not the
appliance executable listed above.


## Reviewed package removal — 2026-10-02

[CI run 37070724533](https://github.com/Digital-Frontier-LDA/regalia-kms/actions/runs/37070724533)
passed all 33 functional jobs. Its fresh appliance installation, real daemon
confinement checks, normal UEFI boot and acknowledged shutdown passed. Startup:
11.82 seconds. Actual source: `fabdb86c3af413a2eff47dc62eaaea338bfd1c6e`.
Installed inventory decreased **274 → 259 packages**, all 259 still bound to the
GPG-authenticated Debian snapshot indexes. Exact-image scanning decreased
**296 → 280 High/Critical matches**: 38 Critical and 242 High. The release gate
remains blocked; no exception, signature or publication is issued.

The reviewed removal set is locales/libc-l10n, util-linux-locales, eject, fdisk
and installer language/task packages. APT simulation must not expand that set,
select an Essential package, or remove the required appliance roles. Normal
cleanup removes orphaned dependencies; fresh acceptance verifies the requested
packages are absent and the actual daemon/boot restrictions still hold. Final
systemd startup uses built-in `C.UTF-8`, verified through `/etc/locale.conf` and
the boot manager's environment. Initial refused builds are retained: one caught
an unreviewed dependent language task, and two caught the obsolete locale path.
Those did not grant build or release admission.

Exact removed package names from the retained SBOM comparison:
`dictionaries-common, eject, emacsen-common, fdisk, iamerican, ibritish, ienglish-common, ispell, libc-l10n, locales, task-english, tasksel, tasksel-data, util-linux-locales, wamerican`.

| Artifact | SHA-256 |
|---|---|
| Disk (runner claim) | `2c669dbad6869a527ca48bad471ef6f0d2de88967db3c98b8613cca10139434a` |
| Root filesystem export (runner claim) | `ccc8f216eb5d1ce4b0ae2bf7e98d5486c02720a91871e93db2482c88e0dcb971` |
| Executable (runner claim) | `01f284512bc67ed9389680a2c47dc2356708c02232817c5267b046a7dd95cbbd` |
| Package inventory | `122c2e595550b64a8f388895435bb0e82b5bbd031cff933d1f964b8d469d30b8` |
| Build report | `e073d27b68b65796cee4253896b7d8e2ac0cbc03410f706b35fbec2689b26bf7` |
| Scan report | `e9d71ca28ce03566ecf15a0a3b3ac80ed4de5476a3157015553a720cd1ace472` |
| Normal boot log | `e72146edcdb879ceb74411263b77343aa9f41bf5a4d863318a525bf5832f4fa4` |

Downloaded public evidence is under `lab/appliance/.artifacts/ci-760b15e/`.
The image/rootfs/executable remain runner claims because those bytes are not
published. The 280 remaining matches include required kernel/runtime components;
package removal is not a proof of advisory reachability or patch applicability.
The snapshot expiry and production commissioning gates remain in effect.

## Vulnerability remediation — 2026-10-03

[Final code CI 37111898894](https://github.com/Digital-Frontier-LDA/regalia-kms/actions/runs/37111898894)
passes all 36 functional jobs. The image has 247 authenticated packages, down
from 259; actual daemon confinement, persistent mount/umount privilege removal,
ordinary-UID bind-mount denial and normal UEFI boot/shutdown pass. Four libfdisk1
matches disappear; vulnerability-database changes leave the total unchanged at
38 Critical + 242 High. The scan alone blocks release. Exact source/rootfs/report
hashes, database deltas, signed-index update checks and remaining source-level
actions are recorded in
[VULNERABILITY-REMEDIATION.md](../../deploy/images/VULNERABILITY-REMEDIATION.md).
