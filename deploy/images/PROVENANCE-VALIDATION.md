# Provenance pipeline validation — 2026-10-02

Adapted the release/SBOM/attestation patterns from
[provenance-template](https://github.com/redoubt-cysec/provenance-template) at
`90544029e6c4793c3bc7046aa50a47b18853731b`. Regalia adds exact signer identities,
mandatory scanner publisher verification, artifact-set equality, scan failure
gates and cryptographic verification before provenance parsing. The template's
arbitrary `.pyz` version execution and broad signer regex are not carried over.

## Security Findings

The live scan of the existing `regalia-bootstrap-lab:dev` development image
reported **20 Critical, 94 High, 96 Medium, 23 Low and 107 Negligible matches**
across 155 cataloged packages. Matches can repeat a CVE across binary packages;
these counts are not unique vulnerabilities or an exploitability determination.
Many are marked `wont-fix` by the scanner's Debian source. No findings were waived.
The pipeline returned exit 1 and `status: blocked`, retaining all results.
This development container is not the newly installed appliance image.

The authenticated Grype binary embeds an older Syft schema parser than the pinned
Syft producer (16.1.10 versus 16.1.11). It emitted a warning and completed the
scan; the JSON match/database structures were checked against the actual output.
That compatibility warning remains visible, rather than suppressed.

## Checks Performed

- Real Syft 1.54.0 signed checksum bundle verified by Cosign 3.0.6 against
  `https://github.com/anchore/syft/.github/workflows/release.yaml@refs/heads/main`
  and exact GitHub OIDC issuer, with default transparency verification.
- Real Grype 0.119.0 checksum certificate/signature verified against the same
  exact release-workflow path in `anchore/grype`. Reviewed archive hashes match.
- Real native darwin/arm64 archives downloaded and authenticated before extracting
  only their regular executable members. Installed executable hashes rechecked.
- Live filesystem scan: 6,633 archive members, 208,478,519 regular-file bytes;
  486 links skipped. Syft JSON, SPDX and CycloneDX SBOMs produced from the final
  exported container filesystem. Grype database valid, built 2026-10-02 06:31:53Z.
- Real offline GPG release signature accepted; tampering refused. Contract tests
  cover wrong source, missing/extra/changed files, failed scans, absent signatures,
  attestation subject binding, scanner failures and unsafe archives.
- Scanner installation tests refuse wrong publishers before archive download,
  changed policy pins, altered archives and modified installed executables.
- Native Go 1.26.6 darwin/arm64 KMS executable rebuilt from two independently
  extracted source directories and compiler caches, source
  `4dd517748e0d73e886e3c342d25da3ba00763417`. Outputs identical:
  SHA-256 `e193a45b814563c29badeda9f38a40711c52fc345799c2279922386eab4905dc`,
  11,718,882 bytes. An initial comparison caught changing Mach-O UUIDs;
  the macOS rebuild explicitly omits that optional linker debugger UUID.
- Actionlint, shell syntax checks and Python compilation passed.

Raw local evidence is ignored under `deploy/images/.artifacts/scanners/`,
`lab-scan/evidence-validated/` and `rebuild-native-v2/`. CI repeats signature
verification, release tests and executable repeatability on Linux.

## Residual Risk

The host, verifier bootstrap pin, repository policy and local artifact directory
are trusted. Grype database distribution uses HTTPS and checksums, with no
independently verified database signature in this implementation. Regular-file
SBOM projection does not fully inventory link-only or device metadata. Scan
results require review and are not a proof of safety. No production signing key
was used. Actual GitHub OIDC signing/attestation remains to be exercised after
merge and environment protection; locally its verifier contracts were tested.
The same-host binary comparison is not independent builder verification.

## Recommendation

Keep the Docker lab restricted to development. Review the retained findings
against Debian's authoritative tracker before proposing narrow, justified policy
exceptions. Do not suppress `wont-fix` globally. Keep signing disabled until the
image scan passes and the repository's signing environment is protected.

### Initial authoritative triage (no waivers)

Three sampled findings were checked against Debian's security tracker:

- [CVE-2026-19931](https://security-tracker.debian.org/tracker/CVE-2026-19931):
  the installed curl source version is listed vulnerable in trixie; Debian labels
  its stable handling `no-dsa` with a minor-issue note. The scanner's severity and
  `wont-fix` label should not be treated as Debian's deployment risk assessment.
- [CVE-2026-7210](https://security-tracker.debian.org/tracker/CVE-2026-7210):
  trixie's Python 3.13 package is listed vulnerable, with a `no-dsa` minor-issue
  note. This concerns XML processing; reachability in each lab/appliance role
  still needs assessment. No automated exception was introduced.
- [CVE-2026-85091](https://security-tracker.debian.org/tracker/CVE-2026-85091):
  the tracker lists trixie's zlib source as vulnerable and no packaged fixed
  version. Upstream fix references are present; consuming an unauthenticated
  arbitrary patched binary is not an acceptable remediation.

Keep the complete scanner findings and package inventory while deciding whether
to remove unnecessary packages, consume authenticated Debian fixes when available,
or seek a reviewed, time-limited exception for a specific unreachable issue.

## Debian tracker review — 2026-10-02

The hash-bound cleaned appliance findings were compared with an HTTPS snapshot
of Debian's security tracker. All 345 High/Critical matches remain blocking,
covering 224 distinct CVEs and 224 source/version review groups. The diagnostic
reports 279 vendor-open matches, 57 vendor-fixed candidates, six vendor-not-affected
candidates, two unknown records and one installed version older than a recorded
fix. No waiver was issued and the scanner verdict was not changed.

The actionable package is `libpcre2-8-0`: installed source `10.46-1~deb13u2`,
Debian's trixie-security fix `10.46-1~deb13u3` for
[CVE-2026-103111](https://security-tracker.debian.org/tracker/CVE-2026-103111).
Kernel candidates require separate review: the cataloged kernel path maps to its
unique signed Debian image package; binary version `6.12.111-1` is compared to
Linux source fixes instead of the signed wrapper's `6.12.111+1` source version.
This is package ownership evidence, not proof that every upstream advisory or
patch is applicable. Generic CPE matches stay in the original scan.

Snapshot hash: `88cc970658bade2e79e754a6067398dea5e453f5b9b8c89882ab5dafe2caf22c`.
Fetched at `2026-10-02T15:52:28.218357+00:00`; distribution relies on HTTPS without
an independent tracker signature. Full snapshot, grouped JSON and Markdown are
retained under `lab/appliance/.artifacts/triage-clean/`. Nine targeted guards
cover version ordering/tool failure, source-version matching, package/scan
binding, unique kernel ownership, repeated binary matches and no-waiver behavior.


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
passes all 36 functional jobs. The rebuilt image contains 247 packages, all bound
to signed Debian indexes, with normal boot and daemon confinement verified.
Freshly verified October 3 indexes offer no newer installed package versions.
The exact scan remains blocked at 38 Critical + 242 High; no exceptions or release
signatures are issued. Public evidence bindings and the diagnostic remediation
report are recorded in
[VULNERABILITY-REMEDIATION.md](VULNERABILITY-REMEDIATION.md).
