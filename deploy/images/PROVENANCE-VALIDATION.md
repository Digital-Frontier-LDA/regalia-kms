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
