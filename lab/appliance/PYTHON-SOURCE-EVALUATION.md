# Authenticated Python source evaluation — 2026-10-03

## Security Findings

The qualified appliance's four Python 3.13 packages retain **four Critical and
16 High matches**, covering five advisories. Removing Python would also remove
required appliance tooling and AppArmor utilities. The current interpreter is
Debian `3.13.5-2+deb13u5`; no signed stable/security upgrade was available in the
reviewed October 3 snapshot.

| Advisory | Required upstream change | Primary evidence |
| --- | --- | --- |
| CVE-2026-15308 | Prevent repeated HTML declaration parsing from consuming quadratic CPU | [Debian review and 3.13.15 commit](https://security-tracker.debian.org/tracker/CVE-2026-15308) |
| CVE-2026-19445 | Keep the server SSL context alive across an SNI context switch | [Debian review and 3.13.16 commit](https://security-tracker.debian.org/tracker/CVE-2026-19445) |
| CVE-2026-19553 | Require a hostname when SSLObject hostname verification is enabled | [Debian review and 3.13.16 commit](https://security-tracker.debian.org/tracker/CVE-2026-19553) |
| CVE-2026-7210 | Correct Expat hash-flooding entropy; also require system Expat at least 2.8.0 | [Debian review and 3.13.14 commit](https://security-tracker.debian.org/tracker/CVE-2026-7210) |
| CVE-2026-82049 | Correct extraction-filter handling of hard links to symlinks | [Debian review and 3.13 backport](https://security-tracker.debian.org/tracker/CVE-2026-82049) |

Upstream [Python 3.13.16](https://www.python.org/downloads/release/python-31316/)
is the next source candidate. The installed system Expat is 2.8.3, but its own
four High matches remain; satisfying the Python entropy dependency does not
clear those separate findings. No applicability statement grants a waiver.

## Checks Performed

`deploy.images.python_source` verifies the fixed source bundle. The pinned
Debian 13 authority freshly verifies InRelease and the source-index SHA-256.
Its exact Python source record binds all four Debian inputs, including packaging
SHA-256 `a51f456e654ce2c9b40cc1db8005e5041cdb0b2c3aa96ab0871c49fe95280366`.
That packaging's upstream key anchors full primary fingerprint
`7169605F62C751356D054A26A821E680E5FA6305`, consistent with Python's
[published release-manager identity](https://www.python.org/downloads/metadata/pgp/).

The packaged key's self-certification is expired. A refreshed public key keeps
that exact primary identity; a keyserver supplies bytes, not a new authority.
GPG in an isolated home verifies the compressed 3.13.16 tar against its detached
signature without expiry exceptions, automatic key retrieval or ambient trust.

- Source tar SHA-256: `f4b1bfb3c79b5bb11b8d228a12504163b4c0dab4d679828d8f5f26b6cb6ab35d`.
- Signature SHA-256: `34ca55d174d627771a78db0bdb4838243791cd1f23eb2f3a1cc284dcd75672c8`.
- Refreshed authority SHA-256: `1de2bbd31e2dd10aab4098c3ab2f937c530d924ddbfa2dd091f0c7cfb2ee182a`.

The actual capture passes the repository verifier. Parsers and GPG consume the
same bounded bytes that passed hash checks. Negative fixtures reject changed
inputs, oversized inputs, symlinks, duplicate/missing/redirected authority
members and failed signature verification. Source authentication explicitly
grants neither package admission nor production approval. The maintainer DSC
signature and the optional Sigstore signature are not separately verified.

The original [source review receipt](evidence/python-source-review-20261003.json),
at `f4226a5`, binds
source verification, reviewed source-file hashes and the implementation. These
are authenticated input checks; runtime exploit regression remains required.

### Original stable-packaging patch applicability

The original authenticated Debian 3.13.5 packaging contains 62 enabled patches. GNU patch 2.8
runs each independently against clean 3.13.16, with `--dry-run`, zero fuzz and
forced direction. Eighteen apply forward, 18 apply only in reverse and 26 fail
both directions. No patch has been applied, omitted or approved by this check.
A reverse match is a review candidate; a changed upstream implementation can
also make an already-fixed patch fail both ways.

`--batch` alone can silently ignore `--reverse` and report forward success.
The repeatable checker uses `--force` to prevent that direction correction.
An actual GNU patch regression fixture verifies forward success and reverse
failure for an unapplied change. Malformed series, duplicate names and failed
source authentication are rejected before publication.

Run from the repository root (GNU patch must be available):

```sh
python3 -I tools/lab_cli.py appliance-python-patch-review PYTHON_SOURCE_OUTPUT --output PATCH_REVIEW_OUTPUT
```

On macOS with Homebrew GNU patch, add `--patch /opt/homebrew/bin/gpatch`.
The original [patch review receipt](evidence/python-patch-review-20261003.json),
at `f4226a5`, records all
62 patch hashes and verdicts. The repository command freshly authenticates the
complete source bundle; an independent ordinary-user, network-disabled,
readonly development container produces the same patch verdicts. That cached
container is unsigned. Neither trial compiles or installs Python.

### Newer Debian packaging and source profile

Debian also publishes `3.13.15-1` packaging. It is an explicit source-only
candidate, authenticated from the fixed October 3 sid InRelease and Sources
index under the existing Debian 13 primary signer
`04B54C3CDCA79751B16BC6B5225629DF75B188BD`. No additional authority is enrolled.
The source-only sid index must carry an unexpired Valid-Until. Each of its three
source files has a pinned SHA-256 and length; its packaged upstream key has the
same pinned hash and primary identity. The upstream 3.13.16 signature is freshly
verified again. The appliance binary package policy remains trixie/security.

Capture and review the newer candidate from the repository root:

```sh
python3 -Es -m deploy.images.python_source PYTHON_NEWER_OUTPUT --snapshot SNAPSHOT_DIR --packaging-suite sid
python3 -I tools/lab_cli.py appliance-python-patch-review PYTHON_NEWER_OUTPUT --packaging-suite sid --output PATCH_REVIEW_OUTPUT
```

This series has 26 enabled patches: 22 apply independently; four need review.
`python_profile` retains all 26 patches and the complete vendor build/test rules.
It rebases the turtle import diagnostic and freeze libdir filter without
changing their behavior, and updates the deletion context for the regenerated
SSL error table. Multiarch succeeds after its preceding prerequisite patch.
Actual sequential application of all 26 patches succeeds with zero fuzz.
Reapplying preparation refuses; changed input hashes refuse before edits.

```sh
python3 -I tools/lab_cli.py appliance-python-profile EXTRACTED_CANDIDATE_SOURCE
```

Prepare a freshly extracted upstream/packaging tree. The profile changes local
version/maintainer metadata truthfully and grants no package admission.
The [newer-packaging review receipt](evidence/python-newer-packaging-review-20261003.json)
at `64f18f4` binds signed inputs, the three reviewed patch edits and that profile.
The earlier 62-patch receipt remains historical evidence.

The SSL rebase preserves Debian's `_ssl_data_34.h` path. Upstream's newer 3.6
error table differs in legacy compression reason names and numeric fallbacks;
it must not be described as an exact superset. This candidate needs explicit
error-mapping and SSL regression checks with the actual Debian runtime library.
A native runtime package trial compiled the static and non-PIE interpreters,
with all 112 configured modules passing import checks. It then failed in
Debian's minimal-module dependency check: the packaging's legacy `imp` helper
imports `_ERR_MSG`, which upstream no longer exposes. That helper needs a
reviewed compatibility correction; the minimal-module gate remains required.
The trial uses pinned trixie/security apt authorities and a dedicated non-root
build UID. Its cached base is unsigned, so it cannot qualify production
compiler payloads or an appliance image.

The subsequent profile pins `debian/imp.py` and replaces only its private
constant import and use with the original `No module named {name!r}` diagnostic.
Builtin/source lookup and the missing-module message/`ImportError.name` are
preserved. With `_ERR_MSG` deliberately absent, the original helper refuses
and the corrected helper loads successfully. All 26 patches still apply with
zero fuzz. The [helper profile receipt](evidence/python-imp-profile-review-20261004.json)
binds this edit and the clean source tar for the next native trial; host-generated
bytecode is excluded. The full 3.13.16 minimal-module check and package build
still need to pass. No vendor test target is disabled.

### Documentation compatibility and runtime package target

The native `dpkg-buildpackage -b` trial exposed an OpenGraph extension error:
trixie's extension concatenates a list with custom tags, whereas upstream's
configuration provides a tuple. The profile now pins the signed `Doc/conf.py`
input and converts the completed tuple to a list, retaining every tag value.
Both social-card configuration branches are verified against the original
source, and all 26 patches still apply sequentially with zero fuzz. The
[documentation profile receipt](evidence/python-doc-profile-review-20261003.json)
binds this additional edit and the source tar used by the native builder.

The corrected documentation build no longer raises that TypeError, but still
fails on **199 warnings treated as errors**. No warning policy is relaxed, and
the separate documentation package remains unqualified. The appliance needs
runtime packages, so the current trial uses Debian's `dpkg-buildpackage -B`
binary-arch target. The vendor runtime test/mincheck policy, benchmark settings
and full patch series are unchanged. Those vendor rules exclude the full SSL
suite and disable pybench, so package-build success alone cannot qualify the
SSL fixes or performance. Explicit SSL regressions and inspection of actual
test results remain required. This target selection is not evidence that the
full documentation package builds.

### Installed security regression gate

`appliance-python-regressions` freshly verifies the complete source bundle, then
extracts only its upstream `test/` fixtures. The standard libraries under test
must come from the installed `/usr/lib/python3.13` tree or built-in modules,
never the source checkout. It requires the four installed candidate package
versions, an isolated interpreter and an ordinary user. Each advisory runs in
a separate process with a 90-second timeout; failed, skipped, missing or
expected-failure tests cannot produce a passing receipt. The CPU resource is
explicitly enabled for the HTML parser regressions.

```sh
python3.13 -I tools/lab_cli.py appliance-python-regressions PYTHON_NEWER_OUTPUT --output INSTALLED_REGRESSION_OUTPUT
```

The targeted cases cover HTML parser CPU behavior, SNI context lifetime,
SSLObject hostname enforcement and tar hard-link relocation. Calibration on
the installed Debian `3.13.5-2+deb13u5` interpreter produces four real assertion
failures in the hostname and tar cases, with no import errors or skips. This
demonstrates that those checks distinguish the vulnerable runtime; the candidate
still needs a positive run after installation. Expat version and XML parsing
checks establish compatibility only. A separate disposable-process probe
interposes the system Expat salt APIs and requires one accepted 16-byte API call
and no legacy calls from each of pyexpat and ElementTree. Calibration on the
old interpreter observes the legacy API in both paths. A failed preload or
successful XML parse without the required trace cannot pass. No salt bytes are
logged. This API-width evidence must still be combined with authenticated
built-source and library provenance; it is not a statistical entropy estimate
or scanner clearance. The qualification environment requires `cc`, Expat
development headers and an executable temporary filesystem for the probe.

The [baseline calibration receipt](evidence/python-regression-calibration-20261003.json)
binds the authenticated test archive, exact worker/probe recipes, observed
failures and limits of the unsigned development parent. It grants no candidate
positive result. The [prerequisite appliance receipt](evidence/python-prerequisite-appliance-review-20261003.json)
records the `64f18f4` CI rebuild: normal boot passes, its linked SBOM and scan
hashes verify, and all **105 Critical / 640 High matches** are unchanged from
the prior qualified utility image. That image still contains the old Python;
its functional result cannot qualify this candidate.

## Residual Risk

No new Python package has been produced, installed or admitted into the appliance.
The Python API/ABI, AppArmor modules, Debian maintainer scripts, extension
modules, boot tooling and actual scanner clearance remain unproved. Existing
Python findings stay blocking. Published fixed-version notes alone cannot
establish protection of the final executable or filesystem.

## Recommendation

Evaluate the authenticated source with Debian's runtime package identities and
configuration preserved. Build twice in separate paths with authenticated
compiler inputs, retain vendor tests and run the five advisory regressions.
Verify system Expat linkage, required extension modules and AppArmor operation.
Review downstream patches individually before replacing any that were upstreamed.
Then require actual package/rootfs admission, normal boot, daemon confinement
and the unchanged final-filesystem scan.

Maintaining this fork requires an owner for every upstream security release,
Debian patch refresh, signer/key refresh, reproducibility failure and ABI check.
This source verifier is an evaluation entry point, not the production installer.
