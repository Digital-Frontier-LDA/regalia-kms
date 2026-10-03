# Verified-source TPM laboratory profile

## Security Findings

The qualified appliance still includes both curl libraries and all 36 associated
High/Critical matches. This experiment removes the curl-based EK downloader and
FAPI tools from the candidate TPM binary. It is not yet installed in the appliance
and grants no scanner clearance. ESYS quote, sealing, NV and recovery tools stay.

## Checks Performed

First obtain a fresh authenticated package snapshot using the reviewed policy:

```sh
python3 -Es -m deploy.images.snapshot /tmp/regalia-tpm-snapshot
python3 -Es -m deploy.images.source /tmp/regalia-tpm-source \
  --snapshot /tmp/regalia-tpm-snapshot
```

The source command reverifies the pinned signing authority, signed source-index
SHA-256, exact source version and all three reviewed source-file hashes/lengths.
No downloaded source is executed by that command. `tpm_profile.py` refuses
unexpected source bytes and applies six reviewed edits only after checking all
three files. `--disable-fapi` is an upstream configuration option; removing the
single downloader prevents linking curl without weakening TLS behavior.

To repeat the compiler experiment, create a private Docker context containing:

- the authenticated `tpm2-tools_5.7.orig.tar.gz` and both pinned archive keys;
- a copy of `tpm_profile.py` and `Dockerfile.tpm-source` from this reviewed checkout;
- `sources.list` containing only the dated Debian/security repositories below.

```text
deb [signed-by=/inputs/archive-key-13.asc] https://snapshot.debian.org/archive/debian/20261003T000000Z/ trixie main
deb [signed-by=/inputs/archive-key-13-security.asc] https://snapshot.debian.org/archive/debian-security/20261003T000000Z/ trixie-security main
```

The Dockerfile pins the same Debian 13 multi-platform digest as the existing
bootstrap laboratory and registers that exact input in the development policy.
Record the resolved native-platform image ID. No base override or rolling tag
is accepted by the inventory guard. Publisher signatures remain unverified for
this development base. New compiler
dependencies use signed, dated APT indexes; the Dockerfile retains normal
signature and expiry checks. It does not mount credentials, host devices or the
Docker socket into a container.

Build once with `BUILD_DIRECTORY=/build/first` and once with
`BUILD_DIRECTORY=/build/second`, using `--pull=false` and
`env -u DOCKER_DEFAULT_PLATFORM docker build`. Record both resulting image IDs,
compiler/package inventory and exact TPM executable hashes. Inspect ELF NEEDED
entries and `/inputs/runtime-libraries.txt`; neither curl nor FAPI may be linked.
Compare binary bytes before making any reproducibility claim.

Run the existing `/opt/lab.py` and `/opt/tpm_soak.py` harnesses with candidate tools
first in PATH. Bind only the five public harness files and a private evidence
directory. Use an ordinary UID, `--network none --read-only --cap-drop ALL`,
`--security-opt no-new-privileges`, and a private noexec/nosuid/nodev `/tmp`.
The harness file paths and `/opt/packages.tsv` contract are unchanged; retain
the public build-package inventory at that path. Use `--cycles 4 --output ...`
for the initial cold-restart qualification. No real TPM or HSM is accessed.

Bind and run `ek_nv_cases.py --output /evidence/ek-nv.json` under the same
container restrictions to check offline certificate retrieval with fixture CAs.
Its 14 cases cover actual RSA/ECC EK public keys and NV readback, valid chain/key
binding, missing indices, wrong roots, wrong keys and malformed/corrupt DER.
This script is a feasibility fixture, not a production enrollment verifier.

Measured results and hashes are in
[the remediation checkpoint](../../deploy/images/VULNERABILITY-REMEDIATION.md).
The current experiment passed 121 bootstrap assertions and four cold restarts;
the two candidate arm64 binaries matched exactly across compilation paths.
The checked-in [public experiment receipt](evidence/tpm-source-20261003.json)
retains source authentication, recipe hashes, image IDs, compiler inventory
binding, all behavioral outcomes and limits. The repository Docker recipe also
produces that same executable hash and passes the 121 bootstrap checks using
its actual 255-package build inventory. The compiler image is not minimized.
That receipt describes the first recipe's cached-base experiment. CI correctly
refused its selectable FROM input; the current recipe uses the literal digest
above. A current recipe result requires its own fresh evidence and must not be
inferred from the earlier cached-base result.

The [pinned recipe receipt](evidence/tpm-source-pinned-20261003.json) records
that fresh result: both compilation paths produce the same executable hash as
the earlier experiment, and all 121 bootstrap assertions, 14 EK/NV cases and
four cold restarts pass again against the current recipe and actual compiler
inventory. All 96 image guards and five Python invocation guards pass with the
new input registered. Source names in the advisory table are formatted as code
identifiers so the command guard does not misread a Python package name as a
piped invocation; no command guard is weakened.

## Residual Risk

The two development builds share a cached unsigned base/toolchain. They do not
qualify independent builders, final appliance reproducibility or physical
hardware. The suite intentionally reports the known software-state rollback
limitation. The source profile adds a local maintenance responsibility.

The existing bare-metal checklist uses `tpm2_getekcertificate`. Before removing
it from the appliance, test native TPM NV certificate retrieval, manufacturer
chain validation and EK binding. Devices needing its network download feature
require a separately authenticated enrollment/recovery tool. Do not silently
remove or weaken that enrollment step.

## Recommendation

The appliance recipe now proposes a separately admitted local Debian package.
See [source package qualification](../../deploy/images/VULNERABILITY-REMEDIATION.md).
The host's verifier remains mandatory: an unsigned local package is not silently
added to the signed-index inventory. One exact source-built package is bound to
freshly authenticated sources, the reviewed recipe, archive-bound compiler
inputs and reproducible executable/package bytes. All other packages retain
their signed-index checks; the High/Critical gate is unchanged.

Package the candidate with truthful Debian/source metadata, bind it to freshly
authenticated sources, compiler inputs and reproducible output, and verify its
complete dependency closure. Then physically remove unused runtime curl/FAPI
packages and rebuild/boot/confine/SBOM/scan the exact appliance filesystem. Retain
all findings until the unchanged scanner gate clears. Review and repeat this
process for every source/security update; no production signing or publication.
