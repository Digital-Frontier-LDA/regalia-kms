# Verified util-linux source evaluation — 2026-10-03

## Security Findings

The qualified appliance retains 36 High matches against nine required
`util-linux` binary packages at `2.41.5-0+deb13u1`. Removing SUID mount privileges
is mitigation; these matches remain. Upstream's published advisories identify
maintenance releases containing fixes:

| Advisory | Upstream evidence | Next step |
| --- | --- | --- |
| CVE-2026-76642 | [Helper failure](https://github.com/util-linux/util-linux/security/advisories/GHSA-m25x-3hj9-m26f): 2.41.6 / 2.42.3 | Review the hook failure fix and test it in the actual image |
| CVE-2026-78408 | [Cgroup authority](https://github.com/util-linux/util-linux/security/advisories/GHSA-55fx-f4gg-cfhj): 2.41.6 / 2.42.3; 2.42.4 adds explicit descriptor closure | Validate descriptor inheritance under the required kernel and privilege model |
| CVE-2026-78409 | [Subdirectory resolution](https://github.com/util-linux/util-linux/security/advisories/GHSA-8f2p-47x3-43mv): affected code first released in 2.42 | Review actual code applicability; retain the unmodified scanner result |
| CVE-2026-78410 | [Bind-source resolution](https://github.com/util-linux/util-linux/security/advisories/GHSA-rh77-686x-2f2m): 2.41.6 / 2.42.3 | Compare Debian's existing patches with the complete upstream fix |

This review does not establish scanner clearance, and a patched-version field
alone does not establish complete protection. In particular, upstream
[2.42.4 notes](https://www.kernel.org/pub/linux/utils/util-linux/v2.42/v2.42.4-ReleaseNotes)
describe further security changes after 2.42.3. The next integration must review
those changes rather than assume the earliest listed fix is sufficient.

## Checks Performed

The Debian signing authority freshly verifies the October 3 InRelease and source
index. Its exact `util-linux` source record binds the packaging archive
`util-linux_2.41.5-0+deb13u1.debian.tar.xz` to SHA-256
`5b327ccd22f0f4ed28a389870aa51d04ecedb8693e52a1d122850f2b3188cbf6`.
The archive's `debian/upstream/signing-key.asc` anchors upstream's primary signer:
`B0C6 4D14 301C C6EF AEDF 60E4 E4B7 1D5E EC39 C284`.
Its bundled self-certification is expired. A refreshed public key obtained from
a keyserver retains that exact primary fingerprint and provides a valid newer
self-certification; the keyserver is not a new trust authority. GPG in a private
home verifies the source tar, changelog and release notes, rejecting expired,
revoked, weak or invalid signatures. Automatic key retrieval and ambient user
trust are disabled. The maintainer's Debian DSC signature is not separately
verified.

Authenticated upstream [2.41.6 sources](https://www.kernel.org/pub/linux/utils/util-linux/v2.41/):

- Compressed tar SHA-256: `e596083744e746be7d2823b62b43f4418dd7bf56303b4dc09e6fe8112fe3d7ed`.
- Signed uncompressed tar SHA-256: `9cf490c2a1f4077e1fb9eb3c513bbb989ec50ebda13c44023f5bbe2af0e263a1`.
- Source signature SHA-256: `83987ffd5dcaca4f63954af3194abaf5ca2ea1ced627d7628dc2c6259205fad5`.

The native ARM64 trial initially fails to compile `hook_idmap.c`: the file uses
`RESOLVE_NO_SYMLINKS` without including its definition. Adding only
`#include "fileutils.h"` after `#include "mountP.h"` permits compilation;
no security feature is disabled. The receipt pins the original file and records
this local build patch. Two separate compilation directories on the same cached
builder then produce identical hashes for all **123 installed ELF files**.
Both builds use the same prefix, source-date epoch, path mapping and explicit
RELRO/NOW linker settings. The recorded compiler inventories also match.

Six CLI version/load checks run as an ordinary UID with a readonly root,
no network, no capabilities and NoNewPrivileges. The five installed libraries
(`libmount`, `libblkid`, `libuuid`, `libsmartcols`, `liblastlog2`) preserve the
exact exported symbol names and versions found in the development system's
libraries. The [receipt](evidence/util-linux-source-20261003.json) records both
builder identities, all executable/library hashes, signature status, the exact
experimental recipe, build patch and limitations. This cached recipe is
laboratory evidence; it is not an approved appliance build entry point.

### Debian package evaluation of 2.42.4

Two native ARM64 builds in different directories now produce identical bytes
for all **43 Debian packages**, including the nine identities installed in the
appliance. Both preserve the `bsdutils` version epoch and the Essential flags
of `bsdutils` and `util-linux`. Debian's generated source metadata remains
truthful: `Source` is implicit for the `util-linux` binary itself. The local
fork has version `2.42.4-0+regalia1` and an explicit laboratory maintainer.

The [package evaluation receipt](evidence/util-linux-debian-package-20261003.json)
records both package hash sets, required package controls, recipes, compiler
index signatures and runtime restrictions. All **338 compiler package versions**
match freshly verified signed ARM64 archive records. This proves the version
inventory binding, not every installed compiler filesystem byte or the cached
development base's publisher signature.

The initial root build skipped the upstream non-root suite. A BuildKit build
as an ordinary user instead ran its suite and correctly failed `setarch` when
Docker denied personality flags. A separate probe passes with only two exact
personality argument values added to a pinned
[Moby syscall profile](https://github.com/moby/profiles/blob/2ceae35d351c156cb5a8efc0fdc4a08cf94569d8/seccomp/default.json).
Docker documents this restriction in its
[seccomp reference](https://docs.docker.com/engine/security/seccomp/).
This private test policy changes no appliance confinement setting.

Both final ordinary-user builds pass Debian's gate, which reports 368 test cases.
Their logs each contain **180 SKIPPED lines and eight KNOWN FAILED lines**;
the latter comprise five individual subtests and three summaries. The actual
Docker runtime causes upstream's `setarch` test to skip itself, so the separate
probe is the available personality evidence. Root mount/cgroup operations,
PAM integration and real initramfs recovery remain unproved for these packages.
No test or vulnerability exception was added to the repository's gates.

## Residual Risk

The initial 2.41.6 evaluation built no Debian packages. The 2.42.4 evaluation
reproduces actual Debian packages, but none are admitted or installed into the
appliance. All 36 matches remain. Tests skipped by upstream for missing root
permissions or tools are not evidence that those operations work. This is one
development builder with an unsigned cached base, not independent reproduction
or complete signed compiler payload admission.
Version/load checks and symbol equality do not prove structure/calling ABI,
mount security, PAM/login, initramfs recovery, cgroup descriptor behavior or
actual exploit resistance. Debian downstream patches and package scripts still
need explicit review. The existing source-package verifier admits only the
reviewed TPM package and cannot admit this candidate.

The repeatable source verifier is now `deploy.images.util_source`. It freshly
verified upstream 2.42.4's tar, changelog and release notes using the same pinned
primary authority as the authenticated Debian packaging. The exact refreshed
public key is vendored; runtime keyserver responses are not accepted as policy
updates. The compressed source SHA-256 is
`fbd62a100ab7bb8746ba0661255c3c48185b1e9021507c624da01fbc696330ec`,
and the signed uncompressed tar SHA-256 is
`5eec78fac0908c1bc18dbe91478741115a3209156dc6105a78ec46dce0f590b3`.
Source substitution tests reject a different Debian version, duplicate records,
unsafe source paths, modified inputs, duplicate/symlinked authority members,
unreviewed tar expansion and unauthenticated downloads. These fixtures test
boundary handling; fresh verification of the actual bundle establishes its
signature evidence. The TPM source report retains identical values after the
shared verifier refactor.

## Recommendation

Review the complete upstream fixes, including later 2.42.4 changes; authenticate
any additional patch and pin its exact bytes. Build the nine existing binary
package identities with truthful `util-linux` source metadata and preserve
Essential/Protected flags, dependency relationships, PAM/systemd configuration
and Debian's reviewed downstream changes. Do not force removal of essential
packages or conceal source identities to influence matching.

Before changing the appliance, extend narrowly scoped package admission to the
reviewed payloads and compiler inputs. Prove reproductions, run benign security
regressions and the existing recovery tests, then build, boot and scan the exact
final filesystem. Local forks require continuing upstream/vendor advisory
tracking, authenticated patch review and rebuild qualification for every update.
A Debian advisory database correction may still be needed where the scanner
has no fixed-version constraint; retain the blocker until the original scanner
with its unmodified current database clears it. Keep PR #91 draft.
