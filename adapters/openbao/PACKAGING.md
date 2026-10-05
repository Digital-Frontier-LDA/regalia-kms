# Development packages

`tools/package_openbao.py` builds the native seal/External Keys binary for
Linux amd64 and arm64 from a **clean committed checkout**, with Go 1.26.6,
CGO disabled, readonly modules, trimmed source paths and embedded source/version
identities. It never publishes a release or installs a plugin.

```sh
python3 -I tools/package_openbao.py --output /absolute/new/artifact-directory
python3 -I tools/package_openbao.py --verify --output /absolute/artifact-directory
```

The version is `v0.1.0-dev.<commit-prefix>`. Each deterministic gzip/tar contains
the executable, `compatibility.json` with its binary SHA-256 and source/SDK
identities, and the repository license. `manifest.json` describes both targets;
`checksums.txt` hashes it and both archives. Archive verification reads members
without extracting them. `openbao-plugin-kms-regalia --version` displays its
embedded development version and commit without requiring plugin handshake.

CI builds twice from the same commit, compares checksums and uploads the verified
packages as development artifacts only after the real-server job passes.
Checksums establish integrity; select artifacts from the trusted repository's
successful run for the intended source commit. They are not a substitute for
source/release authenticity or hardware qualification.

OpenBao registration must bind the executable's SHA-256, **not the archive's**,
and use the exact packaged version. Archive metadata carries that executable
hash. Keep installed binaries and their directory protected against modification
by the service caller. Synthetic configuration examples are in the root
compatibility contract and [EXTERNAL-KEYS.md](EXTERNAL-KEYS.md).

Both targets build; the real-server workflow requires independent native Linux
amd64 and arm64 checks in the [development matrix](COMPATIBILITY-MATRIX.md).
Each deployed architecture still needs physical qualification. No production environment, HA,
upgrade/migration, inspected PKI or physical recovery claim follows from a
package. The development environment gate remains enabled. Promotion requires
the [witnessed hardware record](HARDWARE-QUALIFICATION.md) and remaining #123
evidence; this packager intentionally cannot name a production release.
