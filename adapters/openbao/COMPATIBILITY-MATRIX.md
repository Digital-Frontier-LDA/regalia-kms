# Development conformance matrix

Every claimed entry must pass its own real-server CI job. Cross-compilation or
execution under a foreign architecture emulator is insufficient. The workflow
checks Linux, kernel machine architecture, Go host/target architecture and the
architecture-specific checksum-pinned OpenBao release. The upgrade drill also
checks the ELF architecture of OpenBao and both plugin revisions.

| Native target | Runner | OpenBao | Go | Wrapping SDK / plugin SDK | Required check |
| --- | --- | --- | --- | --- | --- |
| Linux amd64 | ubuntu-24.04 | 2.7.1 | 1.26.6 | 2.9.0 / 2.4.0 | real-server-amd64 |
| Linux arm64 | ubuntu-24.04-arm | 2.7.1 | 1.26.6 | 2.9.0 / 2.4.0 | real-server-arm64 |

Both checks require the complete unit/race suite and eight real-server drills:
initialization/outage/identity/restore, legacy generation recovery, native
generation recovery, interrupted-plugin response/respawn, three-node software
HA, External Keys/Transit, native revision upgrade/rollback, and the isolated
[inspected PKI/internal ACME software experiment](PKI-E2E-POC.md). Missing real
OpenBao or predecessor fixtures fail CI. Matrix failures are independent;
failure of one architecture does not cancel the other's evidence.
The existing `real-server` check is an aggregate gate: it passes only when
both native jobs succeed, so an ARM64 failure cannot leave that check green.

The [revision pair](UPGRADES.md) is pinned to predecessor
`c16a52f8dd5abbecbc5a7497fb21fe3796526165` and the tested candidate checkout;
it covers native seal/KV, not rollback of External Keys configurations.
OpenBao cross-version upgrades and other SDK combinations have no passing
matrix entry and must not be represented as qualified.

Each native job builds both Linux development packages twice, verifies complete
unique checksums and uploads a separate artifact named with the tested source
and runner architecture. Compare downloaded manifests/checksums to assess
reproducibility across build hosts. Artifact metadata names the actual PR merge
source, which can differ from the branch head. Checksums establish integrity;
the intended source and CI identity establish provenance.

Latest sanitized run IDs and results are recorded in existing issue #123 and
draft PR #137; the PKI experiment is recorded separately under #122. A passing
entry remains development evidence with software tokens;
production topology, partitions, load, physical custody/fencing/recovery,
off-host audit reconciliation, deployed-daemon recovery and inspected PKI
retain separate acceptance gates. Packages and the plugin remain development-only.

The runner labels are documented by
[GitHub's hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
