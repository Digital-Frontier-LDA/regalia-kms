# Native plugin revision upgrade and rollback

`TestOpenBao271NativePluginUpgradeAndRollback` qualifies the earlier native-only
development revision `c16a52f8dd5abbecbc5a7497fb21fe3796526165` against the current
checkout, using real OpenBao 2.7.1. The predecessor predates typed retries and
External Keys; it implements the same native Regalia envelope format. The test
requires distinct binaries, verifies the predecessor checksum, and requires
both plugins and OpenBao to match the test process's ELF architecture.

This is revision interoperability evidence, not an upgrade between released
plugin versions or OpenBao versions. `v0.0.1`/`v0.0.2` are fixture catalog
versions used to exercise versioned, checksum-bound registration. Actual source
identities, checksums and architecture are recorded in CI; they are not inferred
from those fixture names.

The sequence uses the same Raft storage and explicit seal binding:

1. Install the predecessor, initialize under synthetic g1 and persist a KV value.
2. Stop the node, promote g2 with g1 retired, atomically replace the plugin and
   its checksum/version registration, and restart. The candidate reads the
   existing data, discovers g2 and rewraps its stored/recovery keys. A fresh
   CAS-protected KV value is written once.
3. Stop the node and revoke g1 in the real KMS registry. Reinstall the predecessor
   and its original registration. It must read the candidate's g2 state and new
   KV value, authorize the original recovery share and commit another value.
4. Reinstall the candidate. Both new values and original data survive. A normal
   Raft snapshot restores onto fresh storage with independently issued mTLS
   credentials; the original token/data replace that node's initialization state.
5. Restart with an incorrect plugin checksum. Protected KV is unavailable and
   no successful KMS operation occurs. Correcting the registration restores
   access. After stopping all nodes, storage/logs contain no synthetic plaintext,
   original recovery share or tested initialization token.

Each replacement occurs after the process stops, using an atomic rename inside
the private fixture directory. No deployment, force restore, configuration
reload or automatic rotation service is exercised.

## Run the pinned pair

Use Linux and Go 1.26.6 on the target architecture. From the repository root,
prepare the trusted, fixed predecessor source in a new private directory:

```sh
upgrade_fixture=$(mktemp -d)
git fetch --no-tags --depth=1 origin c16a52f8dd5abbecbc5a7497fb21fe3796526165
git archive c16a52f8dd5abbecbc5a7497fb21fe3796526165 | \
  tar --extract --directory "$upgrade_fixture"
(
  cd "$upgrade_fixture/adapters/openbao"
  go build -mod=readonly -trimpath -buildvcs=false \
    -o "$upgrade_fixture/previous-plugin" ./cmd/openbao-plugin-kms-regalia
)
upgrade_checksum=$(sha256sum "$upgrade_fixture/previous-plugin")
upgrade_checksum=${upgrade_checksum%% *}
cd adapters/openbao
OPENBAO_POC_BAO=/absolute/path/to/checksum-verified/bao \
OPENBAO_POC_PREVIOUS_PLUGIN="$upgrade_fixture/previous-plugin" \
OPENBAO_POC_PREVIOUS_SHA256="$upgrade_checksum" \
OPENBAO_POC_REQUIRE_E2E=1 \
  go test -race -count=1 -v -timeout 4m \
    -run '^TestOpenBao271NativePluginUpgradeAndRollback$' .
```

The complete conformance suite additionally requires these predecessor settings;
missing fixtures fail when `OPENBAO_POC_REQUIRE_E2E=1`. CI builds the exact pinned
source on each native runner and supplies its checksum. The same build settings
and SDK versions apply to both revisions.

## Qualification limits

This pair covers the native seal and KV state only. The predecessor has no
External Keys factory: rollback of configured Transit/External Keys workloads
to it is not qualified. Old experimental outer frames cannot be migrated by
replacing this binary; they have a different format.

Single-node software tokens do not qualify production rollback, hardware
custody/recovery, deployed KMS restarts, cluster rolling upgrades, partitions,
other OpenBao/SDK/plugin releases or CA signing. Those remain under #123/#122.
Production environments remain refused and PR #137 remains draft. Record real
operational rollback decisions and custody evidence in the restricted hardware
qualification record, not public issues.
