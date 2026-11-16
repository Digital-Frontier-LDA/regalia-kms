# OpenBao three-node software HA drill

`TestOpenBao271NativeThreeNodeHA` extends #123's real-server conformance evidence
for OpenBao 2.7.1, wrapping SDK 2.9.0 and plugin SDK 2.4.0. It uses the native
`regalia` entrypoint and the real Regalia HTTP/authentication, policy, registry,
replay and audit stack with a test-only software RSA provider. The provider is
never linked into the plugin.

Three independent OpenBao processes have separate Raft storage, node IDs and
plugin processes. Each registers the same checksum-bound development plugin
and explicit synthetic mTLS seal binding. Only the first node initializes;
the other two join its cluster. The fixture waits for Autopilot to promote all
three nodes to voters before injecting a fault. Listener addresses are loopback
only; the disposable HTTP API configuration is not a deployment example.

The drill requires:

1. Exactly three expected voting peers and one active leader. All nodes serve
   the synthetic KV value. The test client refuses
   HTTP redirects, so a redirect cannot masquerade as a successful member.
2. SIGKILL of the active OpenBao process, election of another node, persistence
   of the original value and a successful new KV write with the surviving
   two-voter quorum. Restarting the failed node rejoins the existing cluster.
3. SIGKILL of only the active node's exact plugin child process, observed
   replacement PID and continued KV availability without a leader change.
4. Removal of the KMS fixture listener while all three nodes remain unsealed.
   KV reads and a fresh write through a standby still work. Killing the active
   OpenBao process again permits the two already-unsealed survivors to elect a leader and
   commit another fresh write without a successful KMS call.
5. Restarting the failed member while KMS is offline cannot expose protected
   KV. Restoring the listener and restarting the member permits auto-unseal
   and recovery of all values. No manual unseal or alternate KMS is used.
6. After stopping every node, the synthetic plaintext, root token and recovery
   share are absent from each node's Raft storage and captured logs.

Each new write uses a distinct path and `cas=0`, once. Read-only readiness,
membership and missing-value checks are polled; follower application can lag
a successful commit. Redirects, transport errors and authorization failures are
not accepted as missing values. Ambiguous writes are not repeated. Elections
and readiness checks have bounded deadlines. The test prints election/write
durations as observations, not production availability objectives.

Run on Linux with a checksum-verified OpenBao 2.7.1 executable:

```sh
cd adapters/openbao
OPENBAO_POC_BAO=/absolute/path/to/bao OPENBAO_POC_REQUIRE_E2E=1 \
  go test -race -count=1 -v -timeout 3m \
  -run '^TestOpenBao271NativeThreeNodeHA$' .
```

The existing conformance workflow runs this drill as part of the complete suite;
absence of the real server is a failure. No deployment or additional daemon API
is introduced.

This qualifies a single-version, same-host, three-node software scenario. It
does not qualify network partitions, quorum-loss recovery, cross-site latency,
load/SLOs, deployed-daemon recovery, independent physical custody, production
HA, upgrades or outer-frame migration. The KMS outage retains its in-memory
software keys; restarting a listener does not prove recovery of the KMS process
or token. External signing and PKI availability are not measured by this KV
drill. The earlier ambiguous seal-response drill remains the operation/audit boundary
reference; off-host audit reconciliation remains separate work.

The plugin remains development-only, PR #137 remains draft, and #123 remains
open until the release matrix and production qualification evidence are complete.
Use the existing [witnessed hardware record](HARDWARE-QUALIFICATION.md) for
physical acceptance and keep operational inventories and custody records restricted.

Pinned upstream Raft join/configuration contract:
[OpenBao 2.7.1 Raft API](https://github.com/openbao/openbao/blob/v2.7.1/website/content/docs/api/system/storage/raft.mdx).
