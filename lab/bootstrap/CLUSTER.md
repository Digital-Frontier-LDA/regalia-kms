# Software cluster validation

Scope: implement all four development-machine experiments: signed mesh policy,
runtime access leases, a SoftHSM service gate and reproducible randomized faults.
This is a separate disposable runner; production custody, native PKA and the
independent single-signer contract in `FENCING.md` remain architecture gates.

## Contract and decisions

Each node has separate `wg-bootstrap` and `wg-service` identities. Bootstrap
allows only port 8443. Runtime permits membership on 8444, lease exchanges on
8445 and the test signing service on 8446. No listener is exposed on the cleartext
Docker bridge. All setup capabilities are dropped before daemons run.

The membership route accepts signed `apply_manifest`, bounded `get_manifests`
after an epoch, and signed `install_freshness`. Root/revocation roles and hash
chains follow `MEMBERSHIP.md`. Receiving an authentic update is sufficient;
transport possession does not confer administrative signing authority.
Unsigned policy injection is disabled in this runner. An update invalidates
pending bootstrap requests, freshness and runtime leases. Replayed identical
updates preserve existing state. Catch-up consumes bounded batches in order.

| Route | Accepted operations | Binding / bounds |
|---|---|---|
| `/bootstrap` :8443 | `challenge`, `authorize` | Existing TPM quote, enrolled identity/PCR and boot-session recipient contract |
| `/membership` :8444 | `apply_manifest`, `get_manifests`, `install_freshness` | Known runtime WireGuard source; signed roles/cluster/hash chain; ordered batches of at most 8 |
| `/lease` :8445 | `lease_challenge`, `renew_lease` | Runtime source must match requesting node; ACTIVE issuer/target; signed single-use request and response |
| `/kms` :8446 | `sign` | ACTIVE runtime caller; valid current service lease; exact fields; 16-byte client request ID and message of at most 4096 bytes |

All routes use the shared strict JSON parser: duplicate keys, unknown fields,
incorrect types and bodies over 64 KiB are refused. Worker/queue counts and socket
deadlines are bounded. No remote route accepts local control commands. Expected
refusals use `DENIED` or `INVALID_REQUEST`; unexpected tool/internal failures
fail verification rather than becoming successful negative checks.

A lease request binds version, cluster ID, node/issuer IDs, epoch/manifest digest,
boot generation, service-public-key SHA-256, challenge ID and nonce. The response
removes the nonce and adds `not_before`/`expires_at`, with separate signature
domains for request, lease and service response. A request consumes its owned
challenge before signature verification: a forged request or lost response needs
a new challenge. Wrong runtime sources cannot consume another node's challenge.
Pending issuer challenges expire after 5 seconds and are capped at 16.

A third, disposable online freshness signer issues a signed reference to the
current cluster ID, epoch and manifest digest with `not_before`/`expires_at`
in UTC milliseconds. Its maximum lifetime is 30 seconds. Every protected
operation rechecks the reference. A wall/monotonic time guard detects jumps;
clock faults close authorization until explicit trusted reset. A partitioned
stale pair cannot authorize after its reference expires. This experiment adds
an independent online authority and trusted time assumption; it is a concrete
availability tradeoff, not a silently adopted production design. Signatures
alone do not provide immediate revocation or hardware rollback resistance.

Lease renewal uses a fresh, single-use issuer challenge, a signed request bound
to node, policy, boot generation and service public key, and a signed response
with a short expiry. Only ACTIVE targets and ACTIVE issuers are eligible.
Either peer can renew. Runtime leases grant access to this test service; they
do not grant exclusive blockchain signing authority. External client validation
checks current signed policy/freshness, lease signature, subject, service key,
message binding and expiry using its own clock. A compromised local process
ignoring expiry must still be rejected by that client.

The device adapter uses PyKCS11 and the real SoftHSM library. It generates a
disposable non-extractable RSA key through PKCS#11, logs in only after bootstrap
and a valid access lease, and logs out on invalidation. Removal/reinsertion is
modeled by withdrawing/restoring the disposable token directory and reloading
the module. Reauthentication requires a fresh peer lease. SO/admin credentials
never enter the online authorization protocol. SoftHSM is software storage,
not physical key protection or native vendor public-key authentication.

Randomized testing records the seed, operations and sanitized outcomes. It
injects partitions, lost responses, logical reboots, signed revocations/conflicts,
malformed requests, clock faults and token removal. Assertions check a specific
recovery or closed-state result after each action; internal failures are failures,
not accepted authorization refusals. Chaos reboots model authorization loss;
actual emulated encrypted-root boots remain the separate QEMU suite.

## Verification and limits

Run `bash lab/bootstrap/run-cluster.sh` from the repository root. The default
seed is 20261002 with 36 fault actions. `REGALIA_CHAOS_SEED` accepts an unsigned
64-bit integer; `REGALIA_CHAOS_STEPS` accepts 13–256 actions. Every schedule
includes all 13 families. Reboots in this runner reset authorization state on
actual LUKS fixtures; real boot/mount/switch_root is covered by `run-vm.sh`.

Local native arm64 validation completed 272 assertions with seed 20261002 and
36 fault actions. Counts vary with the chosen seed because fault families carry
different assertions. The original IPC regression passed 121 checks and the
repository Python guards passed 190 tests. CI independently reruns the cluster
suite with both configured seeds.

The daemon renews automatically through either configured peer, checks readiness
before and after each PKCS#11 operation, and closes its session after expiry.
The test lease lasts 1.5 seconds and has a protocol ceiling of 5 seconds. The
clock guard latches wall/monotonic disagreement exceeding 2 seconds. These short
windows are test settings; slower deployments need measured deadlines and an
explicit production time policy. Tests wait beyond expiry rather than assuming
instant revocation or treating a transport exception as proof of a refusal.

The history API retains 64 signed updates and returns at most 8 per request.
Sequential signature/hash-chain verification rejects missing history. It is not
an unbounded archive or a complete node replacement/checkpoint protocol.

Evidence includes source hashes, package versions, platform, image ID, seed,
each assertion and project cleanup. The pinned Debian image index spans both
architectures; apt packages are recorded, not snapshot-pinned. Host requirements
are pinned in `harness-requirements.txt`. No existing token, host disk or
production key is used. Reports omit signatures, recovery keys, PINs, quotes,
private token data and TPM state.

## Security Findings

Review focused on remote administrative mutations, source identity, signed
policy/lease binding, client verification and PKCS#11 session lifecycle.
Acknowledgments are checked before the harness reports successful delivery.
A quarantined runtime caller cannot use the signing endpoint. Internal errors
fail the harness and are not counted as expected authorization refusals.

## Checks Performed

- All six directed recoveries under signed policy, interrupted replies,
  conflicting epochs, missed-update catch-up and restrictive authority limits.
- Running-node revocation, automatic renewal and peer failover, clock jumps,
  expiry, altered/replayed responses and concurrent single-use challenge races.
- Independent client rejection of a genuinely signed response created by
  bypassing the local lease gate, after a verified positive signing control.
- Real PKCS#11 generation, private attribute refusal, logout, wrong PIN,
  token disappearance, reinsertion and fresh peer reauthentication on all nodes.
- Seeded faults with verified live-service checks before and after each action;
  full-cluster authorization loss requires one offline LUKS recovery credential.

## Residual Risk

No native Nitrokey/PicoHSM PKA, wrapped-key interoperability, hardware key custody,
TPM NV epoch journal, complete DL360 measured boot, authenticated time, production
membership/recovery ceremonies or production API integration is established.
Software TPMs and SoftHSM stores are cloneable. Python buffers are not guaranteed
to be locked or erased. Valid freshness references allow a bounded stale-policy
window; expiry adds an online signer availability dependency. Authorization
loss in chaos is not a physical power-loss test. The independent fencing
contract and separate device key domains remain intact.

## Recommendation

Use this runner as repeatable software evidence and as a contract prototype.
Production acceptance still requires the physical-device and boot/time/custody
gates above. Keep the PR in draft until its broader architecture is reviewed.

References: [PyKCS11 API](https://pkcs11wrap.sourceforge.io/api/api.html),
[SoftHSM source](https://github.com/softhsm/SoftHSMv2),
[signed membership contract](MEMBERSHIP.md), and
[secret inventory and trust boundaries](THREAT-MODEL.md).
