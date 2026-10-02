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

## Work sequence

1. Signed policy across all three nodes; bounded freshness and interrupted delivery.
2. Runtime leases and independent client rejection, including clock faults.
3. Real PKCS#11 service readiness, removal, reinsertion and reauthentication.
4. Seeded chaos and CI, regressions, review, sanitized evidence and PR update.

Required evidence includes source hashes, package versions, platform, image ID,
seed, each assertion and project cleanup. Test secrets stay in disposable node
state or harness memory. No existing token, host disk or production key is used.
