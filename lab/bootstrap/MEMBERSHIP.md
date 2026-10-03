# Signed membership experiment

This extends the disposable local peer contract. It exercises phase 8/9 policy
authentication in software; it does not change production custody or fencing.

## Contract

`init` optionally accepts `authorities`, an exact object containing `cluster_id`
(32-byte lowercase hex), `membership_root` and `revocation` (distinct Ed25519
public keys, each 32-byte lowercase hex). Pins are trusted commissioning inputs.
With these pins, bootstrap is denied until a root-signed genesis is installed.
The original unsigned fixtures remain available for existing network/guest tests.

`apply_manifest` accepts exactly `op` and `envelope`. The envelope has exactly
`authority`, `manifest`, and `signature`. Authority is `membership_root` or
`revocation`; signature is 64-byte lowercase hex. It signs:

```text
regalia-bootstrap-lab/v1/membership\0
|| canonical_json({authority, manifest})
```

Canonical JSON uses sorted keys, compact separators and ASCII escaping, as in
the peer response contract. The manifest has exactly:

| Field | Meaning |
|---|---|
| `version` | Exact integer 1 |
| `cluster_id` | Commissioned cluster ID |
| `epoch` | Exact integer in 1..2^64-1 |
| `previous_digest` | SHA-256 of the preceding canonical manifest; 32 zero bytes at genesis |
| `nodes` | Exactly A, B, C, each with `state`, `ak_sha256`, `approved_pcr` |

AK hashes cover DER SubjectPublicKeyInfo; approved PCR values are the 32-byte
SHA-256 PCR 7 fixture. States use the architecture's six names. An enrolled
target's AK must match its commissioning pin. Replacement/enrollment and signer
rotation are future slices. The root can restore states and approve new PCRs.

The revocation signer can only change ACTIVE, MAINTENANCE, DRAINING or
QUARANTINED to QUARANTINED, RETIRED or REVOKED_STOLEN, with an actual change.
RETIRED and REVOKED_STOLEN are terminal for this signer. All AK hashes and PCR
policies must remain identical. It cannot sign genesis or restore trust.

Every update must be the next epoch and reference the exact preceding digest.
Updates with skipped epochs, a conflicting predecessor, or older epochs are
denied. An authenticated duplicate of the current manifest is idempotent.
This sequential rule trades availability for a clear chain; checkpoint recovery
is future work. Accepted updates clear pending boot challenges and replace node
capabilities and enrolled-target PCR policies under the existing process lock.
Signature verification precedes state mutation. Result fields are `epoch` and
`manifest_digest`; errors follow the existing DENIED/INVALID_REQUEST contract.
Network bootstrap endpoints continue to accept only challenge/authorize.

## Limits

The highest accepted epoch and digest survive verifier process restarts in a
software file. Restoring that entire file also restores its high-water mark.
The lab must demonstrate that limitation, not claim TPM-backed anti-rollback.
Authenticity and a local hash chain do not prove freshness: two stale nodes can
still cooperate using their last accepted policy. Production needs a separate
freshness design and rollback-resistant storage. No offline root private key or
real administrator credential is used; signing keys are disposable test values.

## Verification and review

The IPC runner adds 46 cross-process checks. They exercise genuine target TPM
quotes, signature/payload/role/cluster tampering, immutable AK enrollment,
malformed manifests, epoch gaps/conflicts, idempotent replay, restart rollback
refusal, concurrent conflicting updates, root trust restoration, restrictive
revocation, pending-request invalidation, and actual PCR-policy enforcement.
Rejected updates leave the state file byte-for-byte unchanged. Unenrolled B/C
AK hashes in this fixture are opaque placeholders, not additional TPM enrollments.

## Security Findings

No required implementation findings remain for this disposable local experiment.
Restoring software state defeats its epoch high-water mark; production requires
a rollback-resistant store and a separate freshness policy.

## Checks Performed

Input schemas/types/encodings are bounded; signature/cluster/chain verification
precedes mutation; signer roles limit policy changes; updates use the existing
process lock and atomic file replacement. Actual bootstrap subprocesses and
TPM quote verification exercise the accepted and rejected policies.

## Residual Risk

The trusted host can restore state, copy signer keys, or modify the program.
Local signatures do not establish global freshness, crash durability, physical
device custody or hardware anti-rollback. Replacement and signer rotation remain
unimplemented. Python does not provide reliable secret zeroization.

## Recommendation

Use this as software evidence for the membership PoC; keep production acceptance
gated on the remaining storage, freshness, transport and hardware work.

## Signed mesh extension

The separate [cluster runner](CLUSTER.md) commissions these pins on three nodes,
delivers signed updates over the runtime WireGuard administrative route, and
adds expiring signed policy references plus access leases. The original network
and guest runners retain their unsigned measurement/freshness limitation drills.
Cluster policy files remain software state and provide no hardware rollback
resistance. The freshness experiment adds online authority and trusted-time
dependencies; it is not a production revocation decision.
