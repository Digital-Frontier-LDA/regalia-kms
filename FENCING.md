# Serving and fencing contract: every server serves (ADR-0002 D32)

> **Decided by the owner, 2026-10-05 (ADR-0002 D32, regalia-kms#432). Not built yet.**
> - Every healthy KMS server serves. There is no main server, no promotion and no operator step at failover:
>   "just like a CockroachDB is multi-master".
> - This replaces the single-active contract, in which one site holds the lease and an independent authority
>   never issues overlapping leases. That contract is still what runs today (`regalia-fence` and the v1
>   `internal/fencing.Gate`) until #432 lands, so it is kept at the end of this file.

## The contract

1. **A server serves only while it holds its own lease, and the lease is not exclusive.**
   - Two of the three servers co-sign it with their TPM-held signing keys, and the server's own signature
     must be one of them.
   - It names the server, its registry site, the registry digest, and the membership manifest it was
     granted under.
   - It lives 30 seconds and is renewed every 10 seconds. A server cut off from the majority can't renew, so
     it stops serving within one lease.
   - It carries no epoch and nothing is exclusive, so there is no grant record and no epoch for the Gate to
     keep monotonic. The Gate's epoch journal stays, for audit only.
2. **Sign and decrypt need no coordination.** Every server's HSM holds the same keys (one users' DKEK, D29.1).
   Two servers signing at the same moment is safe, because nothing in a signature depends on a single signer.
3. **A stateful operation is committed by a majority before the HSM is used.** This is the default for every
   key purpose. Stateful operations are:
   - spending an approval: once, bound to the approval id, the key, the payload's SHA-256 and the one server
     that signs, so D25 is not loosened;
   - advancing a per-key high-water mark (a chain's sign height or sequence): a repeated or lower value is
     refused, as tmkms and Horcrux do;
   - changing a key's state (enable, disable, destroy): honoured on every server within one lease.
4. **No server acts on key state older than its lease.** The lease carries `state_revision`: the highest
   etcd revision any of its signers had applied when it signed (each co-signer stamps its own). A server
   serves under the lease only once it has applied that revision itself.
5. **The store orders and replicates; it never decides.**
   - The store is etcd: Raft, crash-fault tolerant, not Byzantine-tolerant.
   - Every entry carries its own authorization (the approvers' signatures, the policy authority's, or the
     spending server's), and every server verifies an entry before applying it.
   - The TPM-held lease, not etcd, is the authority to serve.
   - etcd holds operational state only, and no secret. Everything is under one prefix, and every value is
     `{"entry": …, "signatures": […]}`:
     - `/regalia/v1/keys/<object_id>/state`: a key's state, signed under D25 (approvers or the owner);
     - `/regalia/v1/approvals/<id>`: a spend (approval id, key, payload SHA-256, the one server that signs),
       signed by that server. It is written by a transaction that requires the key not to exist, **before** the
       HSM signs;
     - `/regalia/v1/hwm/<object_id>/<chain_id>`: a high-water mark, signed by the server that advanced it. It
       is written by a transaction that requires the previous value.
   - The format, its Python verification and the shared vector (`tests/vectors/opstate-v1.json`) are
     regalia-kms-48's. The Go verification and the daemon's transactions are regalia-kms-ed's.
6. **A lone survivor serves only under the owner's recovery authorization** (D28.6 amendment 5, kept).
   - The authorization carries the owner's typed attestation that the other servers are powered off or cut
     off.
   - The survivor serves stateless operations only, from the last committed key state.
   - It stops serving a key whose state it can't refresh for longer than the authorization's life.
   - Stateful keys wait for a majority.

## What the Gate checks, on every call

`internal/fencing` (the Go Gate) answers "may this server serve now?". `FencedRunner` asks it three times:
before the executor admits an operation, before the hardware is used, and before the result is handed back.

1. **The membership.**
   - The published chain (`/var/lib/regalia-sync/chain.json`) must verify from the pinned root key.
   - Its tip must be the manifest the admission file names (epoch and digest).
   - regalia-admission checked that manifest against the TPM anchor, so the daemon is bound to the anchor
     without touching the TPM.
2. **The lease file** (`/var/lib/regalia-sync/activation-lease.json`).
   - regalia-sync writes it atomically. The Gate reads it without following a link, and refuses it unless it
     is owned by regalia-sync or root, writable by no one else, and at most 16 KiB.
   - Its signatures must meet the current manifest's `activation_signers` under the current keys. This is
     `membership.VerifyActivation`, held to the Python by `tests/vectors/activation-v2.json`.
   - It must name this server's node, site and registry.
3. **The lease's window, on two clocks.**
   - On the wall clock: not before `not_before`, with up to 60 s of slack for a signer whose clock is a
     little fast, and not at or after `expires_at`.
   - On CLOCK_BOOTTIME, which nobody can set: at most the lease's own length after this Gate first saw those
     bytes. A server whose wall clock is behind can never keep a lease longer than it lasts. Clock skew can
     shorten a lease; it never lengthens one.
4. **The state is current.**
   - The daemon keeps a cache of the store, maintained by an etcd watch with progress notification.
   - The Gate refuses while the cache has applied less than the revision the lease carries.
   - It also refuses when the last progress notification is older than the lease's length. A stalled watch
     means stale state, not quiet state.

Checks 1 and 2 are cached on the chain file's identity, the lease bytes, and the admission's epoch and
digest. They are redone when any of these changes, and at least once a minute. Checks 3 and 4 run on every
call.

## Latency: servers up to about 500 km apart

- **Expected round trip:** 5 to 20 ms, plus jitter.
  - Only stateful operations pay a majority round trip, about 10 to 40 ms.
  - Ordinary signatures pay nothing extra.
- **etcd timings come from the measured p99 round trip, never the LAN defaults.**
  - The heartbeat is set near the worst round trip, and the election timeout to at least ten times that.
  - The client's timeouts derive from the same measurement.
  - Timings out of bounds are refused at commissioning (enrolment).
  - After commissioning, a round trip above half the heartbeat raises an alert, and so does leader churn. The
    server keeps running.
- **Authenticated time (NTS) stays required**, because approvals and leases carry wall-clock times.

## Commissioning tests

These must pass in production commissioning, and in a required CI scenario that adds delay, jitter and loss
between the servers (at least 100 ms round trip):

- leases renew under that delay;
- a cut-off minority stops serving within one lease;
- when one server dies, the other two keep serving with no operator step;
- a healed server catches up to the committed revision before it serves;
- one approval spent at the same time on two servers is spent once and signed once;
- a disabled key is refused on every server within one lease;
- a lease kept past its length by a slow clock is refused (the first-seen fence);
- a stalled watch stops the server;
- a server restored from an old disk doesn't serve until it has caught up, because peers co-sign only at the
  current committed revision;
- a lone survivor serves stateless keys only, and only under the owner's authorization.

## What goes

- the cross-site exclusivity rule, and the rule that "no test may accept two simultaneous successful hardware
  operations at different sites";
- the promotion command;
- the lease's `activation_epoch`, the grant record, and the per-server activation NV counter with its busy
  window: at a 30 s lease, renewed every 10 s, the counter would wear out the TPM;
- the amendment-5 exit rule and `recovery_ends_by`;
- `regalia-fence` and its single authority key.

That key also verifies the commissioning record (#220). The record moves to the membership root key before
`regalia-fence` is retired, so no host is stranded.

## Limitations

- **Not built.** Everything above is #432's work. Until it lands, the single-active contract below is what
  runs.
- **etcd is not Byzantine-tolerant.**
  - A compromised member (root on a server) could break spend-once or skip the Gate.
  - The external audit collector detects this: every approval-gated signature must name exactly one committed
    spend.
  - The exposure is no larger than before D32, since the PIN credential is already on every server.
- **Key state can be up to one lease stale** (30 s). Cloud KMSs document a similar bound for theirs.
- **etcd's own keys are files, not TPM keys.** etcd has no PKCS#11 support. The files sit inside the encrypted
  root.

---

## For the record: the single-active contract (superseded by D32)

This is what the code does today, until #432 replaces it.

Backend health is not failover authority. Each site needs a short-lived Ed25519-signed activation lease
issued by an independently administered fencing authority. The canonical lease binds one site, a
monotonically increasing epoch, an exact registry digest, and a validity window no longer than ten minutes.
The authority must never issue overlapping valid leases to different sites.

`internal/fencing.Gate` verifies the signature, site, registry, time window and durable local epoch
journal. An expired, future, corrupt, substituted, stale or rolled-back lease makes readiness false.

- `FencedRunner` checks once before executor admission and again immediately before hardware use.
- It never promotes a standby because the primary looks unhealthy.
- A lease is refreshed by atomically replacing the public lease file, not by restarting the daemon.

The local hash-chained epoch journal detects accidental alteration and ordinary rollback. It doesn't defeat
a storage administrator who can restore both disk and time. Production therefore couples the lease to:

- off-host authority state;
- authenticated time;
- a host that is never imaged or restored from an image (`deploy/baremetal/README.md`, Backups);
- off-host audit.

Promotion either waits for the previous lease to expire or obtains independently evidenced hard fencing of
the previous site, then issues a higher epoch for the standby. Recovery from Shamir shares doesn't itself
grant an activation lease.

### The authority today: `regalia-fence` (retired by #432)

`cmd/regalia-fence` is the separate authority binary. The component that decides which site may sign must
not be the component that signs, or a compromised daemon could promote itself.

```
regalia-fence -key authority.key -state issuer.json -out /run/regalia-kms/site-lease.json \
              -site sitea -epoch 12 -registry-digest sha256:... -valid-for 10m
```

It enforces two rules:

- **A strictly increasing epoch.** A repeated or lower epoch would let a superseded lease, still on a
  demoted site's disk, be replayed.
- **No overlap between different sites.** Each daemon reads only its own lease file, so two overlapping
  leases for two sites would make both active with no observable fault.

It records each grant before writing the lease, and refuses when its issuer state can't be read.
`fencing.MaxLeaseDuration` is the ten-minute bound, shared by the issuer and the daemon.
