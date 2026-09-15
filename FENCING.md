# Active/passive fencing contract

Backend health is not failover authority. Each site needs a short-lived Ed25519-signed activation
lease issued by an independently administered fencing authority. The canonical lease binds one
site, a monotonically increasing epoch, an exact registry digest, and a validity window no longer
than ten minutes. The authority must never issue overlapping valid leases to different sites.

`internal/fencing.Gate` verifies the signature, site, registry, time window and durable local epoch
journal. An expired, future, corrupt, substituted, stale or rolled-back lease makes readiness false.
`FencedRunner` checks once before executor admission and again immediately before hardware use; it
never promotes a standby because the primary looks unhealthy. Refresh is an atomic replacement of
the public lease file, not a daemon restart.

The local hash-chained epoch journal detects accidental alteration and ordinary rollback. It does
not defeat a storage administrator who can restore both disk and time; production therefore couples
the lease to off-host authority state, authenticated time, the no-snapshot Proxmox gate and off-host
audit. Promotion waits for the previous lease to expire or obtains independently evidenced hard
fencing of the previous site, then issues a higher epoch for the standby. Recovery from Shamir
shares does not itself grant an activation lease.

Production commissioning must test network partition, authority outage, clock skew, expired lease,
old-disk restore, simultaneous promotion attempts, and loss of the active token. No test may accept
two simultaneous successful hardware operations at different sites.

## The authority: `regalia-fence`

The contract above was written before anything implemented it. `internal/fencing` verified leases
from the first commit and the daemon has consumed them since it was wired; nothing produced one, so
an operator could enable fencing and then had no way to make any site active.

`cmd/regalia-fence` is that authority. It is a separate binary on purpose: the component that
decides which site may sign must not be the component that signs, or a compromised daemon promotes
itself.

```
regalia-fence -key authority.key -state issuer.json -out /run/regalia-kms/site-lease.json \
              -site sitea -epoch 12 -registry-digest sha256:... -valid-for 10m
```

It enforces the two properties this document requires of an authority, and neither is enforceable
anywhere else:

**A strictly increasing epoch.** A repeated or lower epoch lets a superseded lease, still on a
demoted site's disk, be replayed. The daemon refuses a regression it can see, but only the authority
knows what it has already issued.

**No overlap between different sites.** This is the one nothing downstream can catch. Each daemon
reads only its own lease file, so two leases for two sites — each correctly signed, each
individually valid, overlapping in time — make both sites active with no observable fault anywhere.
Handover is therefore measured: a lease for a different site may not begin before the previous one
expires. Renewing the *same* site may overlap, because there is one signer either way and refusing
would force an outage on every renewal.

The issuer records each grant *before* writing the lease. A crash between the two costs an epoch
number, which is free; the other order hands out a lease the authority has no record of, and the
next grant repeats its epoch. Unreadable issuer state refuses rather than assuming no previous
grant, for the same reason.

`fencing.MaxLeaseDuration` is the ten-minute bound named above, and the issuer and the daemon now
share that one constant. They did not at first: the cap was a literal inside the gate, the issuer
defaulted to an hour, and it signed valid-looking documents its only consumer silently refused.
