# Fleet certificates and the KMS boundary

Decision (#104): **the KMS does not manage public TLS certificates.** Issuing, renewing, storing and
reloading a public certificate is the job of the host that serves it. The KMS protects the few
long-lived secrets around that work when a consumer asks it to, through operations it already has.

The decision was prompted by two certificate incidents in the fleet. In one, a certificate was
renewed on disk and the services holding it were never reloaded. In the other, a certificate was
uploaded by hand and its renewal was never scheduled. Neither exposed a key. Both are lifecycle
failures: ownership, renewal, reload, and a check of what each endpoint actually serves. Custody
does not address them, so the fix is not in this repository.

The fleet inventory (owner, environment, SANs, every consumer port, reload behaviour, probes) is
kept with the fleet monitoring that checks it, not here. An entry may name a KMS object ID when a
consumer uses one of the profiles below; the custody manifest stays the only routing source
([`config/REGISTRY.md`](config/REGISTRY.md)).

## What the daemon does not do

- It is not an ACME client. It holds no ACME account, places no orders and parses no ACME messages.
- It calls no DNS or CDN provider API.
- It does not store, distribute or serve leaf certificates or their private keys.
- It takes no part in a TLS handshake other than its own listener's.

A change to any of these is a change to the KMS trust boundary. It needs its own reviewed design and
a consumer whose need the local design cannot meet.

## What it already offers

| Need | Existing operation | Reference |
|---|---|---|
| Keep a DNS or CDN provider token under hardware-rooted custody | `seal-envelope`, `release-secret` on an `opaque` object | [`ENVELOPE.md`](ENVELOPE.md) |
| Issue an internal certificate from a CA key held on the token | `certificate-sign` | [`API.md`](API.md) |
| Authenticate a workload to the KMS | mTLS with a `spiffe://regalia/` URI SAN | [`IDENTITY.md`](IDENTITY.md) |

`certificate-sign` issues internal certificates. It confers no browser trust and does not replace a
public CA.

## Custody profiles

| Object | Where it lives | KMS role | Exportable |
|---|---|---|---|
| Public TLS leaf key | The host that serves it | None | Local file, by design |
| Leaf key uploaded to a CDN | The issuing job, then the provider | None. The KMS never exports a private key, so it cannot hold this one | Yes, the provider requires it |
| DNS or CDN provider token | The ACME client's host or CI | Optional: an `opaque` envelope, released to one exact workload identity | It is a secret; release is the point |
| ACME account key | The ACME client | None for now; see "Deferred" | Local file |
| Internal CA key | The token | `certificate-sign` under policy | No |
| KEK | The token | Wraps envelope data keys | No |

A provider token is scoped at the provider. Holding it in an envelope narrows who can read it; it
does not narrow what the token can do. Per-name DNS scoping, for example delegating
`_acme-challenge.<name>` to a zone whose credential can do nothing else, is DNS configuration and
is tracked outside this repository.

## Dependencies in both directions

**Fleet TLS does not depend on the KMS.** Serving, restarting and renewing a public certificate need
no KMS call. The one exception is a consumer that chose to keep its provider token in an envelope:
its renewal needs a release, so that consumer must

- keep serving and restarting on the certificate it already has while the KMS is unavailable,
- start renewal early enough that an outage shorter than the renewal window costs nothing, and
- alert when renewal is blocked, well before expiry.

**The KMS does not depend on fleet certificates.** Both directions of its mTLS are internal:

- Client identities are issued from a dedicated workload CA ([`IDENTITY.md`](IDENTITY.md)) and
  verified against `tls_client_ca_path`.
- The listener's certificate (`tls_certificate_path`) is issued from an internal CA as well, and
  clients trust that CA explicitly rather than the public roots. It is rotated by the same reviewed
  issue, overlap and revoke steps as a client certificate. No ACME order, DNS record or public CA is
  involved, so none of them can block a KMS restart or a certificate rotation.

Do not put a public ACME certificate on the KMS listener, and do not make KMS recovery wait on a
fleet ACME service, a DNS provider or a mesh that itself needs the KMS to come up. Operator access
for recovery must have a path that does not run through a service the KMS unlocks.

Because the chosen design creates no dependency in either direction, there is no outage drill to
run for it here. A design that adds one (a consumer adopting the envelope profile at scale, a
broker, an issuer) owes that drill before adoption: KMS unavailable, consumer restarted, valid TLS
still served, renewal-blocked alert raised.

## Alternatives considered

| Option | Outcome | Reason |
|---|---|---|
| Better local automation (renew, reload, probe every consumer) | **Chosen** | It is what the incidents needed, and it adds no shared dependency |
| Per-name scoped DNS delegation | Chosen where a broad token is the exposure | Removes cross-name authority at the source; DNS-side work |
| Shared DNS validation broker | Rejected for now | A new privileged service with authority across names, and no failure it would have prevented |
| Central issuer backed by the KMS | Rejected | Every public endpoint would depend on the KMS for renewal; leaf keys gain nothing from hardware custody |

### Compromise and failure, per option

"Scoped local" is local automation with a per-name credential. "Broad local" is the starting point:
one provider token covering whole zones, present on every host that renews.

| Scenario | Broad local | Scoped local | Validation broker | Central issuer |
|---|---|---|---|---|
| Application container compromised | Issues for any name in the zones and can rewrite their records, if the token is in its environment | Nothing: the token is given to the proxy only | Nothing | Nothing |
| Proxy or ACME client host compromised | Any name in the token's zones, plus record changes | Its own names only; no record changes outside the challenge | The names the broker grants that caller | Its own leaf only |
| Validation worker compromised | n/a | n/a | Every name the broker serves | n/a |
| Issuer compromised | n/a | n/a | n/a | Every name, and every leaf key it distributes |
| Operator or CI identity compromised | Whatever broad tokens that identity can read | The names of that repository only | What the broker grants CI | The names granted to it |
| Unauthorized cross-name issuance | Possible from any renewing host | Not possible | Possible from the broker | Possible from the issuer |
| Global renewal failure | Only if the public CA or DNS provider fails | The same, plus the validation zone if one is shared | Broker outage blocks every renewal | Issuer or KMS outage blocks every renewal |
| Migration and upkeep | None | One delegation and one credential per name | A new service to build, patch, monitor and recover | A new service, a delivery agent and a KMS dependency |

Scoped local removes cross-name authority without adding a component that holds it. The broker and
the issuer both reintroduce it in one place and add a fleet-wide renewal dependency.

## Gates

The local standard counts as adopted when the fleet can show, per environment:

1. Every consumer endpoint in the inventory, including ports other than 443, has a probe of the
   certificate it actually serves.
2. A forced renewal reaches every consumer of that certificate with no human action.
3. A blocked renewal raises an alert at least 14 days before expiry.
4. No application container holds a DNS or CDN credential, shown by inspection rather than by
   configuration.

Central validation or issuance is reconsidered only if all of these hold:

- the four measures above are in place, and an incident occurs that they could not have prevented;
- the provider cannot scope a credential to the names one host needs, by token or by delegation;
- the KMS backend it would depend on is production-qualified.

A prototype then runs on named staging hostnames only, apart from the KMS daemon, and must show the
outage drill above and a smaller cross-name authority than scoped local before any migration.

## Precedent

This follows the usual split. AWS keeps certificate management (ACM) apart from KMS. Vault and
OpenBao speak ACME as a server for their own internal CA; they are not an ACME client for other
services' public certificates.

## Deferred

- **ACME account key custody.** The account key is long-lived and a fair candidate. No consumer has
  asked, and no incident points at it.
- **An internal ACME server.** If the fleet wants automatic internal certificates, that belongs to a
  PKI service in front of the KMS, with the CA key held here, not in the daemon.
