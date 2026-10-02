# Fleet certificates and the KMS boundary

Decision (#104): **the KMS does not manage public TLS certificates.** Issuing, renewing, storing and
reloading a public certificate is the job of the host that serves it. The KMS protects the few
long-lived secrets around that work when a consumer asks it to, through operations it already has.

The decision was prompted by two certificate incidents in the fleet. In one, a certificate was
renewed on disk and the services holding it were never reloaded. In the other, a certificate was
uploaded by hand and its renewal was never scheduled. Neither exposed a key. Both are lifecycle
failures: ownership, renewal, reload, and a check of what each endpoint actually serves. Custody
does not address them, so the fix is not in this repository.

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

**The KMS does not depend on fleet certificates.** Client identities are issued from a dedicated
workload CA ([`IDENTITY.md`](IDENTITY.md)) and verified against `tls_client_ca_path`. Do not put a
public ACME certificate on the KMS listener, and do not make KMS recovery wait on a fleet ACME
service, a DNS provider or a mesh that itself needs the KMS to come up.

## Alternatives considered

| Option | Outcome | Reason |
|---|---|---|
| Better local automation (renew, reload, probe every consumer) | **Chosen** | It is what the incidents needed, and it adds no shared dependency |
| Per-name scoped DNS delegation | Chosen where a broad token is the exposure | Removes cross-name authority at the source; DNS-side work |
| Shared DNS validation broker | Rejected for now | A new privileged service with authority across names, and no failure it would have prevented |
| Central issuer backed by the KMS | Rejected | Every public endpoint would depend on the KMS for renewal; leaf keys gain nothing from hardware custody |

This follows the usual split. AWS keeps certificate management (ACM) apart from KMS. Vault and
OpenBao speak ACME as a server for their own internal CA; they are not an ACME client for other
services' public certificates.

## Deferred

- **ACME account key custody.** The account key is long-lived and a fair candidate. No consumer has
  asked, and no incident points at it.
- **An internal ACME server.** If the fleet wants automatic internal certificates, that belongs to a
  PKI service in front of the KMS, with the CA key held here, not in the daemon.
