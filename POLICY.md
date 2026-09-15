# Purpose-bound policy contract

The KMS must evaluate policy immediately before hardware use. Authentication and RBAC identify who
may ask; they do not make request purpose, payload, digest, transaction metadata, approvals, nonce or
time trustworthy. A successful `policy.Decision` is required but does not replace registry routing
or audit acknowledgement.

The versioned policy file binds one logical object to an exact purpose, environment, operation,
algorithm, bounded content type/payload, freshness window and approval set. Wildcards and ambiguous
object policies are invalid. Approval identities passed to the evaluator must come from a separately
authenticated approval record bound to the canonical request hash—not from a client JSON list.

Cosmos policies additionally allowlist chain IDs, account numbers, protobuf message type URLs,
destinations and denominations, with per-transaction and UTC-day caps. The coordinator now parses
the complete canonical protobuf SignDoc at the trust boundary and passes only the resulting
`CosmosTransaction` to the evaluator. The parser currently supports the message types it can
inspect safely (including `MsgSend`); adding another message type requires a parser, policy, and
negative-test slice together. Client-asserted fields or opaque digests are never an acceptable
substitute.

Replay nonce and quota consumption are serialized into a mode-0600 append-only hash-chained journal
and fsynced before allow. State loss, corruption, cancellation, replay, overflow and quota exhaustion
fail closed. A nonce stays consumed if the later hardware result is indeterminate. The journal chain
detects accidental/local alteration but must be covered by encrypted Proxmox storage, backup and
off-host audit heads because a fully compromised root can rewrite both data and hashes.

Policy decisions expose stable codes and rule identifiers suitable for the redacted audit event.
They never include destination, amount, certificate, payload or internal state error details.
