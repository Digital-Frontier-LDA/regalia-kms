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
detects accidental/local alteration but must be covered by the host's encrypted disk, the
control-plane export and off-host audit heads because a fully compromised root can rewrite both data and hashes.

Policy decisions expose stable codes and rule identifiers suitable for the redacted audit event.
They never include destination, amount, certificate, payload or internal state error details.

## Denial rules

A denial carries the rule that produced it, and the audit record stores it as
`policy-DENIED:<rule>`. The API answer does not change with the rule: the caller is told `DENIED`
(`API.md`), so the rule is evidence for the operator, never an oracle for the client.

A Cosmos transaction is checked one dimension at a time, in this order, and the first refusal is the
one reported:

| Rule | The transaction is refused because |
|---|---|
| `cosmos-transaction` | there is no parsed transaction, or it carries no messages |
| `cosmos-chain` | its chain ID is not one the policy lists |
| `cosmos-account` | its account number is not one the policy lists |
| `cosmos-message` | a message is of a type the policy does not list, or moves no coins |
| `cosmos-destination` | a message pays a destination the policy does not list |
| `cosmos-source` | a message spends from a source the policy does not list |
| `cosmos-amount` | a coin is in an unknown denomination, is zero, or the transaction moves more than the per-transaction cap |
| `cosmos-gas` | the gas limit is zero or over the cap |
| `cosmos-fee` | a fee coin is in an unknown denomination, is zero, or the fee is over the cap |

After these, the durable state can still refuse: `sequence` (not the next account sequence),
`quota` (the daily cap), `epoch` (a superseded fencing epoch) and `replay` (a nonce already used).

`TestCosmosPolicyRejectsEveryControlledDimension` provokes every rule in the table and fails if one
is never produced; `TestTheFirstRefusingCosmosDimensionIsTheOneReported` pins the order.
`e2e/cosmos-simapp-kms-tx.sh` asserts the same rules against a live node.
