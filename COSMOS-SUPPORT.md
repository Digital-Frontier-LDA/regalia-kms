# Cosmos support inventory

This is the current, deliberately narrow Cosmos transaction contract. It is a pre-1.0 inventory,
not a claim of general Cosmos SDK compatibility.

## Accepted wire envelope

The KMS accepts `application/vnd.cosmos.tx+protobuf` only for a canonical Cosmos SDK
`tx.v1beta1.SignDoc`. The parser requires exactly one each of `body_bytes`, `auth_info_bytes`,
`chain_id`, and `account_number`, rejects unknown fields and wrong wire types, and rejects repeated
scalar fields. `TxBody` must contain at least one message encoded as `google.protobuf.Any`.

Only the canonical encoding is accepted: the four fields in field-number order, every tag, length
and varint in its minimal form, and a field holding its zero value (`account_number` 0, an empty
string or bytes) left out, which is how a generated encoder writes it and how a chain rebuilds it to
verify. A document that means the same transaction in any other encoding (fields reordered, a
non-minimal varint, an explicit `account_number` 0) is refused (`ErrCosmosSignDoc`, audit outcome
`policy-cosmos-malformed`) before policy, so it spends no nonce, sequence or quota. It is refused, not
re-encoded: the KMS signs only bytes the caller sent.

The complete SignDoc is parsed before policy evaluation. A malformed or unsupported document is
refused before hardware use. The independent generated fixture in
[`internal/policy/testdata/signdoc-akashnet2-msgsend.hex`](internal/policy/testdata/signdoc-akashnet2-msgsend.hex)
proves the wire shape outside the repository's hand-written test encoder.

## Message support

| message type | decoded fields | status |
|---|---|---|
| `/cosmos.bank.v1beta1.MsgSend` | source, destination, denomination, decimal amount | implemented and tested |
| `/cosmos.staking.v1beta1.MsgDelegate` | delegator, validator, denomination, decimal amount | implemented and tested |
| every other message type | none | refused until a dedicated parser and policy tests exist |

The parser currently rejects unknown `Any` type URLs rather than passing opaque messages to a
signer. This is intentional: a policy cannot constrain a message it cannot inspect.

## Policy semantics currently enforced

- chain ID allowlist;
- account-number allowlist;
- source-address allowlist;
- message-type allowlist;
- destination allowlist;
- denomination allowlist;
- per-transaction denomination caps;
- durable UTC-day denomination caps;
- replay nonce reservation;
- verified approver signatures;
- canonical SignDoc parsing before policy and hardware.
- SHA-256 hashing of the canonical SignDoc before the hardware signing operation. The token signs
  that digest with pre-hashed ECDSA (`CKM_ECDSA`), so the signature is over exactly the digest a
  Cosmos verifier computes;
- in-daemon verification of every signature before success (below).

## Signature verification before success

Before a Cosmos signature is returned, the daemon reads the object's public key from the token
(`public-key`) and verifies the signature against SHA-256 of the canonical SignDoc. The token's own
report of its key is never enough on its own, because a token that signs with the wrong key reports
that wrong key. The key must also be bound to something the token does not choose:

- when the binding pins `public_key_sha256`, the key read must hash to the pin;
- when the SignDoc's single `SignerInfo` carries `public_key` (the key the chain verifies with),
  the key read must be the same point. The SignDoc's key is compressed SEC1 and the token's an
  uncompressed SPKI, so the two are compared as points, not bytes. Its type must be the one for the
  object's curve: `/cosmos.crypto.secp256k1.PubKey` for `secp256k1`,
  `/cosmos.crypto.secp256r1.PubKey` for `p256`.

A binding with neither cannot sign. A DevAut-only binding (no `public_key_sha256`) signing a SignDoc
that leaves `public_key` out, or that carries a key of another type or one that is not a point, is
refused with `INVALID_ARGUMENT` and audited `cosmos-signer-key-unbound`, before policy reserves
anything and before the token is called. The Cosmos SDK lets a signer omit `public_key` once its key
is on chain, so an unpinned binding refuses those transactions. The remedy is to pin the binding's
`public_key_sha256` at commissioning (a pinned binding signs with or without the SignDoc's key), or
to have the caller always include the signer's public key.

The signature must be raw `r||s` with `r` and `s` in `[1, N-1]`, never reduced modulo `N`, and
`s` low (at most `N/2`) on both curves, as the Cosmos SDK's secp256k1 and secp256r1 keys require.
The Nitrokey backend normalises secp256k1 signatures to low S; it does not normalise `p256`, so a
`p256` Cosmos object whose token returns the high-S twin gets `signature-unverified` for it. `p384`
has no Cosmos key type, and it and any other algorithm are refused before the token is called. A
signature that does not verify is never success: the caller gets a non-retryable `INTERNAL` error
with no signature, and the audit trail records `signature-unverified`. It is a token or daemon defect
for an operator to look at, not an outage. A token that signs but then cannot answer `public-key` is
an outage: `backend-failed`, retryable, as any other backend error.

Policy's reservation for that request stands, as it does for an indeterminate hardware result: its
nonce and the account sequence it carried are spent, while the chain never saw a valid transaction
for that sequence. A request carrying the sequence the chain still expects is then refused as a
repeat, and one carrying the next sequence is accepted by policy but not by the chain.

There is no supported way to recover from this yet. No operation re-initialises an object's expected
sequence once it has history: the journal accepts only the previous sequence plus one, and the
commissioning step below sets only the first sequence. The account stays blocked at that sequence
until a named recovery procedure lands (regalia-kms-4t4; the procedure is tracked as regalia-kms-47g).
Until then, an operator who sees `signature-unverified` for a Cosmos object should:

1. Stop submitting signing requests for that account.
2. Keep the request id and its `signature-unverified` audit entry, and escalate them as a token or
   daemon defect.
3. Leave the policy journal and the active/passive signer state as they are. Editing, truncating
   or replacing the journal is not a recovery path; the journal refuses a truncated, rewritten or
   broken-chain file at open.

Nothing else is supported.

## Sequence, fee, and gas semantics

The parser exposes signer sequence, fee coins, and gas limit from `AuthInfo`. Cosmos policies require
a positive gas limit at or below `max_gas_limit`, and every fee coin must be explicitly allowlisted at or below
its `max_fee` cap. The durable policy journal requires each subsequent reservation for an object to
carry the next account sequence; gaps and repeats refuse before hardware use. A sequence is consumed
when the reservation is durably committed, including an indeterminate later hardware result, so a
retry cannot accidentally reuse it.

The current policy does not query a live chain. Operators must initialize the first expected sequence
from a trusted chain observation during commissioning and keep the active/passive signer state and
policy journal together through failover.

## Hardware qualification command

The software pipeline is runnable without a token. For a staging PicoHSM2 or compatible PKCS#11
device, `e2e/cosmos-hardware-sign-verify.sh` hashes the
generated SignDoc fixture, signs the digest through the configured secp256k1 object, and verifies
the raw ECDSA result against the public key read from that same token. It requires explicit
`REGALIA_COSMOS_PKCS11_MODULE`, a token selector (`REGALIA_COSMOS_PKCS11_SERIAL` with any module but
SoftHSM, where the card is chosen by serial only; a label or slot with SoftHSM), and
`REGALIA_COSMOS_PKCS11_PIN` variables; it never guesses a PIN or runs as part of ordinary tests.
The same check can be selected after the standard software battery with
`e2e/run.sh --mode cosmos-hardware`.

## Expansion rule

Adding a message type requires all of the following in one reviewed change:

1. generated upstream protobuf fixture;
2. parser implementation that rejects unknown and duplicate fields;
3. explicit policy dimensions for every security-relevant field;
4. allow and refusal tests, including a test proving the refusal occurs before hardware;
5. end-to-end signing and signature-verification coverage.

Sequence handling, fee/gas limits, replay, quota durability, and active/passive wallet failover are
separate controls and must not be inferred from message parsing alone.

## Evidence boundary

The repository currently proves SignDoc parsing, policy decisions, concrete PKCS#11 signing, and
signature verification against a disposable SoftHSM token. With an explicitly supplied, reviewed
Cosmos SDK `simd` binary, `e2e/cosmos-simapp-tx.sh` also submits a real `MsgSend` and confirms its
commitment through RPC. This proves chain acceptance for the disposable devnet, not acceptance by a
production chain and not that the devnet transaction was signed by the KMS hardware. Physical
PicoHSM2 qualification likewise requires an approved operator PIN and is never substituted by the
SoftHSM credential.
