# Cosmos support inventory

This is the current, deliberately narrow Cosmos transaction contract. It is a pre-1.0 inventory,
not a claim of general Cosmos SDK compatibility.

## Accepted wire envelope

The KMS accepts `application/vnd.cosmos.tx+protobuf` only for a canonical Cosmos SDK
`tx.v1beta1.SignDoc`. The parser requires exactly one each of `body_bytes`, `auth_info_bytes`,
`chain_id`, and `account_number`, rejects unknown fields and wrong wire types, and rejects repeated
scalar fields. `TxBody` must contain at least one message encoded as `google.protobuf.Any`.

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
- for a `cosmos-account` key, the chain ID, account number, sequence and signer equal to what the chain said just before signing;
- canonical SignDoc parsing before policy and hardware.
- SHA-256 hashing of the canonical SignDoc before the hardware signing operation.

## Signing profile: the KMS is a blockchain user, not a validator (#432)

Every secp256k1 key has a `signing_profile` in the custody manifest. The owner decided on 2026-10-05 that the KMS
uses chains and does not validate them.

- **`cosmos-account`** is the default and today the only profile. Just before signing, the daemon asks the chain's
  endpoint (`cosmos_rpc`, one https URL per chain) for:
  - the signer's account number and sequence (`/cosmos/auth/v1beta1/accounts/{address}`);
  - the chain's ID (`node_info`, trusted for 5 minutes).

  The SignDoc must carry **exactly** those values: the chain ID, the account number, the sequence, and every
  message's signer. If any differs, the request is refused before the hardware.
  - **The chain arbitrates the sequence.** The KMS keeps no sequence high-water for such a key. Two servers
    signing for one account at once both get a signature, and the chain takes one transaction per sequence.
  - **On one server,** a key's requests are serialised from the chain's answer to the result, so two requests
    there never read the same sequence.
- **`cosmos-validator`** (vote signing, with height and round high-water marks) is **refused at load**. No vote
  signing exists in this KMS.
- **Unordered transactions** (Cosmos SDK 0.53, `TxBody.unordered`) are refused by name: they carry no sequence for
  the chain to arbitrate.
- **The endpoint can only deny service.** A lying or intercepted endpoint can make the values differ, and the KMS
  then refuses. It can't make the KMS sign anything the SignDoc and its policy wouldn't allow, because the check is
  equality, never substitution.
  - Endpoints are https with normal certificate validation, and redirects aren't followed.
  - The daemon resolves no names through DNS, so each host is an address or in `/etc/hosts`.
  - The host's egress names exactly these hosts.

## Fee and gas semantics

The parser exposes signer sequence, fee coins, and gas limit from `AuthInfo`. Cosmos policies require a positive
gas limit at or below `max_gas_limit`, and every fee coin must be explicitly allowlisted at or below its `max_fee`
cap. A key with no profile (no current manifest leaves one out for a secp256k1 key) would fall back to the durable
policy journal's gap-free sequence. That path stays only for the journal's own tests.

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
