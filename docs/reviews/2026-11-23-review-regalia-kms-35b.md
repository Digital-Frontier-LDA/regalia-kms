# Review: regalia-kms-35b (PR #774), run cc611723

Reviewed head `09a4ee5d` (bead/regalia-kms-35b, base `3dad6c93`) against the bead's AC1-AC6.
Own test runs: `git archive 09a4ee5d` into a scratch dir, `golang:1.26-alpine` (go1.26), uid 501,
`go test -count=1 ./internal/policy ./internal/operations`. The worktree was not modified.

## Verdict

**Fixes needed. NEXT: feedback.** The canonical-bytes half (AC1, AC3) is done and proven. The
verification half (AC4) holds only for bindings that pin `public_key_sha256`. Two guard branches
have no test that kills them.

## Findings, by severity

### 1. HIGH: AC4 not met for unpinned bindings. The signature is checked against a key the token chooses.
`internal/operations/coordinator.go:376-380`, `internal/operations/cosmos_verify.go:57-63`.
When `route.Binding.PublicKeySHA256` is empty (a DevAut-only nitrokey binding, which the registry
allows: `internal/registry/registry.go:1341`), the key used for verification is whatever the same
token answers to `public-key`. A token that signs with key B and reports B passes. Nothing outside the
token binds the signature to the object's key or to the account the chain checks.
- Input that shows it: a fake card that signs with a fresh key and reports that same key, unpinned route.
  Probe output at head: `PROBE unpinned token-chosen key: err=<nil> bytes=64 audit=[authorized success]`.
- The existing case `TestCosmosSignatureFromWrongKeyIsNotSuccess/signed_by_another_key,_no_pin` only
  covers a token that signs with one key and reports a different one.
- The council on PR #774 requires (A): verify under the signer public key in the walked AuthInfo
  (compared as points, compressed vs SPKI), also check the pin when present, and refuse before any
  token call when neither exists. Also document the "pubkey omitted after the first tx" consequence.
  Feedback note: the reference fixture `internal/policy/testdata/signdoc-akashnet2-msgsend.hex` carries
  NO signer public key (no `/cosmos.crypto.secp256k1.PubKey` Any in it). Under rule (A), that fixture
  is refused on an unpinned route. Tests need a fixture with a signer key, or a pinned route.

### 2. MEDIUM: the key-read error branch has no test (council M10).
`internal/operations/coordinator.go:376-379`. Mutation `if keyErr != nil && false {`: every test in
policy and operations still PASSES. The probe shows what changes: the outcome goes from
`[authorized backend-failed]` (retryable BACKEND_UNAVAILABLE) to `[authorized signature-unverified]`
(non-retryable INTERNAL). A token outage would be misfiled as a token/daemon defect. In both cases the
token has already signed (`signs=1`) and the reservation is spent, as the doc says for indeterminate
results.

### 3. MEDIUM: the r/s range check has no test (council M5).
`internal/operations/cosmos_verify.go:101`. Mutation: call `SetByteSlice` but ignore its overflow
result. Every test still PASSES. Without the check, an r or s at or above N is reduced mod N and verified,
but a chain refuses it. A killing test needs a signature whose s (or r) is below 2^256-N, so that s+N
still fits in 32 bytes. Build it with a chosen private key: pick k and s, then solve for d.

### 4. LOW: P-256 high-S signatures are reported as verified.
`internal/operations/cosmos_verify.go:107-118`. `verifyNISTCurve` uses `ecdsa.Verify`, which accepts
both s and N-s. Probe: `PROBE p256 low-S verify=<nil> high-S verify=<nil>`. The nitrokey normalizer
rewrites only secp256k1 (`internal/backend/nitrokey/lows.go:40-43`), so a P-256 Cosmos key would get
about half of its signatures in high-S form. Per the Cosmos SDK's secp256r1 key type, which requires
normalized s, a chain refuses those. COSMOS-SUPPORT.md says "`p256` and `p384` are verified too". I found no
deployed or tested Cosmos object on p256 or p384: every cosmos-transaction object in the registry tests is
secp256k1. So the impact is latent. Cosmos has no P-384 account key type at all. Either require low-S
for p256, or fail closed on p256/p384 for the Cosmos content type.

### Observation (not a code defect): a red ci-gate on the exact head
Run 45266307734 (the draft-time run) was re-run as attempt 2. Its ci-gate failed at 21:57Z with "a
draft pull request never passes ci-gate", which is by design for that run's draft event context:
https://github.com/Digital-Frontier-LDA/regalia-kms/actions/runs/45266307734/job/138044147375 .
The run for the ready PR, 45266397641, is green: ci-gate SUCCESS (job 138032275058), and build-test is
green in both runs. mergeStateStatus is CLEAN. The feedback push will produce a fresh run anyway.

## Checked and correct
- `canonicalSignDocBytes` (cosmos.go): fields 1-4 in order, minimal tag, length and varint, zero
  account_number and empty fields left out. Compared with `bytes.Equal` after all other diagnostics, before policy.
- The refusal happens before `policy.Evaluate`, so there is no reservation and no token call
  (TestAReorderedSignDocIsRefusedBeforeTheToken, with a canonical control that reserves once).
- Digest and mechanism: sha256(request.Data) goes to bare CKM_ECDSA. Bead defect 1 was a misreading,
  agreed by plan, check-plan and this review.
- secp256k1 verification: length 64, r and s nonzero and below N, low-S, then the decred Verify.
  The pin is compared in constant time. Output is zeroed on every error path. An unknown algorithm fails closed.
- The production hardware (`certs.Issuer` over `backend.Manager`) serves `public-key` for nitrokey
  (`provider.go:406`, after `verifyPinnedPublicKey`) and yubikey (`provider.go:334`). The cosmos-node and
  pkcs11-e2e CI jobs are green.
- AC6: a grep of the diff for DENK, serial and site names finds only the identifier `SerializeUncompressed`.
  The PR body lists the deviations.

## Acceptance criteria, one line each
- AC1: MET. Refuse route (`internal/policy/cosmos.go:174`), and pre-hashed CKM_ECDSA over sha256 of the canonical bytes is stated in COSMOS-SUPPORT.md and coordinator.go:361-365.
- AC2: MET. TestCosmosSignatureVerifiesIndependently uses a test-local math/big verifier. It passes on base by design (defect 1 was a misreading), and its red proof is mutation (c), reproduced here.
- AC3: MET (refuse route). Reordered fixture gives 400 INVALID_ARGUMENT, 0 token calls, 0 reservations, audit `policy-cosmos-malformed`.
- AC4: PARTIAL. Met for pinned bindings and for corrupt or high-S secp256k1 signatures. NOT met for unpinned bindings (finding 1).
- AC5: PARTIAL. Named mutations (a) and (b) turn tests RED (reproduced). CI is green on the ready run at the exact head. Guard mutants M5 and M10 survive (findings 2 and 3).
- AC6: MET. No device or site identity. Deviations (i)-(iv) are in the PR body. The council accepted 1, 3 and 4; 2 is finding 1.

## Each relied-on test shown to FAIL without the fix (own runs at 09a4ee5d)
- Base (coordinator.go and cosmos.go from 3dad6c93): FAIL TestCosmosSignDocRefusesNonCanonical (7 subtests),
  TestCosmosSignatureFromWrongKeyIsNotSuccess (3), TestCosmosCorruptedSignatureIsNotSuccess (2),
  TestCosmosVerificationRefusesAKeyTypeItCannotCheck, TestAReorderedSignDocIsRefusedBeforeTheToken.
- (a) verify replaced by `_ = publicKey; return nil`: FAIL WrongKey, Corrupted, RefusesAKeyType.
- (b) `if false && !bytes.Equal(...)`: FAIL TestCosmosSignDocRefusesNonCanonical, TestAReorderedSignDocIsRefusedBeforeTheToken.
- (c) `sha256.Sum256(data[1:])`: FAIL TestCosmosSignatureVerifiesIndependently, TestCoordinatorHashesCanonicalCosmosSignDocBeforeHardware.
- TestCosmosSignDocAcceptsCanonicalFixtures is the green control (no red proof needed).
- M5 and M10: NO test fails (findings 2 and 3).

## Public interface changes
1. `policy.ParseCosmosSignDoc` now refuses non-canonical encodings. In-repo caller: `internal/operations/coordinator.go:319` only.
   External effect: API clients that send a non-canonical SignDoc now get 400. The bead asked for this (AC1).
2. New audit outcome `signature-unverified` (audit records, metrics label). Consumers: the audit
   journal and collector, the outcome metric (cardinality comment updated), and the off-repo spendaudit
   (`tests/vectors/spendaudit-v1.json` only shows `backend-failed`). The bead asked for this (AC4).
3. New API failure for cosmos sign: `INTERNAL`, 500, non-retryable. Callers: KMS HTTP clients. The bead asked for this (AC4).
4. Each cosmos sign now makes a second `Hardware.Execute(..., "public-key", ...)` call. The interface is unchanged.
   For DevAut-only bindings this adds one token round-trip.
5. New dependency `github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0`. It is operator-visible and accepted by the council (deviation 1).
No exported name, signature or return type changed. The new helpers are unexported.
