package policy

// THE OPERAND LEDGER (#237): every boolean operand in this package that no test detected,
// classified, with the reachable ones pinned here.
//
// WHAT WAS SWEPT, AND IN WHAT UNIT. Enumerated with tools/guardenum built from source, whose
// records are byte ranges rather than text matches:
//
//	cosmos.go  37 sites /  46 operands        state.go  50 sites / 74 operands
//	load.go     9 sites /  13 operands        wire.go   10 sites / 12 operands
//	policy.go  40 sites /  80 operands        ------------------------------
//	                                          total    146 sites / 225 operands
//
// Each operand was neutralised in BOTH directions -- 450 operand-directions -- because the
// direction that preserves an operand's siblings answers only half the question. `(false &&
// operand)` narrows a refusing || chain and asks whether anything notices a bad input being
// admitted; `(true || operand)` widens an && chain and asks whether anything notices a good one
// being refused. Sweeping one direction per operand is what left state.go's same-length-rewrite
// check below with no test that ever provokes it: the widening direction was measured under
// #334 and recorded as covered, and the narrowing direction -- a rewritten journal verifying
// CLEAN -- had never been asked.
//
// WHAT WAS ALREADY DONE AND IS NOT REDONE HERE. Three pieces of #237 landed before this ledger
// and their operands are classified where they landed, not here:
//
//	the fault-injection layer (#334)   19 sites / 28 leaves at the os/fs boundary,
//	                                   in fault_injection_test.go and its ledger
//	the ErrReplay join in Evaluate     replay_decision_test.go
//	the parser boundary in cosmos.go   parser_boundary_test.go
//
// SEVEN of the survivors below the line are #334 leaves reported again by this sweep and are NOT
// repeated as rows here: cosmos.go's account-number redecode, load.go's LoadFile stat, and
// state.go's writeHighWater marshal, VerifyState read-state ErrNotExist, OpenFileState stat,
// Reserve marshal-event, and readState stat. Their rows are in fault_injection_leaves_test.go and
// this sweep agreed with every one of that ledger's 28 verdicts. One #334 leaf IS repeated here --
// VerifyState's `mark.Hash != stateGenesisHash` -- because this sweep asked it in the direction
// that ledger did not, and the row records both answers.
//
// RESULT for this package, over those 450 directions: 328 killed outright, 51 killed with a panic
// in the failing set, 71 survivors. A panicking run's failing set is a LOWER BOUND -- the panic
// aborts the test binary -- so those 51 are recorded as killed and not as evidence about which
// tests killed them. No mutation failed to build and none hung; a build failure emits no
// `--- FAIL:` line and would otherwise be indistinguishable from "nothing detected it", so the
// harness classified that case separately and was shown to report it on a planted undefined symbol.
//
// TWO THINGS FOR WHOEVER SWEEPS THIS PACKAGE NEXT, both learned here at cost.
//
// RESTORING THE MUTATED FILES IS NOT RESTORING THE TREE. A mutation that empties FileState.path
// makes writeHighWater put its sidecar at ".high-water" -- in the CWD, which under `go test` is
// the package directory. That run left one behind in internal/policy, internal/operations,
// internal/controlplane, internal/integration and cmd/regalia-kms, all of them untracked, none of
// them noticed by a harness that proves only the FILES IT MUTATED byte-identical on the way out.
// Check the tree, not the operands.
//
// AND A LEDGER'S OWN DRIFT GUARD MUST BE NEUTRAL TO THE HARNESS. See internal/sweeptext, which
// carries the shape table this drift guard depends on:
// a check that compares a row's guard against the source fires when the guard is neutralised, so
// it co-detects every row it describes and no row can be shown to be the sole detector of
// anything. That is not a one-round inconvenience; it poisons attribution for every later sweep.
//
// THE VERDICTS are the four #334 uses, plus one this sweep needed:
//
//	covered          — the row below IS the sole detector. Neutralise the operand and this row
//	                   is the only failure in the package.
//	pinned-elsewhere — an existing test already detects it, named in `why`. The row is
//	                   documentation and can never be the sole failure.
//	unreachable      — no input reaches it (TESTING.md §17). The row states the property that
//	                   makes it unreachable and, where that property is checkable, checks it.
//	undetectable     — reachable, but every input that distinguishes the operand is one whose
//	                   refusal would be an improvement, so pinning one would pin a gap.
//	masked           — NEW. Reachable, and it can never be the SOLE refuser: a sibling operand or
//	                   a downstream guard refuses every input that reaches it. Different from
//	                   pinned-elsewhere, which says a test exists; this says no test CAN exist
//	                   that fails on this operand alone. The row names the masking guard and the
//	                   derivation, and the pair was neutralised together to check it.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/sweeptext"
)

// verdictMasked is the fifth classification. The other four are declared in
// fault_injection_leaves_test.go and are reused rather than restated, so a change to that
// vocabulary reaches this ledger too.
const verdictMasked = "masked"

// operandLeaf is one operand-direction of one guard.
type operandLeaf struct {
	// file and guard together are the drift guard: `guard` must occur EXACTLY ONCE in `file`,
	// and `operand` must occur inside it. A guard that is edited, moved between files or
	// deleted breaks the row rather than leaving it asserting about code that is gone.
	//
	// Line numbers are deliberately absent. Six cross-references in this repository went stale
	// in one day because they cited a line; the source text cannot go stale silently.
	file    string
	guard   string
	operand string
	// direction is the neutralisation this row is about, written as it was applied.
	direction string
	verdict   string
	why       string
	run       func(*testing.T)
}

func operandLedger() []operandLeaf {
	return append(append(append(
		cosmosOperandRows(), loadOperandRows()...), policyOperandRows()...),
		append(stateOperandRows(), wireOperandRows()...)...)
}

// ---------------------------------------------------------------------------------------------
// cosmos.go
// ---------------------------------------------------------------------------------------------

func cosmosOperandRows() []operandLeaf {
	return []operandLeaf{
		{
			file:      "cosmos.go",
			guard:     `if !seenBody || !seenAuth || !seenChain {`,
			operand:   "!seenBody",
			direction: "(false && !seenBody)",
			verdict:   verdictCovered,
			why: "The two siblings are killed by TestParseCosmosSignDocRejectsMissingRequiredFields, " +
				"which asserts only that an error came back. body_bytes is the one field whose absence " +
				"is refused DOWNSTREAM anyway -- an absent body parses as an empty TxBody and " +
				"parseTxBodyMessages says 'TxBody carries no messages' -- so the operand does not guard " +
				"the refusal, it guards the DIAGNOSIS. An operator told a signed document carries no " +
				"messages goes looking at the encoder that built the body; what actually arrived is a " +
				"SignDoc with no body field at all, which is a different bug in a different place.",
			run: func(t *testing.T) {
				withoutBody := append(append(append([]byte{},
					encodeLengthDelimited(2, encodeAuthInfo())...),
					encodeString(3, "cosmoshub-4")...),
					encodeTopVarint(4, 42)...)
				_, err := ParseCosmosSignDoc(withoutBody)
				if err == nil {
					t.Fatal("a SignDoc with no body_bytes parsed")
				}
				if !strings.Contains(err.Error(), "missing required SignDoc field") {
					t.Fatalf("a SignDoc with no body_bytes was refused as %q — the required-field rule "+
						"is what should answer here, and 'TxBody carries no messages' sends an operator "+
						"to inspect a transaction body that was never in the document", err)
				}
			},
		},
		{
			file:      "cosmos.go",
			guard:     `if len(text) > 1 && text[0] == '0' {`,
			operand:   "len(text) > 1",
			direction: "(true || len(text) > 1)",
			verdict:   verdictCovered,
			why: "The canonicality rule has a refusing side and an accepting side, and only the " +
				"refusing one was written: cosmos_reference_test.go pins that \"01\" is refused and " +
				"nothing pins that \"0\" is not. Widen this operand and the single digit zero -- a " +
				"perfectly canonical Cosmos Int -- is refused as having a leading zero, so a zero-amount " +
				"coin comes back from the PARSER as a malformed document instead of reaching the policy " +
				"layer that has an opinion about zero amounts. This row is the accepting side; it " +
				"deliberately does not restate the \"01\" refusal, because a second detector for an " +
				"operand that already has one takes sole-detector status away from both.",
			run: func(t *testing.T) {
				amount, err := decodeCoinAmount("0")
				if err != nil {
					t.Fatalf("decodeCoinAmount(\"0\") = %v — zero is one digit, so the leading-zero rule "+
						"must not reach it, and a Coin.amount of \"0\" is a document a conforming "+
						"encoder does produce", err)
				}
				if amount != 0 {
					t.Fatalf("decodeCoinAmount(\"0\") = %d, want 0", amount)
				}
				// The control, chosen so that it cannot double as a detector for any refusal
				// operand: a two-digit value that no rule here objects to. Without it the row above
				// is equally consistent with a decoder that returns (0, nil) for everything.
				if amount, err := decodeCoinAmount("10"); err != nil || amount != 10 {
					t.Fatalf("decodeCoinAmount(\"10\") = (%d, %v) — the row above would pass against a "+
						"decoder that answers zero and nil to everything", amount, err)
				}
			},
		},
	}
}

// ---------------------------------------------------------------------------------------------
// load.go
// ---------------------------------------------------------------------------------------------

func loadOperandRows() []operandLeaf {
	return []operandLeaf{
		{
			file:      "load.go",
			guard:     `if err := decoder.Decode(&document); err != nil {`,
			operand:   "err != nil",
			direction: "(false && err != nil)",
			verdict:   verdictPinnedElsewhere,
			why: "Detected by TestPolicyLoaderRejectsUnknownFieldsAndTrailingDocuments, whose fixtures " +
				"this change repaired. Both of them read \"policies\":[] , so BOTH were refused by the " +
				"empty-policies guard three lines below whatever this operand did -- the test was green " +
				"against a loader with neither rule. It matters because encoding/json's " +
				"DisallowUnknownFields error does NOT abandon the value: measured, " +
				"{\"schema_version\":1,\"policies\":[{...}],\"default\":\"allow\"} decodes to a fully " +
				"populated document AND an error, so ignoring the error loads the policy set and drops " +
				"the unknown key on the floor.",
		},
		{
			file:      "load.go",
			guard:     `if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {`,
			operand:   "!errors.Is(err, io.EOF)",
			direction: "(false && !errors.Is(err, io.EOF))",
			verdict:   verdictPinnedElsewhere,
			why: "Same repaired test, same fixture defect: the trailing-document row also used an empty " +
				"policies array, so the empty-policies guard refused it and this rule was never the " +
				"reason. Without the rule a file holding two JSON documents loads the first and ignores " +
				"the second, which is the malleability the duplicate-scalar rules in cosmos.go exist to " +
				"prevent arriving through the configuration file instead of the wire.",
		},
	}
}

// ---------------------------------------------------------------------------------------------
// policy.go
// ---------------------------------------------------------------------------------------------

func policyOperandRows() []operandLeaf {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	return []operandLeaf{
		{
			file:      "policy.go",
			guard:     "if engine == nil {\n\t\treturn 0\n\t}",
			operand:   "engine == nil",
			direction: "(false && engine == nil)",
			verdict:   verdictCovered,
			why: "Engine.Ready has the same nil-receiver guard and TestAnEngineWithNoPoliciesIsNeverReady " +
				"pins it, with the reason written out: readiness is polled before everything is " +
				"necessarily wired. QuotaRejections is read from the same place -- the telemetry " +
				"handler's source function -- and had the guard without the test. Without it a nil " +
				"engine dereferences an atomic on a nil struct.",
			run: func(t *testing.T) {
				var engine *Engine
				if got := engine.QuotaRejections(); got != 0 {
					t.Fatalf("QuotaRejections on a nil engine = %d, want 0", got)
				}
			},
		},
		{
			file:      "policy.go",
			guard:     `if _, exists := seenIDs[policy.ID]; exists {`,
			operand:   "exists",
			direction: "(false && exists)",
			verdict:   verdictCovered,
			why: "TestNewRejectsDuplicateAndUnsafePolicy passes the SAME policy twice, which trips this " +
				"guard and the ambiguous-object guard four lines below it at once -- so neither was " +
				"pinned, and defeating either one alone left the suite green. One fixture, two operands, " +
				"pins neither. This row separates them: same id, different object.",
			run: func(t *testing.T) {
				first := basePolicy()
				second := basePolicy()
				second.ObjectID = "a-different-object"
				_, err := New([]Policy{first, second}, &reportingState{ready: true}, clock)
				if err == nil {
					t.Fatal("two policies sharing an id compiled — the id is what a decision, an audit " +
						"record and the custody manifest all name, so two of them is an unresolvable " +
						"reference in three places")
				}
				if !strings.Contains(err.Error(), "duplicate policy id") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
		{
			file:      "policy.go",
			guard:     `if _, exists := engine.policies[key]; exists {`,
			operand:   "exists",
			direction: "(false && exists)",
			verdict:   verdictCovered,
			why: "The other half of the pair above. Same (object, operation), different ids: only this " +
				"guard can refuse it. Without it the second policy silently replaces the first in the " +
				"map, so which of two declared rules is enforced depends on slice order.",
			run: func(t *testing.T) {
				first := basePolicy()
				second := basePolicy()
				second.ID = "cosmos-hot-wallet-shadow"
				_, err := New([]Policy{first, second}, &reportingState{ready: true}, clock)
				if err == nil {
					t.Fatal("two policies compiled for one (object, operation) — one of them silently " +
						"wins, and which one depends on the order they were listed in")
				}
				if !strings.Contains(err.Error(), "ambiguous") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
		{
			file:      "policy.go",
			guard:     `if denom == "" || transactionCap == 0 || !exists || dailyCap < transactionCap {`,
			operand:   `denom == ""`,
			direction: `(false && denom == "")`,
			verdict:   verdictCovered,
			why: "The fourth operand of this guard has a sole detector and the first three did not. An " +
				"empty denomination in the cap maps declares a cap for a coin that cannot exist -- the " +
				"wire decoder refuses an empty Coin.denom -- so the policy reads as protecting something " +
				"and protects nothing, and the operator who wrote it gets no warning.",
			run: func(t *testing.T) {
				err := compileErr(t, func(p *Policy) {
					p.Cosmos.MaxPerTransaction = map[string]uint64{"": 5}
					p.Cosmos.MaxPerDay = map[string]uint64{"": 10}
				})
				if err == nil {
					t.Fatal("a Cosmos policy compiled with an empty denomination in its cap maps")
				}
				if !strings.Contains(err.Error(), "denomination caps are incomplete or inconsistent") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
		{
			file:      "policy.go",
			guard:     `if denom == "" || transactionCap == 0 || !exists || dailyCap < transactionCap {`,
			operand:   "transactionCap == 0",
			direction: "(false && transactionCap == 0)",
			verdict:   verdictCovered,
			why: "A per-transaction cap of zero refuses every transaction in that denomination at " +
				"request time, because validateCosmos compares each coin against it and a coin of zero " +
				"is refused by its own operand. The policy therefore denies a denomination it appears " +
				"to authorise. Both maps are set to zero so the daily-below-transaction operand cannot " +
				"fire and this one is the only thing left.",
			run: func(t *testing.T) {
				err := compileErr(t, func(p *Policy) {
					p.Cosmos.MaxPerTransaction = map[string]uint64{"uatom": 0}
					p.Cosmos.MaxPerDay = map[string]uint64{"uatom": 0}
				})
				if err == nil {
					t.Fatal("a Cosmos policy compiled with a zero per-transaction cap — every " +
						"transaction in that denomination is refused at request time by a policy that " +
						"looks like it authorises them")
				}
				if !strings.Contains(err.Error(), "denomination caps are incomplete or inconsistent") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
		{
			file:      "policy.go",
			guard:     `if denom == "" || transactionCap == 0 || !exists || dailyCap < transactionCap {`,
			operand:   "!exists",
			direction: "(false && !exists)",
			verdict:   verdictMasked,
			why: "Masked by dailyCap < transactionCap, the operand immediately after it. A denom absent " +
				"from MaxPerDay reads back as the zero value, and the preceding operand has already " +
				"ruled out transactionCap == 0, so dailyCap(0) < transactionCap holds for every input " +
				"that reaches this one. Measured: neutralising both together makes " +
				"TestACosmosPolicyWithPerDayDenominationsNotMatchingPerTransactionIsRefused's shape " +
				"compile, and neutralising this one alone changes nothing.",
			run: func(t *testing.T) {
				// The property the masking rests on, checked rather than argued: a missing key in a
				// map[string]uint64 reads as zero, and zero is below every non-zero cap.
				caps := map[string]uint64{"uatom": 1}
				if missing := caps["uosmo"]; missing != 0 {
					t.Fatalf("a missing denomination read back as %d — if it ever stops being zero, "+
						"this operand becomes reachable alone and needs a real detector", missing)
				}
			},
		},
		{
			file:      "policy.go",
			guard:     `if engine == nil || len(engine.policies) == 0 {`,
			operand:   "len(engine.policies) == 0",
			direction: "(false && len(engine.policies) == 0)",
			verdict:   verdictCovered,
			why: "TestAnEngineWithNoPoliciesIsNeverReady covers the NIL engine, which is the sibling " +
				"operand. An engine with a live map holding nothing is a different value and no test " +
				"held one. New refuses to build it, so the fixture is white-box -- the same standing as " +
				"the state.Ready/nil-file row in the #334 ledger, and for the same reason: this " +
				"package's tests can construct it, so the operand is coverable and therefore should be " +
				"covered. Without it an engine enforcing no rules at all answers a readiness probe with " +
				"'ready'.",
			run: func(t *testing.T) {
				engine := &Engine{policies: map[string]compiledPolicy{}, state: &reportingState{ready: true}}
				if engine.Ready(context.Background()) {
					t.Fatal("an engine holding no policies reported itself ready — it authorises " +
						"nothing, so every request it is sent will be denied as an unknown object, and " +
						"the readiness probe says the daemon is fine")
				}
			},
		},
		{
			file:      "policy.go",
			guard:     "if !exists {\n\t\treturn denied(\"unknown-object\")\n\t}",
			operand:   "!exists",
			direction: "(false && !exists)",
			verdict:   verdictCovered,
			why: "TestEvaluateRejectsMismatchesBeforeState's 'unknown object' row asserts only that the " +
				"request was not allowed. Neutralise this and the zero compiledPolicy is used instead: " +
				"every field of it is empty, so the binding-mismatch guard refuses the request a few " +
				"lines later and the row stays green. The refusal survives; the reason does not, and " +
				"the reason is what an operator acts on -- 'binding-mismatch' says the request named " +
				"the wrong purpose or algorithm for a policy that exists, when in fact no policy " +
				"governs the object at all.",
			run: func(t *testing.T) {
				engine, err := New([]Policy{basePolicy()}, &reservationState{}, clock)
				if err != nil {
					t.Fatal(err)
				}
				request := baseRequest(now)
				request.ObjectID = "an-object-no-policy-governs"
				decision := engine.Evaluate(context.Background(), request)
				if decision.Allowed {
					t.Fatalf("a request for an ungoverned object was allowed: %#v", decision)
				}
				if decision.Rule != "unknown-object" {
					t.Fatalf("an ungoverned object was refused as %q — 'binding-mismatch' is what this "+
						"becomes when the lookup guard stops firing, and it sends an operator to "+
						"compare a request against a policy that does not exist", decision.Rule)
				}
			},
		},
		invalidContextRow(now, clock, "request.Principal == \"\"", "principal", func(request *Request) {
			request.Principal = ""
		}),
		invalidContextRow(now, clock, "request.RequestID == \"\"", "request id", func(request *Request) {
			request.RequestID = ""
		}),
		invalidContextRow(now, clock, "!noncePattern.MatchString(request.Nonce)", "nonce", func(request *Request) {
			request.Nonce = "short"
		}),
		{
			file: "policy.go",
			guard: "if request.Purpose != policy.policy.Purpose || request.Environment != policy.policy.Environment ||\n" +
				"\t\trequest.Operation != policy.policy.Operation || request.Algorithm != policy.policy.Algorithm {",
			operand:   "request.Operation != policy.policy.Operation",
			direction: "(false && request.Operation != policy.policy.Operation)",
			verdict:   verdictUnreachable,
			why: "The three siblings are covered by TestEvaluateRejectsMismatchesBeforeState and this one " +
				"cannot be: the policy was fetched by policyKey(request.ObjectID, request.Operation), and " +
				"New stores every policy under policyKey(policy.ObjectID, policy.Operation). A lookup " +
				"that succeeded therefore returns a policy whose Operation IS the request's, by " +
				"construction. The 'wrong operation' row of that test is refused as an unknown object, " +
				"not by this operand.",
			run: func(t *testing.T) {
				// The construction, checked: every key in the map re-derives from the policy it holds.
				wrap := Policy{ID: "sops-wrap", ObjectID: "production-sops", Purpose: "sops-data-key",
					Environment: "production", Operation: "wrap", Algorithm: "rsa2048",
					ContentTypes: []string{"application/vnd.regalia.data-key"}, MaxPayloadBytes: 4096,
					MaxFuture: time.Minute}
				unwrap := wrap
				unwrap.ID, unwrap.Operation = "sops-unwrap", "unwrap"
				engine, err := New([]Policy{wrap, unwrap}, &reservationState{}, clock)
				if err != nil {
					t.Fatal(err)
				}
				if len(engine.policies) != 2 {
					t.Fatalf("the fixture compiled %d policies, want 2", len(engine.policies))
				}
				for key, compiled := range engine.policies {
					if key != policyKey(compiled.policy.ObjectID, compiled.policy.Operation) {
						t.Fatalf("a policy is stored under a key that does not re-derive from it "+
							"(%q vs %q) — the operation operand in Evaluate is then reachable and "+
							"needs a real detector", key, policyKey(compiled.policy.ObjectID, compiled.policy.Operation))
					}
				}
			},
		},
		{
			file:      "policy.go",
			guard:     `if _, ok := policy.contentTypes[request.ContentType]; !ok || request.PayloadBytes < 0 || request.PayloadBytes > policy.policy.MaxPayloadBytes {`,
			operand:   "request.PayloadBytes < 0",
			direction: "(false && request.PayloadBytes < 0)",
			verdict:   verdictCovered,
			why: "The upper bound has a detector ('oversized' in TestEvaluateRejectsMismatchesBeforeState) " +
				"and the lower one did not -- a bound named on one side only. PayloadBytes is an int64 " +
				"the caller supplies, and a negative one passes the upper comparison unchallenged: it " +
				"is not greater than the cap. The request is then authorised and the size recorded in " +
				"the audit trail is a number no payload can have.",
			run: func(t *testing.T) {
				state := &reservationState{}
				engine, err := New([]Policy{basePolicy()}, state, clock)
				if err != nil {
					t.Fatal(err)
				}
				request := baseRequest(now)
				request.PayloadBytes = -1
				decision := engine.Evaluate(context.Background(), request)
				if decision.Allowed {
					t.Fatalf("a request declaring %d payload bytes was allowed: %#v",
						request.PayloadBytes, decision)
				}
				if decision.Rule != "content" {
					t.Fatalf("a negative payload size was refused as %q, want the content rule", decision.Rule)
				}
				if len(state.reservations) != 0 {
					t.Fatal("a negative payload size reached the durable state")
				}
			},
		},
		{
			file:      "policy.go",
			guard:     "} else if request.Cosmos != nil {",
			operand:   "request.Cosmos != nil",
			direction: "(false && request.Cosmos != nil)",
			verdict:   verdictCovered,
			why: "Nothing sent Cosmos domain data to a policy that has no Cosmos section. Without this " +
				"branch such a request is ALLOWED and the transaction is neither checked nor recorded: " +
				"no chain allowlist, no destination allowlist, no spend cap, and an empty amounts map " +
				"in the reservation, so the daily quota sees a signing operation that spent nothing. " +
				"The operation still signs whatever bytes it was given.",
			run: func(t *testing.T) {
				plain := Policy{ID: "sops-wrap", ObjectID: "production-sops", Purpose: "sops-data-key",
					Environment: "production", Operation: "wrap", Algorithm: "rsa2048",
					ContentTypes: []string{"application/vnd.regalia.data-key"}, MaxPayloadBytes: 4096,
					MaxFuture: time.Minute}
				state := &reservationState{}
				engine, err := New([]Policy{plain}, state, clock)
				if err != nil {
					t.Fatal(err)
				}
				request := Request{RequestID: "018f0000-0000-7000-8000-000000000001",
					Principal: "spiffe://regalia/workload/sops", ObjectID: "production-sops",
					Purpose: "sops-data-key", Environment: "production", Operation: "wrap",
					Algorithm: "rsa2048", ContentType: "application/vnd.regalia.data-key",
					PayloadBytes: 32, ExpiresAt: now.Add(time.Minute), Nonce: "nonce_0123456789abcdef",
					Cosmos: &CosmosTransaction{ChainID: "cosmoshub-4", AccountNumber: 42,
						Messages: []CosmosMessage{{Type: "/cosmos.bank.v1beta1.MsgSend", Source: "cosmos1source",
							Destination: "cosmos1attacker", Amounts: []Coin{{Denom: "uatom", Amount: 1}}}}}}
				decision := engine.Evaluate(context.Background(), request)
				if decision.Allowed {
					t.Fatalf("a request carrying a Cosmos transaction was allowed by a policy with no "+
						"Cosmos section (%#v) — no chain, destination or spend rule was applied to it, "+
						"and the reservation records no amounts at all", decision)
				}
				if decision.Rule != "unexpected-domain-data" {
					t.Fatalf("refused as %q, want unexpected-domain-data", decision.Rule)
				}
			},
		},
		{
			file:      "policy.go",
			guard:     "if policy.policy.RequiredApprovals == 0 {",
			operand:   "policy.policy.RequiredApprovals == 0",
			direction: "(false && policy.policy.RequiredApprovals == 0)",
			verdict:   verdictUndetectable,
			why: "Behaviour-equivalent, not merely hard to reach. The early return says true; the " +
				"fallthrough returns len(seen) >= RequiredApprovals, which for RequiredApprovals == 0 " +
				"is len(seen) >= 0 and therefore true for every input. The two paths agree on every " +
				"value this function can be called with, so no test can distinguish them and any test " +
				"claiming to would be asserting something else. Recorded rather than left as an " +
				"unexplained survivor.",
			run: func(t *testing.T) {
				// The derivation, checked: the fallthrough's comparison is true for every count.
				for _, seen := range []int{0, 1, 7} {
					if !(seen >= 0) {
						t.Fatalf("len(seen)=%d is not >= 0 — the two paths of this guard can disagree "+
							"after all, and the operand becomes detectable", seen)
					}
				}
				compiled := compiledPolicy{approvers: map[string]struct{}{"a": {}}}
				for _, values := range [][]string{nil, {"someone-else"}, {"a"}} {
					if !compiled.approvalsSatisfied(values) {
						t.Fatalf("approvalsSatisfied(%v) = false for a policy requiring zero approvals", values)
					}
				}
			},
		},
		{
			file:      "policy.go",
			guard:     "if _, allowed := policy.approvers[value]; allowed {",
			operand:   "allowed",
			direction: "(true || allowed)",
			verdict:   verdictCovered,
			why: "The approval threshold was tested by removing the approvers entirely ('missing " +
				"approval'), which counts zero either way. Nothing ever presented a principal who is " +
				"NOT on the allowlist. Widen this operand and the allowlist stops being consulted: any " +
				"name in VerifiedApprovers counts toward the threshold, so a caller supplies its own " +
				"approvers and satisfies a two-of-three policy by naming itself twice.",
			run: func(t *testing.T) {
				state := &reservationState{}
				engine, err := New([]Policy{basePolicy()}, state, clock)
				if err != nil {
					t.Fatal(err)
				}
				request := baseRequest(now)
				request.VerifiedApprovers = []string{"spiffe://regalia/workload/tx-signer"}
				decision := engine.Evaluate(context.Background(), request)
				if decision.Allowed {
					t.Fatalf("a principal who is not on the approver allowlist satisfied the approval "+
						"threshold (%#v) — the requester approved its own request", decision)
				}
				if decision.Rule != "approval" {
					t.Fatalf("refused as %q, want the approval rule", decision.Rule)
				}
				// The control: the real approver must still satisfy it, or this row is equally
				// consistent with an engine that approves nobody.
				request.VerifiedApprovers = []string{"spiffe://regalia/approver/treasury"}
				if decision := engine.Evaluate(context.Background(), request); !decision.Allowed {
					t.Fatalf("the allowlisted approver was refused (%#v) — the assertion above would "+
						"pass against an engine that satisfies no threshold at all", decision)
				}
			},
		},
		{
			file:      "policy.go",
			guard:     "if transaction == nil || len(transaction.Messages) == 0 {",
			operand:   "transaction == nil",
			direction: "(false && transaction == nil)",
			verdict:   verdictCovered,
			why: "The only thing between a Cosmos policy handed no transaction and a nil-pointer " +
				"dereference inside Evaluate. The sibling operand reads transaction.Messages, so " +
				"removing this one does not admit a bad request -- it panics on the request path, " +
				"upstream of anything that could turn the panic into a refusal with an audit record. " +
				"Every existing Cosmos test attaches a transaction, so nothing had ever called this " +
				"function with nil.",
			run: func(t *testing.T) {
				state := &reservationState{}
				engine, err := New([]Policy{basePolicy()}, state, clock)
				if err != nil {
					t.Fatal(err)
				}
				request := baseRequest(now)
				request.Cosmos = nil
				decision := engine.Evaluate(context.Background(), request)
				if decision.Allowed {
					t.Fatalf("a Cosmos policy allowed a request carrying no transaction: %#v", decision)
				}
				if decision.Rule != "cosmos" {
					t.Fatalf("refused as %q, want the cosmos rule", decision.Rule)
				}
			},
		},
		{
			file:      "policy.go",
			guard:     "if transaction == nil || len(transaction.Messages) == 0 {",
			operand:   "len(transaction.Messages) == 0",
			direction: "(false && len(transaction.Messages) == 0)",
			verdict:   verdictCovered,
			why: "A transaction with no messages walks the loop zero times and returns an empty total " +
				"set with valid = true, so it is ALLOWED. Every spend rule this function enforces is " +
				"inside that loop, which means a transaction that carries nothing to check passes all " +
				"of them.",
			run: func(t *testing.T) {
				state := &reservationState{}
				engine, err := New([]Policy{basePolicy()}, state, clock)
				if err != nil {
					t.Fatal(err)
				}
				request := baseRequest(now)
				request.Cosmos = &CosmosTransaction{ChainID: "cosmoshub-4", AccountNumber: 42}
				decision := engine.Evaluate(context.Background(), request)
				if decision.Allowed {
					t.Fatalf("a Cosmos transaction carrying no messages was allowed (%#v) — every rule "+
						"this policy enforces lives inside the per-message loop, so an empty one "+
						"satisfies all of them", decision)
				}
				if decision.Rule != "cosmos" {
					t.Fatalf("refused as %q, want the cosmos rule", decision.Rule)
				}
			},
		},
		{
			file:      "policy.go",
			guard:     "if _, ok := policy.messages[message.Type]; !ok || len(message.Amounts) == 0 {",
			operand:   "len(message.Amounts) == 0",
			direction: "(false && len(message.Amounts) == 0)",
			verdict:   verdictCovered,
			why: "The message-type sibling is covered by TestCosmosPolicyRejectsEveryControlledDimension; " +
				"a message of an allowed type carrying no coins was never presented. Such a message " +
				"contributes nothing to the totals and passes, so a transaction can name an allowed " +
				"MsgSend to an allowed destination and move an amount the cap logic never sees. The " +
				"wire decoder refuses it one layer up, which is why this is defence in depth -- and " +
				"defence in depth with no test is a line the next edit deletes as redundant.",
			run: func(t *testing.T) {
				state := &reservationState{}
				engine, err := New([]Policy{basePolicy()}, state, clock)
				if err != nil {
					t.Fatal(err)
				}
				request := baseRequest(now)
				request.Cosmos.Messages = []CosmosMessage{{Type: "/cosmos.bank.v1beta1.MsgSend", Source: "cosmos1source",
					Destination: "cosmos1destination"}}
				decision := engine.Evaluate(context.Background(), request)
				if decision.Allowed {
					t.Fatalf("a MsgSend carrying no coins was allowed (%#v)", decision)
				}
				if decision.Rule != "cosmos" {
					t.Fatalf("refused as %q, want the cosmos rule", decision.Rule)
				}
			},
		},
		{
			file:      "policy.go",
			guard:     "if !known || coin.Amount == 0 || coin.Amount > maximum || ^uint64(0)-totals[coin.Denom] < coin.Amount {",
			operand:   "!known",
			direction: "(false && !known)",
			verdict:   verdictMasked,
			why: "Masked twice over. An unknown denomination reads its cap back as zero, so " +
				"coin.Amount > maximum refuses every non-zero coin and coin.Amount == 0 refuses the " +
				"rest; and if BOTH of those were also gone, totals > maximum below the loop refuses it. " +
				"No coin exists that only this operand objects to. What it buys is the fail-fast, not " +
				"the refusal.",
		},
		{
			file:      "policy.go",
			guard:     "if !known || coin.Amount == 0 || coin.Amount > maximum || ^uint64(0)-totals[coin.Denom] < coin.Amount {",
			operand:   "coin.Amount == 0",
			direction: "(false && coin.Amount == 0)",
			verdict:   verdictCovered,
			why: "A zero-amount coin is still refused without this operand, but by validateReservation " +
				"in the state layer, because the reservation then carries an amount of zero. That turns " +
				"a policy DENIAL into a durable-state failure: operations maps CodeStateUnavailable to " +
				"DEPENDENCY_UNAVAILABLE, HTTP 503 and retryable=true, so a malformed transaction is " +
				"answered with an invitation to send it again and the audit reason names infrastructure " +
				"trouble on a host whose infrastructure is fine. Same shape as the ErrReplay join.",
			run: func(t *testing.T) {
				state := &reservationState{}
				engine, err := New([]Policy{basePolicy()}, state, clock)
				if err != nil {
					t.Fatal(err)
				}
				request := baseRequest(now)
				request.Cosmos.Messages[0].Amounts = []Coin{{Denom: "uatom", Amount: 0}}
				decision := engine.Evaluate(context.Background(), request)
				if decision.Allowed {
					t.Fatalf("a coin of zero was allowed: %#v", decision)
				}
				if decision.Code != CodeDenied || decision.Rule != "cosmos" {
					t.Fatalf("a zero-amount coin came back as code %q rule %q, want %q / cosmos. "+
						"CodeStateUnavailable is what this becomes when the amount reaches the "+
						"reservation instead of being refused here, and it is a 503 the caller is "+
						"told to retry", decision.Code, decision.Rule, CodeDenied)
				}
			},
		},
		{
			file:      "policy.go",
			guard:     "if !known || coin.Amount == 0 || coin.Amount > maximum || ^uint64(0)-totals[coin.Denom] < coin.Amount {",
			operand:   "coin.Amount > maximum",
			direction: "(false && coin.Amount > maximum)",
			verdict:   verdictMasked,
			why: "Masked by the totals check below the loop. totals is the running sum for the " +
				"denomination and the coin has just been added to it, so coin.Amount > maximum implies " +
				"totals >= coin.Amount > maximum: the guard after the accumulation refuses every coin " +
				"this one would have. Measured by neutralising the pair together, which makes " +
				"TestCosmosPolicyRejectsEveryControlledDimension's 'transaction limit' row fail.",
		},
		{
			file:      "policy.go",
			guard:     "if !known || coin.Amount == 0 || coin.Amount > maximum || ^uint64(0)-totals[coin.Denom] < coin.Amount {",
			operand:   "^uint64(0)-totals[coin.Denom] < coin.Amount",
			direction: "(false && ^uint64(0)-totals[coin.Denom] < coin.Amount)",
			verdict:   verdictCovered,
			why: "The overflow operand, and the fixture that reaches it needs a cap large enough that " +
				"the per-coin comparison does not refuse first -- which is why no existing test did. " +
				"MaxPerTransaction is a uint64, so a policy may legitimately declare the largest one. " +
				"Two coins of 2^63 then wrap the running total to zero, the totals check compares zero " +
				"against the cap and is satisfied, and the transaction is authorised with a reservation " +
				"that records a spend of nothing. That is #198's silent-truncation shape at the policy " +
				"layer instead of the wire.",
			run: func(t *testing.T) {
				policy := basePolicy()
				policy.Cosmos.MaxPerTransaction = map[string]uint64{"uatom": math.MaxUint64}
				policy.Cosmos.MaxPerDay = map[string]uint64{"uatom": math.MaxUint64}
				state := &reservationState{}
				engine, err := New([]Policy{policy}, state, clock)
				if err != nil {
					t.Fatal(err)
				}
				request := baseRequest(now)
				request.Cosmos.Messages[0].Amounts = []Coin{
					{Denom: "uatom", Amount: 1 << 63}, {Denom: "uatom", Amount: 1 << 63}}
				decision := engine.Evaluate(context.Background(), request)
				if decision.Allowed {
					t.Fatalf("two coins summing past 2^64 were allowed: %#v", decision)
				}
				if decision.Code != CodeDenied || decision.Rule != "cosmos" {
					t.Fatalf("an overflowing sum came back as code %q rule %q, want %q / cosmos — "+
						"without the overflow operand the total wraps to zero, every later comparison "+
						"is satisfied, and the refusal that does happen comes from the reservation "+
						"validator complaining about an amount of zero", decision.Code, decision.Rule, CodeDenied)
				}
				if len(state.reservations) != 0 {
					t.Fatalf("a reservation was made for an overflowing transaction: %#v", state.reservations)
				}
			},
		},
		{
			file:      "policy.go",
			guard:     "if totals[coin.Denom] > maximum {",
			operand:   "totals[coin.Denom] > maximum",
			direction: "(false && totals[coin.Denom] > maximum)",
			verdict:   verdictCovered,
			why: "The per-transaction cap is enforced across ALL coins of a denomination in a message, " +
				"and every fixture in this package carried exactly one coin -- so the accumulation was " +
				"never exercised and the per-coin comparison answered every case. Two coins each under " +
				"the cap and summing over it are then authorised, and the reservation records the full " +
				"sum against a daily cap that happily accommodates it.",
			run: func(t *testing.T) {
				state := &reservationState{}
				engine, err := New([]Policy{basePolicy()}, state, clock)
				if err != nil {
					t.Fatal(err)
				}
				request := baseRequest(now)
				request.Cosmos.Messages[0].Amounts = []Coin{
					{Denom: "uatom", Amount: 600_000}, {Denom: "uatom", Amount: 600_000}}
				decision := engine.Evaluate(context.Background(), request)
				if decision.Allowed {
					t.Fatalf("two coins of 600000 uatom were allowed against a 1000000 per-transaction "+
						"cap (%#v) — the cap is per transaction, and splitting a payment across coins "+
						"is the obvious way to exceed one", decision)
				}
				if decision.Rule != "cosmos" {
					t.Fatalf("refused as %q, want the cosmos rule", decision.Rule)
				}
				// The control: two coins that DO fit must still be allowed, or this row is
				// consistent with a validator that refuses every multi-coin message.
				request.Nonce = "nonce_0123456789abcdee"
				request.Cosmos.Messages[0].Amounts = []Coin{
					{Denom: "uatom", Amount: 400_000}, {Denom: "uatom", Amount: 400_000}}
				if decision := engine.Evaluate(context.Background(), request); !decision.Allowed {
					t.Fatalf("two coins summing to 800000 under a 1000000 cap were refused (%#v)", decision)
				}
			},
		},
		{
			file:      "policy.go",
			guard:     `if value == "" || value == "*" {`,
			operand:   `value == ""`,
			direction: `(false && value == "")`,
			verdict:   verdictCovered,
			why: "The dimension guard's message promises 'must not contain duplicates or wildcards' and " +
				"only duplicates were ever tested. This operand is half of what makes the wildcard " +
				"clause true: an empty entry is dropped from the set, the length comparison notices, " +
				"and the policy is refused. Without it the empty string becomes an allowed value in " +
				"every dimension -- so a transaction whose destination is empty matches an allowlist " +
				"the operator wrote to be exhaustive.",
			run: func(t *testing.T) {
				err := compileErr(t, func(p *Policy) {
					p.Cosmos.Destinations = []string{"cosmos1destination", ""}
				})
				if err == nil {
					t.Fatal("a Cosmos policy compiled with an empty destination in its allowlist — the " +
						"empty string then matches, and the refusal message already claims wildcards " +
						"are rejected")
				}
				if !strings.Contains(err.Error(), "must not contain duplicates or wildcards") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
		{
			file:      "policy.go",
			guard:     `if value == "" || value == "*" {`,
			operand:   `value == "*"`,
			direction: `(false && value == "*")`,
			verdict:   verdictCovered,
			why: "The other half. A '*' in a dimension list is what an operator writes when they mean " +
				"'any', and this package's answer is to refuse the policy rather than to honour or " +
				"silently ignore it. Without the operand the star is kept as a literal, so the policy " +
				"compiles and matches exactly one destination: the string '*'. The operator believes " +
				"they authorised everything; the engine authorised nothing that exists.",
			run: func(t *testing.T) {
				err := compileErr(t, func(p *Policy) {
					p.Cosmos.Destinations = []string{"cosmos1destination", "*"}
				})
				if err == nil {
					t.Fatal("a Cosmos policy compiled with a '*' destination — a wildcard is either " +
						"honoured or refused, and being kept as a literal is neither")
				}
				if !strings.Contains(err.Error(), "must not contain duplicates or wildcards") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
	}
}

// invalidContextRow builds one of the three rows for Evaluate's invalid-context guard. They share
// a consequence and differ only in which field is emptied, and writing them out three times would
// have made the differences hard to see rather than easy.
func invalidContextRow(now time.Time, clock func() time.Time, operand, field string, mutate func(*Request)) operandLeaf {
	return operandLeaf{
		file:      "policy.go",
		guard:     `if request.Principal == "" || request.RequestID == "" || !noncePattern.MatchString(request.Nonce) {`,
		operand:   operand,
		direction: "(false && " + operand + ")",
		verdict:   verdictCovered,
		why: "None of the three operands of this guard had a detector: TestEvaluateRejectsMismatchesBeforeState " +
			"walks purpose, environment, operation, algorithm, content, size, freshness and approvals " +
			"and never touches the request's own identity. Two of the three are then refused DOWNSTREAM " +
			"by validateReservation, which turns a 400-shaped denial into CodeStateUnavailable -- a 503 " +
			"the caller is told to retry, with an audit reason naming a durable-state failure. The third, " +
			"the request id, is not carried in the reservation at all, so removing its operand ALLOWS a " +
			"request that nothing can be correlated with.",
		run: func(t *testing.T) {
			state := &reservationState{}
			engine, err := New([]Policy{basePolicy()}, state, clock)
			if err != nil {
				t.Fatal(err)
			}
			request := baseRequest(now)
			mutate(&request)
			decision := engine.Evaluate(context.Background(), request)
			if decision.Allowed {
				t.Fatalf("a request with no valid %s was allowed: %#v", field, decision)
			}
			if decision.Code != CodeDenied || decision.Rule != "invalid-context" {
				t.Fatalf("a request with no valid %s came back as code %q rule %q, want %q / "+
					"invalid-context — CodeStateUnavailable is what this becomes when the check moves "+
					"to the reservation validator, and operations answers that with HTTP 503 and "+
					"retryable=true", field, decision.Code, decision.Rule, CodeDenied)
			}
			if len(state.reservations) != 0 {
				t.Fatalf("a request with no valid %s reached the durable state", field)
			}
		},
	}
}

// ---------------------------------------------------------------------------------------------
// state.go
// ---------------------------------------------------------------------------------------------

// forgedAmounts is chained() with the amount and cap under the row's control, which is what the
// two apply() rows need: the journal must be internally valid -- correctly chained, and carrying
// reservations validateReservation accepts -- so that the only thing left to object is the replay
// or the overflow inside apply.
func forgedAmounts(sequence uint64, previous, nonce string, amount, cap uint64) stateEvent {
	event := stateEvent{
		Sequence: sequence,
		Reservation: Reservation{
			PolicyID: "cosmos-hot-wallet", ObjectID: "production-wallet-signer",
			Principal: "spiffe://regalia/workload/tx-signer", Nonce: nonce, UTCDate: "2026-09-04",
			Amounts: map[string]uint64{"uatom": amount}, DailyCaps: map[string]uint64{"uatom": cap},
		},
		PreviousHash: previous,
	}
	event.Hash = stateEventHash(event)
	return event
}

func stateOperandRows() []operandLeaf {
	return []operandLeaf{
		{
			file:      "state.go",
			guard:     "if err := replay.apply(event.Reservation); err != nil {",
			operand:   "err != nil",
			direction: "(false && err != nil)",
			verdict:   verdictCovered,
			why: "VerifyState replays every reservation and this is where the replay's own objection " +
				"surfaces. Nothing forged a journal that is correctly chained and still impossible, so " +
				"the branch had never fired. The fixture here overflows the running total: two " +
				"reservations of 2^63 in one denomination, each individually valid against a cap of " +
				"MaxUint64. Without the guard the error is dropped and the summary reports a clean " +
				"journal whose recorded spend has wrapped to a smaller number than was actually spent.",
			run: func(t *testing.T) {
				first := forgedAmounts(1, stateGenesisHash, "nonce_000000000001", 1<<63, math.MaxUint64)
				second := forgedAmounts(2, first.Hash, "nonce_000000000002", 1<<63, math.MaxUint64)
				path := forgedJournal(t, first, second)
				if _, err := VerifyState(path); err == nil {
					t.Fatal("a journal whose reservations overflow the quota total verified clean — " +
						"the total wraps to a smaller number than was spent, so the difference becomes " +
						"available again")
				} else if !strings.Contains(err.Error(), "invalid reservation") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
		{
			file:      "state.go",
			guard:     "if err := state.apply(event.Reservation); err != nil {",
			operand:   "err != nil",
			direction: "(false && err != nil)",
			verdict:   verdictCovered,
			why: "The OpenFileState twin, with the other apply failure so that neither row can stand in " +
				"for the other: a journal naming one nonce twice. Each line is well formed, correctly " +
				"chained and accepted by the reservation validator, so the hash chain has nothing to " +
				"say about it. Without the guard the journal OPENS, the duplicate is folded into the " +
				"nonce set once, and the service starts having silently accepted a record it would " +
				"never have written.",
			run: func(t *testing.T) {
				first := forgedAmounts(1, stateGenesisHash, "nonce_000000000001", 10, 100)
				second := forgedAmounts(2, first.Hash, "nonce_000000000001", 10, 100)
				path := forgedJournal(t, first, second)
				state, err := OpenFileState(path)
				if err == nil {
					_ = state.Close()
					t.Fatal("a journal recording one nonce twice opened for writing — the replay " +
						"record it is supposed to be is self-contradictory and nothing said so")
				}
				if !strings.Contains(err.Error(), "invalid reservation") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
		{
			file: "state.go",
			guard: "if _, exists := state.nonces[nonce]; exists {\n\t\treturn ErrReplay\n\t}\n" +
				"\tfor denom, amount := range reservation.Amounts {\n\t\tkey := quotaKey(reservation, denom)",
			operand:   "exists",
			direction: "(false && exists)",
			verdict:   verdictPinnedElsewhere,
			why: "apply()'s own replay check. Inside Reserve it is masked -- the identical check runs " +
				"before the quota loop -- but on the replay path it is the only thing that notices a " +
				"journal naming one nonce twice, and the OpenFileState row above is what fails when it " +
				"stops firing. It can never be the sole failure, because it is the mechanism that row " +
				"depends on.",
		},
		{
			file:      "state.go",
			guard:     "if ^uint64(0)-state.totals[key] < amount {",
			operand:   "^uint64(0)-state.totals[key] < amount",
			direction: "(false && ^uint64(0)-state.totals[key] < amount)",
			verdict:   verdictPinnedElsewhere,
			why: "apply()'s overflow check, and the VerifyState row above is what fails when it stops " +
				"firing. Unreachable from Reserve, whose own cap comparison bounds the sum; reachable " +
				"from the replay path, where the amounts come from the file rather than from a policy.",
		},
		{
			file:      "state.go",
			guard:     "case errors.Is(statErr, os.ErrNotExist):",
			operand:   "errors.Is(statErr, os.ErrNotExist)",
			direction: "(true || errors.Is(statErr, os.ErrNotExist))",
			verdict:   verdictUndetectable,
			why: "Widening this clause makes the switch's default arm unreachable, and the #334 ledger " +
				"already establishes -- by measurement, not argument -- that the default is unreachable " +
				"anyway: readHighWater reads the same path four lines earlier and returns on any error " +
				"that is not ErrNotExist. So the mutation removes an arm nothing can reach, and no input " +
				"distinguishes the two versions.",
		},
		{
			file:      "state.go",
			guard:     "if len(events) >= 1 && markFileExists && mark.Sequence == 0 {",
			operand:   "len(events) >= 1",
			direction: "(true || len(events) >= 1)",
			verdict:   verdictUndetectable,
			why: "Widening it refuses an EMPTY journal that has a present mark sitting at genesis. No " +
				"writer produces that state -- the mark is only ever written by Reserve, after an " +
				"append, with the appended event's sequence -- so the only input that distinguishes " +
				"the two versions is a forged one whose refusal would be an improvement. Pinning it " +
				"would pin a gap.",
		},
		verifyStateRewriteRow("replay.sequence == mark.Sequence", true),
		verifyStateRewriteRow("mark.Hash != stateGenesisHash", false),
		verifyStateRewriteRow("replay.lastHash != mark.Hash", false),
		{
			file:      "state.go",
			guard:     "if replay.sequence == mark.Sequence && mark.Hash != stateGenesisHash && replay.lastHash != mark.Hash {",
			operand:   "mark.Hash != stateGenesisHash",
			direction: "(true || mark.Hash != stateGenesisHash)",
			verdict:   verdictUndetectable,
			why: "The widening direction, already classified undetectable in the #334 ledger and " +
				"re-measured here with the same result: the only inputs that distinguish it are forged " +
				"marks whose refusal would be an improvement.",
		},
		{
			file:      "state.go",
			guard:     "if state.sequence == mark.Sequence && mark.Hash != stateGenesisHash && state.lastHash != mark.Hash {",
			operand:   "state.sequence == mark.Sequence",
			direction: "(true || state.sequence == mark.Sequence)",
			verdict:   verdictCovered,
			why: "This operand is what keeps the write order's own crash window openable. Reserve " +
				"appends, fsyncs, and only then writes the mark, deliberately so that a crash leaves the " +
				"mark BEHIND the journal rather than ahead of it. Widen the operand and that state -- a " +
				"journal one event past its mark, with a different head hash because it advanced -- is " +
				"refused on the next open. The service then fails to start because of a fault that did " +
				"not happen, which is the outage the ordering was chosen to avoid. " +
				"TestAFailedAppendLeavesTheHighWaterMarkBehindTheJournal creates the state and never " +
				"reopens it.",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "policy-state.jsonl")
				state, err := OpenFileState(path)
				if err != nil {
					t.Fatal(err)
				}
				for _, nonce := range []string{"nonce_000000000001", "nonce_000000000002"} {
					if err := state.Reserve(context.Background(), reservation(nonce, "2026-09-04", 10, 100)); err != nil {
						t.Fatalf("reserve %s: %v", nonce, err)
					}
				}
				if err := state.Close(); err != nil {
					t.Fatal(err)
				}
				// Rewind the mark to where a crash between the second append and its mark write
				// would have left it: at the FIRST event, with the first event's hash.
				events, err := readState(path)
				if err != nil || len(events) != 2 {
					t.Fatalf("readState(%s) = %d events, %v — the fixture is not in the state this row "+
						"reasons about", path, len(events), err)
				}
				if err := writeHighWater(path, highWaterMark{Sequence: events[0].Sequence, Hash: events[0].Hash}); err != nil {
					t.Fatal(err)
				}
				reopened, err := OpenFileState(path)
				if err != nil {
					t.Fatalf("a journal one append ahead of its mark was refused (%v) — that is the "+
						"state the append-fsync-then-mark order deliberately creates, so refusing it "+
						"turns every crash in that window into a daemon that will not start", err)
				}
				_ = reopened.Close()
			},
		},
		{
			file:      "state.go",
			guard:     "if state.sequence == mark.Sequence && mark.Hash != stateGenesisHash && state.lastHash != mark.Hash {",
			operand:   "mark.Hash != stateGenesisHash",
			direction: "(true || mark.Hash != stateGenesisHash)",
			verdict:   verdictUndetectable,
			why: "The OpenFileState twin of the VerifyState row above, undetectable for the same reason: " +
				"a mark whose recorded hash is genesis while its sequence matches the journal's head is " +
				"a forgery, and refusing it would be an improvement rather than a regression.",
		},
		{
			file:      "state.go",
			guard:     "if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {",
			operand:   "!info.Mode().IsRegular()",
			direction: "(false && !info.Mode().IsRegular())",
			verdict:   verdictMasked,
			why: "Masked by readState, which OpenFileState calls first and which refuses a non-regular " +
				"journal with its own message -- that operand is covered by the #334 ledger's " +
				"state.readState/stat row. Every fixture that reaches this one has already been refused. " +
				"The permission-bits sibling on the same line IS reachable and is covered by " +
				"file_mode_test.go.",
		},
		{
			file:      "state.go",
			guard:     "if err := validateReservation(reservation); err != nil {\n\t\treturn err\n\t}\n\tif err := ctx.Err(); err != nil {",
			operand:   "err != nil",
			direction: "(false && err != nil)",
			verdict:   verdictMasked,
			why: "The first of two context checks; the second runs after the mutex is taken and refuses " +
				"the same input. Neither can be the sole refuser while the other stands. They are not " +
				"redundant -- the first declines the work before contending for the lock, the second " +
				"closes the window between the two -- but no fixture separates them, and neutralising " +
				"BOTH is what makes TestACancelledContextReservesNothing fail.",
		},
		{
			file:      "state.go",
			guard:     "if state.failed {\n\t\treturn errors.New(\"policy state unavailable\")\n\t}\n\tif err := ctx.Err(); err != nil {",
			operand:   "err != nil",
			direction: "(false && err != nil)",
			verdict:   verdictMasked,
			why: "The second of the two context checks, masked by the first for the same reason and in " +
				"the same measurement.",
		},
		{
			file:      "state.go",
			guard:     "if state.closed {\n\t\treturn errors.New(\"policy state unavailable\")\n\t}",
			operand:   "state.closed",
			direction: "(false && state.closed)",
			verdict:   verdictMasked,
			why: "Masked by the journal handle itself. closed is only ever set by Close, which closes " +
				"the descriptor, so a reservation that gets past this guard fails at the append with " +
				"'file already closed' and latches the state failed. The refusal survives; only its " +
				"sentence changes, and TestAClosedStateRefusesEverything asserts neither.",
		},
		{
			file:      "state.go",
			guard:     "if state.failed {",
			operand:   "state.failed",
			direction: "(false && state.failed)",
			verdict:   verdictCovered,
			why: "The latch is tested through the write path, where the descriptor is broken and would " +
				"refuse the next append anyway -- so the guard itself was never the reason. The path " +
				"where it IS the only reason is the high-water mark: the append lands, the mark write " +
				"fails, and the journal is now permanently ahead of a mark that will never catch up. " +
				"This row injects that fault, REMOVES it, and then attempts a second reservation: the " +
				"descriptor is fine and the sidecar is writable, so nothing but the latch can refuse.",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "policy-state.jsonl")
				state, err := OpenFileState(path)
				if err != nil {
					t.Fatal(err)
				}
				defer state.Close()
				temporary := path + highWaterSuffix + ".tmp"
				directoryAt(t, temporary)
				if err := state.Reserve(context.Background(), reservation("nonce_000000000001", "2026-09-04", 10, 100)); err == nil {
					t.Fatal("a reservation succeeded while its mark could not be written")
				}
				if !state.failed {
					t.Fatal("the state did not latch failed after the mark write failed, so this row " +
						"is about to test the wrong thing")
				}
				// Clear the fault. From here the journal handle is open and the sidecar path is
				// writable, so the ONLY thing that can refuse the next reservation is the latch.
				if err := os.RemoveAll(temporary); err != nil {
					t.Fatal(err)
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := state.Reserve(context.Background(), reservation("nonce_000000000002", "2026-09-04", 10, 100)); err == nil {
					t.Fatal("a reservation was accepted after the mark write had failed and the fault " +
						"was cleared — the journal is ahead of its mark, so this append widens a gap " +
						"that makes the next truncation undetectable")
				}
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before, after) {
					t.Fatalf("the journal grew by %d bytes after the state had latched failed",
						len(after)-len(before))
				}
			},
		},
		{
			file:      "state.go",
			guard:     "if cap == 0 || amount > cap || current > cap-amount {",
			operand:   "cap == 0",
			direction: "(false && cap == 0)",
			verdict:   verdictUnreachable,
			why: "validateReservation runs at the top of Reserve and refuses any denomination whose " +
				"DailyCaps entry is zero, so cap is non-zero by the time this line runs. The guard reads " +
				"like the quota check and only its third operand does quota work.",
			run: func(t *testing.T) { requireValidatorRefusesAheadOfTheQuotaGuard(t) },
		},
		{
			file:      "state.go",
			guard:     "if cap == 0 || amount > cap || current > cap-amount {",
			operand:   "amount > cap",
			direction: "(false && amount > cap)",
			verdict:   verdictUnreachable,
			why: "Same reason as its neighbour: validateReservation already refuses a reservation whose " +
				"amount exceeds its own daily cap, and it runs first. The property is checked by the " +
				"same helper.",
			run: func(t *testing.T) { requireValidatorRefusesAheadOfTheQuotaGuard(t) },
		},
		{
			file:      "state.go",
			guard:     "if _, err := state.file.Write(append(encoded, '\\n')); err != nil {",
			operand:   "err != nil",
			direction: "(false && err != nil)",
			verdict:   verdictMasked,
			why: "Masked by the fsync that follows it. The only write fault this package can inject is a " +
				"severed descriptor, and a severed descriptor fails the Sync as well, which reports and " +
				"latches identically. Isolating this operand needs a fault where the write fails and the " +
				"sync succeeds, which the filesystem does not offer.",
		},
		{
			file:      "state.go",
			guard:     "if err := state.file.Sync(); err != nil {",
			operand:   "err != nil",
			direction: "(false && err != nil)",
			verdict:   verdictMasked,
			why:       "The other half of that pair, masked by the write above it under every inducible fault.",
		},
		{
			file:      "state.go",
			guard:     "if err := state.apply(reservation); err != nil {",
			operand:   "err != nil",
			direction: "(false && err != nil)",
			verdict:   verdictUnreachable,
			why: "apply can fail two ways and Reserve has ruled out both before it gets here: the nonce " +
				"was checked against the same map a few lines up, and the quota loop bounded the sum by " +
				"the daily cap, so the addition cannot overflow. It is the post-commit apply, run after " +
				"the append is durable, and by then there is nothing left for it to object to.",
		},
		readyRow("!state.closed", true),
		readyRow("!state.failed", false),
		readyRow("state.file != nil", false),
		{
			file:      "state.go",
			guard:     "if state.closed {\n\t\treturn nil\n\t}",
			operand:   "state.closed",
			direction: "(false && state.closed)",
			verdict:   verdictCovered,
			why: "Close is idempotent and nothing said so. Several tests close a state and then let a " +
				"deferred Close run again, but every one of them discards the second error, so the " +
				"guard could be deleted and the suite would stay green while Close started reporting " +
				"'file already closed' to a shutdown path that has nowhere to put it.",
			run: func(t *testing.T) {
				state, err := OpenFileState(filepath.Join(t.TempDir(), "policy-state.jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				if err := state.Close(); err != nil {
					t.Fatalf("the first Close failed: %v", err)
				}
				if err := state.Close(); err != nil {
					t.Fatalf("the second Close returned %v — Close is called from shutdown paths that "+
						"cannot distinguish 'already closed' from a real failure, and every test in "+
						"this package that double-closes discards the error", err)
				}
			},
		},
		{
			file:      "state.go",
			guard:     "if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {",
			operand:   "!errors.Is(err, io.EOF)",
			direction: "(false && !errors.Is(err, io.EOF))",
			verdict:   verdictCovered,
			why: "One journal LINE must hold exactly one event. Without this rule a line may carry a " +
				"valid event followed by anything at all: the integrity check hashes the decoded struct, " +
				"not the line, so the trailing bytes change the file without changing any hash. Two " +
				"byte-different journals then verify identically, which is the malleability the chain " +
				"exists to remove.",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "policy-state.jsonl")
				state, err := OpenFileState(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := state.Reserve(context.Background(), reservation("nonce_000000000001", "2026-09-04", 10, 100)); err != nil {
					t.Fatal(err)
				}
				if err := state.Close(); err != nil {
					t.Fatal(err)
				}
				contents, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				appended := bytes.Replace(contents, []byte("\n"), []byte(" {\"smuggled\":true}\n"), 1)
				if bytes.Equal(appended, contents) {
					t.Fatal("the fixture did not append anything to the journal line")
				}
				if err := os.WriteFile(path, appended, 0o600); err != nil {
					t.Fatal(err)
				}
				reopened, err := OpenFileState(path)
				if err == nil {
					_ = reopened.Close()
					t.Fatal("a journal line carrying a second JSON document after its event opened — " +
						"the event hash covers the decoded struct, so the extra bytes ride along " +
						"invisibly and two different files verify the same")
				}
				if !strings.Contains(err.Error(), "trailing data") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
		{
			file:      "state.go",
			guard:     "if err := validateReservation(event.Reservation); err != nil {",
			operand:   "err != nil",
			direction: "(false && err != nil)",
			verdict:   verdictCovered,
			why: "The reservation validator runs on the way IN, at Reserve, and again on the way OUT, " +
				"here. Only the first had a test, because every corrupted-journal fixture in this " +
				"package changes bytes and is caught by the hash chain first. A journal FORGED with the " +
				"production hasher is correctly chained and reaches this line, and without it a " +
				"reservation the writer would have refused -- here, one spending more than its own " +
				"recorded daily cap -- is replayed into the in-memory quota at startup.",
			run: func(t *testing.T) {
				forged := forgedAmounts(1, stateGenesisHash, "nonce_000000000001", 500, 100)
				path := forgedJournal(t, forged)
				state, err := OpenFileState(path)
				if err == nil {
					_ = state.Close()
					t.Fatal("a journal recording a reservation of 500 against its own cap of 100 " +
						"opened — the writer would never have produced it, and it is replayed into " +
						"the quota as though it had")
				}
				if !strings.Contains(err.Error(), "reservation is invalid") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
		{
			file:      "state.go",
			guard:     "if err := scanner.Err(); err != nil {",
			operand:   "err != nil",
			direction: "(false && err != nil)",
			verdict:   verdictCovered,
			why: "bufio.Scanner reports a line longer than its buffer by stopping and setting Err, so " +
				"dropping the error turns an unreadable journal into a SHORTER one. With no mark beside " +
				"it -- the first write's crash window, which this package deliberately keeps openable -- " +
				"there is nothing else to notice, and the state opens with an empty nonce set and a " +
				"full daily quota. The buffer is a megabyte and nothing had ever handed the scanner a " +
				"line past it.",
			run: func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "policy-state.jsonl")
				oversized := append(bytes.Repeat([]byte("x"), 2<<20), '\n')
				if err := os.WriteFile(path, oversized, 0o600); err != nil {
					t.Fatal(err)
				}
				state, err := OpenFileState(path)
				if err == nil {
					_ = state.Close()
					t.Fatal("a journal the scanner could not read opened as though it were empty — " +
						"every nonce it recorded is spendable again and the daily quota is back to full")
				}
				if !strings.Contains(err.Error(), "read policy state") {
					t.Fatalf("refused by a different rule: %v — the scanner error must not be reported "+
						"as malformed content, which sends an operator to inspect a line they cannot "+
						"see", err)
				}
			},
		},
		{
			file:      "state.go",
			guard:     "if err != nil || parsed.Format(utcDateLayout) != reservation.UTCDate {",
			operand:   "err != nil",
			direction: "(false && err != nil)",
			verdict:   verdictMasked,
			why: "The two operands of this guard are equivalent predicates on every input that reaches " +
				"it, so neither can be the sole refuser. When Parse fails, parsed is the zero time and " +
				"Format gives \"0001-01-01\", which differs from any input Parse rejected -- so the " +
				"round-trip operand fires too. TestTheDateRoundTripCheckIsUnreachableAndWhyItStays " +
				"records the other half of this symmetry (no input makes Parse succeed and the " +
				"round-trip fail); this row is the measured completion of it, and the comment there was " +
				"only ever describing one direction.",
			run: func(t *testing.T) {
				// The half that test does not state, checked here: a failed Parse leaves a value
				// whose Format cannot equal the input.
				for _, value := range []string{"yesterday", "2026-9-5", "2026-02-30", " 2026-01-02"} {
					parsed, err := time.Parse(utcDateLayout, value)
					if err == nil {
						t.Fatalf("%q parses, so it is not evidence about the Parse-error operand", value)
					}
					if parsed.Format(utcDateLayout) == value {
						t.Fatalf("%q fails to parse and still round-trips — the two operands are then "+
							"distinguishable and this one needs a real detector", value)
					}
				}
			},
		},
		{
			file:      "state.go",
			guard:     "if err != nil || parsed.Format(utcDateLayout) != reservation.UTCDate {",
			operand:   "parsed.Format(utcDateLayout) != reservation.UTCDate",
			direction: "(false && parsed.Format(utcDateLayout) != reservation.UTCDate)",
			verdict:   verdictMasked,
			why: "The other side of the same symmetry, and the side " +
				"TestTheDateRoundTripCheckIsUnreachableAndWhyItStays already documents: every non-canonical spelling fails at Parse, so this " +
				"operand never fires alone. Kept as defence in depth against the layout being loosened, " +
				"which is what that test exists to say.",
		},
		{
			file:      "state.go",
			guard:     `if denom == "" || amount == 0 || reservation.DailyCaps[denom] == 0 || amount > reservation.DailyCaps[denom] {`,
			operand:   "reservation.DailyCaps[denom] == 0",
			direction: "(false && reservation.DailyCaps[denom] == 0)",
			verdict:   verdictMasked,
			why: "Masked by the operand after it. A denomination with no cap entry reads back as zero, " +
				"and the amount is already known to be non-zero because the preceding operand ruled that " +
				"out, so amount > 0 holds for every input that reaches this one.",
		},
		{
			file:      "state.go",
			guard:     `if denom == "" || amount == 0 || reservation.DailyCaps[denom] == 0 || amount > reservation.DailyCaps[denom] {`,
			operand:   "amount > reservation.DailyCaps[denom]",
			direction: "(false && amount > reservation.DailyCaps[denom])",
			verdict:   verdictCovered,
			why: "TestASingleReservationLargerThanTheCapIsRefused asserts only that an error came back, " +
				"and an error does come back without this operand -- from the quota guard inside Reserve, " +
				"as ErrLimit. The two are not interchangeable: ErrLimit is the durable quota saying a " +
				"workload reached its cap, which operations counts and an operator is meant to act on, " +
				"while this is the reservation being malformed before any quota is consulted. This row " +
				"pins which one answers.",
			run: func(t *testing.T) {
				state := openState(t)
				err := state.Reserve(context.Background(), reservation("nonce_000000000001", "2026-09-05", 1001, 1000))
				if err == nil {
					t.Fatal("a reservation of 1001 against its own cap of 1000 was accepted")
				}
				if errors.Is(err, ErrLimit) {
					t.Fatalf("a malformed reservation was reported as a quota rejection (%v) — "+
						"ErrLimit is counted as 'a workload hit its cap' and sends an operator to "+
						"raise a limit, when what arrived is a reservation that contradicts itself", err)
				}
				if !strings.Contains(err.Error(), "invalid policy reservation amount") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
	}
}

// requireValidatorRefusesAheadOfTheQuotaGuard checks the property that makes the first two operands
// of Reserve's quota guard unreachable: validateReservation runs first and already refuses both
// shapes. If it ever stops doing so, those operands become live and need real detectors.
func requireValidatorRefusesAheadOfTheQuotaGuard(t *testing.T) {
	t.Helper()
	noCap := Reservation{PolicyID: "p", ObjectID: "o", Principal: "s", Nonce: "nonce_0123456789abcdef",
		UTCDate: "2026-09-05", Amounts: map[string]uint64{"uatom": 1}, DailyCaps: map[string]uint64{}}
	if err := validateReservation(noCap); err == nil {
		t.Fatal("validateReservation accepted a denomination with no daily cap — Reserve's `cap == 0` " +
			"operand is then reachable and needs a detector")
	}
	overCap := noCap
	overCap.DailyCaps = map[string]uint64{"uatom": 1}
	overCap.Amounts = map[string]uint64{"uatom": 2}
	if err := validateReservation(overCap); err == nil {
		t.Fatal("validateReservation accepted an amount above its own daily cap — Reserve's " +
			"`amount > cap` operand is then reachable and needs a detector")
	}
}

// verifyStateRewriteRow builds one of the three rows for VerifyState's same-length-rewrite guard.
//
// ONLY ONE OF THE THREE CARRIES THE FIXTURE, and the other two say so. Narrowing any operand of an
// && chain makes the whole condition false, so every fixture that provokes the refusal fails for
// all three operands alike -- no fixture can isolate one of them, by construction rather than by
// omission. Giving all three the same detector would report three failures for one neutralisation
// and make each row look like it had a detector of its own.
func verifyStateRewriteRow(operand string, detector bool) operandLeaf {
	row := operandLeaf{
		file:      "state.go",
		guard:     "if replay.sequence == mark.Sequence && mark.Hash != stateGenesisHash && replay.lastHash != mark.Hash {",
		operand:   operand,
		direction: "(false && " + operand + ")",
		verdict:   verdictPinnedElsewhere,
		why: "Narrowing this operand makes the whole && chain false, which is the same observable " +
			"state as narrowing either of its siblings — so the row for `replay.sequence == " +
			"mark.Sequence` is what fails, and this one can never be the sole failure. Recorded " +
			"because the operand IS reachable and IS now detected; what it cannot have is a " +
			"detector of its own.",
	}
	if !detector {
		return row
	}
	row.verdict = verdictCovered
	row.why = "VerifyState's rewrite refusal had no test that provokes it. The #334 ledger swept this " +
		"chain in the WIDENING direction only -- the direction in which a legitimate journal is " +
		"wrongly refused -- so 'covered' there meant the good case, and the bad case had never " +
		"been asked. TestRewrittenJournalOfEqualLengthIsDetected exercises the OpenFileState twin " +
		"and says nothing about the verifier, which is the tool an operator points at a journal " +
		"they cannot take the lock on. This fixture is the detector for all three operands of the " +
		"chain; the other two rows say so rather than repeating it."
	row.run = func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "policy-state.jsonl")
		state, err := OpenFileState(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := state.Reserve(context.Background(), reservation("nonce_000000000001", "2026-09-04", 10, 100)); err != nil {
			t.Fatal(err)
		}
		if err := state.Close(); err != nil {
			t.Fatal(err)
		}
		// A different one-event history, built the same way, so it is internally consistent and
		// exactly as long. The mark beside the original journal is left where it is.
		other := filepath.Join(t.TempDir(), "other.jsonl")
		swapped, err := OpenFileState(other)
		if err != nil {
			t.Fatal(err)
		}
		if err := swapped.Reserve(context.Background(), reservation("nonce_000000000009", "2026-09-04", 10, 100)); err != nil {
			t.Fatal(err)
		}
		if err := swapped.Close(); err != nil {
			t.Fatal(err)
		}
		replacement, err := os.ReadFile(other)
		if err != nil {
			t.Fatal(err)
		}
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(original, replacement) {
			t.Fatal("the two journals are byte-identical, so nothing was rewritten and this row " +
				"proves nothing")
		}
		if err := os.WriteFile(path, replacement, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyState(path); err == nil {
			t.Fatal("a journal swapped for a different history of the same length VERIFIED CLEAN " +
				"— the mark records the head of a chain this file does not contain, which is the " +
				"one thing the mark exists to notice")
		} else if !strings.Contains(err.Error(), "rewritten rather than shortened") {
			t.Fatalf("refused by a different rule: %v", err)
		}
	}
	return row
}

// readyRow builds one of the three rows for FileState.Ready's boolean return. All three tests of
// this predicate assert the FALSE direction -- closed, failed, no handle -- so narrowing any
// operand, which makes Ready answer false forever, was invisible.
//
// As with the rewrite chain above, one row carries the fixture and the other two say why they
// cannot: making any operand of an && chain false has one observable consequence, so there is no
// fixture that separates them.
func readyRow(operand string, detector bool) operandLeaf {
	row := operandLeaf{
		file:      "state.go",
		guard:     "return !state.closed && !state.failed && state.file != nil",
		operand:   operand,
		direction: "(false && " + operand + ")",
		verdict:   verdictPinnedElsewhere,
		why: "Narrowing this operand makes the whole return false, which is indistinguishable from " +
			"narrowing either sibling, so the `!state.closed` row is what fails and this one can " +
			"never be the sole failure. The operand is reachable and is now detected; it cannot " +
			"have a detector of its own.",
	}
	if !detector {
		return row
	}
	row.verdict = verdictCovered
	row.why = "Nothing asserted that a HEALTHY policy state reports itself ready. Three tests assert " +
		"it is not ready when closed, when failed and when it has no handle, and all three pass " +
		"against a predicate that answers false to everything -- at which point the daemon never " +
		"reports ready, never receives traffic, and the suite is green. This is the §18 known-good " +
		"half of that trio, and the detector for all three operands of the chain."
	row.run = func(t *testing.T) {
		state, err := OpenFileState(filepath.Join(t.TempDir(), "policy-state.jsonl"))
		if err != nil {
			t.Fatal(err)
		}
		defer state.Close()
		if !state.Ready(context.Background()) {
			t.Fatal("a freshly opened policy state reported itself NOT ready — readiness gates " +
				"serving, so a state that never says yes is a daemon that never serves, and every " +
				"existing test of this predicate asserts the other direction")
		}
	}
	return row
}

// ---------------------------------------------------------------------------------------------
// wire.go
// ---------------------------------------------------------------------------------------------

func wireOperandRows() []operandLeaf {
	return []operandLeaf{
		{
			file:      "wire.go",
			guard:     "if end < offset || end > len(input) {",
			operand:   "end > len(input)",
			direction: "(false && end > len(input))",
			verdict:   verdictCovered,
			why: "The overflow half of this guard was found by mutation and pinned by " +
				"TestAnOverflowingLengthFieldIsRefusedNotPanicked, whose own comment explains that the " +
				"upper operand is satisfied by the wrap and therefore cannot fire on that fixture. The " +
				"upper operand was left without one. It guards the ordinary truncation: a length prefix " +
				"that simply claims more bytes than remain, which is what a cut-off message looks like. " +
				"Without it input[offset:end] panics with slice bounds, in a parser reading " +
				"attacker-supplied bytes. The row goes through the exported parser so the panic arrives " +
				"as the boundary's refusal rather than aborting the test binary and truncating the " +
				"failing set — the message is what separates the two.",
			run: func(t *testing.T) {
				// body_bytes claiming 64 bytes with 4 present: no overflow, just past the end.
				truncated := append(append(encodeTag(1, 2), encodeVarint(64)...), []byte("body")...)
				_, err := ParseCosmosSignDoc(truncated)
				if err == nil {
					t.Fatal("a length prefix claiming more bytes than the buffer holds was accepted")
				}
				if strings.Contains(err.Error(), "parser panic") {
					t.Fatalf("a truncated length-delimited field PANICKED inside the parser and was "+
						"caught by the boundary (%v) — the guard is what turns it into a refusal, and "+
						"the boundary is the net for the paths nobody has enumerated yet, not a "+
						"substitute for the ones that are", err)
				}
				if !strings.Contains(err.Error(), "exceeds buffer") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
	}
}

// ---------------------------------------------------------------------------------------------
// the ledger's own controls
// ---------------------------------------------------------------------------------------------

// stripMutationWrappers removes the two neutralisations this ledger's own sweep applies, so that
// the drift check below is NEUTRAL TO THE HARNESS THAT PRODUCED THE LEDGER.
//
// WITHOUT THIS THE DRIFT CHECK IS A CO-DETECTOR FOR EVERY ROW IT DESCRIBES, which was measured
// before it existed: neutralising an operand rewrites the guard's source text, the check fires
// because the guard "moved", and it fires ALONGSIDE whichever row was under test. Every covered
// row then has two failures instead of one and cannot be shown to be the sole detector, and every
// row classified masked or unreachable looks detected. A future sweep of this package inherits the
// same problem, so this is not a convenience for one round.
//
// The stripping is exact rather than textual: it finds the wrapper's opening and its MATCHING
// close paren by counting depth, so an operand containing parens of its own -- `^uint64(0)-...`,
// `!noncePattern.MatchString(...)` -- is restored intact. It would be confused by an unbalanced
// paren inside a string literal within a wrapped operand; no operand in this package has one, and
// an unbalanced count leaves the text untouched rather than corrupting it.
//
// On unmutated source it is a no-op: neither prefix occurs.
// unwrapOnce removes ONE paren pair, and only when it encloses the whole expression.
//
// The harness that neutralises an operand has to parenthesise it whenever the operand sits in
// a boolean chain: `a || (false && b) || c` is the mutation, and `a || false && b || c` is a
// different expression, because && binds tighter than ||. So the falsifier form this repository
// documents everywhere else -- `if false && (<original>)`, in auth, yubikey and fencing -- leaves
// a redundant pair behind after the prefix and its matching paren come off, and the guard text no
// longer matches the row that names it.
//
// That failure is silent in the dangerous direction. The ledger row goes red, the sweep harness
// reads a red as KILLED, and an operand no behavioural test detects is retired as covered.

// A ROW THAT NAMES CODE THAT MOVED IS A ROW THAT ASSERTS NOTHING. Every guard string must occur
// exactly once in the file the row names, and the operand must occur inside that guard. Both
// directions matter: a guard that was edited breaks the first check, and an operand renamed
// within an intact guard breaks the second.
func TestEveryOperandLedgerRowStillNamesLiveSource(t *testing.T) {
	sources := map[string]string{}
	for _, name := range faultInjectionSources(t) {
		contents, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		sources[name] = sweeptext.StripMutationWrappers(string(contents))
	}
	rows := operandLedger()
	if len(rows) == 0 {
		t.Fatal("the ledger is empty — an empty ledger and a broken one look identical from here")
	}
	// The control for the control. Every assertion below is a count against a source string, and
	// a scan that returned the wrong text -- or nothing -- would make all of them pass. A guard
	// that is deliberately not in the file must count zero, and one that is must count one; the
	// loop covers the second, this covers the first.
	if count := strings.Count(sources["policy.go"], "if thisGuardHasNeverBeenInPolicyGo {"); count != 0 {
		t.Fatalf("a guard that does not exist was found %d times — the scan is not reading what "+
			"it claims to, and every row below would pass whatever it named", count)
	}
	for _, row := range rows {
		source, known := sources[row.file]
		if !known {
			t.Errorf("row for %q names %s, which is not one of this package's non-test sources (%v)",
				row.operand, row.file, faultInjectionSources(t))
			continue
		}
		if count := strings.Count(source, row.guard); count != 1 {
			t.Errorf("%s: the guard this row names occurs %d times, want exactly 1:\n%s",
				row.file, count, row.guard)
			continue
		}
		if !strings.Contains(row.guard, row.operand) {
			t.Errorf("%s: operand %q does not occur in the guard the row names:\n%s",
				row.file, row.operand, row.guard)
		}
	}
}

func TestEveryOperandLedgerRowIsClassifiedAndExplained(t *testing.T) {
	known := map[string]bool{
		verdictCovered: true, verdictPinnedElsewhere: true, verdictUnreachable: true,
		verdictUndetectable: true, verdictMasked: true,
	}
	// The tally is DERIVED and logged rather than typed into the header, so a reader quoting it
	// is quoting the rows rather than a number somebody kept up to date by hand.
	tally := map[string]int{}
	defer func() {
		t.Logf("operand ledger: %d rows — covered %d, pinned-elsewhere %d, masked %d, "+
			"unreachable %d, undetectable %d", len(operandLedger()), tally[verdictCovered],
			tally[verdictPinnedElsewhere], tally[verdictMasked], tally[verdictUnreachable],
			tally[verdictUndetectable])
	}()
	for _, row := range operandLedger() {
		tally[row.verdict]++
		name := row.file + " " + row.operand + " " + row.direction
		if !known[row.verdict] {
			t.Errorf("%s: verdict %q is not one of the five", name, row.verdict)
		}
		if len(row.why) < 80 {
			t.Errorf("%s: the explanation is %d characters — a verdict without a derivation is an "+
				"assertion, and the derivation is the part a reader can check", name, len(row.why))
		}
		if row.verdict == verdictCovered && row.run == nil {
			t.Errorf("%s: classified covered with nothing to run, so nothing detects it", name)
		}
		if row.verdict == verdictPinnedElsewhere && row.run != nil {
			t.Errorf("%s: classified pinned-elsewhere and carries a detector — a row that can fail "+
				"is a second detector, and two detectors mean neither is the sole one", name)
		}
	}
}

// operandRowName is the subtest name for a row, and it has to carry the GUARD as well as the
// operand. `exists` occurs in two different guards in policy.go and so does `!exists`; `err != nil`
// occurs in six guards in state.go. Named by the operand alone, Go appends #01 to the second
// subtest and a failing name then identifies the row by declaration order rather than by what it
// is about -- measured, in the first falsification round, where four kills were attributed to a
// name ending in #01.
//
// No slash: a slash nests the subtest, and a nested name makes "was this row the sole failure" a
// harder question to ask of `go test` output than it needs to be.
func operandRowName(row operandLeaf) string {
	collapsed := []rune(strings.Join(strings.Fields(row.guard), " "))
	if len(collapsed) > 44 {
		collapsed = append(collapsed[:44:44], '…')
	}
	return row.file + ": " + row.operand + " " + row.direction + " in " + string(collapsed)
}

// TWO ROWS SHARING A SUBTEST NAME ARE ONE ROW AS FAR AS THE OUTPUT IS CONCERNED, and a sweep that
// attributes a kill to the wrong row is worse than one that attributes it to nothing.
func TestEveryOperandLedgerRowHasItsOwnSubtestName(t *testing.T) {
	seen := map[string]bool{}
	for _, row := range operandLedger() {
		name := operandRowName(row)
		if seen[name] {
			t.Errorf("two rows are both named %q — Go will call the second one #01, and the "+
				"failing name then says which was declared first rather than which was neutralised", name)
		}
		seen[name] = true
	}
}

// A duplicate (file, operand, direction) would let one row silently stand in for another.
func TestNoOperandLedgerRowIsRecordedTwice(t *testing.T) {
	seen := map[string]bool{}
	for _, row := range operandLedger() {
		key := row.file + "\x00" + row.operand + "\x00" + row.direction + "\x00" + row.guard
		if seen[key] {
			t.Errorf("%s %s %s is recorded twice", row.file, row.operand, row.direction)
		}
		seen[key] = true
	}
}

func TestOperandLedger(t *testing.T) {
	for _, row := range operandLedger() {
		if row.run == nil {
			continue
		}
		t.Run(operandRowName(row), func(t *testing.T) { row.run(t) })
	}
}

// The forged-journal helper must produce something readState ACCEPTS, or the two apply() rows are
// equally consistent with a reader that refuses everything. It runs after them (TESTING.md §18) as
// a separate test rather than inside them, so a broken helper cannot stop them reporting first.
//
// This is not the same claim as the #334 ledger's own forged-journal control, which chains the
// default reservation; forgedAmounts builds a different one, with the amount and cap under the
// row's control, and it is that shape whose acceptance is in question here.
func TestTheForgedAmountsHelperProducesAJournalReadStateAccepts(t *testing.T) {
	first := forgedAmounts(1, stateGenesisHash, "nonce_000000000001", 10, 100)
	second := forgedAmounts(2, first.Hash, "nonce_000000000002", 20, 100)
	events, err := readState(forgedJournal(t, first, second))
	if err != nil {
		t.Fatalf("a correctly chained forged journal was refused (%v) — the apply() rows above would "+
			"then pass against a readState that refuses everything", err)
	}
	if len(events) != 2 {
		t.Fatalf("read %d events from a two-event journal", len(events))
	}
	if events[1].Reservation.Amounts["uatom"] != 20 {
		t.Fatalf("the helper did not carry the amount it was given: %#v", events[1].Reservation)
	}
	// And the encoding round-trips, so a row that breaks one field and re-hashes is breaking the
	// field it means to.
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	var decoded stateEvent
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Hash != stateEventHash(decoded) {
		t.Fatal("a forged event does not hash to the value it carries after a round trip")
	}
}
