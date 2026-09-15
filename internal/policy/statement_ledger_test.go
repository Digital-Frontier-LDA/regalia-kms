package policy

// THE STATEMENT LEDGER (#237): the mutations no single boolean operand can express.
//
// An operand sweep asks "does anything notice if this decision changes". It cannot ask "does
// anything notice if the decision is made correctly and then NOT RECORDED", because the answer
// and the record are written by ONE statement and no operand separates them. Two shapes, both
// swept here by hand after the 450 operand-directions were done:
//
//	a statement writing two facts     x, y = answer, record
//	a value derived here that a guard somewhere else consumes
//
// 46 statement-level mutations in internal/policy, plus 8 in tools/guardenum's output path. Five
// of the internal/policy mutations did not build on the first attempt -- dropping a value was the
// variable's only use -- and were rewritten to keep the variable read and change only what the
// statement records; a build failure emits no `--- FAIL:` line, so classifying it separately is
// the difference between "nothing detected it" and "nothing ran". One guardenum mutation needed
// the same treatment, for the same reason.
//
// The verdicts are the operand ledger's five, used the same way.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

type statementFact struct {
	file  string
	where string
	// anchor is the exact source text the mutation replaced, recorded so the measurement can be
	// reproduced. It is DELIBERATELY NOT the drift check: a statement mutation removes the
	// anchor, so a test asserting its presence would fail alongside whichever row was under
	// test and no row could ever be shown to be the sole detector. The operand ledger solves the
	// same problem by stripping the wrappers, which works because an operand mutation preserves
	// the text; a statement mutation does not, so there is nothing to strip.
	anchor string
	// landmark is what IS checked: a unique substring of the file that no mutation in EITHER
	// sweep touches -- in practice a function signature. It catches the function being renamed,
	// moved or deleted, which is the drift a ledger row actually rots against; it does not catch
	// the statement inside it changing, and says so.
	//
	// "No mutation in either sweep" is a real constraint, measured rather than assumed. Two
	// landmarks here were originally the statement's own neighbourhood -- `engine.quotaRejections
	// .Add(1)` and `if err := state.file.Sync(); err != nil {` -- and the second of those contains
	// an OPERAND. Neutralising it rewrote the landmark, this test fired, and state.go's masked
	// fsync operand was reported as detected by a drift check rather than surviving as classified.
	// A landmark inside a boolean condition is a landmark the operand sweep moves.
	landmark string
	dropped  string
	verdict  string
	why      string
	run      func(*testing.T)
}

func statementLedger() []statementFact {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	return []statementFact{
		{
			file:     "policy.go",
			where:    "Evaluate, the decision seed",
			landmark: "func (engine *Engine) Evaluate(ctx context.Context, request Request) Decision {",
			anchor:   "\tdecision := Decision{PolicyID: policy.policy.ID}\n",
			dropped:  "the policy id every subsequent denial inherits",
			verdict:  verdictCovered,
			why: "One statement establishes both the value the denials are built from and the only " +
				"link between a refusal and the rule that produced it. Drop the id and every denial " +
				"Evaluate issues after the lookup is anonymous: operations records the reason but not " +
				"the policy, so an operator reading an audit trail of refusals cannot tell which of " +
				"several rules on the same object is doing the refusing. Nothing asserted the id on a " +
				"DENIED decision; TestEvaluateAllowsExactPolicyAndReservesReplayAndQuota asserts it on " +
				"an allow.",
			run: func(t *testing.T) {
				engine, err := New([]Policy{basePolicy()}, &reservationState{}, clock)
				if err != nil {
					t.Fatal(err)
				}
				request := baseRequest(now)
				request.PayloadBytes = 100_001
				decision := engine.Evaluate(context.Background(), request)
				if decision.Allowed {
					t.Fatalf("the fixture was allowed, so it is not a denial: %#v", decision)
				}
				if decision.PolicyID != "cosmos-hot-wallet" {
					t.Fatalf("a denial named policy %q, want %q — a refusal an operator cannot trace "+
						"to a rule is a refusal they cannot act on, and this object may carry a "+
						"different policy per operation", decision.PolicyID, "cosmos-hot-wallet")
				}
			},
		},
		{
			file:     "policy.go",
			where:    "Decision.deny, the verdict and the reason",
			landmark: "func (decision Decision) deny(rule string) Decision {",
			anchor:   "\tdecision.Code, decision.Rule = CodeDenied, rule\n",
			dropped:  "the rule naming which check refused, while the refusal itself stands",
			verdict:  verdictPinnedElsewhere,
			why: "One statement writes the verdict and the record of why. Before this change nothing " +
				"asserted the reason: TestEvaluateRejectsMismatchesBeforeState and " +
				"TestCosmosPolicyRejectsEveryControlledDimension check that a request was refused and " +
				"not what refused it, so replacing `rule` with the field's own previous value left " +
				"every denial anonymous while the suite stayed green -- and operations builds its " +
				"audit reason by appending exactly this field. It is detected now by the operand " +
				"ledger's rows, which had to assert the rule to isolate their own operands from the " +
				"siblings that share a message. The verdict half was already covered, by the same " +
				"Cosmos test's CodeDenied assertion.",
		},
		{
			file:     "policy.go",
			where:    "Evaluate, the quota refusal",
			landmark: "func (engine *Engine) Evaluate(ctx context.Context, request Request) Decision {",
			anchor:   "\t\t\treturn Decision{Code: CodeLimitExceeded, PolicyID: policy.policy.ID, Rule: \"quota\"}\n",
			dropped:  "the policy id on a limit-exceeded decision",
			verdict:  verdictCovered,
			why: "The quota counter is asserted by TestQuotaRejectionsAreCountedSeparatelyFromOtherDenials " +
				"and the CODE by TestReplayQuotaStateFailureFailsClosed; the id on the same literal was " +
				"asserted by neither. A quota rejection is the one refusal an operator is expected to " +
				"act on -- the runbook's RegaliaQuotaRejectionsSustained row sends them to find which " +
				"workload hit which cap -- and without the id the alert names neither.",
			run: func(t *testing.T) {
				engine, err := New([]Policy{basePolicy()}, &reservationState{err: ErrLimit}, clock)
				if err != nil {
					t.Fatal(err)
				}
				decision := engine.Evaluate(context.Background(), baseRequest(now))
				if decision.Code != CodeLimitExceeded {
					t.Fatalf("decision = %#v, want limit-exceeded", decision)
				}
				if decision.PolicyID != "cosmos-hot-wallet" {
					t.Fatalf("a quota refusal named policy %q — the operator alert for a sustained "+
						"quota rejection asks which cap was reached, and this is the field that "+
						"answers", decision.PolicyID)
				}
			},
		},
		{
			file:     "policy.go",
			where:    "Evaluate, the durable-state refusal",
			landmark: "Rule: \"durable-state\"",
			anchor:   "\t\t\treturn Decision{Code: CodeStateUnavailable, PolicyID: policy.policy.ID, Rule: \"durable-state\"}\n",
			dropped:  "the policy id on a state-unavailable decision",
			verdict:  verdictCovered,
			why: "Same statement shape, same gap: TestReplayQuotaStateFailureFailsClosed asserts the " +
				"code and nothing asserts the id. This is the decision the daemon returns as a 503, " +
				"and the audit record it produces is the one an operator reads while the service is " +
				"already failing -- the moment least convenient to be missing the name of the rule " +
				"that was being applied.",
			run: func(t *testing.T) {
				engine, err := New([]Policy{basePolicy()},
					&reservationState{err: fmt.Errorf("the journal is unreachable")}, clock)
				if err != nil {
					t.Fatal(err)
				}
				decision := engine.Evaluate(context.Background(), baseRequest(now))
				if decision.Code != CodeStateUnavailable {
					t.Fatalf("decision = %#v, want state-unavailable", decision)
				}
				if decision.PolicyID != "cosmos-hot-wallet" {
					t.Fatalf("a durable-state refusal named policy %q — this is the 503 an operator "+
						"reads during an incident", decision.PolicyID)
				}
			},
		},
		{
			file:     "policy.go",
			where:    "policyKey",
			landmark: "func policyKey(objectID, operation string) string",
			anchor:   "func policyKey(objectID, operation string) string { return objectID + \"\\x00\" + operation }\n",
			dropped:  "the separator between the object and the operation",
			verdict:  verdictCovered,
			why: "reservation_test.go pins this exact property for the nonce key and the quota key, " +
				"with a fixture pair built to concatenate identically without their separator. The " +
				"policy key has the same shape and no such pair, so removing ITS separator was " +
				"invisible. The consequence runs the other way from the quota one: two legitimately " +
				"distinct (object, operation) pairs collide, so New refuses a valid configuration as " +
				"ambiguous and the daemon does not start.",
			run: func(t *testing.T) {
				// Built to concatenate alike: "regalia" + "sign" and "regaliasign" + "" would not
				// compile (an empty operation is refused), so the split is moved inside the word.
				first := Policy{ID: "first", ObjectID: "regalia-signer", Operation: "wrap",
					Purpose: "sops-data-key", Environment: "production", Algorithm: "rsa2048",
					ContentTypes:    []string{"application/vnd.regalia.data-key"},
					MaxPayloadBytes: 4096, MaxFuture: time.Minute}
				second := first
				second.ID, second.ObjectID, second.Operation = "second", "regalia-signerw", "rap"
				if first.ObjectID+first.Operation != second.ObjectID+second.Operation {
					t.Fatalf("the fixtures do not collide without a separator (%q vs %q) — this row "+
						"proves nothing about the separator",
						first.ObjectID+first.Operation, second.ObjectID+second.Operation)
				}
				engine, err := New([]Policy{first, second}, &reservationState{}, clock)
				if err != nil {
					t.Fatalf("two distinct (object, operation) pairs were refused as one policy "+
						"(%v) — they concatenate to the same string, and the separator is the only "+
						"thing keeping them apart", err)
				}
				for _, want := range []struct{ object, operation, id string }{
					{first.ObjectID, first.Operation, "first"},
					{second.ObjectID, second.Operation, "second"},
				} {
					id, ok := engine.GoverningPolicyID(want.object, want.operation)
					if !ok || id != want.id {
						t.Fatalf("GoverningPolicyID(%q, %q) = (%q, %v), want %q",
							want.object, want.operation, id, ok, want.id)
					}
				}
			},
		},
		{
			file:     "state.go",
			where:    "nonceKey",
			landmark: "func nonceKey(reservation Reservation) string {",
			anchor:   "return reservation.PolicyID + \"\\x00\" + reservation.ObjectID + \"\\x00\" + reservation.Principal + \"\\x00\" + reservation.Nonce\n",
			dropped:  "the principal component of the replay key",
			verdict:  verdictCovered,
			why: "TestTwoIdentitiesThatConcatenateAlikeAreNotOneNonce varies the policy and the object " +
				"and holds the principal fixed, so dropping the principal from the key entirely left " +
				"it green. Without it two different workloads share one replay namespace: the second " +
				"principal to present a nonce the first already used is refused as a replay of a " +
				"request it never made, which is a denial of service one tenant can inflict on " +
				"another by choosing nonces.",
			run: func(t *testing.T) {
				state := openState(t)
				first := Reservation{PolicyID: "cosmos", ObjectID: "hotwallet",
					Principal: "spiffe://regalia/workload/one", Nonce: "nonce_000000000001",
					UTCDate: "2026-09-05", Amounts: map[string]uint64{"uatom": 10},
					DailyCaps: map[string]uint64{"uatom": 100}}
				second := first
				second.Principal = "spiffe://regalia/workload/two"
				if err := state.Reserve(context.Background(), first); err != nil {
					t.Fatalf("the first reservation failed: %v", err)
				}
				if err := state.Reserve(context.Background(), second); err != nil {
					t.Fatalf("a second principal using the same nonce was refused as %v — the replay "+
						"key must separate principals, or one workload's choice of nonce blocks "+
						"another's request", err)
				}
			},
		},
		{
			file:     "state.go",
			where:    "readState, the per-line decoder",
			landmark: "func readState(path string) ([]stateEvent, error) {",
			anchor:   "\t\tdecoder.DisallowUnknownFields()\n",
			dropped:  "the refusal of a journal line carrying a field this type does not have",
			verdict:  verdictCovered,
			why: "The hash covers the DECODED STRUCT, not the line, so a field the struct does not " +
				"have rides along without changing any hash: the chain verifies, the integrity check " +
				"passes, and the extra content is invisible to every rule in this file. Load has the " +
				"same call for the policy document and it now has a detector; the journal's had none.",
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
				smuggled := strings.Replace(string(contents), `{"sequence"`, `{"note":"anything at all","sequence"`, 1)
				if smuggled == string(contents) {
					t.Fatal("the fixture did not rewrite the journal line, so it smuggles nothing")
				}
				if err := os.WriteFile(path, []byte(smuggled), 0o600); err != nil {
					t.Fatal(err)
				}
				reopened, err := OpenFileState(path)
				if err == nil {
					_ = reopened.Close()
					t.Fatal("a journal line carrying a field the event type does not have opened — " +
						"the hash is computed over the decoded struct, so the extra field changes " +
						"the file and nothing else, and two different journals verify identically")
				}
				if !strings.Contains(err.Error(), "invalid JSON") {
					t.Fatalf("refused by a different rule: %v", err)
				}
			},
		},
		{
			file:     "state.go",
			where:    "readState, the scanner's buffer",
			landmark: "scanner := bufio.NewScanner(file)",
			anchor:   "\tscanner.Buffer(make([]byte, 64<<10), 1<<20)\n",
			dropped:  "the megabyte line limit, leaving bufio's 64 KiB default",
			verdict:  verdictCovered,
			why: "A reservation's two amount maps are unbounded, so a journal line is only as short as " +
				"the policy that produced it. Every fixture in this package carries one denomination " +
				"and a line of a couple of hundred bytes, so the raised limit was never exercised and " +
				"removing it changed nothing any test could see. It matters because of what the " +
				"scanner does when a line is too long: it stops and reports through Err, which turns " +
				"a readable journal into a SHORTER one -- the state opens with the nonces and quota " +
				"of a prefix.",
			run: func(t *testing.T) {
				// A line comfortably over bufio's 64 KiB default and comfortably under the 1 MiB
				// this call asks for, so it distinguishes the two and depends on neither exactly.
				amounts := map[string]uint64{}
				caps := map[string]uint64{}
				for index := 0; index < 3000; index++ {
					denom := "udenom" + strconv.Itoa(index)
					amounts[denom], caps[denom] = 1, 10
				}
				wide := Reservation{PolicyID: "cosmos-hot-wallet", ObjectID: "production-wallet-signer",
					Principal: "spiffe://regalia/workload/tx-signer", Nonce: "nonce_000000000001",
					UTCDate: "2026-09-04", Amounts: amounts, DailyCaps: caps}
				path := filepath.Join(t.TempDir(), "policy-state.jsonl")
				state, err := OpenFileState(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := state.Reserve(context.Background(), wide); err != nil {
					t.Fatalf("writing a many-denomination reservation failed: %v", err)
				}
				if err := state.Close(); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Size() <= 64<<10 || info.Size() >= 1<<20 {
					t.Fatalf("the journal line is %d bytes — it must sit between bufio's 64 KiB "+
						"default and the megabyte this call asks for, or it cannot tell them apart",
						info.Size())
				}
				reopened, err := OpenFileState(path)
				if err != nil {
					t.Fatalf("a journal whose line is %d bytes could not be reopened (%v) — the "+
						"scanner stops at its buffer limit, so the state would come back with the "+
						"nonces and quota of a shorter journal", info.Size(), err)
				}
				defer reopened.Close()
				if err := reopened.Reserve(context.Background(), wide); err != ErrReplay {
					t.Fatalf("the reopened state answered %v to a nonce the journal already records, "+
						"want ErrReplay — the line was not read back", err)
				}
			},
		},
		{
			file:     "load.go",
			where:    "Load, the document decoder",
			landmark: "func Load(reader io.Reader) ([]Policy, string, error) {",
			anchor:   "\tdecoder.DisallowUnknownFields()\n",
			dropped:  "the refusal of a policy document carrying a key this loader does not know",
			verdict:  verdictPinnedElsewhere,
			why: "Detected by TestPolicyLoaderRejectsUnknownFieldsAndTrailingDocuments once its " +
				"fixtures were repaired: both of them used an empty policy array, so the empty-policies " +
				"guard refused them whatever this call did. A key the loader does not understand is a " +
				"rule somebody wrote and nothing enforces.",
		},
		{
			file:     "state.go",
			where:    "Reserve, the fsync failure",
			landmark: "func (state *FileState) Reserve(ctx context.Context, reservation Reservation) error {",
			anchor:   "if err := state.file.Sync(); err != nil {\n\t\tstate.failed = true\n",
			dropped:  "the latch beside the fsync failure",
			verdict:  verdictMasked,
			why: "The only write fault this package can inject is a severed descriptor, and a severed " +
				"descriptor fails the Write immediately above as well -- which reports and latches " +
				"identically. Isolating this statement needs a fault where the write succeeds and the " +
				"fsync fails, which no filesystem here offers. The append-side latch IS covered, by " +
				"TestAJournalWriteFailureLatchesTheStateClosed.",
		},
		{
			file:     "state.go",
			where:    "VerifyState, the mark-presence seed",
			landmark: "switch _, statErr := os.Stat(path + highWaterSuffix); {",
			anchor:   "\tmarkFileExists := true\n",
			dropped:  "the initial value of the mark-presence flag",
			verdict:  verdictUndetectable,
			why: "A dead store. Both reachable arms of the switch below assign the flag and the third " +
				"returns, so the initialiser's value never survives to be read -- setting it to false " +
				"changes nothing about any input. Recorded rather than left as an unexplained " +
				"survivor, because the obvious reading of a `:= true` beside a switch is that it is " +
				"the default for a case nobody wrote, and it is not.",
			run: func(t *testing.T) {
				// Both reachable arms, exercised: the flag's value comes from the switch either way,
				// so neither answer depends on what it was initialised to.
				withMark := journalWith(t, 2)
				if _, err := VerifyState(withMark); err != nil {
					t.Fatalf("a journal with its mark present failed verification: %v", err)
				}
				withoutMark := journalWith(t, 2)
				if err := os.Remove(withoutMark + highWaterSuffix); err != nil {
					t.Fatal(err)
				}
				if _, err := VerifyState(withoutMark); err == nil {
					t.Fatal("a two-reservation journal with no mark verified clean — the absent arm " +
						"of the switch is not being taken, so this row is not exercising what it says")
				}
			},
		},
		{
			file:     "cosmos.go",
			where:    "parseSignDoc and decodeAny, the defensive copies",
			landmark: "func parseSignDoc(input []byte) (*CosmosTransaction, error) {",
			anchor:   "\t\t\tbodyBytes = append([]byte(nil), value...)\n",
			dropped:  "the copy of the walker's slice into the parser's own storage",
			verdict:  verdictUndetectable,
			why: "Both copies -- body_bytes here and the Any payload in decodeAny -- are defensive " +
				"against a future change rather than against a present one, and no test can tell " +
				"them from an alias today: nothing []byte-typed escapes ParseCosmosSignDoc. Every " +
				"field of the returned CosmosTransaction is a string or a uint64, and a Go string " +
				"conversion copies, so the caller's buffer is unreachable from the result whether the " +
				"copies are there or not. The row checks THAT property instead, because it is the one " +
				"that makes the copies redundant: the day a []byte field is added to the returned " +
				"type, the copies become load-bearing and this row fails.",
			run: func(t *testing.T) {
				var walk func(reflect.Type, string, map[reflect.Type]bool)
				var found []string
				walk = func(typ reflect.Type, path string, seen map[reflect.Type]bool) {
					if seen[typ] {
						return
					}
					seen[typ] = true
					switch typ.Kind() {
					case reflect.Ptr:
						walk(typ.Elem(), path, seen)
					case reflect.Slice, reflect.Array:
						if typ.Elem().Kind() == reflect.Uint8 {
							found = append(found, path)
							return
						}
						walk(typ.Elem(), path+"[]", seen)
					case reflect.Map:
						walk(typ.Elem(), path+"[k]", seen)
					case reflect.Struct:
						for index := 0; index < typ.NumField(); index++ {
							field := typ.Field(index)
							walk(field.Type, path+"."+field.Name, seen)
						}
					}
				}
				walk(reflect.TypeOf(&CosmosTransaction{}), "CosmosTransaction", map[reflect.Type]bool{})
				if len(found) != 0 {
					t.Fatalf("the parsed transaction now reaches raw bytes at %v — those bytes alias "+
						"the caller's buffer unless parseSignDoc and decodeAny copy, so the two "+
						"copies this row calls redundant have just become load-bearing and need "+
						"real detectors", found)
				}
			},
		},
	}
}

// The same drift guard the operand ledger uses: a statement that was edited or moved must break
// its row rather than leave it asserting about code that is gone.
func TestEveryStatementLedgerRowStillNamesLiveSource(t *testing.T) {
	rows := statementLedger()
	if len(rows) == 0 {
		t.Fatal("the ledger is empty — an empty ledger and a broken one look identical from here")
	}
	for _, row := range rows {
		source, err := os.ReadFile(row.file)
		if err != nil {
			t.Errorf("row %q names %s, which cannot be read: %v", row.where, row.file, err)
			continue
		}
		if count := strings.Count(string(source), row.landmark); count != 1 {
			t.Errorf("%s (%s): the landmark this row is anchored to occurs %d times, want exactly 1:\n%s",
				row.file, row.where, count, row.landmark)
		}
	}
}

func TestEveryStatementLedgerRowIsClassifiedAndExplained(t *testing.T) {
	known := map[string]bool{
		verdictCovered: true, verdictPinnedElsewhere: true, verdictUnreachable: true,
		verdictUndetectable: true, verdictMasked: true,
	}
	tally := map[string]int{}
	defer func() {
		t.Logf("statement ledger: %d rows — covered %d, pinned-elsewhere %d, masked %d, "+
			"unreachable %d, undetectable %d", len(statementLedger()), tally[verdictCovered],
			tally[verdictPinnedElsewhere], tally[verdictMasked], tally[verdictUnreachable],
			tally[verdictUndetectable])
	}()
	for _, row := range statementLedger() {
		tally[row.verdict]++
		name := row.file + " " + row.where
		if !known[row.verdict] {
			t.Errorf("%s: verdict %q is not one of the five", name, row.verdict)
		}
		if row.dropped == "" {
			t.Errorf("%s: the row does not say what the mutation dropped", name)
		}
		if row.anchor == "" || row.landmark == "" {
			t.Errorf("%s: a row needs both the statement it mutated and a landmark to anchor on", name)
		}
		if len(row.why) < 80 {
			t.Errorf("%s: the explanation is %d characters — a verdict without a derivation is an "+
				"assertion", name, len(row.why))
		}
		if row.verdict == verdictCovered && row.run == nil {
			t.Errorf("%s: classified covered with nothing to run", name)
		}
		if row.verdict == verdictPinnedElsewhere && row.run != nil {
			t.Errorf("%s: classified pinned-elsewhere and carries a detector", name)
		}
	}
}

func TestStatementLedger(t *testing.T) {
	for _, row := range statementLedger() {
		if row.run == nil {
			continue
		}
		t.Run(row.file+": "+row.where, func(t *testing.T) { row.run(t) })
	}
}
