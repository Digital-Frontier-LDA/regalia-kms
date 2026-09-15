package approval

// A second mutation sweep over this package found two more refusals that nothing in the module
// detects. Each comment below records what the code does when the named guard -- or, where the
// claim is about one operand of a larger `||` chain, that operand alone -- is forced false, using
// the value the mutant was observed producing rather than a description of what it might do.
//
// The assertion style is the one guard_coverage_test.go's header states, for the same reason:
// Verify never reports a message for bad evidence, because an approval that fails a check is not
// an error, it is simply not an approver. There is no message to match on. What distinguishes a
// Verify case instead is the pair -- the evidence under test counts nobody, and a control that
// differs in exactly one respect counts the approver who signed it -- with the control placed
// AFTER the refusal per TESTING.md §18, so an anchor that fatals cannot foreclose the assertion
// it exists to support.
//
// The shared fixtures (binding, approver, sign, header) live in approval_test.go and keyFile /
// realApproverKey in guard_coverage_test.go; this file deliberately redefines none of them.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// AN OVERSIZED HEADER COUNTS NOBODY EVEN WHEN THE EVIDENCE INSIDE IT IS PERFECTLY GOOD.
//
// Verify refuses on `set == nil || header == "" || len(header) > MaxHeaderBytes`. The first two
// operands are covered (TestANilKeySetCountsNobody, and the "" entry in
// TestAMalformedHeaderVerifiesNobodyAndDoesNotPanic). THIS TEST COVERS THE THIRD OPERAND ONLY:
// the fixture is a header that is well-formed in every other respect, so nothing but the byte
// bound can refuse it.
//
// The existing suite cannot reach the operand. TestAMalformedHeaderVerifiesNobodyAndDoesNotPanic
// passes `strings.Repeat("A", MaxHeaderBytes+1)`, which is 16385 characters -- 16385 % 4 == 1, so
// base64.StdEncoding.DecodeString stops with `illegal base64 data at input byte 16384` after
// recovering 12288 bytes of nothing in particular. With the size operand forced false that header
// is still refused, by the decode-error guard, and the module stays green: the sweep observed
// TEST_EXIT=0 across all four packages with the operand dead.
//
// What the operand admits, forced false: a genuine approval by alice padded past the bound with
// legal JSON whitespace (`[{...}` + 14000 spaces + `]`, base64 length 19060 > MaxHeaderBytes
// 16384) was observed verifying as `[spiffe://regalia/approver/alice]` instead of `[]`. The bound
// is not decoration around a parse limit -- the docstring says why it exists ("without a bound,
// one request can ask the daemon to perform unlimited ed25519 verifications"), and with the
// operand dead the amplification was measured: a 10,667,060-byte header decoded and parsed in
// 43ms and a 64,000,396-byte one in 264ms, both fully base64-decoded and JSON-parsed BEFORE
// MaxApprovals is ever consulted. MaxApprovals bounds the list after the decode; only this
// operand bounds the decode.
func TestAnOversizedHeaderCountsNobodyEvenWhenItsEvidenceIsValid(t *testing.T) {
	alice, aliceKey, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	set := NewKeySet(map[string]ed25519.PublicKey{alice: alicePublic})

	evidence := sign(t, alice, aliceKey, binding(), binding())
	one, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	// Whitespace between the last element and the closing bracket is legal JSON, so padding
	// changes the header's LENGTH and nothing else about it: same single approval, same
	// signature, same binding.
	padded := func(spaces int) string {
		return base64.StdEncoding.EncodeToString([]byte("[" + string(one) + strings.Repeat(" ", spaces) + "]"))
	}

	// The premise, checked against the primitives rather than assumed: the padded header decodes
	// as base64 without error, and Verify's own decoder -- json with DisallowUnknownFields -- reads
	// the decoded bytes back as exactly the one approval that was signed. Every later refusal
	// inside Verify (decode error, JSON error, MaxApprovals, and each check in counts()) therefore
	// passes on this input, which is what makes the size bound its only possible refuser. If this
	// ever stops holding, some other guard does the refusing below and this test silently stops
	// covering the bound.
	onlySizeCanRefuse := func(t *testing.T, encoded string) {
		t.Helper()
		if len(encoded) <= MaxHeaderBytes {
			t.Fatalf("fixture premise broken: header is %d bytes, not over MaxHeaderBytes=%d — the "+
				"operand under test is false for this input", len(encoded), MaxHeaderBytes)
		}
		decoded, decodeErr := base64.StdEncoding.DecodeString(encoded)
		if decodeErr != nil {
			t.Fatalf("fixture premise broken: the padded header is not valid base64 (%v), so Verify's "+
				"decode-error guard refuses it and the size bound stays uncovered", decodeErr)
		}
		var list []Approval
		decoder := json.NewDecoder(strings.NewReader(string(decoded)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&list); err != nil {
			t.Fatalf("fixture premise broken: the decoded bytes do not parse under Verify's own "+
				"decoder (%v), so the JSON guard refuses this header and the size bound stays "+
				"uncovered", err)
		}
		if len(list) != 1 || list[0] != evidence {
			t.Fatalf("fixture premise broken: the padded header carries %d approvals and its first "+
				"entry %+v is not the signed evidence %+v — padding must change the length and "+
				"nothing else", len(list), list, evidence)
		}
	}

	for _, oversized := range []struct {
		what   string
		spaces int
	}{
		// The size the sweep measured: 19060 base64 bytes, a whisker over the 16384 bound.
		{"a header just past the bound", 14000},
		// Eighty-five times the bound. With the operand dead a header this shape is base64-decoded
		// and JSON-parsed in full before anything counts the list -- the amplification the bound
		// exists to prevent -- and the bound must not care how far past it the header is. The
		// sweep measured the same shape at 10 MB and 64 MB; a megabyte makes the point without
		// putting tens of megabytes through the race detector on every run.
		{"a header a megabyte past the bound", 1 << 20},
	} {
		t.Run(oversized.what, func(t *testing.T) {
			// Named to avoid shadowing the package's header() fixture helper.
			encoded := padded(oversized.spaces)
			onlySizeCanRefuse(t, encoded)

			// Verify reports no message for bad evidence by design (see this file's header
			// comment); the count is the assertion.
			if verified := set.Verify(encoded, binding()); len(verified) != 0 {
				t.Fatalf("DEFECT: a %d-byte header verified %v — MaxHeaderBytes=%d does not bound the "+
					"header, so an attacker-controlled string of any size is base64-decoded and "+
					"JSON-parsed before MaxApprovals is consulted", len(encoded), verified, MaxHeaderBytes)
			}
		})
	}

	// ANCHOR, after the refusals: the SAME approval with no padding must verify alice. It differs
	// from each case above only in the run of spaces before the closing bracket, which is what
	// attributes those refusals to the length and not to the signature, the binding, the base64 or
	// the JSON. Without it, both cases are equally consistent with a Verify that counts nobody.
	control := padded(0)
	if len(control) > MaxHeaderBytes {
		t.Fatalf("anchor failed: the unpadded control is itself %d bytes, over MaxHeaderBytes=%d, so "+
			"it is not a control for the bound", len(control), MaxHeaderBytes)
	}
	if verified := set.Verify(control, binding()); len(verified) != 1 || verified[0] != alice {
		t.Fatalf("anchor failed: the same approval unpadded verified %v, want [%s] — the refusals "+
			"above would then prove nothing about the header size", verified, alice)
	}
}

// AN UNCONFIGURED DEPLOYMENT HAS NO KEY SET, AND SOMETHING ASKS IT HOW MANY KEYS IT HAS.
//
// (*KeySet)(nil) is a value this system really produces, not a synthetic one: cmd/regalia-kms's
// preflight declares `var approverKeys *approval.KeySet` and leaves it nil when ApproverKeysPath
// is unset, main hands that nil to operations.New, and internal/operations' seal_separation_test
// constructs `(*approval.KeySet)(nil)` explicitly.
//
// Without the `if set == nil { return 0 }` guard, Len falls through to `return len(set.keys)`,
// which dereferences the nil receiver. Observed on the mutant: `(*KeySet)(nil).Len() PANICKED:
// runtime error: invalid memory address or nil pointer dereference`, re-panicked for the frame as
// `[signal SIGSEGV: segmentation violation code=0x2 addr=0x0]` inside
// `approval.(*KeySet).Len(...)`. Nothing in the module went red: the daemon's only Len call is
// preflight's note() of "approver key set loads, %d approvers", which sits inside the arm where
// the key set was just loaded successfully and is therefore never nil. The crash is reachable
// only from a caller that asks an UNCONFIGURED deployment for the count -- exactly the caller a
// health endpoint, a startup banner or a decision record would be.
//
// Scope: Digest carries the identical guard and is already covered by
// TestANilKeySetHasAnEmptyDigestAndDoesNotPanic in guard_coverage_test.go, so this test asserts
// Len alone. Asserting both in one place would leave neither guard with a sole detector.
//
// The panic is recovered deliberately. An unrecovered one takes the whole test binary down, which
// fails every other test in the package as collateral and makes "this test is the only detector"
// impossible to measure.
func TestANilKeySetReportsZeroLengthWithoutPanicking(t *testing.T) {
	var unconfigured *KeySet

	var length int
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("DEFECT: (*KeySet)(nil).Len() panicked: %v — an unconfigured deployment "+
					"crashes the daemon wherever anything counts the approver keys, and the "+
					"unconfigured case is precisely the one that has none", recovered)
			}
		}()
		length = unconfigured.Len()
	}()
	if length != 0 {
		t.Fatalf("(*KeySet)(nil).Len() = %d, want 0: a deployment with no approver key path has no "+
			"approver keys", length)
	}

	// ANCHOR, after the assertion: a configured key set reports its real count. Without it, the
	// zero above is equally consistent with a Len that always returns 0 -- which would make the
	// nil answer an accident rather than the deliberate "no keys are configured".
	alice, _, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	bob, _, bobPublic := approver(t, "spiffe://regalia/approver/bob")
	configured := NewKeySet(map[string]ed25519.PublicKey{alice: alicePublic, bob: bobPublic})
	if configured.Len() != 2 {
		t.Fatalf("anchor failed: a two-key set reported Len=%d, want 2, so the zero above says "+
			"nothing about the nil receiver", configured.Len())
	}
}
