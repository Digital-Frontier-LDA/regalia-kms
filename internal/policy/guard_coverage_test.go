package policy

// BOUND COVERAGE (#237 class sweep, internal/policy): nine two-sided refusal bounds exist
// in the tree; five have at least one untested side, and three of those five are here. Each
// row below kills its own operand — polarity matched to the connective, per the harness
// notes that cost a re-run apiece: an operand of a refusing || is disabled with `false ||`,
// never `true &&`.
//
// The three findings, classified:
//
//   wire.go:42  end < offset — the OVERFLOW operand. Not a nicety: a wire-type-2 field
//              whose varint length is 2^63 makes int(length) negative and input[offset:end]
//              PANIC. The guard converts an attacker-triggered panic in a wire parser into
//              a refusal. Row asserts the refusal message; under mutation the test dies
//              with the slice-bounds panic, which is the consequence stated.
//   load.go:82  max_future_seconds — NEITHER side tested. Both rows here, plus the
//              boundary itself (3600 accepted), because a bound check that refuses 3600
//              is off by one and every row above would still pass.
//   cosmos.go:269  text[index] < '0' — NOT §17, and the interesting one: removing it does
//              not make "-5" ACCEPTED, it makes it refused BY ParseUint with the message
//              "exceeds the largest expressible per-transaction cap". The operand guards
//              the DIAGNOSIS, not the refusal — the same wrong-sentence class as #246,
//              and the row pins the message, not just the exit code.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// policyWithBound rewrites the shipped example's first policy to the requested bound and
// loads it, so the fixture cannot drift from what operators are told to copy.
func policyWithBound(t *testing.T, maxFuture int64) ([]Policy, string, error) {
	t.Helper()
	dir := t.TempDir()
	source, err := os.ReadFile(filepath.Join("..", "..", "config", "policy.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(source), `"max_future_seconds": 300`,
		`"max_future_seconds": `+strconv.FormatInt(maxFuture, 10), 1)
	if rewritten == string(source) {
		t.Fatal("fixture failed to rewrite the bound — the example moved and this row asserts nothing")
	}
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(rewritten), 0o644); err != nil {
		t.Fatal(err)
	}
	return LoadFile(path)
}

func TestMaxFutureSecondsBounds(t *testing.T) {
	t.Run("zero is refused by the lower operand", func(t *testing.T) {
		_, _, err := policyWithBound(t, 0)
		if err == nil || !strings.Contains(err.Error(), "between 1 and 3600") {
			t.Fatalf("max_future_seconds=0 loaded (err=%v) — a zero window authorises nothing and should say so", err)
		}
	})
	t.Run("3601 is refused by the upper operand", func(t *testing.T) {
		_, _, err := policyWithBound(t, 3601)
		if err == nil || !strings.Contains(err.Error(), "between 1 and 3600") {
			t.Fatalf("max_future_seconds=3601 loaded (err=%v) — an hour-plus window is outside the bound", err)
		}
	})
	t.Run("3600 itself is accepted — the bound is inclusive", func(t *testing.T) {
		policies, _, err := policyWithBound(t, 3600)
		if err != nil {
			t.Fatalf("max_future_seconds=3600 refused (err=%v) — the message promises 'between 1 and 3600' and 3600 is in it", err)
		}
		// The example carries four policies; the rewrite changed the first. Find it by
		// its bound rather than by position, so reordering the example cannot flip the
		// row into asserting about the wrong entry.
		for _, loaded := range policies {
			if loaded.MaxFuture == 3600*time.Second {
				return
			}
		}
		t.Fatalf("none of the %d loaded policies carries the rewritten bound", len(policies))
	})
}

func TestAnOverflowingLengthFieldIsRefusedNotPanicked(t *testing.T) {
	// The only fixture shape where end < offset is the SOLE objecting operand: a varint
	// length of 2^63. int(length) is then negative, end wraps below offset, the upper
	// operand (end > len(input)) is satisfied-BY-the-wrap (a negative end is not greater
	// than the buffer), and without the lower operand input[offset:end] panics with slice
	// bounds — in a parser reading attacker-supplied bytes.
	huge := append(append(encodeTag(1, 2), encodeVarint(1<<63)...), []byte("body")...)
	_, err := ParseCosmosSignDoc(huge)
	if err == nil || !strings.Contains(err.Error(), "exceeds buffer") {
		t.Fatalf("an overflowing length field was not refused as such (err=%v) — the overflow operand is the one that turns a panic into a refusal", err)
	}
}

func TestANegativeAmountGetsTheRightDiagnosis(t *testing.T) {
	// cosmos.go:269's lower operand does not guard the REFUSAL of "-5" — ParseUint
	// refuses it downstream — it guards the DIAGNOSIS. Without it, a signer presenting
	// Coin.amount "-5" is told the value "exceeds the largest expressible per-transaction
	// cap", which sends an operator to inspect an encoder for a non-negative-int bug the
	// document does not have. The row pins the message.
	_, err := decodeCoinAmount("-5")
	if err == nil || !strings.Contains(err.Error(), "is not a decimal integer") {
		t.Fatalf("a negative amount was misdiagnosed (err=%v) — 'not a number' and 'exceeds any cap' send an operator to different places", err)
	}
	// And the byte-quoting claim the function makes: the error must carry the ACTUAL text.
	if !strings.Contains(err.Error(), `"-5"`) {
		t.Fatalf("the diagnosis does not quote the offending text: %v", err)
	}
}

func TestAnUnknownSignDocFieldIsRefused(t *testing.T) {
	// C97 from the broad pass: an unexpected top-level field was silently accepted —
	// `return nil` for the refusal. Consequence: two SignDocs that hash differently parse
	// identically, because a field no conforming encoder emits is dropped on the floor.
	// That is the malleability the duplicate-scalar and canonicality rules in this file
	// exist to prevent, arriving through the front door.
	base := encodeValidSignDoc(t)
	withExtra := append(append([]byte(nil), base...), encodeString(5, "unexpected")...)
	_, err := ParseCosmosSignDoc(withExtra)
	if err == nil || !strings.Contains(err.Error(), "unexpected field") {
		t.Fatalf("an unknown top-level field was not refused AS unknown (err=%v) — two documents that hash differently must not parse identically", err)
	}
}

func encodeValidSignDoc(t *testing.T) []byte {
	t.Helper()
	// A COMPLETE SignDoc: body_bytes(1), auth_info_bytes(2), chain_id(3),
	// account_number(4). The first version omitted chain_id, so the row was red by the
	// missing-required rule under mutation AND on clean code — a wrong detector in the
	// row written for a wrong-detector finding, caught because the mutation survived.
	body := encodeLengthDelimited(1, encodeAny("/cosmos.bank.v1beta1.MsgSend", encodeString(2, "cosmos1target")))
	return append(append(append(append([]byte(nil),
		encodeLengthDelimited(1, body)...),
		encodeLengthDelimited(2, nil)...),
		encodeString(3, "test-chain")...),
		encodeTopVarint(4, 1)...)
}

func TestASchemaVersionOtherThanOneIsRefused(t *testing.T) {
	// L78 from the broad pass: neither the schema version nor the empty-policies half
	// had a detector. A schema_version the loader has never heard of must refuse rather
	// than load under whatever rules happen to apply — version N+1 may carry meanings
	// this loader would silently misread.
	source, err := os.ReadFile(filepath.Join("..", "..", "config", "policy.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(source), `"schema_version": 1`, `"schema_version": 2`, 1)
	if rewritten == string(source) {
		t.Fatal("fixture failed to rewrite the schema version — the example moved")
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(rewritten), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadFile(path); err == nil {
		t.Fatal("a schema_version=2 policy loaded — an unknown version is not 'anything goes'")
	}
	// Direct empty-policies shape: the version refusal must not be the only thing
	// standing between an emptied file and a clean load.
	emptyDoc := `{"schema_version": 1, "policies": []}`
	if err := os.WriteFile(path, []byte(emptyDoc), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadFile(path); err == nil {
		t.Fatal("a policy document with no policies loaded — an empty ruleset is not a configuration")
	}
}
