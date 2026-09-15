package envelope

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// The validateEnvelopeMetadata guard has four operands. Three of them
// had no test in the module. Each test below rewrites the JSON to expose one operand
// alone and asserts Parse refuses it. Pinned by mutation, see PR body.
//
// The fourth operand, `!objectIDPattern.MatchString(envelope.ObjectID)`, is caught by
// TestSealAssembledRefusesANonHardwareBackendEvenWhenTheCiphertextAuthenticates/an_object_id_the_pattern_refuses,
// so this file does not duplicate it.
//
// All three rewrite top-level fields of an envelope produced by sealedFixture; no
// in-package path produces a malformed envelope, so the JSON is the only way to reach
// these leaves alive.

// The three guards are all FAIL-FAST IN FRONT OF A BINDING, not the binding itself.
// Measured for each by defeating the operand alone and re-driving Parse and Open:
//
//	[1] version rewritten to 1         Parse=OK    Open=ErrInvalidEnvelope (contentAAD refuses)
//	[3] algorithm rewritten             Parse=OK    Open=ErrInvalidEnvelope (contentAAD refuses)
//	[4] createdAt zeroed                Parse=OK    Open=ErrBackendUnavailable (wrapAAD refuses)
//
// Version and Algorithm live in contentAAD; an attacker rewriting
// those fields changes the AEAD tag input and the tag fails at Open. CreatedAt does
// NOT live in contentAAD but DOES live in wrapAAD, so its binding
// refuses one layer earlier — at the unwrap step, before content decrypt runs. The
// metadata guards exist to make Parse refuse the bad envelope before either binding
// runs; the bindings are the actual security boundary. Each test below pins the
// fail-fast line, not the binding.

// TestParseRefusesAnEnvelopeNamingACreatedAtBeforeTheClockStarted is the lead finding
// because it is the one whose binding sits in a different layer from the other two:
// wrapAAD rather than contentAAD. Removing the metadata guard does not bypass the
// wrapAAD refusal — the unwrap still fails — but Parse is no longer where an
// operator sees the envelope rejected, and the lifetime bound measured from Peek's
// return value would see an envelope with no creation instant.
func TestParseRefusesAnEnvelopeNamingACreatedAtBeforeTheClockStarted(t *testing.T) {
	// ANCHOR: a freshly-sealed envelope must Parse cleanly, or a Parse that refused
	// everything would satisfy the gate below.
	_, encoded := sealedFixture(t, "1", time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC))
	if _, err := Parse(encoded); err != nil {
		t.Fatalf("anchor: Parse(envelope) = %v, want nil — a Parse that refused everything would satisfy the gate below", err)
	}

	// GATE: rewrite created_at to the Go zero value. The RFC3339 encoding is what
	// json.Marshal emits for time.Time{}, and what Parse accepts back; rewriting the
	// field to it is the smallest possible change.
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	document["created_at"], _ = json.Marshal("0001-01-01T00:00:00Z")
	rewritten, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Parse(rewritten); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Parse accepted an envelope naming a zero CreatedAt: error = %v — without the CreatedAt operand in validateEnvelopeMetadata, an envelope with no createdAt parses and Peek returns time.Time{}, leaving the lifetime bound measuring from the zero instant",
			err)
	}
}

// TestParseRefusesAnEnvelopeClaimingAPriorVersion. validateEnvelopeMetadata's `Version` operand
// `envelope.Version != Version` is the only Parse-time check that refuses a
// wire-incompatible prior version. Version is in contentAAD, so the
// AEAD tag check at Open refuses a v1 envelope regardless of this guard — measured by
// defeating [1] alone: Parse returns nil and Open returns ErrInvalidEnvelope. The
// metadata guard exists to make Parse refuse first.
func TestParseRefusesAnEnvelopeClaimingAPriorVersion(t *testing.T) {
	// ANCHOR.
	_, encoded := sealedFixture(t, "1", time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC))
	if _, err := Parse(encoded); err != nil {
		t.Fatalf("anchor: Parse(envelope) = %v, want nil — a Parse that refused everything would satisfy the gate below", err)
	}

	// GATE: rewrite the version field. The wire format this code no longer speaks is the
	// one the version guard exists to refuse; if the field still parses, the check is gone.
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	priorVersion := Version - 1
	document["version"], _ = json.Marshal(priorVersion)
	rewritten, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Parse(rewritten); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Parse accepted an envelope claiming version %d: error = %v — without the version operand in validateEnvelopeMetadata, the prior-version envelope parses and only the contentAAD AEAD tag mismatch at Open time catches it",
			priorVersion, err)
	}
}

// TestParseRefusesAnEnvelopeNamingAnAlgorithmThisVersionWillNotDecrypt.
// validateEnvelopeMetadata's `Algorithm` operand `envelope.Algorithm != "AES-256-GCM"` is the
// only Parse-time check that refuses an envelope whose algorithm field names a cipher
// the code does not implement. Algorithm is in contentAAD, so the
// AEAD tag check at Open refuses a wrong-algorithm envelope regardless of this guard —
// measured by defeating [3] alone: Parse returns nil and Open returns ErrInvalidEnvelope.
// The metadata guard exists to make Parse refuse first.
func TestParseRefusesAnEnvelopeNamingAnAlgorithmThisVersionWillNotDecrypt(t *testing.T) {
	// ANCHOR.
	_, encoded := sealedFixture(t, "1", time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC))
	if _, err := Parse(encoded); err != nil {
		t.Fatalf("anchor: Parse(envelope) = %v, want nil — a Parse that refused everything would satisfy the gate below", err)
	}

	// GATE: rewrite the algorithm field to one the code does not implement. Anything other
	// than "AES-256-GCM" exercises the same operand; a name that LOOKS plausible is the one
	// an operator rewriting JSON would choose, so we use it.
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	foreignAlgorithm := "AES-128-GCM"
	document["algorithm"], _ = json.Marshal(foreignAlgorithm)
	rewritten, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Parse(rewritten); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Parse accepted an envelope claiming algorithm %q: error = %v — without the algorithm operand in validateEnvelopeMetadata, an envelope can name a cipher the code does not implement and only the contentAAD AEAD step catches it",
			foreignAlgorithm, err)
	}
}
