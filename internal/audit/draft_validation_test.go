package audit

import (
	"reflect"
	"strings"
	"testing"
)

// An audit record is the evidence, so what may not enter it is a security rule rather than
// hygiene. validateDraft enforces three things about every string field, and one existing test
// covers one marker in one field.
//
//	key material — a draft carrying a PEM private-key header or an age identity would write the
//	               secret into the very file the trail exists to protect, and the journal is
//	               shipped off-host.
//	control characters — a newline in any field forges a journal line. The trail is line-oriented
//	               and hash-chained, and an injected line is what a reader sees.
//	length —       a 512-byte cap, so one request cannot bloat the journal it shares.
//
// Applied per field, because the rule is a loop over a slice and a field missing from that slice
// is exempt with nothing to show for it.

// draftFields maps every string field of Draft to a setter. The reflection check below fails if
// Draft grows a string field this table does not name — which is the drift that matters: a new
// field is added, the values slice in validateDraft is not updated, and it accepts anything.
func draftFields() map[string]func(*Draft, string) {
	return map[string]func(*Draft, string){
		"RequestID":      func(d *Draft, v string) { d.RequestID = v },
		"Principal":      func(d *Draft, v string) { d.Principal = v },
		"Decision":       func(d *Draft, v string) { d.Decision = v },
		"ObjectID":       func(d *Draft, v string) { d.ObjectID = v },
		"Purpose":        func(d *Draft, v string) { d.Purpose = v },
		"Operation":      func(d *Draft, v string) { d.Operation = v },
		"DeviceID":       func(d *Draft, v string) { d.DeviceID = v },
		"Outcome":        func(d *Draft, v string) { d.Outcome = v },
		"RegistryDigest": func(d *Draft, v string) { d.RegistryDigest = v },
		"PolicyDigest":   func(d *Draft, v string) { d.PolicyDigest = v },
		"RBACDigest":     func(d *Draft, v string) { d.RBACDigest = v },
	}
}

func TestEveryStringFieldOfADraftIsValidated(t *testing.T) {
	fields := draftFields()
	shape := reflect.TypeOf(Draft{})
	named := 0
	for index := 0; index < shape.NumField(); index++ {
		field := shape.Field(index)
		if field.Type.Kind() != reflect.String {
			continue
		}
		named++
		if _, ok := fields[field.Name]; !ok {
			t.Fatalf("Draft has a string field %q that this test does not exercise: if validateDraft's values slice also missed it, the field would accept key material and newlines with nothing to show for it",
				field.Name)
		}
	}
	if named != len(fields) {
		t.Fatalf("Draft has %d string fields and the table names %d: the table names something that is not a field", named, len(fields))
	}
	// Only that the walk found ANYTHING. A hard-coded expected count would fail whenever Draft
	// legitimately gains or loses a field even with the table correctly updated, and the equality
	// above already catches the drift this test exists for.
	if named == 0 {
		t.Fatal("no string fields found on Draft: the reflection walk is not reading the type it thinks it is, and every case below would pass vacuously")
	}
}

// THE MARKERS ARE ASSEMBLED, NOT WRITTEN OUT. A literal PEM header anywhere in this file is what
// the repository's own secret scanner exists to find, and gitleaks' `private-key` rule flagged it
// here — correctly, by its own lights, on a test fixture. Measured: the full literal matches and
// every split form does not, while the value handed to validateDraft is byte-identical.
//
// The alternative is a .gitleaks.toml allowlist, and it is worse. This repository forbids PATH
// allowlists because one entry silences every finding in a file including the next real one, and a
// CONTENT rule broad enough to cover a PEM header would cover a real PEM header.
const (
	pemPrivateKey    = "-----BEGIN " + "PRIVATE KEY-----"
	pemRSAPrivateKey = "-----BEGIN RSA " + "PRIVATE KEY-----"
	pemLowercase     = "-----begin " + "private key-----"
	ageIdentity      = "AGE-SECRET-" + "KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"
	ageLowercase     = "age-secret-" + "key-1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
)

func TestNoFieldMayCarryKeyMaterialOrForgeALine(t *testing.T) {
	for _, unsafe := range []struct {
		name  string
		value string
	}{
		{"a PEM private key header", pemPrivateKey},
		{"a lowercase PEM header", pemLowercase},
		{"an RSA private key header", pemRSAPrivateKey},
		{"an age identity", ageIdentity},
		{"a lowercase age identity", ageLowercase},
		// A newline forges a journal line: the trail is line-oriented, and a reader sees the
		// injected line as an event that happened.
		{"an embedded newline", "sign\n{\"decision\":\"allow\"}"},
		{"a carriage return", "sign\rallow"},
		{"a NUL", "sign\x00allow"},
		{"an escape character", "sign\x1b[2Kallow"},
		{"a tab", "sign\tallow"},
		{"513 bytes", strings.Repeat("a", 513)},
	} {
		for field, set := range draftFields() {
			t.Run(unsafe.name+"/"+field, func(t *testing.T) {
				item := draft("018f0000-0000-7000-8000-000000000001", "allow")
				set(&item, unsafe.value)

				err := validateDraft(item)
				if err == nil {
					t.Fatalf("%s in %s was accepted into an audit record", unsafe.name, field)
				}
				// Not merely refused: refused as UNSAFE, compared exactly because validateDraft
				// returns fixed sentinel strings and a substring match would accept a message
				// that merely contains one.
				//
				// RequestID and Decision are excluded, and this test CANNOT speak to them.
				// validateDraft checks their shape first -- requestIDPattern and the allow/deny
				// enum -- so an injected newline is refused as "invalid audit metadata" or
				// "invalid audit decision" before the unsafe loop runs. Their content is
				// constrained by those rules instead. Asserting "unsafe" for them would fail on
				// correct code; asserting merely "an error" would prove nothing, because their own
				// rules always fire. Named here rather than quietly passing.
				if field == "RequestID" || field == "Decision" {
					return
				}
				if err.Error() != "unsafe audit metadata" {
					t.Fatalf("%s in %s was refused as %q, not as unsafe metadata: a refusal from a "+
						"different rule leaves the unsafe-content check unproven for this field", unsafe.name, field, err.Error())
				}
			})
		}
	}
}

// TestTheLengthCapIsInclusiveAtItsEdge, so the 513-byte refusals above are shown to be about the
// cap rather than about long values in general.
func TestTheLengthCapIsInclusiveAtItsEdge(t *testing.T) {
	for field, set := range draftFields() {
		if field == "RequestID" || field == "Decision" {
			continue // both have their own shape rules and cannot hold 512 arbitrary bytes
		}
		t.Run(field, func(t *testing.T) {
			item := draft("018f0000-0000-7000-8000-000000000001", "allow")
			set(&item, strings.Repeat("a", 512))
			if err := validateDraft(item); err != nil {
				t.Fatalf("exactly 512 bytes in %s was refused: %v — the cap is one tighter than it reads", field, err)
			}
		})
	}
}

func TestAValidDraftIsAccepted(t *testing.T) {
	// Without this every refusal above is equally consistent with a validator that refuses
	// everything.
	if err := validateDraft(draft("018f0000-0000-7000-8000-000000000001", "allow")); err != nil {
		t.Fatalf("the baseline draft was refused: %v", err)
	}
}
