package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// envelopeMaxAge parses the bound #161 added and its own failure paths went untested, which is the
// ordinary way a new function arrives: the behaviour it enables is covered end to end and the
// parser's edges are not.
//
// It matters here because two of its answers look alike from outside. A rotation block that is
// ABSENT and one that omits the field both yield zero, meaning unbounded — and a manifest that is
// malformed must not also yield zero, because that would turn a broken policy into a silently
// disabled control.
func TestEnvelopeMaxAgeReadsDaysAndDefaultsToUnbounded(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want time.Duration
	}{
		{"no rotation block at all", "", 0},
		{"a rotation block without the field", `{"maximum_age_days":365,"last_rotated":null}`, 0},
		{"one day", `{"maximum_age_days":365,"last_rotated":null,"envelope_max_age_days":1}`, 24 * time.Hour},
		{"ninety days", `{"maximum_age_days":365,"last_rotated":null,"envelope_max_age_days":90}`, 90 * 24 * time.Hour},
		// A year and a day, to catch a parser that measured in hours or in weeks: those give
		// visibly different durations at this magnitude, where one day would not.
		{"three hundred and sixty-six days", `{"maximum_age_days":365,"last_rotated":null,"envelope_max_age_days":366}`, 366 * 24 * time.Hour},
	} {
		t.Run(test.name, func(t *testing.T) {
			var raw json.RawMessage
			if test.raw != "" {
				raw = json.RawMessage(test.raw)
			}
			got, err := envelopeMaxAge(raw)
			if err != nil {
				t.Fatalf("envelopeMaxAge() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("envelopeMaxAge() = %v, want %v", got, test.want)
			}
		})
	}
}

// A malformed or negative policy must be an error, never zero. Zero means unbounded, so returning
// it here would answer "this manifest is broken" with "this object's envelopes never expire".
func TestAnUnusableRotationBlockIsAnErrorRatherThanUnbounded(t *testing.T) {
	for _, test := range []struct {
		name  string
		raw   string
		wants string
	}{
		{"not JSON at all", `{`, "malformed"},
		{"a JSON array", `[1,2,3]`, "malformed"},
		{"the field as a string", `{"envelope_max_age_days":"ninety"}`, "positive integer of days"},
		// ZERO IS NOT "OFF". The schema and custody_manifest.py both require >= 1 when the field is
		// present, so a daemon that read zero as unbounded would start on a manifest CI rejects --
		// and the operator who wrote 0 meaning "disabled" would get exactly the control they were
		// trying to avoid, or not, depending on which tool looked at it.
		{"an explicit zero", `{"maximum_age_days":365,"last_rotated":null,"envelope_max_age_days":0}`, "positive integer of days"},
		// null is the OTHER way absent and present-but-unusable get confused. The schema says
		// integer and custody_manifest.py checks isinstance(value, int); both refuse null, so a
		// daemon reading it as "unbounded" would start on a manifest CI rejects. It is a field
		// someone began writing and did not finish, not a way to switch the bound off.
		{"an explicit null", `{"maximum_age_days":365,"last_rotated":null,"envelope_max_age_days":null}`, "positive integer of days"},
		{"a floating-point bound", `{"maximum_age_days":365,"last_rotated":null,"envelope_max_age_days":1.5}`, "positive integer of days"},
		{"a boolean bound", `{"maximum_age_days":365,"last_rotated":null,"envelope_max_age_days":true}`, "positive integer of days"},
		{"a negative bound", `{"maximum_age_days":365,"last_rotated":null,"envelope_max_age_days":-1}`, "positive integer of days"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := envelopeMaxAge(json.RawMessage(test.raw))
			if err == nil {
				t.Fatalf("envelopeMaxAge(%s) = %v with no error: a broken rotation policy reads as an object whose envelopes never expire", test.name, got)
			}
			if !strings.Contains(err.Error(), test.wants) {
				t.Fatalf("%s: error = %q, want it to mention %q", test.name, err, test.wants)
			}
			if got != 0 {
				t.Fatalf("%s returned %v alongside its error", test.name, got)
			}
		})
	}
}

// TestTheTwoRotationBoundsAreParsedIndependently. rotationDeadline and envelopeMaxAge read the same
// JSON object, and the whole point of #161 is that they are different bounds — a manifest setting
// one must not move the other.
func TestTheTwoRotationBoundsAreParsedIndependently(t *testing.T) {
	onlyEnvelope := json.RawMessage(`{"maximum_age_days":365,"last_rotated":null,"envelope_max_age_days":30}`)
	deadline, err := rotationDeadline(onlyEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if !deadline.IsZero() {
		t.Fatalf("rotationDeadline = %v for a policy with a null last_rotated: setting the envelope bound moved the object's deadline", deadline)
	}

	onlyObject := json.RawMessage(`{"maximum_age_days":30,"last_rotated":"2026-01-01T00:00:00Z"}`)
	age, err := envelopeMaxAge(onlyObject)
	if err != nil {
		t.Fatal(err)
	}
	if age != 0 {
		t.Fatalf("envelopeMaxAge = %v for a policy that sets only maximum_age_days: the object's deadline was read as an envelope bound", age)
	}
	deadline, err = rotationDeadline(onlyObject)
	if err != nil || deadline.IsZero() {
		t.Fatalf("rotationDeadline = %v, %v — the control case failed, so the independence above is unproven", deadline, err)
	}
}

// TestTheGoLoaderRefusesWhatTheSchemaRefuses reads the published schema rather than restating it.
//
// The Go loader, the JSON schema and custody_manifest.py all decide whether a manifest is
// acceptable, and a value two of them take and one rejects is the worst outcome: CI passes and the
// daemon will not start, or CI fails on a manifest the daemon would have served. This field has
// already been wrong in that direction once -- as a plain int, absent and zero were the same value
// to Go and different to the schema.
func TestTheGoLoaderRefusesWhatTheSchemaRefuses(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "config", "custody-manifest.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs struct {
			Rotation struct {
				Properties struct {
					EnvelopeMaxAgeDays struct {
						Minimum *int `json:"minimum"`
					} `json:"envelope_max_age_days"`
				} `json:"properties"`
				Required []string `json:"required"`
			} `json:"rotation"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(contents, &schema); err != nil {
		t.Fatal(err)
	}
	minimum := schema.Defs.Rotation.Properties.EnvelopeMaxAgeDays.Minimum
	if minimum == nil {
		t.Fatal("the schema publishes no minimum for envelope_max_age_days, so this test compares the loader against nothing")
	}
	for _, field := range schema.Defs.Rotation.Required {
		if field == "envelope_max_age_days" {
			t.Fatal("the schema requires envelope_max_age_days: the loader treats absence as unbounded, so the two now disagree about every existing manifest")
		}
	}

	// One below the published minimum must be refused, and the minimum itself accepted. Read from
	// the schema rather than written here, so raising the floor in one place fails here rather
	// than diverging silently.
	below := fmt.Sprintf(`{"maximum_age_days":365,"last_rotated":null,"envelope_max_age_days":%d}`, *minimum-1)
	if _, err := envelopeMaxAge(json.RawMessage(below)); err == nil {
		t.Fatalf("the loader accepted %d, one below the schema's minimum of %d", *minimum-1, *minimum)
	}
	at := fmt.Sprintf(`{"maximum_age_days":365,"last_rotated":null,"envelope_max_age_days":%d}`, *minimum)
	got, err := envelopeMaxAge(json.RawMessage(at))
	if err != nil {
		t.Fatalf("the loader refused the schema's minimum of %d: %v", *minimum, err)
	}
	if got != time.Duration(*minimum)*24*time.Hour {
		t.Fatalf("the schema's minimum parsed as %v, want %v", got, time.Duration(*minimum)*24*time.Hour)
	}
}
