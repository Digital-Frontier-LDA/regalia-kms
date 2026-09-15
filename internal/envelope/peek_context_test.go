package envelope

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func sealedFixture(t *testing.T, version string, createdAt time.Time) (Envelope, []byte) {
	t.Helper()
	keys := map[string][]byte{"company-kek:" + version: bytes.Repeat([]byte{1}, 32)}
	device := hardware("nitrokey-pkcs11", keys)
	sealed, err := Seal(context.Background(), device, KeyRef{Backend: device.Backend(), ID: "company-kek", Version: version},
		"deployment-api-token", ReleaseContext("deployment-api-token", "deploy", "production"),
		[]byte("top-secret-value"), rand.Reader, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := sealed.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return sealed, encoded
}

// Peek exists because the release path must choose a card before it can verify anything: the AEAD
// needs the data key, and getting the data key needs the card. So both the routing decision and the
// lifetime check read unverified bytes, and what Peek returns has to be exactly the two fields
// those decisions need — nothing that could be mistaken for a verified fact.
func TestPeekReportsTheGenerationAndTheSealTime(t *testing.T) {
	created := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	sealed, encoded := sealedFixture(t, "3", created)

	ref, sealedAt, err := Peek(encoded)
	if err != nil {
		t.Fatalf("Peek() error = %v", err)
	}
	if ref != sealed.KEK {
		t.Fatalf("Peek returned KEK %+v, want %+v", ref, sealed.KEK)
	}
	if !sealedAt.Equal(created) {
		t.Fatalf("Peek returned created_at %s, want %s — a lifetime bound measured from the wrong instant is not a bound", sealedAt, created)
	}
}

func TestPeekRefusesWhatParseRefuses(t *testing.T) {
	_, encoded := sealedFixture(t, "1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	for name, input := range map[string][]byte{
		"nothing at all":       nil,
		"not JSON":             []byte("{not an envelope"),
		"JSON that is not one": []byte(`{"version":1}`),
		"a truncated envelope": encoded[:len(encoded)/2],
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Peek(input); !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("Peek(%s) error = %v, want ErrInvalidEnvelope", name, err)
			}
		})
	}
}

// TestAnEnvelopeWithNoKEKVersionCannotBeParsedAtAll.
//
// Peek carries its own "names no KEK version" check, and that branch is UNREACHABLE: validateKeyRef
// requires the version to match keyVersionPattern, which the empty string does not, so Parse has
// already refused. The check is kept as defence in depth against Parse being relaxed, and this test
// pins the guarantee where it actually lives so a future reader is not misled about which layer is
// doing the work — the same shape as the empty-version guard in the registry's RouteForUnwrap.
//
// Asserted by editing the JSON directly, because no code path in this package will build one.
func TestAnEnvelopeWithNoKEKVersionCannotBeParsedAtAll(t *testing.T) {
	_, encoded := sealedFixture(t, "1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	var document map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	var kek map[string]any
	if err := json.Unmarshal(document["kek"], &kek); err != nil {
		t.Fatal(err)
	}
	if kek["version"] == "" {
		t.Fatal("the fixture already has no version, so this proves nothing")
	}
	kek["version"] = ""
	rewritten, err := json.Marshal(kek)
	if err != nil {
		t.Fatal(err)
	}
	document["kek"] = rewritten
	stripped, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Parse(stripped); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Parse accepted an envelope naming no KEK version: error = %v. Peek's own check is the only thing left standing between that and a route chosen by an empty string", err)
	}
	if _, _, err := Peek(stripped); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Peek() error = %v, want ErrInvalidEnvelope", err)
	}
}

// ReleaseContext is what an envelope is bound to. If two different (object, purpose, environment)
// triples could produce the same context, an envelope sealed for one would open under the other —
// so the separator matters, and it is the one thing about this function worth testing.
func TestReleaseContextCannotBeCollidedByMovingTheFieldBoundaries(t *testing.T) {
	// Each pair concatenates to the same string once the separators are removed. A context built
	// by joining with nothing, or with a character that can appear in a field, would return equal
	// bytes for both halves of any of these.
	for name, pair := range map[string][2][3]string{
		"object absorbs purpose":      {{"api", "token-deploy", "production"}, {"api-token", "deploy", "production"}},
		"purpose absorbs environment": {{"api", "deploy", "prod-uction"}, {"api", "deploy-prod", "uction"}},
		"everything in the first":     {{"apideployproduction", "", ""}, {"api", "deploy", "production"}},
	} {
		t.Run(name, func(t *testing.T) {
			first := ReleaseContext(pair[0][0], pair[0][1], pair[0][2])
			second := ReleaseContext(pair[1][0], pair[1][1], pair[1][2])
			if bytes.Equal(first, second) {
				t.Fatalf("%v and %v produce the same release context %q: an envelope sealed for one opens under the other",
					pair[0], pair[1], first)
			}
		})
	}
}

func TestReleaseContextIsVersionedAndStable(t *testing.T) {
	context := ReleaseContext("deployment-api-token", "deploy", "production")

	// Pinned literally. This value is baked into every envelope ever sealed, through the context
	// digest the content AEAD authenticates: changing the prefix, the separator or the field order
	// makes every existing envelope unopenable, which is not a refactor.
	want := "regalia-release-v1\x00deployment-api-token\x00deploy\x00production"
	if string(context) != want {
		t.Fatalf("ReleaseContext = %q, want %q — every envelope already sealed is bound to the old value", context, want)
	}
	if !bytes.Equal(context, ReleaseContext("deployment-api-token", "deploy", "production")) {
		t.Fatal("ReleaseContext is not deterministic")
	}
}
