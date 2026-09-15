package registry

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"
)

func manifestWithRotation(t *testing.T, rotation string) *Registry {
	t.Helper()
	manifest := fmt.Sprintf(`{
      "schema_version":1,"manifest_id":"rotation","generated_at":"2026-09-04T12:00:00Z",
      "objects":[{"id":"key","name":"K","kind":"asymmetric-key","classification":"restricted",
      "environment":"development","owner":"security","purpose":"signing","custody":"direct-hardware",
      "algorithm":"secp256k1","operations":["sign"],"policy_id":"p","bindings":[{"site":"sitea",
      "backend":"nitrokey-pkcs11","device_id":"d","device_serial":"serial-1",
      "devaut_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "object_id":"01","public_fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "state":"active"}],"recovery":{},"rotation":%s,"migration":{},
      "verification":{"status":"verified"}}]}`, rotation)
	registry, err := Load(bytes.NewBufferString(manifest), "sitea", healthyBackend{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return registry
}

type healthyBackend struct{}

func (healthyBackend) Healthy(context.Context, Binding) bool { return true }

// A ROTATION POLICY NOTHING ENFORCES IS WORSE THAN NONE, because it reads like a control.
// maximum_age_days and last_rotated were parsed as an opaque blob and never interpreted, so an
// object past its own declared deadline kept serving indefinitely.
func TestObjectPastItsDeclaredRotationDeadlineDoesNotRoute(t *testing.T) {
	rotated := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	registry := manifestWithRotation(t, fmt.Sprintf(`{"maximum_age_days":30,"last_rotated":%q}`,
		rotated.Format(time.RFC3339)))

	// One day before the deadline: still serving.
	registry.SetClock(func() time.Time { return rotated.AddDate(0, 0, 29) })
	if _, err := registry.Route(context.Background(), "key", "signing", "sign"); err != nil {
		t.Fatalf("refused before the deadline: %v", err)
	}

	// One day after: refused.
	registry.SetClock(func() time.Time { return rotated.AddDate(0, 0, 31) })
	route, err := registry.Route(context.Background(), "key", "signing", "sign")
	if err == nil {
		t.Fatal("an object past its rotation deadline still routed")
	}
	if !IsCode(err, CodeDenied) {
		t.Fatalf("err = %v, want a denial", err)
	}
	if route.ObjectID != "" {
		t.Fatal("a route was returned for an overdue object")
	}
}

// An overdue object must be visible BEFORE it starts refusing work.
func TestOverdueObjectsAreReportable(t *testing.T) {
	rotated := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	registry := manifestWithRotation(t, fmt.Sprintf(`{"maximum_age_days":30,"last_rotated":%q}`,
		rotated.Format(time.RFC3339)))

	if overdue := registry.OverdueObjects(rotated.AddDate(0, 0, 29)); len(overdue) != 0 {
		t.Fatalf("reported %v as overdue before the deadline", overdue)
	}
	overdue := registry.OverdueObjects(rotated.AddDate(0, 0, 31))
	if len(overdue) != 1 || overdue[0] != "key" {
		t.Fatalf("overdue = %v, want [key]", overdue)
	}
}

// A NULL last_rotated MEANS "NEVER ROTATED", which is not the same as "overdue": there is no
// instant to measure from. Refusing every never-rotated object would deny service for a fact the
// manifest itself records as unknown, so it is reportable but not enforced.
func TestManifestsWithoutAnEnforceableDeadlineKeepServing(t *testing.T) {
	cases := map[string]string{
		"never rotated":  `{"maximum_age_days":365,"last_rotated":null}`,
		"no maximum age": `{"maximum_age_days":0,"last_rotated":"2020-01-01T00:00:00Z"}`,
		"empty rotation": `{}`,
	}
	for name, rotation := range cases {
		t.Run(name, func(t *testing.T) {
			registry := manifestWithRotation(t, rotation)
			registry.SetClock(func() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) })
			if _, err := registry.Route(context.Background(), "key", "signing", "sign"); err != nil {
				t.Fatalf("refused an object with no enforceable deadline: %v", err)
			}
			if overdue := registry.OverdueObjects(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)); len(overdue) != 0 {
				t.Fatalf("reported %v as overdue with no enforceable deadline", overdue)
			}
		})
	}
}

// A malformed rotation block is a manifest error, not something to interpret loosely.
func TestMalformedRotationPolicyIsRejectedAtLoad(t *testing.T) {
	manifest := `{"schema_version":1,"manifest_id":"r","generated_at":"2026-09-04T12:00:00Z",
      "objects":[{"id":"key","name":"K","kind":"asymmetric-key","classification":"restricted",
      "environment":"development","owner":"security","purpose":"signing","custody":"direct-hardware",
      "algorithm":"secp256k1","operations":["sign"],"policy_id":"p","bindings":[{"site":"sitea",
      "backend":"nitrokey-pkcs11","device_id":"d","device_serial":"serial-1",
      "devaut_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "object_id":"01","public_fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "state":"active"}],"recovery":{},"rotation":{"maximum_age_days":"soon"},"migration":{},
      "verification":{"status":"verified"}}]}`
	if _, err := Load(bytes.NewBufferString(manifest), "sitea", healthyBackend{}); err == nil {
		t.Fatal("a malformed rotation policy loaded")
	}
}
