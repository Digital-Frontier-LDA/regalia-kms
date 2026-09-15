package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// reportingState implements the optional readyState interface; silentState deliberately does not.
// The distinction is the whole subject of Engine.Ready.
type reportingState struct {
	reservationState
	ready bool
}

func (state *reportingState) Ready(context.Context) bool { return state.ready }

type silentState struct{ reservationState }

// TestAnEngineIsNotReadyUnlessItsStateSaysSo.
//
// Readiness gates serving. Engine.Ready returns true only when the durable state both implements
// readyState AND reports ready — so a state that cannot answer the question is treated as not
// ready, rather than as ready by omission.
//
// That is the fail-closed direction and it is not the obvious one to write: `ok && state.Ready()`
// reads like a nil-guard, and `!ok || state.Ready()` would look just as reasonable while meaning
// that a state which cannot report is assumed fine. The daemon would then serve while its quota
// and replay journal were in an unknown condition.
func TestAnEngineIsNotReadyUnlessItsStateSaysSo(t *testing.T) {
	for _, test := range []struct {
		name  string
		state State
		ready bool
	}{
		{"a state reporting ready", &reportingState{ready: true}, true},
		{"a state reporting not ready", &reportingState{ready: false}, false},
		{"a state that cannot report at all", &silentState{}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine, err := New([]Policy{basePolicy()}, test.state, func() time.Time { return time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC) })
			if err != nil {
				t.Fatal(err)
			}
			if got := engine.Ready(context.Background()); got != test.ready {
				t.Fatalf("Ready() = %v with %s, want %v", got, test.name, test.ready)
			}
		})
	}
}

func TestAnEngineWithNoPoliciesIsNeverReady(t *testing.T) {
	// New refuses to build one, so the only way to hold an engine with no policies is the nil
	// engine — and a nil receiver must answer false rather than panic, because readiness is polled
	// from the health endpoint before everything is necessarily wired.
	var engine *Engine
	if engine.Ready(context.Background()) {
		t.Fatal("a nil engine reports itself ready")
	}
	if _, err := New(nil, &reportingState{ready: true}, func() time.Time { return time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC) }); err == nil {
		t.Fatal("New built an engine with no policies")
	}
}

// TestGoverningPolicyIDResolvesByObjectAndOperationTogether. Preflight prints this to tell an
// operator which policy will actually apply. One object can carry different policies per operation,
// so a reporter keyed on the object alone would name the wrong one — and it would name it
// confidently, which is worse than saying nothing.
func TestGoverningPolicyIDResolvesByObjectAndOperationTogether(t *testing.T) {
	wrap := basePolicy()
	wrap.ID, wrap.Operation, wrap.Cosmos = "wrap-policy", "wrap", nil
	unwrap := basePolicy()
	unwrap.ID, unwrap.Operation, unwrap.Cosmos = "unwrap-policy", "unwrap", nil

	engine, err := New([]Policy{wrap, unwrap}, &reportingState{ready: true}, func() time.Time { return time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		operation string
		want      string
	}{
		{"wrap", "wrap-policy"},
		{"unwrap", "unwrap-policy"},
	} {
		got, ok := engine.GoverningPolicyID(wrap.ObjectID, test.operation)
		if !ok {
			t.Fatalf("no policy reported for %s", test.operation)
		}
		if got != test.want {
			t.Fatalf("%s is governed by %q, want %q: the reporter is keyed on the object alone", test.operation, got, test.want)
		}
	}

	if id, ok := engine.GoverningPolicyID(wrap.ObjectID, "sign"); ok {
		t.Fatalf("an operation with no policy reported %q: preflight would show a grant nobody wrote", id)
	}
	if id, ok := engine.GoverningPolicyID("another-object", "wrap"); ok {
		t.Fatalf("another object reported %q under this object's policy", id)
	}
	var nilEngine *Engine
	if _, ok := nilEngine.GoverningPolicyID(wrap.ObjectID, "wrap"); ok {
		t.Fatal("a nil engine reported a governing policy")
	}
}

// TestThePolicyFileMustNotBeWritableByAnyoneElse. The policy decides what every key may be used
// for, and the daemon reads it once at startup. A file another user can rewrite is a policy they
// author.
func TestThePolicyFileMustNotBeWritableByAnyoneElse(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "policy.json")
	contents, err := os.ReadFile(filepath.Join("..", "..", "config", "policy.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}

	policies, digest, err := LoadFile(path)
	if err != nil || len(policies) == 0 || digest == "" {
		t.Fatalf("the shipped example failed to load: %d policies, digest %q, err %v", len(policies), digest, err)
	}

	for _, test := range []struct {
		name string
		mode os.FileMode
	}{
		{"group-writable", 0o620},
		{"world-writable", 0o602},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			_, _, err := LoadFile(path)
			if err == nil {
				t.Fatalf("a %s policy loaded: whoever can write it decides what every key may be used for", test.name)
			}
			if !strings.Contains(err.Error(), "non-writable regular file") {
				t.Fatalf("%s: error = %q, want the writability refusal", test.name, err)
			}
		})
	}

	t.Run("readable by others is fine", func(t *testing.T) {
		// The policy is an authority, not a secret — the same distinction the RBAC loader makes.
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadFile(path); err != nil {
			t.Fatalf("a world-readable policy was refused: %v — the refusals above would then be about existence, not writability", err)
		}
	})

	t.Run("a directory is not a policy", func(t *testing.T) {
		_, _, err := LoadFile(directory)
		if err == nil {
			t.Fatal("a directory loaded as a policy")
		}
		if !strings.Contains(err.Error(), "non-writable regular file") {
			t.Fatalf("error = %q, want the regular-file refusal — refused by the read instead leaves that rule unproven", err)
		}
	})

	t.Run("a missing policy", func(t *testing.T) {
		if _, _, err := LoadFile(filepath.Join(directory, "absent.json")); err == nil {
			t.Fatal("a missing policy loaded: the daemon would start governed by nothing")
		}
	})
}
