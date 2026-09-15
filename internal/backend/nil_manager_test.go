package backend

import (
	"context"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// A NIL MANAGER MUST FAIL CLOSED, NOT PANIC.
//
// Ready guarded the nil receiver; Execute and Healthy did not. Execute is the one call that reaches
// the token, so a panic there is the worst of the three outcomes available — not fail-closed, but
// fail-unpredictable, unwinding through whatever the caller had in flight.
func TestNilManagerFailsClosedRatherThanPanicking(t *testing.T) {
	var manager *Manager
	if _, _, err := manager.Execute(context.Background(), registry.Route{}, "sign", "raw", "application/octet-stream", []byte("x"), nil); err == nil {
		t.Fatal("a nil manager executed an operation")
	}
	if manager.Healthy(context.Background(), registry.Binding{}) {
		t.Fatal("a nil manager reported a healthy backend")
	}
	if manager.Ready(context.Background()) {
		t.Fatal("a nil manager reported ready")
	}

	// A constructed manager with no providers must behave the same way.
	empty := &Manager{providers: nil}
	if _, _, err := empty.Execute(context.Background(), registry.Route{}, "sign", "raw", "application/octet-stream", []byte("x"), nil); err == nil {
		t.Fatal("a manager with no providers executed an operation")
	}
}
