package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// appletRegistry loads a one-object manifest bound to the OpenPGP applet. The algorithm, the
// operations and the three binding fields the startup check reads are the caller's; everything else
// is a servable binding.
func appletRegistry(t *testing.T, algorithm, operations, serial, label, pin string) *registry.Registry {
	t.Helper()
	optional := ""
	if serial != "" {
		optional += fmt.Sprintf(`"device_serial":%q,`, serial)
	}
	if label != "" {
		optional += fmt.Sprintf(`"token_label":%q,`, label)
	}
	if pin != "" {
		optional += fmt.Sprintf(`"public_key_sha256":%q,`, pin)
	}
	manifest := fmt.Sprintf(`{"schema_version":1,"manifest_id":"applet","generated_at":"2026-10-02T00:00:00Z","objects":[
	 {"id":"release-ed25519","name":"Release key","kind":"asymmetric-key","classification":"restricted","environment":"staging",
	  "owner":"release","purpose":"release-artifact","custody":"direct-hardware","algorithm":%q,"operations":[%s],"policy_id":"release",
	  "bindings":[{"site":"sitea","backend":"yubikey-openpgp","device_id":"yubikey-sitea","object_id":"01",%s
	    "public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"active","pin_policy":"once","touch_policy":"never"}],
	  "recovery":{"mode":"none","authority_id":"none","minimum_replicas":1,"status":"planned"},
	  "rotation":{"maximum_age_days":365,"last_rotated":null},
	  "migration":{"status":"planned","source":"new"},
	  "verification":{"status":"planned","last_verified":null,"evidence":"issue:541"}}]}`, algorithm, operations, optional)
	loaded, err := registry.Load(strings.NewReader(manifest), "sitea", nil)
	if err != nil {
		t.Fatalf("the fixture manifest does not load, so this test would check nothing: %v", err)
	}
	if routed := loaded.RoutedTo("yubikey-openpgp"); len(routed) != 1 {
		t.Fatalf("the fixture routes %d objects to the applet, want 1", len(routed))
	}
	return loaded
}

// A REGISTRY THE DAEMON CANNOT SERVE IS REFUSED AT STARTUP (regalia#541).
//
// The applet is served for signing, by token label, identified by its pinned public key. The
// manifest loader accepts bindings that miss each of these; left alone, they would fail one
// request at a time as a retryable error.
func TestAppletBindingsTheDaemonCannotServeAreRefusedAtStartup(t *testing.T) {
	const serial, label, pin = "000635718625", "OpenPGP card (User PIN (sig))", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := requireOpenPGPAppletBindingsAreServable(appletRegistry(t, "ed25519", `"sign"`, serial, label, pin)); err != nil {
		t.Fatalf("a servable applet binding was refused: %v", err)
	}
	for name, test := range map[string]struct {
		registry *registry.Registry
		reason   string
	}{
		// rsa4096 is the row of this backend that lists both sign and unwrap.
		"an operation other than sign": {appletRegistry(t, "rsa4096", `"sign","unwrap"`, serial, label, pin), "unwrap"},
		"a key that is not Ed25519":    {appletRegistry(t, "rsa4096", `"sign"`, serial, label, pin), "ed25519 only"},
		"no token label":               {appletRegistry(t, "ed25519", `"sign"`, serial, "", pin), "token_label"},
		"no pinned public key":         {appletRegistry(t, "ed25519", `"sign"`, serial, label, ""), "public_key_sha256"},
	} {
		err := requireOpenPGPAppletBindingsAreServable(test.registry)
		if err == nil || !strings.Contains(err.Error(), "release-ed25519") || !strings.Contains(err.Error(), test.reason) {
			t.Fatalf("%s: err = %v, want a refusal naming the object and %q", name, err, test.reason)
		}
	}
	// A registry with no applet object has nothing to refuse.
	if err := requireOpenPGPAppletBindingsAreServable(nil); err != nil {
		t.Fatalf("an empty registry was refused: %v", err)
	}
}
