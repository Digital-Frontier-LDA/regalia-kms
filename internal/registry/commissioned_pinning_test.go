package registry

// A COMMISSIONED NITROKEY MUST PIN ITS SERIAL AND ITS DevAut FINGERPRINT, and nothing tested
// that. Found by sweeping the surface every mutation sweep in this campaign structurally
// missed: guards whose condition spans MORE THAN ONE LINE. The enumerators all matched
// `if ... {` on a single line, so the multi-line ones were never enumerated at all.
//
// No count of them here. A census of how many such guards exist, or how many lack a detector, is
// true on the day it is taken and reads as current forever after — and a comment is the one venue
// that cannot carry the date honestly, because nothing re-runs it and the reader cannot tell when
// it was last true. To get the current answer, enumerate `if` lines whose condition is left open
// by a trailing && or || and defeat each whole guard in turn. The sibling files found the same
// way are compile_guards_test.go in internal/policy and binding_guard_test.go in
// internal/backend/nitrokey.
//
// It stayed invisible for a second reason worth naming: registry_test.go's `binding()` helper
// ALWAYS supplies device_serial and devaut_fingerprint for a commissioned nitrokey. Every
// fixture in the package satisfies the guard by construction, so no existing test could have
// reached it however it was written. A helper that makes the valid case convenient makes the
// invalid case unreachable.
//
// Each row violates exactly ONE part of the requirement — an absent serial, an absent
// fingerprint, or a fingerprint that is present but malformed — and asserts the message. The
// guard is an OR of two conditions, so a row that broke both would still pass with either
// operand deleted and would pin neither.

import (
	"encoding/json"
	"strings"
	"testing"
)

const commissionedFingerprint = `"devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"`

// nitrokeyBinding writes the binding JSON directly rather than through binding(), which cannot
// express a commissioned nitrokey missing either pin.
func nitrokeyBinding(site, device, extra string) string {
	return nitrokeyBindingWithPublic(site, device, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", extra)
}

func nitrokeyBindingWithPublic(site, device, public, extra string) string {
	return `{"site":"` + site + `","backend":"nitrokey-pkcs11","device_id":"` + device + `","object_id":"01",` +
		`"public_fingerprint":"` + public + `",` +
		`"state":"active"` + extra + `}`
}

// A production object needs TWO hardware bindings, so every case pairs the binding under test
// with a fully pinned sibling. My first version used one binding and all three rows were
// refused by the two-binding rule instead — which the message assertion caught and a bare
// `err != nil` would have hidden, leaving three rows that tested nothing.
const pinnedSibling = `,"device_serial":"siteb-serial",` + commissionedFingerprint

func TestACommissionedNitrokeyMustPinItsSerialAndFingerprint(t *testing.T) {
	// ADR-0002 D1: the card is proven by its serial plus EITHER a DevAut fingerprint OR
	// public_key_sha256 (the commissioned public key, enforced on every use), because a genuine
	// SmartCard-HSM cannot expose its DevAut through PKCS#11 (regalia#448). The advisory
	// public_fingerprint every binding carries does NOT stand in: its encoding was never defined.
	const pinRule = "pinned serial and DevAut fingerprint"
	for _, row := range []struct{ name, public, extra, want string }{
		{"no device serial", "sha256:" + strings.Repeat("a", 64), `,` + commissionedFingerprint, pinRule},
		{"no DevAut, and only the advisory public_fingerprint", "sha256:" + strings.Repeat("a", 64), `,"device_serial":"test-serial"`, pinRule},
		// A malformed pin is refused by the FORMAT rule, which fires in every state (nitrokeyPins).
		{"no DevAut, and a public_key_sha256 that is not a sha256 digest", "sha256:" + strings.Repeat("a", 64), `,"device_serial":"test-serial","public_key_sha256":"not-a-digest"`, "public_key_sha256 must be sha256"},
		{"a DevAut fingerprint that is not a sha256 digest", "sha256:" + strings.Repeat("a", 64), `,"device_serial":"test-serial","devaut_fingerprint":"not-a-digest"`, pinRule},
	} {
		t.Run(row.name, func(t *testing.T) {
			document := manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign",
				nitrokeyBindingWithPublic("sitea", "local-hsm", row.public, row.extra)+","+
					nitrokeyBinding("siteb", "remote-hsm", pinnedSibling)))
			_, err := Load(strings.NewReader(document), "sitea", &healthMap{states: map[string]bool{}})
			if err == nil {
				t.Fatal("a commissioned Nitrokey binding loaded without both pins — the manifest would name hardware it cannot prove it is talking to")
			}
			if !strings.Contains(err.Error(), row.want) {
				t.Fatalf("refused, but by a different rule: %v — this row exists to prove the commissioned-pinning guard fires, and any other refusal means it did not", err)
			}
		})
	}

	// KNOWN-GOOD IN THE SAME TEST (§18): both pins present and the manifest loads, so the rows
	// above are not passing against a loader that refuses every nitrokey binding.
	document := manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign",
		nitrokeyBinding("sitea", "local-hsm", `,"device_serial":"test-serial",`+commissionedFingerprint)+","+
			nitrokeyBinding("siteb", "remote-hsm", pinnedSibling)))
	if _, err := Load(strings.NewReader(document), "sitea", &healthMap{states: map[string]bool{}}); err != nil {
		t.Fatalf("a fully pinned commissioned Nitrokey was refused (%v) — the refusals above would prove nothing", err)
	}

	// THE D1 CASE: serial + commissioned public-key pin, no DevAut — how a real Nitrokey HSM 2 is
	// bound, since its DevAut is in EF 2F02. It must load.
	d1 := manifest(object("wallet-key", "cosmos-transaction", "secp256k1", "sign",
		nitrokeyBinding("sitea", "local-hsm", `,"device_serial":"test-serial","public_key_sha256":"sha256:`+strings.Repeat("c", 64)+`"`)+","+
			nitrokeyBinding("siteb", "remote-hsm", pinnedSibling)))
	if _, err := Load(strings.NewReader(d1), "sitea", &healthMap{states: map[string]bool{}}); err != nil {
		t.Fatalf("a Nitrokey pinned by serial and public_key_sha256 was refused (%v) — every genuine SmartCard-HSM would be unbindable (ADR-0002 D1)", err)
	}
}

// nitrokeyPins' two refusals that apply in EVERY state, not only commissioned ones (review of
// regalia-kms#26): a malformed public-key pin must not load even on a retired binding, where the
// daemon still reaches it for unwrap; and a public-key pin on a symmetric key can never be verified.
func TestAPublicKeyPinIsRefusedWhereItCanNeverBeChecked(t *testing.T) {
	pin := `"public_key_sha256":"sha256:` + strings.Repeat("c", 64) + `"`
	for _, row := range []struct{ name, state, algorithm, extra, want string }{
		{"a malformed pin on a retired binding", "retired", "secp256k1", `,"device_serial":"s","public_key_sha256":"not-a-digest"`, "public_key_sha256 must be sha256"},
		{"a pin on an AES object", "active", "aes-256", `,"device_serial":"s",` + pin, "symmetric key has no public half"},
	} {
		t.Run(row.name, func(t *testing.T) {
			raw := strings.Replace(nitrokeyBindingWithPublic("sitea", "local-hsm", "sha256:"+strings.Repeat("a", 64), row.extra),
				`"state":"active"`, `"state":"`+row.state+`"`, 1)
			var b Binding
			if err := json.Unmarshal([]byte(raw), &b); err != nil {
				t.Fatal(err)
			}
			err := validateBinding(b, row.algorithm, []string{"unwrap"})
			if err == nil || !strings.Contains(err.Error(), row.want) {
				t.Fatalf("err = %v, want it to contain %q", err, row.want)
			}
		})
	}
}
