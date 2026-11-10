package registry

import (
	"strings"
	"testing"
)

// A SECRET'S KEK MUST NOT BE REACHABLE THROUGH ANOTHER OBJECT'S UNWRAP (regalia-kms-091).
//
// release-secret is refused to agents (sv3.2) and is granted per object, but unwrap returns a
// data key to its caller. If an object that declares unwrap is bound to the same physical key as a
// secret's KEK, anyone granted that unwrap -- an agent included -- opens the secret's wrapped data
// key without a release-secret grant. The declared-slot rule ("hardware slot is also assigned")
// compares device_id strings, so it is passed by naming one card twice, or by pinning one public
// key under two coordinates. These cases are the physical identities the drivers resolve by.
func TestASecretKEKIsNotSharedWithAnObjectThatDeclaresUnwrap(t *testing.T) {
	const keyA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const keyB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	type slot struct{ device, serial, objectID, label, publicKey, state string }
	binding := func(s slot, kek bool) string {
		fields := `"site":"sitea","backend":"nitrokey-pkcs11","device_id":"` + s.device + `","object_id":"` + s.objectID + `",` +
			`"public_fingerprint":"` + keyA + `"`
		if s.state == "" {
			s.state = "planned"
		}
		fields += `,"state":"` + s.state + `"`
		if s.serial != "" {
			fields += `,"device_serial":"` + s.serial + `"`
		}
		if s.label != "" {
			fields += `,"token_label":"` + s.label + `"`
		}
		if s.publicKey != "" {
			fields += `,"public_key_sha256":"` + s.publicKey + `"`
		}
		if kek {
			fields += `,"kek_algorithm":"rsa2048","kek_version":"1"`
		}
		return "{" + fields + "}"
	}
	// object() is a production key, which needs two bindings; one is enough to share a KEK.
	staging := func(document string) string {
		return strings.Replace(document, `"environment":"production"`, `"environment":"staging"`, 1)
	}
	load := func(secret slot, otherOperation string, other slot) error {
		objects := r4object("secret", "release-purpose", "release-secret", binding(secret, true)) + "," +
			staging(object("other", "other-purpose", "rsa2048", otherOperation, binding(other, false)))
		_, err := Load(strings.NewReader(manifest(objects)), "sitea", &healthMap{states: map[string]bool{"nk-1": true, "nk-2": true}})
		return err
	}
	secret := slot{device: "nk-1", serial: "S1", objectID: "01", publicKey: keyA}

	for name, other := range map[string]slot{
		"another card":                    {device: "nk-2", serial: "S2", objectID: "01", publicKey: keyB},
		"another key on the same card":    {device: "nk-2", serial: "S1", objectID: "02", publicKey: keyB},
		"an unpinned card with no serial": {device: "nk-2", objectID: "01"},
	} {
		if err := load(secret, "unwrap", other); err != nil {
			t.Fatalf("%s: a distinct key was refused: %v", name, err)
		}
	}
	// Two labelled tokens of one card are two keys under one object id.
	labelled := secret
	labelled.label = "Token one"
	if err := load(labelled, "unwrap", slot{device: "nk-2", serial: "S1", objectID: "01", label: "Token two", publicKey: keyB}); err != nil {
		t.Fatalf("the other token of the same card was refused: %v", err)
	}
	// The rule is about unwrap. A sign key that aliases a secret's KEK cannot return a data key;
	// refusing it would be a different rule (and would refuse TestRoutedToListsTheObjectsOfOneBackend's
	// fixture, which binds one card under two device ids on purpose).
	if err := load(secret, "sign", slot{device: "nk-2", serial: "S1", objectID: "01", publicKey: keyA}); err != nil {
		t.Fatalf("a sign key aliasing a secret's KEK was refused: %v", err)
	}

	for name, other := range map[string]slot{
		"the same card under another device id": {device: "nk-2", serial: "S1", objectID: "01", publicKey: keyB},
		"the same card, unlabelled":             {device: "nk-2", serial: "S1", objectID: "01", label: "", publicKey: ""},
		"the same public key elsewhere":         {device: "nk-2", serial: "S2", objectID: "09", publicKey: keyA},
		// An unlabelled binding may resolve to either token of the card, as in the declared-slot rule.
		"a labelled token of the same card": {device: "nk-2", serial: "S1", objectID: "01", label: "Other token", publicKey: keyB},
	} {
		err := load(secret, "unwrap", other)
		if err == nil || !strings.Contains(err.Error(), "declares unwrap") {
			t.Fatalf("%s: a secret's KEK shared with an unwrap object loaded (err = %v)", name, err)
		}
	}
	// The order of the objects in the manifest must not decide the verdict.
	objects := staging(object("other", "other-purpose", "rsa2048", "unwrap", binding(slot{device: "nk-2", serial: "S1", objectID: "01"}, false))) + "," +
		r4object("secret", "release-purpose", "release-secret", binding(secret, true))
	if _, err := Load(strings.NewReader(manifest(objects)), "sitea", &healthMap{states: map[string]bool{"nk-1": true, "nk-2": true}}); err == nil || !strings.Contains(err.Error(), "declares unwrap") {
		t.Fatalf("unwrap object listed first: the shared KEK loaded (err = %v)", err)
	}
	// A seal-envelope object's envelopes are opened with the same key, so it is a secret here too.
	sealer := slot{device: "nk-1", serial: "S1", objectID: "01", publicKey: keyA, state: "active"}
	seal := func(other slot) error {
		objects := r4object("sealer", "release-purpose", "seal-envelope", binding(sealer, true)) + "," +
			staging(object("other", "other-purpose", "rsa2048", "unwrap", binding(other, false)))
		_, err := Load(strings.NewReader(manifest(objects)), "sitea", &healthMap{states: map[string]bool{"nk-1": true, "nk-2": true}})
		return err
	}
	if err := seal(slot{device: "nk-2", serial: "S2", objectID: "01", publicKey: keyB}); err != nil {
		t.Fatalf("seal-envelope control: a distinct key was refused: %v", err)
	}
	if err := seal(slot{device: "nk-2", serial: "S1", objectID: "01", publicKey: keyB}); err == nil || !strings.Contains(err.Error(), "declares unwrap") {
		t.Fatalf("a seal-envelope KEK shared with an unwrap object loaded (err = %v)", err)
	}
	// The declared-slot rule still answers the plain case first.
	if err := load(secret, "unwrap", slot{device: "nk-1", serial: "S1", objectID: "01"}); err == nil || !strings.Contains(err.Error(), "also assigned to") {
		t.Fatalf("the same declared slot loaded (err = %v)", err)
	}

	// REVIEW F1: the driver hex-decodes object_id, so "0a" and "0A" are one CKA_ID. Case A: the
	// secret pins its key and the unwrap binding re-cases the object id. Case B: the secret pins
	// DevAut only and the unwrap binding pins the real key. Both loaded at 99e15fde.
	devautOnly := slot{device: "nk-1", serial: "S1", objectID: "0a"}
	for name, pair := range map[string][2]slot{
		"A: the secret pins its key, the unwrap object re-cases object_id": {
			{device: "nk-1", serial: "S1", objectID: "0a", publicKey: keyA}, {device: "nk-2", serial: "S1", objectID: "0A"}},
		"B: the secret pins DevAut only, the unwrap object re-cases object_id and pins the key": {
			devautOnly, {device: "nk-2", serial: "S1", objectID: "0A", publicKey: keyA}},
	} {
		if err := load(pair[0], "unwrap", pair[1]); err == nil || !strings.Contains(err.Error(), "lowercase hex") {
			t.Fatalf("%s: loaded (err = %v)", name, err)
		}
	}
	// B': the same pair spelled the same way was already refused, and still is.
	if err := load(devautOnly, "unwrap", slot{device: "nk-2", serial: "S1", objectID: "0a", publicKey: keyA}); err == nil || !strings.Contains(err.Error(), "declares unwrap") {
		t.Fatalf("B': a shared KEK spelled one way loaded (err = %v)", err)
	}
	// With no pin on either side, only the physical coordinate says it is one key.
	if err := load(devautOnly, "unwrap", slot{device: "nk-2", serial: "S1", objectID: "0a"}); err == nil || !strings.Contains(err.Error(), "declares unwrap") {
		t.Fatalf("the same card, neither binding pinning a key: loaded (err = %v)", err)
	}

	// REVIEW F2: a secret that pins DevAut only has no key of its own to compare. If another object
	// pins the key in the secret's slot, an unwrap binding pinning that key on another card reaches
	// it. The sign object is the alias the first block allows; it is what tells the manifest which
	// key the secret's slot holds.
	three := func(signerKey string) error {
		objects := r4object("secret", "release-purpose", "release-secret", binding(devautOnly, true)) + "," +
			staging(object("signer", "sign-purpose", "rsa2048", "sign", binding(slot{device: "nk-3", serial: "S1", objectID: "0a", publicKey: signerKey}, false))) + "," +
			staging(object("other", "other-purpose", "rsa2048", "unwrap", binding(slot{device: "nk-2", serial: "S2", objectID: "09", publicKey: keyA}, false)))
		_, err := Load(strings.NewReader(manifest(objects)), "sitea", &healthMap{states: map[string]bool{"nk-1": true, "nk-2": true, "nk-3": true}})
		return err
	}
	if err := three(keyB); err != nil {
		t.Fatalf("F2 control: the secret's slot pinned to another key was refused: %v", err)
	}
	if err := three(keyA); err == nil || !strings.Contains(err.Error(), "declares unwrap") {
		t.Fatalf("F2: an unwrap binding pinning the key another object pins in the secret's slot loaded (err = %v)", err)
	}
}
