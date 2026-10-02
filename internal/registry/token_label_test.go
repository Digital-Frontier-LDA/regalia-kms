package registry

import (
	"encoding/json"
	"strings"
	"testing"
)

// "token_label": "" is not the same manifest as no token_label. The schema and the Python validator
// refuse it, so the loader must too, and a plain string field cannot tell the two apart.
func TestAPresentEmptyTokenLabelIsRefusedWhenTheManifestIsDecoded(t *testing.T) {
	for name, document := range map[string]string{
		"an empty string": `{"token_label": ""}`,
		"null":            `{"token_label": null}`,
		"a number":        `{"token_label": 7}`,
	} {
		var binding Binding
		if err := json.Unmarshal([]byte(document), &binding); err == nil {
			t.Fatalf("token_label as %s decoded to %q", name, binding.TokenLabel)
		}
	}
	var binding Binding
	if err := json.Unmarshal([]byte(`{"token_label": "OpenPGP card (User PIN (sig))"}`), &binding); err != nil || binding.TokenLabel != "OpenPGP card (User PIN (sig))" {
		t.Fatalf("a real label decoded to %q, %v", binding.TokenLabel, err)
	}
	if err := json.Unmarshal([]byte(`{"site": "sitea"}`), &binding); err != nil {
		t.Fatalf("a binding with no token_label did not decode: %v", err)
	}
}

// token_label is the configured discriminator for a card that PKCS#11 presents as two tokens under
// one serial (regalia#541). The loader's part is to keep it to values the driver can match, and to
// the one backend that reads it.
func TestTokenLabelIsAcceptedOnlyWhereTheDriverCanMatchIt(t *testing.T) {
	pkcs11Binding := func(label string) Binding {
		return Binding{
			Site: "sitea", Backend: "nitrokey-pkcs11", DeviceID: "yubikey-openpgp-sitea", ObjectID: "01",
			PublicFingerprint: "sha256:" + strings.Repeat("a", 64), State: "planned", TokenLabel: TokenLabel(label),
		}
	}
	// The control: the same binding with no label, and with the two labels OpenSC gives a YubiKey's
	// OpenPGP applet, loads. Without it every refusal below could come from something else.
	for _, label := range []string{"", "OpenPGP card (User PIN)", "OpenPGP card (User PIN (sig))", "x", strings.Repeat("a", 32)} {
		if err := validateBinding(pkcs11Binding(label), "p384", []string{"sign"}); err != nil {
			t.Fatalf("token_label %q was refused on the PKCS#11 backend: %v", label, err)
		}
	}
	// A label that could never equal a trimmed CK_TOKEN_INFO.label is a binding that never resolves.
	for name, label := range map[string]string{
		"33 characters":       strings.Repeat("a", 33),
		"a leading space":     " OpenPGP card",
		"a trailing space":    "OpenPGP card ",
		"a single space":      " ",
		"a control character": "OpenPGP\tcard",
		"a non-ASCII letter":  "OpenPGP cärd",
	} {
		err := validateBinding(pkcs11Binding(label), "p384", []string{"sign"})
		if err == nil || !strings.Contains(err.Error(), "token_label") {
			t.Fatalf("token_label with %s was not refused by name: %v", name, err)
		}
	}

	// Only the PKCS#11 driver reads the label. On a backend that ignores it, it would be a field
	// that looks like a pin and enforces nothing.
	piv := Binding{
		Site: "sitea", Backend: "yubikey-piv", DeviceID: "yubikey-sitea", ObjectID: "9c",
		PublicFingerprint: "sha256:" + strings.Repeat("b", 64), State: "planned",
		PINPolicy: "once", TouchPolicy: "never",
	}
	if err := validateBinding(piv, "p256", []string{"sign"}); err != nil {
		t.Fatalf("the PIV control binding does not load, so the refusal below proves nothing: %v", err)
	}
	piv.TokenLabel = "PIV_II"
	if err := validateBinding(piv, "p256", []string{"sign"}); err == nil || !strings.Contains(err.Error(), "token_label") {
		t.Fatalf("token_label on a PIV binding was not refused by name: %v", err)
	}

	// The OpenPGP applet is served through PKCS#11 too, and it is the card the label exists for.
	applet := piv
	applet.Backend, applet.ObjectID, applet.TokenLabel = "yubikey-openpgp", "01", "OpenPGP card (User PIN (sig))"
	if err := validateBinding(applet, "ed25519", []string{"sign"}); err != nil {
		t.Fatalf("token_label on an OpenPGP applet binding was refused: %v", err)
	}
}

// A SLOT IS (SITE, DEVICE, OBJECT ID) AND, ON A CARD THAT IS TWO TOKENS, THE TOKEN.
//
// The same object id under two labels of one device is two keys, so two objects may hold them. A
// binding with no label may resolve to either token, so it shares a slot with every label.
func TestTheTokenLabelIsPartOfTheHardwareSlot(t *testing.T) {
	binding := func(label string) string {
		labelField := ""
		if label != "" {
			labelField = `"token_label":"` + label + `",`
		}
		return `{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"dev-1","object_id":"slot-1",` + labelField +
			`"public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","kek_algorithm":"rsa2048","kek_version":"1","state":"planned"}`
	}
	load := func(first, second string) error {
		objects := r4object("alpha", "release-purpose", "release-secret", binding(first)) + "," +
			r4object("beta", "release-purpose", "release-secret", binding(second))
		_, err := Load(strings.NewReader(manifest(objects)), "sitea", &healthMap{states: map[string]bool{"dev-1": true}})
		return err
	}
	if err := load("OpenPGP card (User PIN)", "OpenPGP card (User PIN (sig))"); err != nil {
		t.Fatalf("one object id under two token labels was refused as a shared slot: %v", err)
	}
	for name, labels := range map[string][2]string{
		"the same label twice":          {"OpenPGP card (User PIN)", "OpenPGP card (User PIN)"},
		"no label on either":            {"", ""},
		"a labelled then an unlabelled": {"OpenPGP card (User PIN)", ""},
		"an unlabelled then a labelled": {"", "OpenPGP card (User PIN)"},
	} {
		err := load(labels[0], labels[1])
		if err == nil || !strings.Contains(err.Error(), "also assigned to") {
			t.Fatalf("%s: two objects in one slot loaded (err = %v)", name, err)
		}
	}
}

// RoutedTo is what a startup check reads to see how a backend's objects are bound. It must list
// exactly the routed objects of that backend, with the binding the daemon will use.
func TestRoutedToListsTheObjectsOfOneBackend(t *testing.T) {
	applet := func(id string) string {
		return r4object(id, "release-purpose", "sign",
			`{"site":"sitea","backend":"yubikey-openpgp","device_id":"yk-`+id+`","device_serial":"000600000001","object_id":"01",`+
				`"token_label":"OpenPGP card (User PIN (sig))","public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",`+
				`"public_key_sha256":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"active","pin_policy":"once","touch_policy":"never"}`)
	}
	objects := strings.ReplaceAll(applet("zulu")+","+applet("alpha"), `"algorithm":"opaque"`, `"algorithm":"ed25519"`) + "," +
		r4object("hsm-object", "release-purpose", "release-secret", r4stagingBinding)
	loaded, err := Load(strings.NewReader(manifest(objects)), "sitea", &healthMap{states: map[string]bool{"dev-1": true}})
	if err != nil {
		t.Fatalf("the fixture does not load: %v", err)
	}
	routed := loaded.RoutedTo("yubikey-openpgp")
	if len(routed) != 2 || routed[0].ObjectID != "alpha" || routed[1].ObjectID != "zulu" {
		t.Fatalf("RoutedTo(yubikey-openpgp) = %+v, want alpha then zulu", routed)
	}
	for _, object := range routed {
		if object.Algorithm != "ed25519" || len(object.Operations) != 1 || object.Operations[0] != "sign" || object.Binding.TokenLabel != "OpenPGP card (User PIN (sig))" || object.Binding.DeviceID != "yk-"+object.ObjectID {
			t.Fatalf("%s: operations %v, binding %+v", object.ObjectID, object.Operations, object.Binding)
		}
	}
	if hsm := loaded.RoutedTo("nitrokey-pkcs11"); len(hsm) != 1 || hsm[0].ObjectID != "hsm-object" {
		t.Fatalf("RoutedTo(nitrokey-pkcs11) = %+v, want the one SmartCard-HSM object", hsm)
	}
	if none := loaded.RoutedTo("yubikey-piv"); len(none) != 0 {
		t.Fatalf("RoutedTo(yubikey-piv) = %+v, want nothing", none)
	}
	var missing *Registry
	if missing.RoutedTo("yubikey-openpgp") != nil {
		t.Fatal("a nil registry routed something")
	}
}
