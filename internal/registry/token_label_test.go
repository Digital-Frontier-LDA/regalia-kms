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
}
