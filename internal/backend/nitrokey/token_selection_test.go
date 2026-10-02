package nitrokey

import (
	"context"
	"testing"

	"github.com/miekg/pkcs11"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// ONE CARD, TWO TOKENS, ONE SERIAL.
//
// OpenSC presents a YubiKey's OpenPGP applet as two PKCS#11 tokens, "OpenPGP card (User PIN)" and
// "OpenPGP card (User PIN (sig))", and both report the card's serial (measured on 35718625,
// regalia#541). The serial alone then names two slots. The driver must not pick one by position;
// the binding's token_label is the configured discriminator, matched exactly.

// slotModule answers the enumeration calls from a table and records which slot was opened.
type slotModule struct {
	fakeCryptoki
	slots  []uint
	infos  map[uint]pkcs11.TokenInfo
	errs   map[uint]error
	opened []uint
}

func (module *slotModule) GetSlotList(bool) ([]uint, error) { return module.slots, nil }
func (module *slotModule) GetTokenInfo(slot uint) (pkcs11.TokenInfo, error) {
	if err := module.errs[slot]; err != nil {
		return pkcs11.TokenInfo{}, err
	}
	return module.infos[slot], nil
}
func (module *slotModule) OpenSession(slot uint, _ uint) (pkcs11.SessionHandle, error) {
	module.opened = append(module.opened, slot)
	return 11, nil
}

const (
	openPGPSerial   = "000635718625"
	openPGPUserPIN  = "OpenPGP card (User PIN)"
	openPGPSigPIN   = "OpenPGP card (User PIN (sig))"
	openPGPUserSlot = uint(8)
	openPGPSigSlot  = uint(9)
)

// yubiKeyAsOpenSCPresentsIt is the slot list measured on the bench: a Nitrokey, and one YubiKey
// showing as two tokens. The labels carry the padding CK_TOKEN_INFO gives them.
func yubiKeyAsOpenSCPresentsIt() *slotModule {
	return &slotModule{
		slots: []uint{4, openPGPUserSlot, openPGPSigSlot},
		infos: map[uint]pkcs11.TokenInfo{
			4:               {SerialNumber: "DENK0404144     ", Label: "regalia-staging                 "},
			openPGPUserSlot: {SerialNumber: openPGPSerial + "    ", Label: openPGPUserPIN + "         "},
			openPGPSigSlot:  {SerialNumber: openPGPSerial + "    ", Label: openPGPSigPIN + "   "},
		},
	}
}

func selectionDriver(t *testing.T, module cryptoki) *PKCS11Driver {
	t.Helper()
	driver, err := newPKCS11Driver(module, fixedDevAuth("sha256:abc"), &recordingSecureChannel{}, fixedRetries(3))
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

func labelled(serial, label string) registry.Binding {
	return registry.Binding{Backend: "nitrokey-pkcs11", DeviceID: "token", DeviceSerial: serial, TokenLabel: registry.TokenLabel(label)}
}

func TestTwoTokensUnderOneSerialAreRefusedWithoutALabel(t *testing.T) {
	module := yubiKeyAsOpenSCPresentsIt()
	driver := selectionDriver(t, module)
	if session, err := driver.Open(context.Background(), labelled(openPGPSerial, "")); err == nil || session != nil {
		t.Fatal("two tokens with one serial were resolved without a label")
	}
	if len(module.opened) != 0 {
		t.Fatalf("a session was opened on slot %v for a token the binding does not single out", module.opened)
	}
	// The control: a serial that names one token still needs no label.
	if _, err := driver.Open(context.Background(), labelled("DENK0404144", "")); err != nil {
		t.Fatalf("a unique serial was refused without a label: %v", err)
	}
	if len(module.opened) != 1 || module.opened[0] != 4 {
		t.Fatalf("opened %v, want slot 4", module.opened)
	}
}

func TestTheConfiguredLabelSelectsExactlyOneOfTwoTokens(t *testing.T) {
	for label, want := range map[string]uint{openPGPUserPIN: openPGPUserSlot, openPGPSigPIN: openPGPSigSlot} {
		module := yubiKeyAsOpenSCPresentsIt()
		if _, err := selectionDriver(t, module).Open(context.Background(), labelled(openPGPSerial, label)); err != nil {
			t.Fatalf("label %q: %v", label, err)
		}
		if len(module.opened) != 1 || module.opened[0] != want {
			t.Fatalf("label %q opened slot %v, want %d", label, module.opened, want)
		}
	}
}

// Every way a label can fail to name exactly one token is a refusal, never a nearest match.
func TestALabelThatDoesNotNameExactlyOneTokenIsRefused(t *testing.T) {
	twins := yubiKeyAsOpenSCPresentsIt()
	twins.infos[openPGPUserSlot] = twins.infos[openPGPSigSlot] // two slots, one serial, one label
	for name, test := range map[string]struct {
		module *slotModule
		serial string
		label  string
	}{
		"a label no token carries":                     {yubiKeyAsOpenSCPresentsIt(), openPGPSerial, "OpenPGP card (Admin PIN)"},
		"a prefix of a real label":                     {yubiKeyAsOpenSCPresentsIt(), openPGPSerial, "OpenPGP card (User PIN"},
		"a prefix only one label starts with":          {yubiKeyAsOpenSCPresentsIt(), openPGPSerial, "OpenPGP card (User PIN (s"},
		"a real label in another case":                 {yubiKeyAsOpenSCPresentsIt(), openPGPSerial, "openpgp card (user pin)"},
		"a real label on another serial":               {yubiKeyAsOpenSCPresentsIt(), "DENK0404144", openPGPSigPIN},
		"a label two tokens of that serial both carry": {twins, openPGPSerial, openPGPSigPIN},
		// A configured label is part of the token's name, not a tie-breaker used only when the
		// serial is ambiguous: a unique serial under the wrong label is a different token.
		"the wrong label on a unique serial": {yubiKeyAsOpenSCPresentsIt(), "DENK0404144", "regalia-production"},
	} {
		session, err := selectionDriver(t, test.module).Open(context.Background(), labelled(test.serial, test.label))
		if err == nil || session != nil {
			t.Fatalf("%s: a session was opened on slot %v", name, test.module.opened)
		}
		if len(test.module.opened) != 0 {
			t.Fatalf("%s: OpenSession was called for slot %v", name, test.module.opened)
		}
	}
}

// A slot that cannot be read might be the twin of the one that can. Counting only the readable
// match would call it unique on no evidence.
func TestAnUnreadableSlotRefusesTheResolution(t *testing.T) {
	module := yubiKeyAsOpenSCPresentsIt()
	module.errs = map[uint]error{openPGPUserSlot: pkcs11.Error(pkcs11.CKR_DEVICE_ERROR)}
	driver := selectionDriver(t, module)
	if session, err := driver.Open(context.Background(), labelled(openPGPSerial, openPGPSigPIN)); err == nil || session != nil {
		t.Fatal("a token was selected while another slot could not be read")
	}
	// Nor is it only the commissioned serial's neighbours that count: the unreadable slot's
	// serial is exactly what is unknown.
	if session, err := driver.Open(context.Background(), labelled("DENK0404144", "")); err == nil || session != nil {
		t.Fatal("a token was selected while another slot could not be read")
	}
	if len(module.opened) != 0 {
		t.Fatalf("a session was opened on slot %v", module.opened)
	}
}

// A card the module does not recognise, or one that left between the two calls, is not a token it
// can drive and cannot be the commissioned one. A memory card in a second reader must not take the
// KMS down: the bench host has exactly that (an SLE-4442 in an ACR40U).
func TestASlotHoldingNothingTheModuleCanDriveIsNotAMatch(t *testing.T) {
	for name, code := range map[string]uint{"not recognised": pkcs11.CKR_TOKEN_NOT_RECOGNIZED, "not present": pkcs11.CKR_TOKEN_NOT_PRESENT} {
		module := yubiKeyAsOpenSCPresentsIt()
		module.slots = append([]uint{0}, module.slots...)
		module.errs = map[uint]error{0: pkcs11.Error(code)}
		if _, err := selectionDriver(t, module).Open(context.Background(), labelled(openPGPSerial, openPGPSigPIN)); err != nil {
			t.Fatalf("a slot whose token is %s refused the resolution: %v", name, err)
		}
		if len(module.opened) != 1 || module.opened[0] != openPGPSigSlot {
			t.Fatalf("a slot whose token is %s: opened %v, want %d", name, module.opened, openPGPSigSlot)
		}
	}
}

// A reader arriving or leaving makes pcscd rebuild its list and OpenSC renumber its slots: on the
// bench, a USB removal test in another process moved the YubiKey's slots while a session was being
// opened (regalia#541). The slot id of the last Open says nothing about the next one.
func TestTheSlotIsResolvedAgainOnEveryOpen(t *testing.T) {
	module := yubiKeyAsOpenSCPresentsIt()
	driver := selectionDriver(t, module)
	if _, err := driver.Open(context.Background(), labelled(openPGPSerial, openPGPSigPIN)); err != nil {
		t.Fatal(err)
	}
	// The Nitrokey leaves. The YubiKey's two tokens move down, and the id that was the signature
	// token is now nothing at all.
	module.slots = []uint{4, 5}
	module.infos = map[uint]pkcs11.TokenInfo{
		4: {SerialNumber: openPGPSerial, Label: openPGPUserPIN},
		5: {SerialNumber: openPGPSerial, Label: openPGPSigPIN},
	}
	if _, err := driver.Open(context.Background(), labelled(openPGPSerial, openPGPSigPIN)); err != nil {
		t.Fatal(err)
	}
	if len(module.opened) != 2 || module.opened[0] != openPGPSigSlot || module.opened[1] != 5 {
		t.Fatalf("opened slots %v, want [%d 5]: the second Open reused a stale slot id", module.opened, openPGPSigSlot)
	}
}

// recordingProbes notes the token name each probe was asked about.
type recordingProbes struct{ serials, labels []string }

func (probes *recordingProbes) Fingerprint(_ context.Context, _, serial, label string) (string, error) {
	probes.serials, probes.labels = append(probes.serials, serial), append(probes.labels, label)
	return "sha256:abc", nil
}
func (probes *recordingProbes) Remaining(_ context.Context, _, serial, label string) (int, error) {
	probes.serials, probes.labels = append(probes.serials, serial), append(probes.labels, label)
	return 3, nil
}

// The probes resolve the slot themselves. Asked by serial alone they would refuse the very token
// the session was opened on, or, with one token of that serial, answer for whichever it was.
func TestTheSessionAsksItsProbesAboutTheTokenItWasOpenedOn(t *testing.T) {
	probes := &recordingProbes{}
	driver, err := newPKCS11Driver(yubiKeyAsOpenSCPresentsIt(), probes, &recordingSecureChannel{}, probes)
	if err != nil {
		t.Fatal(err)
	}
	session, err := driver.Open(context.Background(), labelled(openPGPSerial, openPGPSigPIN))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := session.Identity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := session.PINRetries(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(probes.labels) != 2 {
		t.Fatalf("the probes were asked %d times, want 2", len(probes.labels))
	}
	for index := range probes.labels {
		if probes.serials[index] != openPGPSerial || probes.labels[index] != openPGPSigPIN {
			t.Fatalf("probe %d was asked about (%q, %q), not the session's token", index, probes.serials[index], probes.labels[index])
		}
	}
}

// The two tokens of one card have separate PIN states: PW1 for signatures and PW1 for everything
// else are verified independently. A retry count read off the wrong one is a wrong count.
func TestTheProbesReadTheLabelledToken(t *testing.T) {
	module := &probeModule{slots: []uint{8, 9}, infos: map[uint]pkcs11.TokenInfo{
		8: {SerialNumber: openPGPSerial, Label: openPGPUserPIN},
		9: {SerialNumber: openPGPSerial, Label: openPGPSigPIN, Flags: pkcs11.CKF_USER_PIN_FINAL_TRY},
	}}
	probes, err := NewTokenProbes(module)
	if err != nil {
		t.Fatal(err)
	}
	for label, want := range map[string]int{openPGPUserPIN: 3, openPGPSigPIN: 1} {
		got, err := probes.Remaining(context.Background(), "token", openPGPSerial, label)
		if err != nil || got != want {
			t.Fatalf("label %q: %d tries, %v; want %d", label, got, err, want)
		}
	}
	if _, err := probes.Remaining(context.Background(), "token", openPGPSerial, ""); err == nil {
		t.Fatal("the probes answered for two tokens with one serial and no label")
	}
	if _, err := probes.Remaining(context.Background(), "token", openPGPSerial, "OpenPGP card"); err == nil {
		t.Fatal("the probes answered for a label no token carries")
	}
}
