package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeReach struct {
	missing []string
	held    bool
	err     error
	calls   *[]string
}

func (cards fakeReach) Reach(context.Context) ([]string, bool, error) {
	if cards.calls != nil {
		*cards.calls = append(*cards.calls, "reach")
	}
	return cards.missing, cards.held, cards.err
}

func TestADaemonWhosePKCS11ModuleHoldsItsYubiKeyDoesNotStart(t *testing.T) {
	var calls []string
	enumerate := func(context.Context) bool { calls = append(calls, "enumerate"); return true }
	err := requirePIVCardsOpenBesidePKCS11(context.Background(), enumerate, fakeReach{missing: []string{"yubikey-site-a"}, held: true, calls: &calls})
	if err == nil {
		t.Fatal("a daemon that cannot open its PIV card, with a reader held by another connection, started")
	}
	// The operator is told which device, what to set, and where the file is.
	for _, want := range []string{"yubikey-site-a", "OPENSC_CONF", "ignored_readers", "deploy/opensc/ignore-yubikey.conf"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	// The module must have looked at the readers BEFORE the cards are tried: it takes its
	// connections when it enumerates, and a check made before that would pass on a host that
	// then refuses every PIV request.
	if len(calls) != 2 || calls[0] != "enumerate" || calls[1] != "reach" {
		t.Fatalf("order of calls = %v, want enumerate then reach", calls)
	}
}

func TestOnlyTheLockoutStopsTheDaemon(t *testing.T) {
	enumerate := func(context.Context) bool { return true }
	for name, test := range map[string]struct {
		enumerate func(context.Context) bool
		cards     pivReach
	}{
		"every card opens":                         {enumerate, fakeReach{}},
		"every card opens, another reader is held": {enumerate, fakeReach{held: true}},
		"a card is not attached, nothing is held":  {enumerate, fakeReach{missing: []string{"yubikey-site-a"}}},
		"the readers cannot be looked at":          {enumerate, fakeReach{missing: []string{"yubikey-site-a"}, held: true, err: errors.New("pcsc")}},
		"no PKCS#11 module":                        {nil, fakeReach{missing: []string{"yubikey-site-a"}, held: true}},
		"no PIV provider":                          {enumerate, nil},
	} {
		if err := requirePIVCardsOpenBesidePKCS11(context.Background(), test.enumerate, test.cards); err != nil {
			t.Errorf("%s: the daemon was stopped: %v", name, err)
		}
	}
}
