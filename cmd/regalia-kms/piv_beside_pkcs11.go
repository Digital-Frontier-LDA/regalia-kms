package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// pivReach is what the PIV provider can say about its cards at startup (yubikey.Provider.Reach).
type pivReach interface {
	Reach(context.Context) (missing []string, held bool, err error)
}

// requirePIVCardsOpenBesidePKCS11 stops a daemon whose own PKCS#11 module locks it out of its
// YubiKeys.
//
// THE PIV BACKEND OPENS A CARD FOR EXCLUSIVE USE, AND OPENSC KEEPS A CONNECTION TO EVERY CARD IT
// FINDS. A daemon that holds both therefore needs OpenSC told to leave the YubiKey's reader alone
// (deploy/opensc/ignore-yubikey.conf, named by OPENSC_CONF in the unit). Without it the daemon
// used to start, report ready, and refuse every PIV request as "unavailable" with nothing naming
// the cause (regalia#541). The setting lives outside the daemon, so the daemon checks its effect:
// `enumerate` makes the module look at the readers as it does when it serves, and then every
// commissioned PIV card must still open.
//
// A card that is missing while a reader is held by another connection stops the daemon: that is
// this misconfiguration, or another process on the card, and neither heals by waiting. A card that
// is simply not there does not: the daemon starts, as it does with an HSM unplugged, and the key
// is unavailable until the card is.
func requirePIVCardsOpenBesidePKCS11(ctx context.Context, enumerate func(context.Context) bool, cards pivReach) error {
	if enumerate == nil || cards == nil {
		return nil
	}
	enumerate(ctx)
	missing, held, err := cards.Reach(ctx)
	if err != nil {
		slog.Warn("KMS could not look at the PIV card readers at startup: whether the PKCS#11 module leaves the YubiKeys alone is unchecked", "error", err)
		return nil
	}
	if len(missing) == 0 {
		return nil
	}
	if held {
		return fmt.Errorf("YubiKey PIV device(s) %s cannot be opened: another connection holds a card reader. "+
			"This daemon's PKCS#11 module keeps a connection to every card OpenSC is not told to ignore, and the PIV backend needs the card to itself: "+
			"start the daemon with OPENSC_CONF naming a configuration with ignored_readers for the YubiKey (deploy/opensc/ignore-yubikey.conf), "+
			"or stop the other process that is using the card", strings.Join(missing, ", "))
	}
	slog.Warn("KMS YubiKey PIV device(s) not present at startup: their keys are unavailable until the card is attached", "devices", strings.Join(missing, ", "))
	return nil
}
