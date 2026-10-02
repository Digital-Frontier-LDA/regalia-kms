package main

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

var openPGPAppletKeyPin = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// requireOpenPGPAppletBindingsAreServable refuses a registry whose OpenPGP-applet objects the
// daemon could not actually serve.
//
// The applet is served through OpenSC's PKCS#11 module, for Ed25519 signing only (regalia#541).
// Four things the capability matrix and the manifest loader do not say would otherwise surface one
// request at a time, as a retryable "unavailable" that never stops being retried:
//
//   - the matrix row for this backend also lists RSA keys, which the decision does not cover: the
//     applet is served as the home of Ed25519 and of nothing an HSM can hold;
//   - the row also lists unwrap, which belongs to the legacy sops-pgp path and is not implemented
//     here;
//   - OpenSC presents the applet as two tokens under one serial, so a binding with no token_label
//     names no token;
//   - the applet has no device certificate, so the commissioned public key is the only thing that
//     identifies the card, and a binding without that pin is never opened.
//
// A configuration the daemon cannot serve is refused at startup, where somebody is watching.
func requireOpenPGPAppletBindingsAreServable(keyRegistry *registry.Registry) error {
	var problems []string
	for _, object := range keyRegistry.RoutedTo(nitrokey.OpenPGPAppletBackend) {
		if object.Algorithm != "ed25519" {
			problems = append(problems, fmt.Sprintf("%s is an %s key (the applet is served for ed25519 only)", object.ObjectID, object.Algorithm))
		}
		for _, operation := range object.Operations {
			if operation != "sign" {
				problems = append(problems, fmt.Sprintf("%s declares %s (the applet is served for sign only)", object.ObjectID, operation))
			}
		}
		if object.Binding.TokenLabel == "" {
			problems = append(problems, fmt.Sprintf("%s has no token_label (the applet is two tokens under one serial)", object.ObjectID))
		}
		// The loader already requires a serial on a commissioned YubiKey binding, and only a
		// commissioned binding is routed. The public key is the half it does not ask for.
		if !openPGPAppletKeyPin.MatchString(object.Binding.PublicKeySHA256) {
			problems = append(problems, fmt.Sprintf("%s does not pin public_key_sha256 (nothing else identifies the card)", object.ObjectID))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("the key registry binds objects to the OpenPGP applet that this daemon cannot serve: %s", strings.Join(problems, "; "))
	}
	return nil
}
