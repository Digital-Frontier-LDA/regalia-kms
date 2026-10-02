package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// tokenOpener is the part of the PKCS#11 driver this check uses.
type tokenOpener interface {
	Open(context.Context, registry.Binding) (nitrokey.Session, error)
}

// requireTokensOfferBoundMechanisms refuses a registry that binds a key to a token which says it
// cannot do what the object declares.
//
// The capability matrix answers per backend, and one backend is several kinds of token: it
// advertises ed25519/sign and aes-256/unwrap for the PKCS#11 backend, and neither SmartCard-HSM
// lists an EdDSA or AES mechanism (regalia#541). Such a binding validated and the daemon started;
// the provider now refuses the operation before presenting a PIN, but it cannot say why to anyone,
// because an error is not a channel. This is where it is said: at startup, by object and token.
//
// ONLY A DEFINITE "NO" IS FATAL. Refusing to start for a token that is absent, or whose list cannot
// be read, would turn a pulled token into a daemon that cannot come back. Those tokens are returned
// as unchecked, for the caller to log: "checked and fine" and "not checked" must not look the same.
// An object on an unchecked token that it cannot serve is still refused per operation by the
// provider, as a retryable error that names nothing.
//
// WHAT IS ASKED ABOUT is the binding each object is routed to at this site. A retired binding kept
// for older envelopes, or a standby one, is not; the provider's own check covers those when used.
func requireTokensOfferBoundMechanisms(ctx context.Context, tokens tokenOpener, keyRegistry *registry.Registry) (unchecked []string, err error) {
	var problems []string
	skipped := make(map[string]struct{})
	// One session per token, however many objects it holds: opening one enumerates every slot,
	// which on a real card takes seconds. A nil entry is a token that could not be opened.
	sessions := make(map[string]nitrokey.Session)
	defer func() {
		for _, session := range sessions {
			if session != nil {
				_ = session.Close()
			}
		}
	}()
	for _, backendName := range []string{"nitrokey-pkcs11", nitrokey.OpenPGPAppletBackend} {
		for _, object := range keyRegistry.RoutedTo(backendName) {
			token := backendName + "\x00" + object.Binding.DeviceSerial + "\x00" + string(object.Binding.TokenLabel)
			name := tokenName(object.Binding)
			session, tried := sessions[token]
			if !tried {
				opened, openErr := tokens.Open(ctx, object.Binding)
				if openErr != nil {
					if opened != nil {
						_ = opened.Close()
					}
					opened = nil
				}
				session, sessions[token] = opened, opened
			}
			if session == nil {
				skipped[name] = struct{}{}
				continue
			}
			for _, declared := range object.Operations {
				// What the provider sends to the token for each declared operation: a certificate
				// is a signature by the CA key, and a secret is released by unwrapping on the KEK
				// the binding names.
				operation, algorithm := declared, object.Algorithm
				switch declared {
				case "certificate-sign":
					operation = "sign"
				case "release-secret":
					operation, algorithm = "unwrap", object.Binding.KEKAlgorithm
				}
				switch answer := session.OffersMechanism(ctx, operation, algorithm); {
				case answer == nil:
				case errors.Is(answer, nitrokey.ErrMechanismNotOffered):
					problems = append(problems, fmt.Sprintf("%s declares %s on a %s key, and token %s offers no mechanism for it",
						object.ObjectID, declared, algorithm, name))
				default:
					skipped[name] = struct{}{}
				}
			}
		}
	}
	for name := range skipped {
		unchecked = append(unchecked, name)
	}
	sort.Strings(unchecked)
	if len(problems) > 0 {
		return unchecked, fmt.Errorf("the key registry binds objects to tokens that cannot serve them: %s", strings.Join(problems, "; "))
	}
	return unchecked, nil
}

// tokenName is how a token is named to an operator: its serial, and its label where the binding
// needs one to tell two tokens of one card apart.
func tokenName(binding registry.Binding) string {
	if binding.TokenLabel != "" {
		return fmt.Sprintf("%s (%s)", binding.DeviceSerial, binding.TokenLabel)
	}
	return binding.DeviceSerial
}
