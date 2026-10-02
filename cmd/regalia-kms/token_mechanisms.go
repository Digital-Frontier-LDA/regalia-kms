package main

import (
	"context"
	"errors"
	"fmt"
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
// ONLY A DEFINITE "NO" IS FATAL. A token that is absent, or whose list cannot be read, is a daemon
// that is not ready yet, which readiness already reports; refusing to start for it would turn a
// pulled token into a daemon that cannot come back.
func requireTokensOfferBoundMechanisms(ctx context.Context, tokens tokenOpener, keyRegistry *registry.Registry) error {
	var problems []string
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
			session, tried := sessions[token]
			if !tried {
				opened, err := tokens.Open(ctx, object.Binding)
				if err != nil {
					opened = nil
				}
				session, sessions[token] = opened, opened
			}
			if session == nil {
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
				if errors.Is(session.OffersMechanism(ctx, operation, algorithm), nitrokey.ErrMechanismNotOffered) {
					problems = append(problems, fmt.Sprintf("%s declares %s on a %s key, and token %s offers no mechanism for it",
						object.ObjectID, declared, algorithm, object.Binding.DeviceSerial))
				}
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("the key registry binds objects to tokens that cannot serve them: %s", strings.Join(problems, "; "))
	}
	return nil
}
