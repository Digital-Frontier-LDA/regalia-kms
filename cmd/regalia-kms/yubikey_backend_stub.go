//go:build !piv

package main

import (
	"errors"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/pin"
)

func newYubiKeyBackend(map[string]string, *pin.LockedFileSource) (backend.Provider, error) {
	return nil, errors.New("yubikey-piv backend requires a piv-tagged build")
}
