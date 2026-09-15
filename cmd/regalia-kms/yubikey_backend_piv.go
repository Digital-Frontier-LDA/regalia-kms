//go:build piv

package main

import (
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/yubikey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/pin"
)

func newYubiKeyBackend(devices map[string]string, pins *pin.LockedFileSource) (backend.Provider, error) {
	driver, err := yubikey.NewPIVDriver(devices)
	if err != nil {
		return nil, err
	}
	provider, err := yubikey.New(driver, pins)
	if err != nil {
		return nil, err
	}
	return provider, nil
}
