//go:build piv

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
)

func TestBuildHardwareServesConfiguredYubiKeyBackend(t *testing.T) {
	directory := t.TempDir()
	pinPath := filepath.Join(directory, "yubi-a.pin")
	if err := os.WriteFile(pinPath, []byte("staging-pin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := config.Config{
		YubiKeyDevices: map[string]string{"yubi-a": "25923905"},
		PINPaths:       map[string]string{"yubi-a": pinPath},
	}
	_, manager, _, closer, err := buildHardware(settings, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	if !manager.Serves("yubikey-piv") {
		t.Fatal("configured yubikey-piv backend was not attached to the daemon manager")
	}
}
