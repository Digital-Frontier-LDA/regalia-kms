package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeKeyFile(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// THE AUTHORITY'S SIGNING KEY IS THE ONE INPUT NOTHING ELSE CHECKS.
//
// Everything downstream — the epoch rules, the overlap refusal, the daemon's verification —
// assumes the bytes loaded here are the key the fleet trusts. There is no second check: a
// wrong-length key that happened to load would sign leases no daemon accepts, and the failure
// would arrive at the site being promoted, during the failover, with no signal here.
//
// The length check is the whole of the validation, so it is what this pins. A 32-byte ed25519
// SEED is the plausible wrong input — it is what most tools print, it is valid base64, and it
// is exactly half of what ed25519.PrivateKey needs.
func TestLoadSigningKeyRefusesAnythingThatIsNotAnEd25519PrivateKey(t *testing.T) {
	directory := t.TempDir()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(private)

	good := writeKeyFile(t, directory, "good.key", encoded)
	loaded, err := loadSigningKey(good)
	if err != nil {
		t.Fatalf("a valid key was refused: %v", err)
	}
	if !loaded.Equal(private) {
		t.Fatal("the loaded key is not the key on disk")
	}

	// Trailing whitespace is what a file written by `echo` or an editor carries.
	spaced := writeKeyFile(t, directory, "spaced.key", "  "+encoded+"\n\n")
	if _, err := loadSigningKey(spaced); err != nil {
		t.Errorf("a key with surrounding whitespace was refused: %v", err)
	}

	seed := base64.StdEncoding.EncodeToString(private.Seed())
	for name, contents := range map[string]string{
		"a 32-byte seed rather than the private key": seed,
		"not base64 at all":                          "this is not base64 !!!",
		"base64 of the wrong length":                 base64.StdEncoding.EncodeToString([]byte("short")),
		"empty file":                                 "",
		// One byte short of a private key, and valid base64 -- the boundary the length check
		// exists for, rather than a second spelling of the empty string.
		"base64 one byte short of the key size": base64.StdEncoding.EncodeToString(
			private[:ed25519.PrivateKeySize-1]),
		"whitespace only": "   \n  ",
	} {
		t.Run(name, func(t *testing.T) {
			path := writeKeyFile(t, t.TempDir(), "bad.key", contents)
			if _, err := loadSigningKey(path); err == nil {
				t.Fatalf("%s was accepted as a signing key", name)
			}
		})
	}

	if _, err := loadSigningKey(filepath.Join(directory, "does-not-exist")); err == nil {
		t.Fatal("a missing key file was accepted")
	} else if !strings.Contains(err.Error(), "read signing key") {
		t.Errorf("a missing file does not say so: %v", err)
	}
}
