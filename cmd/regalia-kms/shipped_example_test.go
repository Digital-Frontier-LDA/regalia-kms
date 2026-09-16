package main

import (
	"os"
	"path/filepath"
	"testing"
)

// shippedExample stages one of the shipped example documents at 0600 and returns the copy's
// path. Every loader in the daemon refuses a group- or world-writable file, and a checked-out
// file carries whatever mode the developer's umask left it (0664 under the 0002 umask common on
// user-private-group systems), so loading straight from the working tree tests the checkout
// rather than the example. Tests that only read the bytes may keep reading the original.
func shippedExample(t *testing.T, name string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", "config", name))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
