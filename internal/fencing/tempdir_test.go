package fencing

import (
	"os"
	"testing"
)

// privateTempDir is t.TempDir() with the mode the issuer requires. testing creates the per-test
// directory with 0777 and lets the umask trim it, so under the 0002 umask common on
// user-private-group systems it comes out 0775 and requireUnwritableDirectory rightly refuses it.
// The tests here want a directory that is unwritable by anyone else regardless of who runs them.
func privateTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}
