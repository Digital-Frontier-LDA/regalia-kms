package fencing

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeAtomically publishes the lease and the issuer record — the two files that decide which site
// may sign. Three properties matter, and the failure of any one is a split-brain risk rather than
// an inconvenience.
//
//	A FAILED WRITE MUST NOT DESTROY WHAT IS ALREADY PUBLISHED. The rename is last, so a failure
//	anywhere before it leaves the previous lease exactly as it was. Truncating in place would
//	leave the daemon with no lease at all, which is not "the old answer" — it is no answer.
//
//	THE TEMPORARY IS UNPREDICTABLE. A fixed `path + ".tmp"` opened with O_TRUNC is a symlink
//	target: anyone who can create that name aims it at a file of their choosing and this process
//	rewrites it with the authority's privileges.
//
//	THE MODE IS SET, NOT INHERITED. os.CreateTemp always makes 0600, and the daemon refuses a
//	lease it cannot read.

func TestAPublishedFileGetsTheModeAskedForNotTheTemporarysOwn(t *testing.T) {
	directory := privateTempDir(t)
	path := filepath.Join(directory, "lease.json")

	if err := writeAtomically(path, []byte("contents\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// 0600 is what CreateTemp produces; inheriting it would publish a lease the daemon cannot read.
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %04o, want 0644 — the temporary's mode was inherited", info.Mode().Perm())
	}

	if err := writeAtomically(filepath.Join(directory, "record.json"), []byte("contents\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	record, err := os.Stat(filepath.Join(directory, "record.json"))
	if err != nil {
		t.Fatal(err)
	}
	if record.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", record.Mode().Perm())
	}
}

// TestNoTemporarySurvivesAFailedWrite is the case that actually exercises the cleanup. On success
// the temporary is renamed away and there is nothing left to remove — measured: deleting the
// deferred Remove leaves the success test green. Only a failure after the temporary exists can see
// it, and a leftover is a readable copy of the lease sitting in the issuer directory with nobody's
// attention on it.
//
// The failure is induced by making the destination a directory, so the rename fails last, after
// every earlier step has succeeded.
func TestNoTemporarySurvivesAFailedWrite(t *testing.T) {
	directory := privateTempDir(t)
	path := filepath.Join(directory, "lease.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := writeAtomically(path, []byte("contents\n"), 0o644); err == nil {
		t.Fatal("writeAtomically renamed over a directory")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "lease.json" {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("after a failed write the directory holds %v, want only the destination: the temporary was left behind, and it is a readable copy of the lease", names)
	}
}

func TestNoTemporarySurvivesASuccessfulWrite(t *testing.T) {
	directory := privateTempDir(t)
	path := filepath.Join(directory, "lease.json")
	if err := writeAtomically(path, []byte("contents\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "lease.json" {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("directory holds %v, want only lease.json: a leftover temporary is a second copy of the lease with nobody's attention on it", names)
	}
}

// TestAFailedWriteLeavesThePublishedLeaseIntact. The directory is made unwritable after the first
// publish, so CreateTemp fails and nothing downstream runs. What matters is not the error — it is
// that the file a daemon is about to read is untouched.
func TestAFailedWriteLeavesThePublishedLeaseIntact(t *testing.T) {
	directory := privateTempDir(t)
	path := filepath.Join(directory, "lease.json")
	if err := writeAtomically(path, []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })

	err := writeAtomically(path, []byte("second\n"), 0o644)
	if err == nil {
		t.Skip("this filesystem allowed a write into a read-only directory, so the failure path was not exercised")
	}

	contents, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("the published lease is unreadable after a failed write: %v", readErr)
	}
	if string(contents) != "first\n" {
		t.Fatalf("the published lease is now %q: a failed write replaced or truncated it, and the daemon would read a lease that was never published", contents)
	}
}

// TestTheTemporaryIsNotAPredictableName. A fixed sibling name is a symlink target. This checks the
// property by pre-creating the predictable name as a DIRECTORY: if writeAtomically used it, the
// open would fail. It succeeding is the evidence that it does not.
func TestTheTemporaryIsNotAPredictableName(t *testing.T) {
	directory := privateTempDir(t)
	path := filepath.Join(directory, "lease.json")
	if err := os.Mkdir(path+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}

	if err := writeAtomically(path, []byte("contents\n"), 0o644); err != nil {
		t.Fatalf("writeAtomically failed with %s occupied: it is using the predictable temporary name, which anyone who can create that path can aim at a file of their choosing", path+".tmp")
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "contents\n" {
		t.Fatalf("published %q, %v", contents, err)
	}
}

// TestPublishingReplacesTheSymlinkRatherThanItsTarget. If the destination is a symlink, the rename
// must replace the link — writing through it would let anyone who can create the lease path
// redirect the authority's write onto a file of their choosing.
func TestPublishingReplacesTheSymlinkRatherThanItsTarget(t *testing.T) {
	directory := privateTempDir(t)
	target := filepath.Join(directory, "elsewhere")
	if err := os.WriteFile(target, []byte("do not touch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "lease.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	if err := writeAtomically(path, []byte("contents\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	victim, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(victim) != "do not touch\n" {
		t.Fatalf("the symlink's target was overwritten with %q: a lease path someone else can create redirects this write", victim)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the lease path is still a symlink: the rename did not replace it")
	}
}

func TestTheIssuerDirectoryMustNotBeWritableByOthers(t *testing.T) {
	directory := privateTempDir(t)

	if err := requireUnwritableDirectory(directory); err != nil {
		t.Fatalf("a 0700 temp directory was refused: %v", err)
	}
	for _, test := range []struct {
		name string
		mode os.FileMode
	}{
		{"group-writable", 0o770},
		{"world-writable", 0o707},
		{"writable by everyone", 0o777},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.Chmod(directory, test.mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(directory, 0o700) })

			err := requireUnwritableDirectory(directory)
			if err == nil {
				t.Fatalf("a %s issuer directory was accepted: write permission on the directory is permission to unlink and recreate the record whatever its own mode is, and it makes the O_EXCL lock forgeable", test.name)
			}
			if !strings.Contains(err.Error(), "group- or world-writable") {
				t.Fatalf("%s: error = %q, want the writability refusal", test.name, err)
			}
		})
	}
}

func TestTheIssuerDirectoryMustBeADirectoryThatExists(t *testing.T) {
	directory := privateTempDir(t)
	file := filepath.Join(directory, "not-a-directory")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := requireUnwritableDirectory(file)
	if err == nil {
		t.Fatal("a regular file was accepted as the issuer directory")
	}
	if !strings.Contains(err.Error(), "is not a directory") {
		t.Fatalf("error = %q, want the not-a-directory refusal", err)
	}

	absent := filepath.Join(directory, "absent")
	err = requireUnwritableDirectory(absent)
	if err == nil {
		t.Fatal("a missing issuer directory was accepted")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("error = %v, want it to wrap ErrNotExist so an operator can tell a missing directory from an unsafe one", err)
	}
}
