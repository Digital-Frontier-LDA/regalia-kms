package sopsadapter

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// socketDir returns a temporary directory short enough to hold a Unix domain socket path.
//
// WHY NOT t.TempDir(). A Unix socket address is capped by sun_path — 104 bytes on macOS, 108 on
// Linux — and the kernel reports an overrun as a bare "invalid argument", which reads like a bug in
// the server rather than a path that is too long. t.TempDir() embeds the test's NAME in the path,
// and these tests have long names, so it can cross that limit on hosts with a deep TMPDIR (macOS
// puts TMPDIR under /var/folders/<...>/T/).
//
// WHY NOT /private/tmp. That was the previous fix and it is macOS-only: /tmp is a symlink to
// /private/tmp there, and the directory does not exist on the Linux CI runners, where both tests
// failed with "stat /private/tmp: no such file or directory" — passing locally and failing in CI.
//
// os.MkdirTemp("") honours TMPDIR, which is short on Linux and acceptable on macOS, and the length
// is asserted here so a future host with a deep TMPDIR fails with a message that says what is wrong.
func socketDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "regalia-sops-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })

	limit := 108 // Linux sun_path
	if runtime.GOOS == "darwin" {
		limit = 104
	}
	if socket := filepath.Join(directory, "sops.sock"); len(socket) >= limit {
		t.Fatalf("socket path %q is %d bytes, at or over the %d-byte sun_path limit on %s; "+
			"set TMPDIR to something shorter", socket, len(socket), limit, runtime.GOOS)
	}
	return directory
}
