package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// A private scratch filesystem models the owner and the production-relative
// layout. These tests do not establish Linux root ownership or service access.
func collectorScratchRoot(t *testing.T) (string, *collectorFileReader) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, collectorOpenFlags|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return root, &collectorFileReader{root: fd, owner: uint32(os.Geteuid()), seen: make(map[collectorFileID]struct{})}
}

func writeCollectorFixtureFile(t *testing.T, root, name string, bytes []byte, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, bytes, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func collectorMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCollectorFilesRejectUntrustedPaths(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, string, string, *collectorFileReader)
	}{
		{"writable-anchor", func(t *testing.T, root, _ string, _ *collectorFileReader) {
			collectorMust(t, os.Chmod(root, 0o770))
		}},
		{"writable-ancestor", func(t *testing.T, root, _ string, _ *collectorFileReader) {
			collectorMust(t, os.Chmod(filepath.Join(root, "parent"), 0o775))
		}},
		{"writable-file", func(t *testing.T, _, file string, _ *collectorFileReader) {
			collectorMust(t, os.Chmod(file, 0o660))
		}},
		{"sticky-world-writable-ancestor", func(t *testing.T, root, _ string, _ *collectorFileReader) {
			collectorMust(t, os.Chmod(filepath.Join(root, "parent"), 0o757|os.ModeSticky))
		}},
		{"world-writable-file", func(t *testing.T, _, file string, _ *collectorFileReader) {
			collectorMust(t, os.Chmod(file, 0o606))
		}},
		{"private-world-readable", func(t *testing.T, _, file string, _ *collectorFileReader) {
			collectorMust(t, os.Chmod(file, 0o644))
		}},
		{"wrong-owner", func(t *testing.T, _, _ string, r *collectorFileReader) {
			// Change the expected UID, not ownership on disk.
			r.owner ^= 1
		}},
		{"symlink-ancestor", func(t *testing.T, root, _ string, _ *collectorFileReader) {
			before := filepath.Join(root, "parent")
			after := filepath.Join(root, "elsewhere")
			collectorMust(t, os.Rename(before, after))
			collectorMust(t, os.Symlink(after, before))
		}},
		{"symlink-file", func(t *testing.T, _, file string, _ *collectorFileReader) {
			collectorMust(t, os.Rename(file, file+".old"))
			collectorMust(t, os.Symlink(file+".old", file))
		}},
		{"fifo", func(t *testing.T, _, file string, _ *collectorFileReader) {
			collectorMust(t, os.Remove(file))
			collectorMust(t, unix.Mkfifo(file, 0o600))
		}},
		{"directory", func(t *testing.T, _, file string, _ *collectorFileReader) {
			collectorMust(t, os.Remove(file))
			collectorMust(t, os.Mkdir(file, 0o700))
		}},
		{"hardlink", func(t *testing.T, _, file string, _ *collectorFileReader) {
			collectorMust(t, os.Link(file, file+".alias"))
		}},
		{"oversize", func(t *testing.T, _, file string, _ *collectorFileReader) {
			collectorMust(t, os.WriteFile(file, []byte("12345"), 0o600))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, reader := collectorScratchRoot(t)
			const name = "/parent/sub/material"
			file := writeCollectorFixtureFile(t, root, name, []byte("1234"), 0o600)
			// A world-writable public file exercises the general write guard
			// without the independent restriction on other-user key bits.
			private := tc.name != "world-writable-file"
			data, err := reader.read(name, 4, private)
			if err != nil || string(data) != "1234" {
				t.Fatalf("safe fixture did not load exactly at the bound: %v", err)
			}
			clear(reader.seen)
			tc.change(t, root, file, reader)
			if opened, err := reader.open(name, 4, private); opened != nil || err != ErrCollectorRoleFile {
				if opened != nil {
					opened.Close()
				}
				t.Fatalf("untrusted material opened or wrong refusal: %v", err)
			}
		})
	}
}

func TestCollectorFilesUseOpenedObjectAndRejectRepeatedIdentity(t *testing.T) {
	root, reader := collectorScratchRoot(t)
	name := "/directory/material"
	file := writeCollectorFixtureFile(t, root, name, []byte("first"), 0o600)
	opened, err := reader.open(name, 32, true)
	collectorMust(t, err)
	defer opened.Close()
	raw, err := opened.SyscallConn()
	collectorMust(t, err)
	var closeOnExec, nonblock int
	var fdErr, flErr error
	collectorMust(t, raw.Control(func(fd uintptr) {
		closeOnExec, fdErr = unix.FcntlInt(fd, unix.F_GETFD, 0)
		nonblock, flErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
	}))
	if fdErr != nil || closeOnExec&unix.FD_CLOEXEC == 0 {
		t.Fatalf("opened credential descriptor lacks close-on-exec: %v", fdErr)
	}
	if flErr != nil || nonblock&unix.O_NONBLOCK == 0 {
		t.Fatalf("opened credential descriptor lacks nonblocking access: %v", flErr)
	}
	collectorMust(t, os.Rename(file, file+".old"))
	writeCollectorFixtureFile(t, root, name, []byte("replacement"), 0o600)
	got, err := readOpenedCollectorFile(opened, 32)
	if err != nil || string(got) != "first" {
		t.Fatalf("trusted read did not use the originally opened object: %v", err)
	}
	if data, err := reader.read(name+".old", 32, true); data != nil || err != ErrCollectorRoleFile {
		t.Fatalf("same inode under a renamed single-link path was accepted twice: %v", err)
	}
	if data, err := reader.read(name, 32, true); err != nil || string(data) != "replacement" {
		t.Fatalf("independent new inode was refused as an alias: %v", err)
	}
}

func TestCollectorFilesRejectGrowthAndCloseDescriptors(t *testing.T) {
	root, reader := collectorScratchRoot(t)
	name := "/directory/material"
	file := writeCollectorFixtureFile(t, root, name, []byte("1234"), 0o600)

	var material, directory unix.Stat_t
	collectorMust(t, unix.Stat(file, &material))
	collectorMust(t, unix.Stat(filepath.Dir(file), &directory))
	count := func() int {
		var active int
		for fd := 0; fd < 512; fd++ {
			var st unix.Stat_t
			if unix.Fstat(fd, &st) == nil && st.Dev == material.Dev && (st.Ino == material.Ino || st.Ino == directory.Ino) {
				active++
			}
		}
		return active
	}
	before := count()
	if before != 0 {
		t.Fatal("fixture descriptors are open before cleanup checks")
	}
	opened, err := reader.open(name, 4, true)
	collectorMust(t, err)
	collectorMust(t, os.WriteFile(file, []byte(strings.Repeat("x", 5)), 0o600))
	data, err := readOpenedCollectorFile(opened, 4)
	collectorMust(t, opened.Close())
	if data != nil || !errors.Is(err, ErrCollectorRoleFile) {
		t.Fatalf("file grew past checked size and read still succeeded: %v", err)
	}

	for range 8 {
		clear(reader.seen)
		if _, err := reader.read(name, 5, true); err != nil {
			t.Fatalf("cleanup control did not load: %v", err)
		}
		if _, err := reader.read(name, 4, true); err != ErrCollectorRoleFile {
			t.Fatal("cleanup refusal control did not fail")
		}
		if _, err := reader.read(name+"/missing", 5, true); err != ErrCollectorRoleFile {
			t.Fatal("cleanup traversal control did not fail")
		}
	}
	if count() != before {
		t.Fatal("trusted reader leaked a material or ancestor descriptor")
	}
}
