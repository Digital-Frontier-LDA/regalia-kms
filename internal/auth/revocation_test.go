package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// THE FALSIFIABLE CONTRACT.
//
// Each test below encodes one direction of the revocation contract. Every test
// was written against the fixed code, run green, then re-run against the
// unfixed code with the offending lines commented out — the failure mode is
// recorded in the test body so a future regression cannot pass silently.
//
// Falsifiability matrix:
//
//   - TestRevocationRejectsSerialAddedMidProcess:           denies on file change
//   - TestRevocationFileUnreadableFailsClosed:              denies, not admits
//   - TestRevocationFileUnparseableFailsClosed:             denies, not admits
//   - TestRevocationAbsentSerialStillAuthenticates:         admits, not denies
//   - TestRevocationMissingFileFailsClosed:                 denies, not admits
//   - TestRevocationNotConfiguredIsANoOp:                   admits
//   - TestRevocationListEmptyPathIsANoOp:                   admits
//   - ParseRevocationListRejectsGarbageAndHandlesBlanks:    parser pin
//   - TestRevocationRejectsWorldWritableFileAtStart:        custody, refuses
//   - TestRevocationRejectsSymlinkAtPath:                   custody, refuses
//   - TestRevocationRejectsNonRegularFileAtPath:            custody, refuses
//   - TestRevocationRejectsFileThatBecomesWorldWritable:    custody, refuses
//   - TestRevocationIsCheckedAfterTLSPresence:              order pin

// TestRevocationRejectsSerialAddedMidProcess is the falsifiable proof that the
// re-read-on-use cache picks up a serial the moment it is appended to the file,
// without a process restart and without a signal.
//
// Delete-fix scenario: comment out the revocation block in Authenticate. The
// second Authenticate call below returns nil error; this test fails with the
// explicit DEFECT message below.
func TestRevocationRejectsSerialAddedMidProcess(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	path := writeRevocationFile(t)
	list, err := NewRevocationList(path)
	if err != nil {
		t.Fatal(err)
	}
	authenticator := NewAuthenticator("spiffe://regalia/", list, func() time.Time { return now }, time.Minute)
	cert := certificate(t, "spiffe://regalia/workload/tx-signer", now.Add(-time.Hour), now.Add(time.Hour), 42)

	if _, err := authenticator.Authenticate(authenticatedRequest(cert)); err != nil {
		t.Fatalf("baseline (serial not yet revoked) refused: %v", err)
	}

	if err := os.WriteFile(path, []byte("42\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := authenticator.Authenticate(authenticatedRequest(cert)); err == nil {
		t.Fatal("DEFECT: serial 42 added to revocation file mid-process was NOT refused on next request — re-read-on-use is broken")
	} else if err.Error() != "request authentication failed" {
		t.Fatalf("revoked cert error = %q, want %q", err.Error(), "request authentication failed")
	}
}

// TestRevocationFileUnreadableFailsClosed pins the fail-closed posture: an
// unreadable revocation file must NOT admit because the cached entry is empty.
//
// Delete-fix scenario: commenting out the revocation block lets the cert pass;
// this test fails with the explicit DEFECT message below.
//
// Implementation note: chmod on the FILE alone does not break os.Stat (stat(2)
// does not require read permission), so the cached mtime remains valid and the
// revocation code returns the cached map without ever re-opening. We chmod the
// PARENT directory, which strips execute permission and breaks Stat on every
// descendant — the path the daemon's stat() actually traverses.
func TestRevocationFileUnreadableFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked.txt")
	if err := os.WriteFile(path, []byte("9999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := NewRevocationList(path)
	if err != nil {
		t.Fatal(err)
	}
	authenticator := NewAuthenticator("spiffe://regalia/", list, func() time.Time { return now }, time.Minute)
	cert := certificate(t, "spiffe://regalia/workload/tx-signer", now.Add(-time.Hour), now.Add(time.Hour), 42)

	if err := os.Chmod(dir, 0o000); err != nil {
		t.Skipf("cannot chmod directory to test unreadable: %v (run as non-root)", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	if _, err := authenticator.Authenticate(authenticatedRequest(cert)); err == nil {
		t.Fatal("DEFECT: unreadable revocation file caused Authenticate() to admit — must fail closed")
	} else if err.Error() != "request authentication failed" {
		t.Fatalf("unreadable-list error = %q, want %q", err.Error(), "request authentication failed")
	}
}

// TestRevocationFileUnparseableFailsClosed pins the second fail-closed
// direction: a file with garbage content must NOT admit because the parse
// failed. The file at startup was valid; the operator replaced it with garbage
// before the next request.
func TestRevocationFileUnparseableFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	path := writeRevocationFile(t) // valid empty file at construction
	list, err := NewRevocationList(path)
	if err != nil {
		t.Fatal(err)
	}
	authenticator := NewAuthenticator("spiffe://regalia/", list, func() time.Time { return now }, time.Minute)
	cert := certificate(t, "spiffe://regalia/workload/tx-signer", now.Add(-time.Hour), now.Add(time.Hour), 42)

	if err := os.WriteFile(path, []byte("not-a-serial\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := authenticator.Authenticate(authenticatedRequest(cert)); err == nil {
		t.Fatal("DEFECT: unparseable revocation file caused Authenticate() to admit — must fail closed")
	} else if err.Error() != "request authentication failed" {
		t.Fatalf("unparseable-list error = %q, want %q", err.Error(), "request authentication failed")
	}
}

// TestRevocationAbsentSerialStillAuthenticates is the negative case. The peer
// requires the test to fail in both directions: revocation must refuse what is
// in the list AND admit what is not. A regression that bans every cert under
// the guise of "fail closed" would pass the three tests above and fail here.
func TestRevocationAbsentSerialStillAuthenticates(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	authenticator := NewAuthenticator("spiffe://regalia/", newRevocationList(t, "99"), func() time.Time { return now }, time.Minute)
	cert := certificate(t, "spiffe://regalia/workload/tx-signer", now.Add(-time.Hour), now.Add(time.Hour), 42)

	principal, err := authenticator.Authenticate(authenticatedRequest(cert))
	if err != nil {
		t.Fatalf("serial 42 is not in revocation list: Authenticate() = %v, want nil", err)
	}
	if principal == "" {
		t.Fatal("serial 42 is not in revocation list: principal = empty, want non-empty")
	}
}

// TestRevocationMissingFileFailsClosed covers the case where the file existed
// at construction (parsed) and is deleted before the next check. The stat()
// returns ENOENT — that is "cannot tell", which must refuse.
func TestRevocationMissingFileFailsClosed(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	path := writeRevocationFile(t)
	list, err := NewRevocationList(path)
	if err != nil {
		t.Fatal(err)
	}
	authenticator := NewAuthenticator("spiffe://regalia/", list, func() time.Time { return now }, time.Minute)
	cert := certificate(t, "spiffe://regalia/workload/tx-signer", now.Add(-time.Hour), now.Add(time.Hour), 42)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := authenticator.Authenticate(authenticatedRequest(cert)); err == nil {
		t.Fatal("DEFECT: missing revocation file caused Authenticate() to admit — must fail closed")
	}
}

// TestRevocationNotConfiguredIsANoOp preserves the pre-revocation posture:
// hosts that have not configured revoked_serials_path see no revocation check
// at all. This is the only test where a nil list is correct.
func TestRevocationNotConfiguredIsANoOp(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	authenticator := NewAuthenticator("spiffe://regalia/", nil, func() time.Time { return now }, time.Minute)
	cert := certificate(t, "spiffe://regalia/workload/tx-signer", now.Add(-time.Hour), now.Add(time.Hour), 42)

	principal, err := authenticator.Authenticate(authenticatedRequest(cert))
	if err != nil {
		t.Fatalf("nil revocation list: Authenticate() = %v, want nil", err)
	}
	if principal != "spiffe://regalia/workload/tx-signer" {
		t.Fatalf("principal = %q", principal)
	}
}

// TestRevocationListEmptyPathIsANoOp: NewRevocationList("") returns a usable
// list whose Check is a no-op. The daemon wires NewRevocationList with the
// configured path; an unset field should not break startup.
func TestRevocationListEmptyPathIsANoOp(t *testing.T) {
	list, err := NewRevocationList("")
	if err != nil {
		t.Fatalf("NewRevocationList(\"\"): %v", err)
	}
	revoked, err := list.Check("anything")
	if err != nil || revoked {
		t.Fatalf("Check on empty-path list = (%v, %v), want (false, nil)", revoked, err)
	}
}

// TestParseRevocationListRejectsGarbageAndHandlesBlanks pins the file-format
// contract: one serial per line, comments allowed, blank lines allowed,
// garbage is an error (no silent dropping).
func TestParseRevocationListRejectsGarbageAndHandlesBlanks(t *testing.T) {
	good := "10\n# a comment\n\n20  \n-1\nnot-a-number\n30\n"
	path := filepath.Join(t.TempDir(), "revoked.txt")
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRevocationList(path); err == nil {
		t.Fatal("DEFECT: a revocation file with negative or non-numeric entries parsed without error")
	}

	clean := "10\n# header\n\n20\n# trailing\n30\n"
	if err := os.WriteFile(path, []byte(clean), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := NewRevocationList(path)
	if err != nil {
		t.Fatalf("clean file: NewRevocationList = %v", err)
	}
	for _, serial := range []string{"10", "20", "30"} {
		revoked, err := list.Check(serial)
		if err != nil || !revoked {
			t.Fatalf("serial %s: Check = (%v, %v), want (true, nil)", serial, revoked, err)
		}
	}
	revoked, err := list.Check("40")
	if err != nil || revoked {
		t.Fatalf("serial 40 (not in list): Check = (%v, %v), want (false, nil)", revoked, err)
	}
}

// Sanity: a non-TLS request still bypasses the revocation check (the request
// fails earlier, at the TLS chain check). This test pins the order so a
// refactor that puts revocation before TLS still calls itself a regression.
func TestRevocationIsCheckedAfterTLSPresence(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	authenticator := NewAuthenticator("spiffe://regalia/", newRevocationList(t, "5"), func() time.Time { return now }, time.Minute)
	request := httptest.NewRequest(http.MethodPost, "/v1/operations/sign", nil) // no TLS at all
	if _, err := authenticator.Authenticate(request); err == nil || err.Error() != "request authentication failed" {
		t.Fatalf("no-TLS request: Authenticate() = %v, want the standard refusal", err)
	}
}

// TestRevocationRejectsWorldWritableFileAtStart pins the file-custody
// invariant at startup. A revocation list that any local user can edit is
// fail-open: an unprivileged user can remove a serial that was revoked
// precisely because the certificate was compromised, and the daemon would
// keep authenticating it without any log of the bypass.
//
// Delete-fix scenario: comment out the permission check in load(). The file
// is otherwise valid and parses cleanly; NewRevocationList returns a usable
// list. This test fails because err is nil.
func TestRevocationRejectsWorldWritableFileAtStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked.txt")
	if err := os.WriteFile(path, []byte("42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// umask(2) narrows the requested mode in os.WriteFile, so chmod directly
	// to the unsafe mode we want the daemon to reject.
	if err := os.Chmod(path, 0o666); err != nil {
		t.Skipf("cannot chmod world-writable: %v (run as non-root)", err)
	}
	list, err := NewRevocationList(path)
	if err == nil {
		t.Fatalf("DEFECT: NewRevocationList accepted a world-writable revocation file (mode 0o666): list=%#v", list)
	}
}

// TestRevocationRejectsSymlinkAtPath pins O_NOFOLLOW: a symlink at the
// configured path could redirect the daemon to a file the operator did not
// choose. The fix is to refuse the symlink at the descriptor; opening with
// O_NOFOLLOW makes the syscall return ELOOP and the load function fails closed.
//
// Delete-fix scenario: drop O_NOFOLLOW from the unix.Open call. The symlink
// resolves, the file is parsed, and NewRevocationList returns a usable list.
// This test fails because err is nil.
func TestRevocationRejectsSymlinkAtPath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "revoked.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	list, err := NewRevocationList(link)
	if err == nil {
		t.Fatalf("DEFECT: NewRevocationList followed a symlink at the revocation path: list=%#v", list)
	}
}

// TestRevocationRejectsNonRegularFileAtPath pins the S_IFREG check via a FIFO
// rather than a directory. A directory at the path is also non-regular, but
// on Darwin reading a directory errors out with EISDIR inside parseRevocationList,
// so a test using a directory would be falsifiable by *two* layers. Using a
// FIFO isolates the S_IFREG check: the FIFO opens, the writer feeds a valid
// serial, the parse would succeed, and only the S_IFREG refusal catches it.
//
// Delete-fix scenario: drop the S_IFREG check in load(). The FIFO opens, the
// parse succeeds with the writer's serial, NewRevocationList returns a usable
// list. This test fails because err is nil.
func TestRevocationRejectsNonRegularFileAtPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Skipf("cannot create FIFO: %v (run on a Unix system)", err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
	// Feed the FIFO so the open + parse does not block. The writer exits as
	// soon as it has written the line; the reader inside load() reads one
	// line and returns.
	go func() {
		// O_WRONLY opens the write end without O_NONBLOCK because the read
		// end is already being opened in load(); the open call blocks until
		// a reader exists, which it does.
		fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_, _ = unix.Write(fd, []byte("42\n"))
	}()
	list, err := NewRevocationList(path)
	if err == nil {
		t.Fatalf("DEFECT: NewRevocationList accepted a non-regular file (FIFO) as a revocation list: list=%#v", list)
	}
}

// TestRevocationRejectsFileThatBecomesWorldWritable pins the second Copilot
// thread: the file was safe at startup (mode 0o600, ModTime T1), but a local
// user chmods it to 0o666 before the next request. ModTime is unchanged, so a
// cache that only validated the file at construction would keep returning the
// cached parse. The cached parse is not the bypass — the file's new mode is,
// because the bypass it enables (un-revoking) does not require writing the
// file in between requests; it requires the daemon to trust whatever sits
// there. The mode check on every Check closes this.
//
// Delete-fix scenario: replace the load()-per-check with a stat()-per-check
// (modtime-only, no mode). The chmod is invisible to ModTime; Check sees no
// change, returns the cached parse, admits the cert. This test fails because
// err is nil.
func TestRevocationRejectsFileThatBecomesWorldWritable(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	path := filepath.Join(dir, "revoked.txt")
	if err := os.WriteFile(path, []byte("9999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := NewRevocationList(path)
	if err != nil {
		t.Fatal(err)
	}
	authenticator := NewAuthenticator("spiffe://regalia/", list, func() time.Time { return now }, time.Minute)
	cert := certificate(t, "spiffe://regalia/workload/tx-signer", now.Add(-time.Hour), now.Add(time.Hour), 42)

	if err := os.Chmod(path, 0o666); err != nil {
		t.Skipf("cannot chmod world-writable: %v (run as non-root)", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	if _, err := authenticator.Authenticate(authenticatedRequest(cert)); err == nil {
		t.Fatal("DEFECT: revocation file chmod'd to 0o666 mid-process was accepted on next request — fail-open on the un-revoke direction")
	}
}

// A REVOCATION ADDED WITHIN ONE MTIME TICK MUST STILL BE SEEN.
//
// Check used to compare the descriptor's ModTime against a cached one and, on a match, return the
// CACHED map while discarding the map load() had already parsed. Two writes inside a single coarse
// mtime tick were therefore indistinguishable, and a serial added in the same tick as a previous
// write would never be seen — a fail-open window on the one control whose entire job is to fail
// closed, and the narrow racy kind that shows up once and is never reproduced.
//
// The cache also saved nothing: load() parses unconditionally, so the discarded work had already
// been done.
func TestRevocationSeesASerialAddedWithinTheSameModTimeTick(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "revoked.txt")
	if err := os.WriteFile(path, []byte("11\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := NewRevocationList(path)
	if err != nil {
		t.Fatal(err)
	}
	if revoked, err := list.Check("22"); err != nil || revoked {
		t.Fatalf("serial 22 reported revoked before it was listed: %v %v", revoked, err)
	}

	// Rewrite with an added serial and force the mtime back to what it was, which is what a
	// coarse-resolution filesystem does on its own for two writes in the same tick.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("11\n22\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(info.ModTime()) {
		t.Fatalf("test setup failed to hold the mtime constant (%v vs %v), so the same-tick case is not being exercised", after.ModTime(), info.ModTime())
	}

	revoked, err := list.Check("22")
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("a serial added without an mtime change was never seen: a revoked certificate would keep authenticating")
	}
}
