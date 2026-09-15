package pin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// EVERY REFUSAL HERE RETURNS THE SAME STRING, deliberately: "PIN credential unavailable" tells a
// caller nothing about which check failed, because distinguishing "no such device" from "the file
// is group-readable" would let anyone who can call PIN map the credential layout of the host.
//
// That removes the usual defence against a wrong-reason pass — the message cannot say which rule
// fired — so each case below is built to differ from a KNOWN-GOOD fixture in exactly one respect,
// and the known-good fixture is asserted to succeed in the same test. That pairing is what makes a
// refusal attributable when the error text cannot be.

// requireRefused asserts the whole refusal contract, not just that one happened.
//
// The uniform message is the security property this file opens by describing, and describing it
// while asserting only `err != nil` is how it would be lost: a future change adding "for device
// hsm-sitea" or ": permission denied" to one branch would keep every case below green while
// turning the error into an oracle for the host's credential layout.
//
// The nil value matters for the same reason a refusal must be total: a provider that received a
// credential alongside an error could use it, and the caller that checks err first would never
// know one existed to be zeroed.
func requireRefused(t *testing.T, value []byte, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s was accepted", what)
	}
	if err.Error() != "PIN credential unavailable" {
		t.Fatalf("%s was refused with %q, not the uniform message: the error now says which check "+
			"failed, which maps the host's credential layout for anyone who can call PIN", what, err)
	}
	if value != nil {
		t.Fatalf("%s returned %d bytes alongside its error", what, len(value))
	}
}

func writeCredential(t *testing.T, dir, name, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	// The Chmod is not belt-and-braces: os.WriteFile's mode is REQUESTED, and the kernel
	// applies the process umask to it. Under `umask 0077` a file asked for as 0644 lands at
	// 0600, and a fixture built to trip the group/other guard then never reaches it.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	// And assert the effect, not the call. Chmod returning nil is not the same as the file
	// carrying those bits, and a fixture that silently fails to build the state it claims
	// accuses the guard it exists to exonerate: the test fails saying the credential was
	// accepted, which is word for word what it prints when the guard is genuinely broken.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("fixture: stat %s: %v", name, err)
	}
	if info.Mode().Perm() != mode.Perm() {
		t.Fatalf("fixture: %s has mode %04o, wanted %04o — the mode did not take effect, and a "+
			"fixture with the wrong bits tests a different guard than the one it names", name, info.Mode().Perm(), mode.Perm())
	}
	return path
}

func TestTheCredentialMustBeBetweenSixAndSixtyFourBytes(t *testing.T) {
	directory := t.TempDir()
	paths := map[string]string{
		"good":      writeCredential(t, directory, "good.pin", "123456", 0o400),
		"five":      writeCredential(t, directory, "five.pin", "12345", 0o400),
		"empty":     writeCredential(t, directory, "empty.pin", "", 0o400),
		"sixtyfour": writeCredential(t, directory, "64.pin", strings.Repeat("9", 64), 0o400),
		"sixtyfive": writeCredential(t, directory, "65.pin", strings.Repeat("9", 65), 0o400),
	}
	source, err := NewLockedFileSource(paths)
	if err != nil {
		t.Fatal(err)
	}

	// The accepted ends of the range first. Without these the refusals below would be consistent
	// with a source that refuses everything.
	for _, deviceID := range []string{"good", "sixtyfour"} {
		value, err := source.PIN(context.Background(), deviceID)
		if err != nil {
			t.Fatalf("%s was refused: %v — the length bound is narrower than the code says", deviceID, err)
		}
		_ = source.Release(value)
	}
	for _, deviceID := range []string{"five", "empty", "sixtyfive"} {
		value, err := source.PIN(context.Background(), deviceID)
		requireRefused(t, value, err, deviceID+" (outside 6..64 bytes)")
	}
}

// The S_IFREG check is defence in depth and this test does not reach it — TESTING.md §17. Measured:
// with the check removed a directory is still refused, because unix.Open succeeds on one, a 0700
// directory passes the mode and owner checks, and io.ReadAll then fails on the descriptor. The
// uniform error string means the test cannot tell the two layers apart either.
//
// The other non-regular types are not constructible here: a FIFO opened O_RDONLY blocks until a
// writer appears, and device nodes need root. So what is pinned is the operator-visible property —
// a path that is not a credential file yields no credential — and the note is what stops a reader
// concluding S_IFREG is what does it and removing the read's error handling as redundant.
// TestEveryRefusalUsesTheSameWords walks the distinct refusal branches and holds each to the
// identical message. The branches differ in what they know — one has a device id that is not
// mapped, one has a file whose bytes are wrong — and it is precisely that knowledge that must not
// reach the caller.
//
// Written after a mutation escaped: adding "no mapping for <device>" to the unknown-device branch
// left every case green, because nothing had asserted the message on THAT branch. Covering one
// refusal's wording does not cover another's — and it happened twice, the second time on the
// unix.Open branch, which carries the errno and the path and so has the most to leak.
//
// WHICH SITES THIS TEST ACTUALLY REACHES. Measured by mutation
// 2026-09-06 (branch test/mutation-sweep-seven-packages):
//
//	absent  — refused by the !exists guard at line 43 in current code.
//	          Removing !exists does not change the outcome: unix.Open on
//	          path="" fails with EBADF from the next line. Redundant-but-
//	          clearer, not load-bearing.
//	link,
//	missing — refused by the unix.Open err guard at line 47 in current
//	          code (broken symlink / missing file). Removing that guard
//	          does not change the outcome: unix.Fstat(-1, ...) fails
//	          with EBADF on the descriptor the failed Open returned.
//	          Redundant-but-clearer, not load-bearing.
//	loose   — reaches the Fstat stat-check; the mode-bits clause
//	          (`stat.Mode&0o077 != 0`) is load-bearing. The S_IFREG clause
//	          is defense-in-depth (a directory is refused by ReadAll's
//	          EISDIR, not by S_IFREG); the uid clause is not constructible
//	          from a unit test running as the credential owner.
//	short,
//	space   — reaches the read/validate compound at line 60-63. Load-bearing.
//
// Three of source.go's seven refusal sites are not this test's. The entry
// guard (line 38-40) is load-bearing for nil-source safety —
// TestANilSourceIsUnavailableRatherThanAPanic fails by PANIC at line 41 if
// the guard is removed. The entry guard's ctx.Err() clause is redundant with
// the read-time check (TestACancelledRequestReadsNoCredential stays green
// when it alone is removed).
//
// Three are not constructible at all: os.NewFile returning nil (line 50-53)
// cannot happen for a descriptor unix.Open has just returned; unix.Mlock
// failing (line 64-67) needs the process at its RLIMIT_MEMLOCK, which is not
// a limit to change inside a unit test; unix.Munlock failing (line 78-80)
// was measured on darwin and linux/arm64 with `Munlock([]byte("anything"))`
// and returned rc=0 errno=0 on both platforms — Munlock errors only on
// unmapped ranges, and a Go []byte is always mapped.
func TestEveryRefusalUsesTheSameWords(t *testing.T) {
	directory := t.TempDir()
	good := writeCredential(t, directory, "good.pin", "123456", 0o400)
	symlink := filepath.Join(directory, "link.pin")
	if err := os.Symlink(good, symlink); err != nil {
		t.Fatal(err)
	}
	source, err := NewLockedFileSource(map[string]string{
		"good":  good,
		"short": writeCredential(t, directory, "short.pin", "12345", 0o400),
		"loose": writeCredential(t, directory, "loose.pin", "123456", 0o644),
		"space": writeCredential(t, directory, "space.pin", "12 456", 0o400),
		// Both reach the unix.Open failure branch, which no other case here does: O_NOFOLLOW
		// refuses the symlink, and the missing path never opens at all.
		"link":    symlink,
		"missing": filepath.Join(directory, "not-there.pin"),
	})
	if err != nil {
		t.Fatal(err)
	}
	value, err := source.PIN(context.Background(), "good")
	if err != nil {
		t.Fatalf("the known-good credential was refused: %v", err)
	}
	_ = source.Release(value)

	for _, test := range []struct {
		deviceID string
		what     string
	}{
		{"absent", "a device with no mapping"},
		{"short", "a credential below the minimum length"},
		{"loose", "a group-readable credential"},
		{"space", "a credential containing a space"},
		{"link", "a symlinked credential path"},
		{"missing", "a credential file that does not exist"},
	} {
		t.Run(test.what, func(t *testing.T) {
			got, refusal := source.PIN(context.Background(), test.deviceID)
			requireRefused(t, got, refusal, test.what)
		})
	}
}

func TestACredentialThatIsNotARegularFileIsRefused(t *testing.T) {
	directory := t.TempDir()
	good := writeCredential(t, directory, "good.pin", "123456", 0o400)
	nested := filepath.Join(directory, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	source, err := NewLockedFileSource(map[string]string{"good": good, "directory": nested})
	if err != nil {
		t.Fatal(err)
	}

	value, err := source.PIN(context.Background(), "good")
	if err != nil {
		t.Fatalf("the known-good credential was refused: %v", err)
	}
	_ = source.Release(value)
	directoryValue, directoryErr := source.PIN(context.Background(), "directory")
	requireRefused(t, directoryValue, directoryErr, "a directory")
}

func TestACancelledRequestReadsNoCredential(t *testing.T) {
	directory := t.TempDir()
	source, err := NewLockedFileSource(map[string]string{
		"good": writeCredential(t, directory, "good.pin", "123456", 0o400),
	})
	if err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	// The PIN is the one secret the daemon holds in plaintext, briefly. A request the caller has
	// abandoned must not put one in memory at all.
	//
	// ctx.Err() is checked twice — once on entry and once after the read — so removing either alone
	// leaves the other and this stays green. Only removing both goes red. Worth knowing before
	// reading a single-guard mutation as evidence about this path.
	cancelledValue, cancelledErr := source.PIN(cancelled, "good")
	requireRefused(t, cancelledValue, cancelledErr, "a cancelled request")
	if value, err := source.PIN(context.Background(), "good"); err != nil {
		t.Fatalf("the same credential was refused afterwards: %v — cancellation left the source unusable", err)
	} else {
		_ = source.Release(value)
	}
}

func TestANilSourceIsUnavailableRatherThanAPanic(t *testing.T) {
	var source *LockedFileSource
	value, err := source.PIN(context.Background(), "anything")
	requireRefused(t, value, err, "a nil source")
}

// TestTheMappingItselfMustBeUsable. A path that is not absolute resolves against whatever the
// daemon's working directory happens to be at the time, which is not a property of the
// configuration — so it is refused at construction rather than producing a credential read from
// somewhere nobody named.
func TestTheMappingItselfMustBeUsable(t *testing.T) {
	for _, test := range []struct {
		name  string
		paths map[string]string
	}{
		{"no mappings at all", map[string]string{}},
		{"a nil map", nil},
		{"an empty device id", map[string]string{"": "/run/credentials/hsm.pin"}},
		{"a whitespace device id", map[string]string{"   ": "/run/credentials/hsm.pin"}},
		{"a relative path", map[string]string{"hsm": "credentials/hsm.pin"}},
		{"a bare filename", map[string]string{"hsm": "hsm.pin"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if source, err := NewLockedFileSource(test.paths); err == nil {
				t.Fatalf("NewLockedFileSource accepted %s and returned %#v", test.name, source)
			}
		})
	}
}

func TestTheMappingIsCopiedSoTheCallerCannotRepointItLater(t *testing.T) {
	directory := t.TempDir()
	good := writeCredential(t, directory, "good.pin", "123456", 0o400)
	other := writeCredential(t, directory, "other.pin", "654321", 0o400)
	paths := map[string]string{"hsm": good}

	source, err := NewLockedFileSource(paths)
	if err != nil {
		t.Fatal(err)
	}
	// The caller still holds the map it passed in. Repointing it must not repoint the source: a
	// configuration that can be edited after validation was never validated.
	paths["hsm"] = other

	value, err := source.PIN(context.Background(), "hsm")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Release(value)
	if string(value) != "123456" {
		t.Fatalf("PIN = %q, want the credential named at construction: the source shares the caller's map", value)
	}
}

func TestReleasingNothingIsNotAnError(t *testing.T) {
	// Constructed directly: the behaviour under test is Release, and routing through the
	// constructor would tie this to whatever NewLockedFileSource validates in future — a check on
	// file existence would break a test that never reads a file.
	source := &LockedFileSource{}
	if err := source.Release(nil); err != nil {
		t.Fatalf("Release(nil) = %v; a provider whose PIN call failed still calls Release, and that must not become a second error", err)
	}
	if err := source.Release([]byte{}); err != nil {
		t.Fatalf("Release(empty) = %v", err)
	}
}
