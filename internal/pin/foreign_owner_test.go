package pin

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// The fourth operand of the Fstat compound in PIN — `stat.Uid != 0 && stat.Uid !=
// uint32(os.Geteuid())` — refuses a credential file owned by neither root nor this
// process. No test in this package reached it: none of the eleven existing tests so
// much as mentions Uid, Chown, or Geteuid, and the sweep in #237 found the operand
// surviving with the whole module green.
//
// It cannot be reached without root. The guard admits a file owned by uid 0 (first
// half of the AND is false) and admits a file owned by the caller (second half is
// false); only a THIRD uid refuses, and creating a file owned by a third uid means
// chown, which means CAP_CHOWN. As the `runner` user this test can only skip, so it
// gets its own CI step that compiles here and runs the binary under sudo.
//
// Note the direction: root makes most permission tests useless, because root ignores
// mode bits and a "this file is unreadable" fixture is simply read. Here root is what
// makes the test possible, and the mode bits are deliberately clean (0400, no group
// or other access) so that a DIFFERENT operand of the same compound cannot be the one
// refusing.
const expectUIDGuardEnforced = "REGALIA_EXPECT_UID_GUARD_ENFORCED"

// foreignUID is neither 0 nor, in any environment where this test runs, the euid —
// the test asserts both of those rather than assuming them. It need not name a user
// that exists: chown takes a number.
const foreignUID = 1

func TestACredentialOwnedByAThirdUserIsRefused(t *testing.T) {
	expected := false
	if raw := os.Getenv(expectUIDGuardEnforced); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			t.Fatalf("%s=%q is not a boolean — an unparseable value must not read as \"not expected\"", expectUIDGuardEnforced, raw)
		}
		expected = parsed
	}
	if os.Geteuid() != 0 {
		if expected {
			t.Fatalf("%s is set but this process runs as euid %d — only root may chown a file to a "+
				"third user, so the ownership operand cannot be reached and the check that was "+
				"expected to run did not", expectUIDGuardEnforced, os.Geteuid())
		}
		t.Skipf("euid is %d, not 0: only root may chown a credential to a third user, so the "+
			"ownership operand cannot be reached here; set %s=1 wherever this runs as root to "+
			"require it rather than skip it", os.Geteuid(), expectUIDGuardEnforced)
	}
	if foreignUID == os.Geteuid() {
		t.Fatalf("the foreign uid %d IS this process's euid — the guard would admit it and this "+
			"test would report a defect that is not there", foreignUID)
	}

	directory := t.TempDir()
	// PROVE THE FIXTURE, not just the code. A chown that silently did not take effect
	// leaves a root-owned file, which this guard correctly ACCEPTS — and the test would
	// then fail saying the credential was accepted, which is exactly what it prints when
	// the guard is genuinely broken. A fixture that can fail the same way as the defect
	// accuses the code it exists to exonerate, so both facts are asserted here.
	write := func(name string, uid int) string {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("123456"), 0o400); err != nil {
			t.Fatalf("fixture: writing %s: %v", name, err)
		}
		if err := os.Chown(path, uid, 0); err != nil {
			t.Fatalf("fixture: chowning %s to uid %d: %v", name, uid, err)
		}
		var stat unix.Stat_t
		if err := unix.Stat(path, &stat); err != nil {
			t.Fatalf("fixture: stat %s: %v", name, err)
		}
		if stat.Uid != uint32(uid) {
			t.Fatalf("fixture: %s is owned by uid %d, wanted %d — the chown did not take effect, "+
				"and a wrong-owner fixture would accuse the guard instead of testing it", name, stat.Uid, uid)
		}
		if stat.Mode&0o077 != 0 {
			t.Fatalf("fixture: %s has mode %04o — group or other access makes a DIFFERENT operand "+
				"of the same compound refuse it, and this test would then pass without the "+
				"ownership check existing at all", name, stat.Mode&0o7777)
		}
		return path
	}

	own := write("root-owned", 0)
	foreign := write("foreign-owned", foreignUID)

	source, err := NewLockedFileSource(map[string]string{"own": own, "foreign": foreign})
	if err != nil {
		t.Fatalf("NewLockedFileSource: %v", err)
	}

	// THE CONTROL, in the same run and through the same call. Without it a PIN that
	// refused everything would pass the assertion below, and so would a fixture whose
	// directory or mode made every file unreadable. It is a root-owned 0400 file, which
	// is the shape systemd's LoadCredentialEncrypted actually produces.
	value, err := source.PIN(context.Background(), "own")
	if err != nil {
		t.Fatalf("control: a root-owned 0400 credential was refused (%v) — every assertion below "+
			"would pass against a PIN that refuses everything, and none of them would be evidence", err)
	}
	if string(value) != "123456" {
		t.Fatalf("control: PIN returned %q, want %q", value, "123456")
	}
	// PIN returns LOCKED pages holding plaintext; leaving them locked would outlive this
	// test in the package's process and be charged against every later RLIMIT_MEMLOCK.
	if err := source.Release(value); err != nil {
		t.Fatalf("control: releasing the credential failed: %v", err)
	}

	// THE GATE. Same directory, same mode, same bytes, same call — ownership is the only
	// thing that differs from the control, so a refusal here is attributable to it.
	value, err = source.PIN(context.Background(), "foreign")
	if err == nil {
		// Report the owner the KERNEL sees, not the one this test asked for. A message that
		// prints foreignUID would keep claiming "owned by uid 1" even in a run where the file
		// is not owned by uid 1 — which is the one run where the reader most needs the truth,
		// because then the fault is the fixture and not the guard.
		var stat unix.Stat_t
		owner := "unknown (stat failed)"
		if err := unix.Stat(foreign, &stat); err == nil {
			owner = strconv.FormatUint(uint64(stat.Uid), 10)
		}
		t.Fatalf("PIN returned %q with no error for a credential owned by uid %s — a third user "+
			"who can write that file chooses the PIN this daemon presents to the HSM, and the "+
			"only thing separating it from the accepted control is the owning uid",
			value, owner)
	}
	// As in mlock_refusal_test.go: the consequence keeps its own branch above, and this adds
	// the contract every other refusal is held to — the uniform message, so the error cannot
	// disclose which check refused, and a nil value rather than a merely empty one.
	// TestEveryRefusalUsesTheSameWords cannot reach this path either; it would need root.
	requireRefused(t, value, err, "a credential owned by a third user")
}
