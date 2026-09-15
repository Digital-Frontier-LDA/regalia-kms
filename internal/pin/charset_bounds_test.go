package pin

// A BOUND NAMED ON ONE SIDE ONLY.
//
// containsUnsafe refuses a credential byte outside printable ASCII:
//
//	if item < 0x21 || item > 0x7e {
//
// The #237 sweep of this package (12 sites / 23 operands / 46 operand-directions) found the
// UPPER operand surviving. The reason is visible in the fixtures: every unsafe-byte case in
// the package uses a SPACE — "12 456" in TestEveryRefusalUsesTheSameWords — and 0x20 is
// below the lower bound. The lower half of the range was covered twice over and the upper
// half not at all.
//
// MEASURED WITH `item > 0x7e` NEUTRALISED: a credential containing 0x7f, or any byte with
// the high bit set, is accepted and returned as the PIN. Nothing in the package or in the
// nine packages that depend on it went red.
//
// It matters because of where these bytes come from. A credential file is written by
// systemd's LoadCredentialEncrypted or by an operator, and the failure this catches is a
// mundane one: a UTF-8 PIN, a stray 0xFF from a truncated decrypt, a byte-order mark. The
// daemon would present those bytes to the token as a PIN, and a PKCS#11 token counts a
// wrong PIN against a retry counter that locks the card after three.

import (
	"context"
	"testing"
)

// TestTheCredentialCharsetIsBoundedAtBothEnds pins BOTH operands of containsUnsafe.
//
// The two rejected rows sit one byte outside each end of the range and the two accepted rows
// sit exactly ON each end, so neither operand can be satisfied by the other: 0x7f is above
// 0x7e but not below 0x21, and 0x20 is below 0x21 but not above 0x7e.
func TestTheCredentialCharsetIsBoundedAtBothEnds(t *testing.T) {
	directory := t.TempDir()
	// Six bytes each, so the length rule is satisfied identically everywhere and cannot be
	// what refuses. Mode 0400 for the same reason.
	paths := map[string]string{
		"bang":  writeCredential(t, directory, "bang.pin", "!23456", 0o400),    // 0x21, the first accepted byte
		"tilde": writeCredential(t, directory, "tilde.pin", "12345~", 0o400),   // 0x7e, the last accepted byte
		"space": writeCredential(t, directory, "space.pin", "12 456", 0o400),   // 0x20, one below the range
		"del":   writeCredential(t, directory, "del.pin", "12345\x7f", 0o400),  // 0x7f, one above it
		"high":  writeCredential(t, directory, "high.pin", "12345\xc3", 0o400), // a UTF-8 lead byte
		"nul":   writeCredential(t, directory, "nul.pin", "12345\x00", 0o400),  // the other extreme
	}
	source, err := NewLockedFileSource(paths)
	if err != nil {
		t.Fatal(err)
	}

	// THE GATE, before the anchors: an anchor that fatals first would foreclose the
	// falsification below it (TESTING.md §18).
	for _, deviceID := range []string{"space", "del", "high", "nul"} {
		value, err := source.PIN(context.Background(), deviceID)
		requireRefused(t, value, err, deviceID+" (a byte outside printable ASCII)")
	}

	// THE ANCHORS, on the range's two exact endpoints. Without them every refusal above is
	// equally consistent with a charset rule that refuses everything, and a bound asserted
	// only from outside is not a bound.
	for _, deviceID := range []string{"bang", "tilde"} {
		value, err := source.PIN(context.Background(), deviceID)
		if err != nil {
			t.Fatalf("%s was refused: %v — 0x21 and 0x7e are the ends of the accepted range, and "+
				"a rule that refuses its own endpoints is a narrower rule than the code says", deviceID, err)
		}
		if err := source.Release(value); err != nil {
			t.Fatalf("releasing %s failed: %v", deviceID, err)
		}
	}
}

// THE OTHER FOURTEEN SURVIVING DIRECTIONS, RE-MEASURED RATHER THAN INHERITED.
//
// custody_test.go already carries a ledger for most of this package, written against a sweep
// dated 2026-09-06. I re-derived the population with the AST enumerator instead of trusting
// it — 12 sites / 23 operands / 46 operand-directions — and re-ran every operand. The
// inherited entries agree with the new measurements wherever they overlap, which is worth
// stating explicitly, because the value of a re-measurement is the same either way and only
// one of the two outcomes usually gets written down.
//
// It did NOT cover the charset bound above. That is the one thing this sweep found here.
//
//	REDUNDANT-BUT-CLEARER, each confirmed by neutralising it alone:
//	  `ctx.Err() != nil` on entry        the read-time check at the ReadAll compound refuses
//	                                     the same request; either alone leaves the other.
//	  `ctx.Err() != nil` after the read  the entry check, symmetrically. Both were already
//	                                     recorded in TestACancelledRequestReadsNoCredential.
//	  `!exists`                          unix.Open on the empty path fails with EBADF.
//	  `err != nil` on unix.Open          unix.Fstat on the -1 descriptor fails with EBADF.
//	  `len(value) == 0` in Release       Munlock over a zero-length slice returns success on
//	                                     both platforms, so Release(nil) is an error either way.
//
//	DEFENCE IN DEPTH, refused by a later layer on every constructible input:
//	  `stat.Mode&S_IFMT != S_IFREG`      a directory is refused by io.ReadAll's EISDIR. The
//	                                     other non-regular types need a blocking FIFO or root.
//	  `err != nil` on unix.Fstat         Fstat cannot fail on a descriptor unix.Open just
//	                                     returned.
//	  `err != nil` on io.ReadAll         no constructible credential file makes a bounded read
//	                                     of a regular file fail.
//	  `err != nil` on unix.Munlock       measured on darwin and linux/arm64: Munlock over a Go
//	                                     []byte returns 0, because a Go slice is always mapped.
//
//	NOT CONSTRUCTIBLE:
//	  `file == nil`                      os.NewFile does not return nil for a descriptor
//	                                     unix.Open has just handed back.
//
//	COVERED, BUT NOT ON THIS RUNNER — these are gated CI steps, not gaps:
//	  `stat.Uid != 0` (both directions) and `stat.Uid != uint32(os.Geteuid())`
//	                                     foreign_owner_test.go pins them and SKIPS unless
//	                                     euid is 0, because only root may chown a file to a
//	                                     third user. This sweep ran unprivileged, so all
//	                                     three surviving directions are the skip, not an
//	                                     absent test.
//	  `err != nil` on unix.Mlock         mlock_refusal_test.go pins it and skips off linux,
//	                                     where PIN's buffer locks even at RLIMIT_MEMLOCK=0.
//	                                     This sweep ran on darwin.
//
// ONE MEASUREMENT HERE IS AN EXPECTATION, NOT A RESULT, and is labelled as such. Removing the
// unix.Mlock CALL — not its guard, the call — left the whole dependent suite green on darwin,
// which re-confirms the note in mlock_refusal_test.go that nothing downstream notices an
// unlocked credential. On linux that same edit should be caught, because it makes PIN succeed
// at RLIMIT_MEMLOCK=0, which is exactly the condition that test's gate asserts against. I did
// not have a linux runner, so that last sentence is reasoning about the existing test and not
// something this sweep observed.
