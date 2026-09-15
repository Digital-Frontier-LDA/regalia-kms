package main

// GUARD COVERAGE, ROUND 1 (#237 sweep): `cmd/regalia-kms` is the daemon's entry point and had
// never been swept. Whole `if` CONDITIONS were mutated one at a time to
// `if false && (<original>)`, verdicts from exit codes. This file pins the three whose absence
// has a consequence a reader would not predict from the code, each proven by building the input
// first.
//
//   main.go loadFencingKey size check   -> without it ed25519.Verify PANICS on the wrong length
//   provenance.go record.Site == ""     -> covered only where a LATER guard cannot also fire
//   provenance.go CommissionedAt.IsZero -> no fixture existed at all; the record was ACCEPTED
//
// THIS ROUND'S POPULATION AND SURVIVOR COUNT ARE NOT REPEATED HERE, and that is the correction
// rather than an omission. They were stated in the present tense, in a file, for a measurement
// taken once against a tree that has moved since — so they read as current and were not. Round 2
// re-derived them from kms/tools/guardenum and got a different unit as well as a different
// number: a whole-condition sweep measures SITES, and a site with three leaves hides two
// operands inside one verdict. The live figures belong in the PR ledger that carries the run
// that produced them; see guard_coverage_round2_test.go for what the leaf-level sweep found,
// including three survivors in a shape guardenum does not enumerate at all.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A WRONG-SIZED KEY IS REFUSED WHERE IT IS READ, BECAUSE THE ALTERNATIVE IS A PANIC.
//
// loadFencingKey's own doc comment already promises this ("an unreadable or wrong-sized file is a
// startup error rather than a site that quietly never becomes ready"), and nothing checked it.
// Measured with the guard mutated away: loadFencingKey returns a 31-byte key and err=<nil>, and
// the first ed25519.Verify to touch it panics with `ed25519: bad public key length: 31` — Go's
// Verify panics on a mis-sized PUBLIC key rather than returning false, which is the asymmetry
// that makes this guard load-bearing rather than defensive. checkProvenance calls Verify on
// exactly this key, so the panic is reachable from a config file typo.
func TestAWrongSizedFencingKeyIsRefusedWhereItIsReadRatherThanPanickingLater(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fencing.pub")
	short := make([]byte, ed25519.PublicKeySize-1)
	for i := range short {
		short[i] = byte(i + 1) // non-zero: a key of zero bytes would be refused by shape checks elsewhere
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(short)), 0o600); err != nil {
		t.Fatal(err)
	}

	key, err := loadFencingKey(path)
	if err == nil {
		t.Fatalf("a %d-byte fencing public key loaded (len=%d) — the next ed25519.Verify panics on it, and a config typo must not be a crash",
			len(short), len(key))
	}
	if !strings.Contains(err.Error(), "32") || !strings.Contains(err.Error(), "31") {
		t.Fatalf("the refusal does not say what was wrong: %v — an operator fixing a key file needs both the expected and the actual length", err)
	}

	// KNOWN-GOOD IN THE SAME TEST (§18): a correctly sized key must still load, or a guard that
	// refused everything would satisfy the assertion above.
	public, _, genErr := ed25519.GenerateKey(rand.Reader)
	if genErr != nil {
		t.Fatal(genErr)
	}
	good := filepath.Join(t.TempDir(), "good.pub")
	if err := os.WriteFile(good, []byte(base64.StdEncoding.EncodeToString(public)), 0o600); err != nil {
		t.Fatal(err)
	}
	if loaded, err := loadFencingKey(good); err != nil || len(loaded) != ed25519.PublicKeySize {
		t.Fatalf("a well-formed fencing key was refused (err=%v len=%d)", err, len(loaded))
	}
}

// AN UNATTRIBUTABLE RECORD, WHERE NO LATER GUARD CAN ALSO REFUSE IT.
//
// provenance_test.go already has an "unattributable record" row, and it does not detect this
// guard. Measured: with `record.Site == ""` mutated away, that row still refuses — but by the
// SITE-MISMATCH guard further down, which reports
//
//	commissioning record names site "" but this host is configured as "sitea"
//	— the record belongs to a different deployment
//
// a different refusal with a different meaning. The row asserts only `err == nil` and so cannot
// tell them apart. The isolating fixture is a host with NO configured site: the mismatch guard
// short-circuits on `settings.Site != ""`, leaving this guard the only thing that can refuse.
func TestAnUnattributableRecordIsRefusedWhereTheSiteMismatchGuardCannotFire(t *testing.T) {
	settings, _ := provenanceSettings(t)
	settings.Site = "" // the mismatch guard below is now unreachable by construction
	key := authorityKeyFor(t, &settings)

	nameless := recordBody
	nameless.Site = ""
	writeRecord(t, settings.CommissioningRecordPath, nameless, key)

	_, err := checkProvenance(settings)
	if err == nil {
		t.Fatal("a validly signed record naming no site passed as provenance on a host with no configured site — an unattributable record is a claim, not evidence")
	}
	if !strings.Contains(err.Error(), "names no site or no time") {
		t.Fatalf("refused, but by a different guard: %v — this row exists to prove the unattributable-record check fires, and any other refusal means it did not", err)
	}
}

// A RECORD THAT NAMES NO TIME. This operand had no fixture at all: every existing row sets a real
// CommissionedAt. Measured with it mutated away, a validly signed record whose commissioned_at is
// the zero time was ACCEPTED — err=<nil> — because the site matches and the signature verifies
// over the zero value like any other. Provenance without a time cannot answer "was this site
// commissioned before or after the incident", which is the question the record exists for.
func TestARecordNamingNoTimeIsNotProvenance(t *testing.T) {
	settings, _ := provenanceSettings(t)
	key := authorityKeyFor(t, &settings)

	timeless := recordBody
	timeless.CommissionedAt = time.Time{}
	writeRecord(t, settings.CommissioningRecordPath, timeless, key)

	_, err := checkProvenance(settings)
	if err == nil {
		t.Fatal("a validly signed record with a zero commissioned_at passed as provenance — a record that cannot be placed in time cannot say whether it predates the incident")
	}
	if !strings.Contains(err.Error(), "names no site or no time") {
		t.Fatalf("refused, but by a different guard: %v", err)
	}

	// KNOWN-GOOD (§18): the same record with a real time is accepted, so the row is not passing
	// against a rule that refuses every record.
	settings2, _ := provenanceSettings(t)
	key2 := authorityKeyFor(t, &settings2)
	writeRecord(t, settings2.CommissioningRecordPath, recordBody, key2)
	if record, err := checkProvenance(settings2); err != nil || record == nil {
		t.Fatalf("a well-formed commissioning record was refused (err=%v)", err)
	}
}

// A BROKEN AUTHORITY KEY FILE IS A CONFIGURATION ERROR, NOT A STACK TRACE.
//
// Found by a class sweep for guards that sit in front of an operation which PANICS rather
// than returning an error — 24 candidates, of which this was the one real finding. Measured
// with the guard mutated away and a key file that is not base64:
//
//	PROBE PANICKED: ed25519: bad public key length: 0
//
// loadFencingKey returns (nil, err); without the caller's error check the nil key reaches
// ed25519.Verify below, and Go's Verify PANICS on a mis-sized public key rather than
// returning false. checkProvenance runs from preflight.go's startup path, before anything
// serves, so there is no net/http recover between it and the process — an operator with a
// truncated or mistyped fencing_public_key_path gets a Go stack trace from the one step whose
// entire job is to tell them what is misconfigured.
//
// This is the sibling of TestAWrongSizedFencingKeyIsRefusedWhereItIsReadRatherThanPanickingLater
// one layer up: that row pins loadFencingKey REFUSING a bad key, this one pins its caller
// HONOURING the refusal. Both are needed — the first can pass while the second is deleted.
func TestABrokenAuthorityKeyFileIsReportedRatherThanPanicking(t *testing.T) {
	settings, _ := provenanceSettings(t)
	key := authorityKeyFor(t, &settings)
	// A well-formed, correctly signed record: the record must be good enough to reach the
	// signature check, or this row would be satisfied by an earlier guard.
	writeRecord(t, settings.CommissioningRecordPath, recordBody, key)

	// Now break only the KEY file. Not base64, so loadFencingKey refuses it.
	if err := os.WriteFile(settings.FencingPublicKeyPath, []byte("!!!not base64!!!"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := checkProvenance(settings)
	if err == nil {
		t.Fatal("a commissioning record was accepted against an unreadable authority key — the record's signature was never verified against anything")
	}
	if !strings.Contains(err.Error(), "commissioning authority key") {
		t.Fatalf("refused, but not by the key-loading check: %v — this row exists to prove the caller honours loadFencingKey's error instead of carrying a nil key into ed25519.Verify", err)
	}

	// KNOWN-GOOD IN THE SAME TEST (§18): restore a valid key and the same record verifies, so
	// the row is not satisfied by a path that refuses every record.
	settings2, _ := provenanceSettings(t)
	key2 := authorityKeyFor(t, &settings2)
	writeRecord(t, settings2.CommissioningRecordPath, recordBody, key2)
	if record, err := checkProvenance(settings2); err != nil || record == nil {
		t.Fatalf("a well-formed record with a valid authority key was refused (%v)", err)
	}
}
