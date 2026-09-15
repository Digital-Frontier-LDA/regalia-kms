package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/fencing"
)

type issuerFixture struct {
	directory string
	key       string
	state     string
	journal   string
	lease     string
	out       *os.File
	outPath   string
}

func newIssuer(t *testing.T) *issuerFixture {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(directory, "lease-signing.key")
	if err := os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(private)), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(directory, "stdout.txt")
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.Close() })
	return &issuerFixture{
		directory: directory, key: key,
		state:   filepath.Join(directory, "issuer-state.json"),
		journal: filepath.Join(directory, "authority.jsonl"),
		lease:   filepath.Join(directory, "site-lease.json"),
		out:     out, outPath: outPath,
	}
}

func (fixture *issuerFixture) grant(site string, epoch string, extra ...string) error {
	// -operator and -journal ride every grant the fixture makes, mirroring the real
	// invocation contract: an unattributed promotion is not auditable and the tool refuses it.
	args := append([]string{
		"-key", fixture.key, "-state", fixture.state, "-journal", fixture.journal,
		"-operator", "on-call", "-out", fixture.lease,
		"-site", site, "-registry-digest", "sha256:" + strings.Repeat("a", 64), "-epoch", epoch,
	}, extra...)
	return run(args, fixture.out)
}

func (fixture *issuerFixture) stdout(t *testing.T) string {
	t.Helper()
	contents, err := os.ReadFile(fixture.outPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func TestGrantWritesTheLeaseAndTheRecordAndSaysWhatItDid(t *testing.T) {
	fixture := newIssuer(t)
	if err := fixture.grant("sitea", "1"); err != nil {
		t.Fatalf("granting: %v", err)
	}
	for _, path := range []string{fixture.state, fixture.lease} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s was not written: %v", filepath.Base(path), err)
		}
	}
	if printed := fixture.stdout(t); !strings.Contains(printed, "granted sitea epoch 1") {
		t.Errorf("the tool did not say what it granted: %q", printed)
	}
}

// THE RECORD IS WRITTEN BEFORE THE LEASE IS HANDED OUT, AND THAT ORDER IS THE SAFETY PROPERTY.
//
// A crash between the two costs an epoch number, which is free. The other order hands out a
// lease the authority has no record of, and the next grant repeats its epoch — two live leases
// at the same epoch is a split brain the daemon cannot detect, because each one verifies.
//
// Testable because the failure is observable from outside: point -out at a directory that does
// not exist, so WriteLease fails after SaveIssuerState succeeded. If the record survives a
// failed hand-out, the order is right. If it does not, the tool is writing the lease first.
func TestTheEpochIsRecordedEvenWhenHandingTheLeaseOutFails(t *testing.T) {
	fixture := newIssuer(t)
	fixture.lease = filepath.Join(fixture.directory, "no-such-directory", "site-lease.json")

	err := fixture.grant("sitea", "1")
	if err == nil {
		t.Fatal("writing the lease into a missing directory succeeded")
	}
	if !strings.Contains(err.Error(), "write lease") {
		t.Fatalf("the failure is not the lease write: %v", err)
	}

	recorded, statErr := os.Stat(fixture.state)
	if statErr != nil {
		t.Fatalf("the issuer forgot an epoch it may have handed out: %v", statErr)
	}
	if recorded.Size() == 0 {
		t.Fatal("the issuer's record is empty after a failed hand-out")
	}

	// And the consequence that makes it matter: the spent epoch cannot be reissued.
	fixture.lease = filepath.Join(fixture.directory, "site-lease.json")
	reissued := fixture.grant("siteb", "1")
	if reissued == nil {
		t.Fatal("epoch 1 was granted twice: the record did not survive the failed hand-out")
	}
	// And for the epoch reason specifically. A refusal for an unrelated cause -- a state file
	// the issuer cannot parse, a permission regression -- would satisfy `err != nil` while
	// proving nothing about monotonicity, which is the property this test exists for.
	if !strings.Contains(reissued.Error(), "does not exceed") {
		t.Fatalf("the second grant was refused for another reason, so monotonicity is not what "+
			"caught it: %v", reissued)
	}
}

func TestAHandoverSaysWhoItTookTheLeaseFrom(t *testing.T) {
	fixture := newIssuer(t)
	if err := fixture.grant("sitea", "1"); err != nil {
		t.Fatal(err)
	}
	// Epoch 2 to a different site, starting after sitea's lease has expired so the issuer
	// does not refuse the overlap.
	later := "-not-before=2099-01-01T00:00:00Z"
	if err := fixture.grant("siteb", "2", later); err != nil {
		t.Fatalf("handover: %v", err)
	}
	printed := fixture.stdout(t)
	if !strings.Contains(printed, "handover from sitea") {
		t.Errorf("a handover did not name the site it came from: %q", printed)
	}
}

func TestRunRefusesIncompleteOrUnparseableArguments(t *testing.T) {
	fixture := newIssuer(t)
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()

	if err := fixture.grant("sitea", "1", "-not-before=the day before yesterday"); err == nil {
		t.Error("an unparseable -not-before was accepted")
	} else if !strings.Contains(err.Error(), "not-before") {
		t.Errorf("the error does not name the flag: %v", err)
	}

	// Each required flag, omitted one at a time, so a check for one of them cannot stand in
	// for all five.
	for _, omit := range []string{"-key", "-state", "-out", "-site", "-registry-digest"} {
		t.Run("without "+omit, func(t *testing.T) {
			args := []string{
				"-key", fixture.key, "-state", fixture.state, "-out", fixture.lease,
				"-site", "sitea", "-registry-digest", "sha256:" + strings.Repeat("a", 64),
			}
			var kept []string
			for index := 0; index < len(args); index += 2 {
				if args[index] != omit {
					kept = append(kept, args[index], args[index+1])
				}
			}
			err := run(kept, devnull)
			if err == nil {
				t.Fatalf("the tool granted a lease with %s missing", omit)
			}
			// It must be the required-flag check that refused, not a downstream failure that
			// happens to error anyway. Omitting -key reaches loadSigningKey and fails there; a
			// test asserting only `err != nil` passes with the check deleted, which is the
			// wrong-reason pass this whole suite exists to avoid. Verified: removing the check
			// leaves this subtest green unless the message is asserted.
			if !strings.Contains(err.Error(), "required") {
				t.Fatalf("%s missing was refused for another reason, so the required-flag check "+
					"is not what caught it: %v", omit, err)
			}
		})
	}
}

func TestEveryDecisionIsJournaledWithItsOperator(t *testing.T) {
	fixture := newIssuer(t)
	if err := fixture.grant("sitea", "1"); err != nil {
		t.Fatal(err)
	}
	stdout := fixture.stdout(t)
	if !strings.Contains(stdout, "recorded: operator on-call") {
		t.Fatalf("the grant transcript does not name the operator or the journal entry: %q", stdout)
	}
	summary, err := fencing.VerifyAuthorityJournal(fixture.journal)
	if err != nil {
		t.Fatalf("verify journal: %v", err)
	}
	if summary.Grants != 1 || summary.Refusals != 0 {
		t.Fatalf("journal shows %+v, want one granted decision", summary)
	}
}

func TestARefusedGrantIsJournaledAsARefusal(t *testing.T) {
	fixture := newIssuer(t)
	if err := fixture.grant("sitea", "1"); err != nil {
		t.Fatal(err)
	}
	// The replay attempt: the epoch floor must refuse it, and the refusal must land in the
	// journal — the split-brain attempt someone made and the authority turned down is the
	// record an auditor cannot get from the leases.
	if err := fixture.grant("sitea", "1"); err == nil {
		t.Fatal("a repeated epoch was granted")
	}
	summary, err := fencing.VerifyAuthorityJournal(fixture.journal)
	if err != nil {
		t.Fatalf("verify journal: %v", err)
	}
	if summary.Grants != 1 || summary.Refusals != 1 {
		t.Fatalf("journal shows %+v, want one grant and one recorded refusal — refusals are decisions too", summary)
	}
	// The refusal reason is the authority's own message, so the journal alone explains itself.
	data, err := os.ReadFile(fixture.journal)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "does not exceed the last issued epoch") {
		t.Fatal("the refusal record does not carry the authority's reason")
	}
}

func TestPromotionWithoutAttributionIsRefused(t *testing.T) {
	fixture := newIssuer(t)
	err := run([]string{
		"-key", fixture.key, "-state", fixture.state, "-out", fixture.lease,
		"-site", "sitea", "-registry-digest", "sha256:" + strings.Repeat("a", 64), "-epoch", "1",
	}, fixture.out)
	if err == nil || !strings.Contains(err.Error(), "auditable") {
		t.Fatalf("an unattributed promotion was accepted (err=%v)", err)
	}
	if _, statErr := os.Stat(fixture.lease); statErr == nil {
		t.Fatal("a lease was written without an attributed, journaled decision")
	}
}

func TestTheJournalVerifiesFromTheCLIAndRefusesTampering(t *testing.T) {
	fixture := newIssuer(t)
	if err := fixture.grant("sitea", "1"); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-verify-journal", fixture.journal}, fixture.out); err != nil {
		t.Fatalf("verify-journal on a good journal failed: %v", err)
	}
	if !strings.Contains(fixture.stdout(t), "1 granted") {
		t.Fatal("the verify output does not summarise the decisions")
	}
	data, err := os.ReadFile(fixture.journal)
	if err != nil || len(data) < 8 {
		t.Fatalf("read %d bytes from the journal (err=%v) — a read failure here would panic in the "+
			"slice below instead of naming the real problem", len(data), err)
	}
	if err := os.WriteFile(fixture.journal, append(data[:len(data)-8], []byte("tamper\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-verify-journal", fixture.journal}, fixture.out); err == nil {
		t.Fatal("a tampered authority journal verified cleanly from the CLI")
	}
}
