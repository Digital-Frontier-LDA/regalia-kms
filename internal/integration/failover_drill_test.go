package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/fencing"
)

// A RECORDED FAILOVER DRILL, NOT ANOTHER UNIT TEST OF THE SAME PROPERTIES.
//
// internal/fencing already proves the pieces: the issuer refuses to overlap two sites, the gate
// refuses a rolled-back epoch, a standby activates without a restart. What #29 AC4 asks for is
// different -- the OPERATIONAL SEQUENCE exercised end to end, with recorded outcomes, so the
// claim "we can fail over" rests on having done it rather than on the parts being individually
// correct.
//
// This runs the two sub-drills that need no hardware: split-brain and stale state. Site loss and
// failback need real hosts and belong with #48.
//
// The clock is injected rather than slept through. Handover latency here is not a machine
// property to be measured with a stopwatch -- it is set by how long the outgoing lease has left,
// which is a policy choice. Driving the clock reports that bound exactly instead of approximating
// it, and the drill still runs in milliseconds.
func TestFailoverDrillSplitBrainAndStaleState(t *testing.T) {
	transcript := &strings.Builder{}
	say := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		t.Log(line)
		transcript.WriteString(line + "\n")
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digestBytes := sha256.Sum256([]byte("drill-registry"))
	registryDigest := "sha256:" + hex.EncodeToString(digestBytes[:])

	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	issuerState := filepath.Join(root, "issuer-state.json")
	siteaLease := filepath.Join(root, "sitea-lease.json")
	sitebLease := filepath.Join(root, "siteb-lease.json")
	siteaJournal := filepath.Join(root, "sitea-epochs.jsonl")
	sitebJournal := filepath.Join(root, "siteb-epochs.jsonl")

	// One clock for both sites and the authority: a drill that let them disagree about the time
	// would be measuring the harness.
	clock := time.Date(2026, 9, 5, 6, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	// The authority refuses anything longer, so this is also the worst-case handover bound.
	leaseFor := fencing.MaxLeaseDuration

	site := func(name, leasePath, journalPath string) *fencing.Standby {
		standby, err := fencing.NewStandby(leasePath, journalPath, name, registryDigest, public, now)
		if err != nil {
			t.Fatalf("%s standby: %v", name, err)
		}
		return standby
	}
	sitea := site("sitea", siteaLease, siteaJournal)
	siteb := site("siteb", sitebLease, sitebJournal)

	// The safety property, checked after every step rather than at the end: two sites that are
	// both ready is the failure this whole mechanism exists to prevent, and it must never hold
	// even transiently.
	ctx := context.Background()
	readiness := func(step string) (bool, bool) {
		l, p := sitea.Ready(ctx), siteb.Ready(ctx)
		if l && p {
			t.Fatalf("SPLIT BRAIN at %q: both sites report ready", step)
		}
		say("    sitea.ready=%-5v siteb.ready=%-5v", l, p)
		return l, p
	}

	// The same sequence regalia-fence performs, in the same order: lock, load, sign, RECORD,
	// then publish. Recording before handing the lease out is the safety property -- a crash
	// between the two must leave the authority remembering an epoch it may not have published,
	// never publishing one it has forgotten. Reversing these two lines models an authority
	// safer than the real one and would make this drill permissive about the crash window.
	grant := func(name, leasePath string, epoch uint64) error {
		release, err := fencing.LockIssuer(issuerState)
		if err != nil {
			return fmt.Errorf("lock issuer: %w", err)
		}
		defer release()
		previous, err := fencing.LoadIssuerState(issuerState)
		if err != nil {
			return fmt.Errorf("load issuer state: %w", err)
		}
		wanted := fencing.Grant{
			Site: name, Epoch: epoch, NotBefore: clock,
			ExpiresAt: clock.Add(leaseFor), RegistryDigest: registryDigest,
		}
		lease, err := fencing.SignGrant(private, wanted, previous)
		if err != nil {
			return err
		}
		if err := fencing.SaveIssuerState(issuerState, wanted); err != nil {
			return err
		}
		return fencing.WriteLease(leasePath, lease)
	}

	say("FAILOVER DRILL -- split brain and stale state")
	say("clock starts %s, lease duration %s (fencing.MaxLeaseDuration, the authority's cap)",
		clock.Format(time.RFC3339), leaseFor)
	say("registry digest %s...", registryDigest[:19])
	say("")

	say("1. COLD START -- no lease has ever been issued")
	l, p := readiness("cold start")
	if l || p {
		t.Fatal("a site was ready before any lease was issued: an unfenced site is an unfenced signer")
	}
	if _, _, _, ok := sitea.Snapshot(); ok {
		t.Fatal("sitea reports a lease evaluation it never made")
	}
	say("    OUTCOME: neither site can sign. never-held is distinguishable from lost (ok=false).")
	say("")

	say("2. GRANT epoch 1 to sitea")
	if err := grant("sitea", siteaLease, 1); err != nil {
		t.Fatalf("granting sitea: %v", err)
	}
	l, p = readiness("after granting sitea")
	if !l || p {
		t.Fatalf("expected sitea active and siteb passive, got sitea=%v siteb=%v", l, p)
	}
	say("    OUTCOME: exactly one site active, with no restart of either.")
	say("")

	say("3. SPLIT-BRAIN ATTEMPT -- authority asked to grant siteb while sitea's lease is live")
	replayErr := grant("siteb", sitebLease, 1)
	if replayErr == nil {
		t.Fatal("the authority reissued epoch 1 to a second site: this is the split brain")
	}
	say("    authority REFUSED: %v", replayErr)
	overlapErr := grant("siteb", sitebLease, 2)
	if overlapErr == nil {
		say("    authority allowed epoch 2 to siteb while sitea's lease runs (see step 4 for what")
		say("    protects the window)")
	} else {
		say("    authority REFUSED an overlapping epoch 2: %v", overlapErr)
	}
	readiness("after the split-brain attempt")
	say("")

	say("4. PLANNED HANDOVER -- wait out sitea's lease, then grant siteb")
	clock = clock.Add(leaseFor)
	say("    clock advanced to %s (sitea's lease has expired)", clock.Format(time.RFC3339))
	l, p = readiness("sitea's lease expired")
	if l {
		t.Fatal("sitea is still ready after its lease expired: the lease bound is not enforced")
	}
	say("    OUTCOME: sitea stood down on its own. No operator action, no restart.")
	if err := grant("siteb", sitebLease, 2); err != nil {
		t.Fatalf("granting siteb: %v", err)
	}
	l, p = readiness("after granting siteb")
	if l || !p {
		t.Fatalf("expected siteb active and sitea passive, got sitea=%v siteb=%v", l, p)
	}
	say("    OUTCOME: siteb active, sitea passive.")
	say("    HANDOVER BOUND: %s -- the outgoing lease's remaining life. Not a machine latency;", leaseFor)
	say("    it is the lease duration, so shortening it shortens the RTO and raises renewal load.")
	say("")

	say("5. STALE STATE -- sitea's expired epoch-1 lease is replayed")
	clock = clock.Add(time.Minute)
	stale, err := os.ReadFile(siteaLease)
	if err != nil {
		t.Fatal(err)
	}
	if err := fencing.WriteLease(siteaLease, []byte(strings.TrimRight(string(stale), "\n"))); err != nil {
		t.Fatal(err)
	}
	l, p = readiness("stale lease replayed at sitea")
	if l {
		t.Fatal("an expired epoch-1 lease reactivated sitea while siteb holds epoch 2: split brain by replay")
	}
	say("    OUTCOME: refused. An old lease file is not a promotion.")
	say("")

	say("6. AUTHORITY ROLLBACK -- asked to reissue epoch 1 after epoch 2 exists")
	rollbackErr := grant("sitea", siteaLease, 1)
	if rollbackErr == nil {
		t.Fatal("the authority reissued a spent epoch: an operator could split the brain by asking twice")
	}
	say("    authority REFUSED: %v", rollbackErr)
	readiness("after the rollback attempt")
	say("")
	say("RESULT: PASS. No step produced two ready sites.")

	if out := os.Getenv("REGALIA_DRILL_TRANSCRIPT"); out != "" {
		if err := os.WriteFile(out, []byte(transcript.String()), 0o644); err != nil {
			t.Fatalf("writing transcript: %v", err)
		}
		t.Logf("transcript written to %s", out)
	}
}
