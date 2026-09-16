package fencing

// THE SPLIT-BRAIN SUITE (#29). The unit tests pin each mechanism separately — the issuer's two
// refusals, the gate's epoch floor, the standby's transitions. What none of them shows is the
// composed protocol: two live sites, a complete handover cycle, and the invariant checked AT
// EVERY INSTANT — at no moment may both sites consider themselves active. A failover
// implementation that has never been shown to fail is indistinguishable from one that cannot,
// so this file drives the failure candidates directly.
//
// The protocol under test, as designed in issue.go and gate.go:
//
//   * the issuer refuses a cross-site grant that begins before the previous lease expires —
//     handover WAITS the old lease out, which is why MaxLeaseDuration is the failover floor;
//   * epochs strictly increase, so a replaced lease is dead at any site that saw its successor;
//   * a site is ready exactly while it holds a valid, unexpired, matching lease;
//   * same-site renewal MAY overlap (one signer either way).
//
// And one boundary this suite pins rather than fixes (#220): a site whose epoch journal was
// LOST re-accepts a superseded same-site lease for the remainder of its window. The headline
// invariant survives that hole — the issuer's no-overlap rule and wall-clock expiry are the
// nets that hold it — but the same-site epoch floor is gone, and this test says so in its
// assertion messages so the eventual #220 fix has to update it deliberately.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// splitBrainClock is a fake clock both sites share, so the whole timeline is deterministic and
// boundary instants (NotBefore, expiry, expiry-minus-a-nanosecond) are sampleable exactly.
type splitBrainClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *splitBrainClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *splitBrainClock) Advance(to time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if to.After(c.now) {
		c.now = to
	}
}

// splitBrainSite is one site of the two: its own lease file, its own epoch journal, a real
// Standby gate on the shared clock.
type splitBrainSite struct {
	name      string
	leasePath string
	statePath string
	standby   *Standby
}

func newSplitBrainSite(t *testing.T, dir, name, registryDigest string, publicKey ed25519.PublicKey, clock *splitBrainClock) *splitBrainSite {
	t.Helper()
	siteDir := filepath.Join(dir, name)
	if err := os.MkdirAll(siteDir, 0o700); err != nil {
		t.Fatal(err)
	}
	site := &splitBrainSite{
		name:      name,
		leasePath: filepath.Join(siteDir, "lease.json"),
		statePath: filepath.Join(siteDir, "epochs.jsonl"),
	}
	var err error
	site.standby, err = NewStandby(site.leasePath, site.statePath, name, registryDigest, publicKey, clock.Now)
	if err != nil {
		t.Fatalf("standby %s: %v", name, err)
	}
	return site
}

// deliver writes a signed lease document to the site, the way the promotion procedure does.
func (site *splitBrainSite) deliver(t *testing.T, document []byte) {
	t.Helper()
	if err := os.WriteFile(site.leasePath, document, 0o600); err != nil {
		t.Fatal(err)
	}
}

// splitBrainAuthority mirrors the issuer's state machine: SignGrant's refusals are the
// protocol's safety rules, and the recorded PreviousGrant is what the issuer's own state file
// would carry between invocations.
type splitBrainAuthority struct {
	key      ed25519.PrivateKey
	previous PreviousGrant
}

func newSplitBrainAuthority(t *testing.T) (*splitBrainAuthority, ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &splitBrainAuthority{key: private}, public
}

// grant signs a lease for site from notBefore until expiresAt at the given epoch, applying the
// issuer's real refusals, and updates the recorded previous grant exactly as a compliant issuer
// would after persisting its state.
func (authority *splitBrainAuthority) grant(t *testing.T, site string, epoch uint64, notBefore, expiresAt time.Time, registryDigest string) []byte {
	t.Helper()
	document, err := SignGrant(authority.key, Grant{
		Site: site, Epoch: epoch, NotBefore: notBefore, ExpiresAt: expiresAt, RegistryDigest: registryDigest,
	}, authority.previous)
	if err != nil {
		t.Fatalf("authority refused a grant the scenario requires (%s epoch %d): %v", site, epoch, err)
	}
	authority.previous = PreviousGrant{Site: site, Epoch: epoch, ExpiresAt: expiresAt}
	return document
}

const splitBrainDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// TestACompleteHandoverNeverMakesBothSitesReady is the headline. Two sites live for the whole
// timeline; a full cycle runs — activate A, renew A, fail over to B (after the refused early
// attempt), fail back to A — and EVERY sampled instant asserts the invariant. The test also
// requires that both sites were genuinely ready at some point: a test in which one site never
// activates proves nothing about dual activation, and would pass on a broken implementation
// for free.
func TestACompleteHandoverNeverMakesBothSitesReady(t *testing.T) {
	dir := privateTempDir(t)
	start := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	clock := &splitBrainClock{now: start}
	authority, publicKey := newSplitBrainAuthority(t)
	alpha := newSplitBrainSite(t, dir, "sitea", splitBrainDigest, publicKey, clock)
	beta := newSplitBrainSite(t, dir, "siteb", splitBrainDigest, publicKey, clock)

	// The planned timeline. Cross-site grants may only begin at or after the previous lease's
	// expiry, so every failover below is scheduled exactly at that boundary.
	type scheduled struct {
		at     time.Time
		site   *splitBrainSite
		epoch  uint64
		until  time.Time
		refuse bool // a grant the issuer must refuse: the split-brain candidate
	}
	timeline := []scheduled{
		{at: start, site: alpha, epoch: 1, until: start.Add(5 * time.Minute)},                                    // activate A
		{at: start.Add(4 * time.Minute), site: alpha, epoch: 2, until: start.Add(9 * time.Minute)},               // renew A (overlap allowed)
		{at: start.Add(6 * time.Minute), site: beta, epoch: 3, until: start.Add(11 * time.Minute), refuse: true}, // early B: must be refused
		{at: start.Add(9 * time.Minute), site: beta, epoch: 3, until: start.Add(14 * time.Minute)},               // fail over at A's expiry
		{at: start.Add(14 * time.Minute), site: alpha, epoch: 4, until: start.Add(19 * time.Minute)},             // fail back at B's expiry
	}

	alphaReady, betaReady := false, false
	sample := time.Second
	for moment := start; !moment.After(start.Add(20 * time.Minute)); moment = moment.Add(sample) {
		clock.Advance(moment)
		// Deliver scheduled leases as their activation instant arrives — the operator's
		// promotion step, including the failed-over site receiving its file.
		for _, event := range timeline {
			if !event.at.Equal(moment) {
				continue
			}
			if event.refuse {
				// The scheduled split-brain attempt: the authority must refuse it, with
				// the issuer's state as it actually is at this instant (an earlier
				// version of this check ran before any grant existed, against a zero
				// PreviousGrant, and a first-ever grant overlaps nothing by definition).
				_, err := SignGrant(authority.key, Grant{
					Site: event.site.name, Epoch: event.epoch, NotBefore: event.at, ExpiresAt: event.until,
					RegistryDigest: splitBrainDigest,
				}, authority.previous)
				if err == nil || !strings.Contains(err.Error(), "both sites would sign") {
					t.Fatalf("at %s the authority issued an overlapping cross-site lease (err=%v) — the split-brain window would be scheduled, not accidental", moment.Format(time.RFC3339), err)
				}
				continue
			}
			document := authority.grant(t, event.site.name, event.epoch, event.at, event.until, splitBrainDigest)
			event.site.deliver(t, document)
		}
		a := alpha.standby.Ready(context.Background())
		b := beta.standby.Ready(context.Background())
		alphaReady, betaReady = alphaReady || a, betaReady || b
		if a && b {
			t.Fatalf("DUAL SIGNING at %s: %s and %s are both ready — the invariant that defines this system is broken",
				moment.Format(time.RFC3339), alpha.name, beta.name)
		}
	}
	if !alphaReady || !betaReady {
		t.Fatalf("the scenario never exercised both sides (alpha ready=%v, beta ready=%v) — a handover test that only ever activates one site proves nothing", alphaReady, betaReady)
	}
}

// TestARestoredSiteReAcceptsASupersededLeaseWhileItLasts pins the #220 boundary honestly: with
// the epoch journal lost, the same-site epoch floor is gone and a superseded-but-unexpired
// lease is accepted again. The headline invariant does NOT fall — the old lease still expires
// on the wall clock, and the next cross-site grant was only issuable after that expiry — but
// the defense-in-depth net is demonstrably absent, which is the fact #220's fix has to change.
func TestARestoredSiteReAcceptsASupersededLeaseWhileItLasts(t *testing.T) {
	dir := privateTempDir(t)
	start := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	clock := &splitBrainClock{now: start}
	authority, publicKey := newSplitBrainAuthority(t)
	site := newSplitBrainSite(t, dir, "sitea", splitBrainDigest, publicKey, clock)

	first := authority.grant(t, "sitea", 1, start, start.Add(10*time.Minute), splitBrainDigest)
	site.deliver(t, first)
	if !site.standby.Ready(context.Background()) {
		t.Fatal("the site should be ready under its first lease")
	}

	// A renewal supersedes it; the gate observes epoch 2 and records it in the journal.
	second := authority.grant(t, "sitea", 2, start.Add(5*time.Minute), start.Add(15*time.Minute), splitBrainDigest)
	site.deliver(t, second)
	clock.Advance(start.Add(6 * time.Minute))
	if !site.standby.Ready(context.Background()) {
		t.Fatal("the site should be ready under its renewal")
	}

	// The restore: the epoch-1 lease file is back, and the journal is GONE (#220's state).
	site.deliver(t, first)
	if err := os.Remove(site.statePath); err != nil {
		t.Fatal(err)
	}
	// The gate must be reopened to re-read the journal — a restored host is a new process.
	restored, err := NewStandby(site.leasePath, site.statePath, "sitea", splitBrainDigest, publicKey, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.Ready(context.Background()) {
		t.Fatal("expected the superseded lease to be RE-ACCEPTED after journal loss — if this fails, #220's boundary moved and this test plus #220 must be updated together")
	}
	// The outer net: the same lease is dead on the wall clock, and the next site's grant
	// could not have started before that expiry.
	clock.Advance(start.Add(10*time.Minute + time.Second))
	if restored.Ready(context.Background()) {
		t.Fatal("the replayed lease outlived its own expiry — the wall clock is the last net and it is broken")
	}
}

// TestTheGateBindsTheLeaseToTheRegistry pins the fact DEV5 measured in the #26 audit: a lease
// names the registry digest it was granted for, and a restored registry that differs by a byte
// leaves the site unable to activate until a new lease is issued. That looks like an outage and
// is the mechanism working: a lease authorises one exact configuration, not "the site".
func TestTheGateBindsTheLeaseToTheRegistry(t *testing.T) {
	dir := privateTempDir(t)
	start := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	clock := &splitBrainClock{now: start}
	authority, publicKey := newSplitBrainAuthority(t)
	site := newSplitBrainSite(t, dir, "sitea", splitBrainDigest, publicKey, clock)

	document := authority.grant(t, "sitea", 1, start, start.Add(10*time.Minute), splitBrainDigest)
	site.deliver(t, document)

	// A gate built for a registry that differs by one byte must not go ready on this lease.
	const restoredDigest = "f3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856"
	restoredGate, err := NewStandby(site.leasePath, filepath.Join(dir, "restored-epochs"), "sitea", restoredDigest, publicKey, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if restoredGate.Ready(context.Background()) {
		t.Fatal("a site whose registry changed became ready on a lease granted for the old registry — the lease does not bind the configuration it authorises")
	}
	if !site.standby.Ready(context.Background()) {
		t.Fatal("the original site should still be ready — the binding must refuse the mismatched site, not the matching one")
	}
}
