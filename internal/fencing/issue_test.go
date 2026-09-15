package fencing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const issueDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

// THE ISSUER AND THE DAEMON MUST AGREE, AND THIS IS THE ONLY TEST THAT PROVES IT.
//
// Everything else here checks a refusal. If SignGrant produced a document the Gate does not
// accept, every refusal test would still pass and the tool would be useless in exactly the
// way the feature already was: configurable, tested, and unable to make any site active.
func TestAnIssuedLeaseIsAcceptedByTheDaemonThatVerifiesIt(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	leasePath := filepath.Join(directory, "lease.json")
	statePath := filepath.Join(directory, "epochs.jsonl")
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	lease, err := SignGrant(private, Grant{
		Site: "sitea", Epoch: 1, NotBefore: now.Add(-time.Minute),
		ExpiresAt: now.Add(5 * time.Minute), RegistryDigest: issueDigest,
	}, PreviousGrant{})
	if err != nil {
		t.Fatalf("SignGrant: %v", err)
	}
	if err := os.WriteFile(leasePath, lease, 0o600); err != nil {
		t.Fatal(err)
	}

	gate, err := Open(leasePath, statePath, "sitea", issueDigest, public, func() time.Time { return now })
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !gate.Ready(context.Background()) {
		t.Fatal("DEFECT: the daemon rejected a lease this repository's own issuer produced — " +
			"the fencing authority cannot make any site active, which is the state before this tool existed")
	}
}

// The epoch is what makes a superseded lease unusable. An issuer that repeats one lets an
// old lease file, still sitting on a demoted site's disk, be replayed.
func TestTheIssuerRefusesAnEpochItHasAlreadyUsed(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	previous := PreviousGrant{Site: "sitea", Epoch: 7, ExpiresAt: now.Add(-time.Hour)}

	for _, epoch := range []uint64{7, 6, 1} {
		_, err := SignGrant(private, Grant{
			Site: "siteb", Epoch: epoch, NotBefore: now, ExpiresAt: now.Add(5 * time.Minute),
			RegistryDigest: issueDigest,
		}, previous)
		if err == nil {
			t.Fatalf("DEFECT: the issuer signed epoch %d after already issuing 7 — a superseded "+
				"lease still on a demoted site's disk could be replayed", epoch)
		}
		// THE MESSAGE, NOT JUST THE REFUSAL. Measured 2026-09-06: the epoch guard is the only
		// thing that refuses this fixture today, so `err == nil` was adequate — and that is
		// exactly the state that rots. Add any earlier guard to SignGrant and the row keeps
		// passing while epoch monotonicity stops being tested.
		if !strings.Contains(err.Error(), "does not exceed the last issued epoch") {
			t.Fatalf("epoch %d was refused by a different rule: %v — this row exists to prove the "+
				"monotonicity check fires, and any other refusal means it did not", epoch, err)
		}
	}
	if _, err := SignGrant(private, Grant{
		Site: "siteb", Epoch: 8, NotBefore: now, ExpiresAt: now.Add(5 * time.Minute), RegistryDigest: issueDigest,
	}, previous); err != nil {
		t.Fatalf("the issuer refused a strictly higher epoch (%v): the refusals above would prove nothing", err)
	}
}

// THE SPLIT-BRAIN CASE, AND THE ONE THE DAEMON CANNOT CATCH FOR ITSELF.
//
// Each daemon reads only its own lease file. Two leases for two sites, each individually
// valid and signed by the real authority, overlapping in time, means both sites believe
// they are active. Nothing downstream can see it: the documents are correct. Only the
// issuer knows both exist, so only the issuer can refuse.
func TestTheIssuerRefusesToOverlapTwoSites(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	siteaHoldsUntil := now.Add(30 * time.Minute)
	previous := PreviousGrant{Site: "sitea", Epoch: 4, ExpiresAt: siteaHoldsUntil}

	_, err := SignGrant(private, Grant{
		Site: "siteb", Epoch: 5, NotBefore: now, ExpiresAt: now.Add(5 * time.Minute), RegistryDigest: issueDigest,
	}, previous)
	if err == nil {
		t.Fatal("DEFECT: the authority granted siteb a lease overlapping sitea's — both sites " +
			"would sign for thirty minutes, from two documents that are each individually valid, " +
			"and ADR-0001 section 8 is violated with nothing downstream able to detect it")
	}
	if !strings.Contains(err.Error(), "both sites would sign") {
		t.Errorf("the refusal does not say what is wrong: %v", err)
	}

	// Handover after the previous lease expires is the whole point of the tool.
	if _, err := SignGrant(private, Grant{
		Site: "siteb", Epoch: 5, NotBefore: siteaHoldsUntil, ExpiresAt: siteaHoldsUntil.Add(5 * time.Minute),
		RegistryDigest: issueDigest,
	}, previous); err != nil {
		t.Fatalf("a measured handover starting exactly at expiry was refused (%v): the check "+
			"above would mean the authority can never promote a second site at all", err)
	}

	// Renewing the SAME site may overlap: there is one signer either way, and refusing
	// would force a gap in which nobody can sign.
	if _, err := SignGrant(private, Grant{
		Site: "sitea", Epoch: 5, NotBefore: now, ExpiresAt: now.Add(5 * time.Minute), RegistryDigest: issueDigest,
	}, previous); err != nil {
		t.Fatalf("renewing the active site was refused (%v): every renewal would need an outage", err)
	}
}

func TestTheIssuerRefusesIncoherentGrants(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	valid := Grant{Site: "sitea", Epoch: 1, NotBefore: now, ExpiresAt: now.Add(5 * time.Minute), RegistryDigest: issueDigest}
	for _, broken := range []struct {
		what  string
		grant Grant
	}{
		{"no site", func() Grant { g := valid; g.Site = ""; return g }()},
		{"no registry digest", func() Grant { g := valid; g.RegistryDigest = ""; return g }()},
		{"epoch zero", func() Grant { g := valid; g.Epoch = 0; return g }()},
		{"expiring before it begins", func() Grant { g := valid; g.ExpiresAt = now.Add(-5 * time.Minute); return g }()},
		{"expiring exactly when it begins", func() Grant { g := valid; g.ExpiresAt = g.NotBefore; return g }()},
	} {
		if _, err := SignGrant(private, broken.grant, PreviousGrant{}); err == nil {
			t.Errorf("the issuer signed a grant with %s", broken.what)
		}
	}
	if _, err := SignGrant(ed25519.PrivateKey("too short"), valid, PreviousGrant{}); err == nil {
		t.Error("the issuer accepted a key that is not an ed25519 private key")
	}
}

// Losing the record is how a repeated epoch gets signed, so an unreadable one refuses.
func TestUnreadableIssuerStateRefusesRatherThanAssumingFirstGrant(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "issuer.json")

	previous, err := LoadIssuerState(path)
	if err != nil || previous.Epoch != 0 {
		t.Fatalf("a missing record must be the first grant, got (%+v, %v)", previous, err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIssuerState(path); err == nil {
		t.Fatal("DEFECT: unreadable issuer state was treated as no previous grant — the next " +
			"lease would repeat an epoch")
	}
}

func TestIssuerStateRoundTrips(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "issuer.json")
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	grant := Grant{Site: "siteb", Epoch: 9, NotBefore: now, ExpiresAt: now.Add(5 * time.Minute), RegistryDigest: issueDigest}
	if err := SaveIssuerState(path, grant); err != nil {
		t.Fatal(err)
	}
	previous, err := LoadIssuerState(path)
	if err != nil || previous.Site != "siteb" || previous.Epoch != 9 || !previous.ExpiresAt.Equal(grant.ExpiresAt) {
		t.Fatalf("round trip lost the grant: (%+v, %v)", previous, err)
	}
	var raw map[string]any
	contents, _ := os.ReadFile(path)
	if json.Unmarshal(contents, &raw) != nil {
		t.Fatalf("issuer state is not JSON: %s", contents)
	}
}

// THE ISSUER'S BOUND AND THE DAEMON'S BOUND ARE THE SAME BOUND.
//
// They were not, when this tool was first written: the daemon capped a lease at ten minutes
// in a literal nobody else could see, and the issuer's default was an hour. It signed a
// perfectly valid document that its only consumer silently refused. This asserts the
// agreement behaviourally rather than by reading the constant twice -- a lease of exactly
// the maximum must be accepted by the real Gate, and one microsecond longer must be refused
// by the issuer before it can be written at all.
func TestTheIssuerWillNotSignALeaseTheDaemonWouldRefuse(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	atTheLimit, err := SignGrant(private, Grant{
		Site: "sitea", Epoch: 1, NotBefore: now.Add(-time.Second),
		ExpiresAt: now.Add(-time.Second).Add(MaxLeaseDuration), RegistryDigest: issueDigest,
	}, PreviousGrant{})
	if err != nil {
		t.Fatalf("the issuer refused a lease of exactly MaxLeaseDuration: %v", err)
	}
	leasePath := filepath.Join(directory, "lease.json")
	if err := os.WriteFile(leasePath, atTheLimit, 0o600); err != nil {
		t.Fatal(err)
	}
	gate, err := Open(leasePath, filepath.Join(directory, "epochs.jsonl"), "sitea", issueDigest,
		public, func() time.Time { return now })
	if err != nil || !gate.Ready(context.Background()) {
		t.Fatalf("DEFECT: the daemon refused a lease of exactly MaxLeaseDuration (%v) — the "+
			"issuer's bound is looser than the daemon's, so the authority can sign leases "+
			"nothing will honour", err)
	}

	if _, err := SignGrant(private, Grant{
		Site: "sitea", Epoch: 2, NotBefore: now,
		ExpiresAt: now.Add(MaxLeaseDuration + time.Microsecond), RegistryDigest: issueDigest,
	}, PreviousGrant{}); err == nil {
		t.Fatal("DEFECT: the issuer signed a lease longer than the daemon will honour — the " +
			"operator gets a valid-looking document and a site that never activates")
	}
}

// WITHOUT THE LOCK EVERY OTHER CHECK IN THIS FILE IS ADVISORY.
//
// The monotonicity and overlap refusals compare a new grant against the recorded previous
// one. Two invocations that read the same record both pass against it and both sign, and
// the authority has then produced exactly what it exists to prevent while verifying each
// lease correctly. A read-check-write over the state of a safety property is a race.
func TestTheIssuerSerialisesItself(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "issuer.json")

	release, err := LockIssuer(statePath)
	if err != nil {
		t.Fatalf("the first caller could not take the lock: %v", err)
	}
	if _, err := LockIssuer(statePath); err == nil {
		t.Fatal("DEFECT: a second issuer took the lock while the first held it — two " +
			"invocations can read the same previous grant, both pass every check against it, " +
			"and both sign")
	}
	release()

	// Released, so the next authority can proceed; otherwise one run would poison the tool.
	second, err := LockIssuer(statePath)
	if err != nil {
		t.Fatalf("the lock was not released (%v): the refusal above would mean regalia-fence "+
			"works exactly once", err)
	}
	second()
}

// The record decides both safety properties, so it is checked the way readLease checks the
// lease. A writable record lets anyone with local access roll the epoch back or erase the
// previous site's expiry and obtain an overlapping lease.
func TestWritableIssuerStateIsRefused(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "issuer.json")
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	if err := SaveIssuerState(path, Grant{Site: "sitea", Epoch: 3, NotBefore: now,
		ExpiresAt: now.Add(5 * time.Minute), RegistryDigest: issueDigest}); err != nil {
		t.Fatal(err)
	}
	// The control: as written by the tool it must load, or the refusal below proves nothing.
	if _, err := LoadIssuerState(path); err != nil {
		t.Fatalf("state written by SaveIssuerState does not load: %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIssuerState(path); err == nil {
		t.Fatal("DEFECT: a world-writable issuer record was trusted — anyone with local access " +
			"can roll the epoch back or hide a live lease and get an overlapping grant")
	}
}

// os.WriteFile does not apply its mode to a file that already exists, so a lease written
// over a group-writable one stays group-writable and readLease refuses it as unsafe.
func TestPublishingALeaseOverAWritableFileStillProducesOneTheDaemonAccepts(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	leasePath := filepath.Join(directory, "lease.json")
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

	// A leftover from an earlier deployment, with permissions the daemon will not accept.
	// Chmod after the write, because umask strips the group and other bits at creation --
	// without it the fixture is not writable, the assertion below holds for that reason
	// instead of the one it claims, and removing the fix leaves this test green. It did.
	if err := os.WriteFile(leasePath, []byte("{}"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(leasePath, 0o666); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(leasePath); err != nil || info.Mode().Perm()&0o022 == 0 {
		t.Fatalf("the fixture is not group- or world-writable (%v), so this test cannot "+
			"observe permissions being inherited", err)
	}
	lease, err := SignGrant(private, Grant{
		Site: "sitea", Epoch: 1, NotBefore: now.Add(-time.Second),
		ExpiresAt: now.Add(5 * time.Minute), RegistryDigest: issueDigest,
	}, PreviousGrant{})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteLease(leasePath, lease); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(leasePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o022 != 0 {
		t.Fatalf("DEFECT: the published lease is %04o — it inherited the old file's permissions "+
			"and the daemon will refuse it as an unsafe fencing lease", info.Mode().Perm())
	}
	gate, err := Open(leasePath, filepath.Join(directory, "epochs.jsonl"), "sitea", issueDigest,
		public, func() time.Time { return now })
	if err != nil || !gate.Ready(context.Background()) {
		t.Fatalf("the daemon refused a lease published over an existing file: %v", err)
	}
}

// A PREDICTABLE TEMPORARY FILE IS A SYMLINK TARGET.
//
// This wrote to path+".tmp" with O_TRUNC. Anyone who can create that name in the directory
// points it at a file of their choosing, and the authority then truncates and rewrites that
// file with its own privileges -- on a host where this process is, by design, the one thing
// trusted to decide which site may sign. os.CreateTemp uses O_EXCL and an unpredictable
// suffix, so the name cannot be pre-created and an existing one cannot be followed.
func TestPublishingDoesNotFollowAPlantedTemporary(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	directory := t.TempDir()
	leasePath := filepath.Join(directory, "lease.json")
	victim := filepath.Join(directory, "victim")
	if err := os.WriteFile(victim, []byte("must survive"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The attack: the old code's temporary path, planted as a symlink at the victim.
	if err := os.Symlink(victim, leasePath+".tmp"); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}

	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	lease, err := SignGrant(private, Grant{
		Site: "sitea", Epoch: 1, NotBefore: now, ExpiresAt: now.Add(5 * time.Minute),
		RegistryDigest: issueDigest,
	}, PreviousGrant{})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteLease(leasePath, lease); err != nil {
		t.Fatalf("publishing failed with a planted temporary present: %v", err)
	}

	survived, err := os.ReadFile(victim)
	if err != nil || string(survived) != "must survive" {
		t.Fatalf("DEFECT: publishing a lease followed a planted symlink and overwrote %s "+
			"(now %q, %v) — anyone who can create a filename in this directory can have the "+
			"fencing authority rewrite a file of their choosing", victim, survived, err)
	}
	if _, err := os.Stat(leasePath); err != nil {
		t.Fatalf("the lease was not published: %v", err)
	}
}

// The record is stat-ed through the descriptor that is read, matching readLease. A
// stat-then-read on the path checks one file and reads whatever the name points at a moment
// later, and this record decides both safety properties.
func TestIssuerStateIsRejectedWhenTheFileItselfIsUnsafe(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "issuer.json")
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	if err := SaveIssuerState(path, Grant{Site: "sitea", Epoch: 3, NotBefore: now,
		ExpiresAt: now.Add(5 * time.Minute), RegistryDigest: issueDigest}); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIssuerState(path); err != nil {
		t.Fatalf("the control failed: state written by the tool must load (%v)", err)
	}

	// A directory is not a regular file, and neither is a device or a fifo.
	if _, err := LoadIssuerState(directory); err == nil {
		t.Error("DEFECT: a directory was accepted as the issuer record")
	}

	// Implausibly large content is refused. The padding is trailing whitespace on a VALID
	// document, so the size bound is the only thing that can reject it: my first attempt
	// padded with zero bytes, which fails the JSON parse whatever the bound is, and the test
	// stayed green with the bound raised a millionfold.
	oversized := `{"site":"sitea","epoch":3,"expires_at":"2026-09-05T12:05:00Z"}` +
		strings.Repeat(" ", maxIssuerStateBytes)
	huge := filepath.Join(directory, "huge.json")
	if err := os.WriteFile(huge, []byte(oversized), 0o600); err != nil {
		t.Fatal(err)
	}
	// The control: the same document without the padding must load, so a refusal above is
	// about the size and not about the content.
	if _, err := LoadIssuerState(write(t, directory, "small.json",
		`{"site":"sitea","epoch":3,"expires_at":"2026-09-05T12:05:00Z"}`)); err != nil {
		t.Fatalf("the unpadded document does not load (%v): the size case proves nothing", err)
	}
	if _, err := LoadIssuerState(huge); err == nil {
		t.Error("DEFECT: an oversized issuer record was read and parsed")
	}
}

func write(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A RECORD THAT PARSES BUT SAYS NOTHING IS NOT "NO PREVIOUS GRANT".
//
// {} unmarshals happily into the zero value, and the zero value is exactly what a first run
// looks like. Every check in SignGrant then passes trivially, so a record damaged down to a
// brace resets the authority's memory instead of stopping it -- and the next grant repeats
// an epoch or overlaps a live lease with nothing anywhere reporting a fault.
func TestAPartialIssuerRecordIsRefusedRatherThanReadAsAFirstRun(t *testing.T) {
	directory := t.TempDir()
	complete := `{"site":"sitea","epoch":3,"expires_at":"2026-09-05T12:05:00Z"}`

	// The control first: a complete record must load, or every refusal below holds because
	// nothing loads at all.
	if previous, err := LoadIssuerState(write(t, directory, "complete.json", complete)); err != nil || previous.Epoch != 3 {
		t.Fatalf("a complete record does not load (%+v, %v): the refusals below prove nothing", previous, err)
	}

	for _, partial := range []struct{ name, contents, missing string }{
		{"empty.json", `{}`, "everything"},
		{"epoch-only.json", `{"epoch":7}`, "the site and the expiry"},
		{"site-only.json", `{"site":"sitea"}`, "the epoch and the expiry"},
		{"no-expiry.json", `{"site":"sitea","epoch":7}`, "the expiry, so the overlap check has nothing to compare against"},
		{"no-epoch.json", `{"site":"sitea","expires_at":"2026-09-05T12:05:00Z"}`, "the epoch, so monotonicity resets to zero"},
	} {
		if _, err := LoadIssuerState(write(t, directory, partial.name, partial.contents)); err == nil {
			t.Errorf("DEFECT: an issuer record missing %s was read as a first run — the authority "+
				"forgets what it has issued and the next grant can repeat an epoch or overlap a live lease",
				partial.missing)
		}
	}
}

// Three bounds on this branch have now had to be told to both the issuer and the daemon.
// Each time the tool would otherwise emit something correct and unusable.
func TestTheIssuerWillNotSignALeaseTooLargeForTheDaemonToRead(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	valid := Grant{Site: "sitea", Epoch: 1, NotBefore: now,
		ExpiresAt: now.Add(5 * time.Minute), RegistryDigest: issueDigest}

	// The control: an ordinary grant signs.
	if _, err := SignGrant(private, valid, PreviousGrant{}); err != nil {
		t.Fatalf("an ordinary grant was refused (%v): the case below proves nothing", err)
	}

	enormous := valid
	enormous.Site = strings.Repeat("s", maxLeaseBytes)
	lease, err := SignGrant(private, enormous, PreviousGrant{})
	if err == nil {
		t.Fatalf("DEFECT: the issuer signed a %d-byte lease and the daemon refuses anything over "+
			"%d — a correctly signed document its only consumer will not read", len(lease), maxLeaseBytes)
	}
	// The fixture is an enormous SITE NAME, so a future site-shape rule would refuse it first
	// and this row would go on passing without ever reaching the size bound.
	if !strings.Contains(err.Error(), "the daemon refuses anything over") {
		t.Fatalf("the oversize lease was refused by a different rule: %v — this row is about the "+
			"size bound, and any other refusal means the bound was never reached", err)
	}
}

// Writing a record the next run refuses as oversized wedges the authority: it cannot read
// its own memory and therefore cannot issue again.
func TestTheIssuerWillNotWriteARecordItCouldNotReadBack(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "issuer.json")
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	ordinary := Grant{Site: "sitea", Epoch: 1, NotBefore: now,
		ExpiresAt: now.Add(5 * time.Minute), RegistryDigest: issueDigest}

	if err := SaveIssuerState(path, ordinary); err != nil {
		t.Fatalf("an ordinary record was refused (%v): the case below proves nothing", err)
	}

	enormous := ordinary
	enormous.Site = strings.Repeat("s", maxIssuerStateBytes)
	if err := SaveIssuerState(filepath.Join(directory, "huge.json"), enormous); err == nil {
		t.Fatal("DEFECT: the issuer wrote a record larger than it will read back — the next " +
			"invocation cannot load its own memory and the authority can never issue again")
	}
	// And the ordinary record must still be readable afterwards: a refusal must not have
	// damaged the state that was already there.
	if _, err := LoadIssuerState(path); err != nil {
		t.Fatalf("the existing record stopped loading after a refused write: %v", err)
	}
}

// WRITE PERMISSION ON A DIRECTORY IS PERMISSION TO REPLACE EVERYTHING IN IT.
//
// Found by DEV5 attacking the branch. The file's mode was checked and the directory's was
// not, so the attack is: unlink the record, write your own -- 0600, owned by you, valid
// JSON. IsRegular passes, the 0o022 check passes, the parse passes, and the authority
// issues epoch 2 believing the last one was 1. Both safety properties defeated with every
// check on the file satisfied.
//
// Narrower than the symlink it sits under: that one gave arbitrary overwrite anywhere the
// authority could write, this needs a directory the attacker already controls. It is still
// the difference between the guarantee the comment claimed and the one the code made.
func TestAReplaceableRecordIsRefusedEvenWhenTheFileItselfLooksSafe(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "issuer.json")
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	if err := SaveIssuerState(path, Grant{Site: "sitea", Epoch: 9, NotBefore: now,
		ExpiresAt: now.Add(5 * time.Minute), RegistryDigest: issueDigest}); err != nil {
		t.Fatal(err)
	}
	// The control: in a private directory the record loads and reports epoch 9.
	previous, err := LoadIssuerState(path)
	if err != nil || previous.Epoch != 9 {
		t.Fatalf("the control failed (%+v, %v): the refusal below would prove nothing", previous, err)
	}

	// The attack: the directory is writable, so the record is replaceable.
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(directory); err != nil || info.Mode().Perm()&0o022 == 0 {
		t.Fatalf("the fixture directory is not group- or world-writable (%v); this test cannot "+
			"observe the defect", err)
	}
	defer func() { _ = os.Chmod(directory, 0o700) }()

	rolledBack := filepath.Join(directory, "issuer.json")
	if err := os.Remove(rolledBack); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rolledBack,
		[]byte(`{"site":"sitea","epoch":1,"expires_at":"2026-09-05T11:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIssuerState(rolledBack); err == nil {
		t.Fatal("DEFECT: a record replaced in a writable directory was trusted — epoch 9 became " +
			"epoch 1 with every permission check on the file passing, and the authority would " +
			"re-issue an epoch it has already used")
	}

	// The lock rests on the same directory and must refuse for the same reason: a lock
	// anyone can create or delete is not a lock.
	if release, err := LockIssuer(rolledBack); err == nil {
		release()
		t.Error("DEFECT: the issuer took a lock in a directory anyone can write to — the lock " +
			"can be held or removed by whoever wants to race it")
	}
}

// A SUB-SECOND BOUNDARY MUST SURVIVE INTO THE LEASE ITSELF.
//
// A measured handover is scheduled by copying the previous expiry into -not-before. Printed
// or stored at second precision a sub-second instant is TRUNCATED, so the lease names an
// earlier moment than the grant did -- and the daemon, which parses these fields with
// RFC3339Nano, is then authoritative about a boundary nobody asked for.
//
// My first version of this test asserted that time.Format then time.Parse round-trips,
// which is a property of the standard library and holds whatever this package does, and
// then checked the Gate accepted the lease -- which it does either way, because a truncated
// NotBefore is still in the past. It passed with the fix removed. This asserts the bytes
// SignGrant actually emits.
func TestASubSecondBoundarySurvivesIntoTheLease(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	instant := time.Date(2026, 9, 5, 12, 0, 0, 123456789, time.UTC)

	encoded, err := SignGrant(private, Grant{
		Site: "siteb", Epoch: 5, NotBefore: instant, ExpiresAt: instant.Add(5 * time.Minute),
		RegistryDigest: issueDigest,
	}, PreviousGrant{})
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		NotBefore string `json:"not_before"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	for _, field := range []struct {
		name, value string
		want        time.Time
	}{
		{"not_before", document.NotBefore, instant},
		{"expires_at", document.ExpiresAt, instant.Add(5 * time.Minute)},
	} {
		parsed, err := time.Parse(time.RFC3339Nano, field.value)
		if err != nil {
			t.Fatalf("%s = %q does not parse: %v", field.name, field.value, err)
		}
		if !parsed.Equal(field.want) {
			t.Errorf("DEFECT: %s in the signed lease is %s, the grant said %s — the instant was "+
				"truncated on the way in, so the lease names a boundary nobody asked for and an "+
				"operator scheduling a handover from it lands in the wrong place",
				field.name, parsed.UTC(), field.want.UTC())
		}
	}

	// The control: a whole-second grant must still render without a fractional part, so the
	// common case reads exactly as it did and this is not a formatting change in disguise.
	whole := instant.Truncate(time.Second)
	encoded, err = SignGrant(private, Grant{
		Site: "siteb", Epoch: 6, NotBefore: whole, ExpiresAt: whole.Add(5 * time.Minute),
		RegistryDigest: issueDigest,
	}, PreviousGrant{})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(document.NotBefore, ".") {
		t.Errorf("a whole-second grant rendered a fractional part: %q", document.NotBefore)
	}
}
