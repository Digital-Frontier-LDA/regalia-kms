package policy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests use the daemon's actual policy engine and journal. The ephemeral
// issuer only formats complete synthetic TBS inputs; no hardware is involved.
type x509ReservationFixture struct {
	key         *ecdsa.PrivateKey
	issuer      *x509.Certificate
	issuerDER   []byte
	fingerprint string
	start       time.Time
}

func newX509ReservationFixture(t *testing.T) x509ReservationFixture {
	t.Helper()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic reservation offline root"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(7 * 24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject:   pkix.Name{CommonName: "synthetic reservation intermediate"},
		NotBefore: now.Add(-12 * time.Hour), NotAfter: now.Add(6 * 24 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"svc.test.invalid"},
	}
	der, err = x509.CreateCertificate(rand.Reader, issuerTemplate, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	return x509ReservationFixture{key: key, issuer: issuer, issuerDER: der,
		fingerprint: "sha256:" + hex.EncodeToString(digest[:]), start: now}
}

func (fixture x509ReservationFixture) policy() Policy {
	return Policy{ID: "internal-ca-policy-v1", ObjectID: "synthetic-internal-ca", Purpose: "internal-pki",
		Environment: "development", Operation: "sign", Algorithm: "p256",
		ContentTypes: []string{"application/vnd.regalia.x509-tbs"}, MaxPayloadBytes: 32 << 10, MaxFuture: time.Minute,
		X509: &X509Policy{ID: "internal-ca-profile-v1", IssuerDER: fixture.issuerDER,
			DNSSuffixes: []string{"svc.test.invalid"}, MaxLeafValidity: 5 * time.Minute,
			MaxCRLValidity: 10 * time.Minute, LeafPerDay: 1, CRLPerDay: 1}}
}

func (fixture x509ReservationFixture) request(t *testing.T, now time.Time, nonce int, kind string) Request {
	t.Helper()
	var raw []byte
	if kind == "certificate" {
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(nonce + 2)), Subject: pkix.Name{CommonName: "web.svc.test.invalid"},
			DNSNames: []string{"web.svc.test.invalid"}, NotBefore: now, NotAfter: now.Add(5 * time.Minute),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, template, fixture.issuer, &fixture.key.PublicKey, fixture.key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		raw = cert.RawTBSCertificate
	} else {
		template := &x509.RevocationList{Number: big.NewInt(int64(nonce + 1)), ThisUpdate: now,
			NextUpdate: now.Add(10 * time.Minute), RevokedCertificateEntries: []x509.RevocationListEntry{
				{SerialNumber: big.NewInt(3), RevocationTime: now.Add(-time.Minute)},
			}}
		der, err := x509.CreateRevocationList(rand.Reader, template, fixture.issuer, fixture.key)
		if err != nil {
			t.Fatal(err)
		}
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatal(err)
		}
		raw = crl.RawTBSRevocationList
	}
	parsed, err := ParseX509TBS(raw)
	if err != nil {
		t.Fatal(err)
	}
	return Request{RequestID: fmt.Sprintf("synthetic-request-%d", nonce), Principal: "spiffe://test.invalid/workload/pki",
		ObjectID: "synthetic-internal-ca", Purpose: "internal-pki", Environment: "development", Operation: "sign",
		Algorithm: "p256", ContentType: "application/vnd.regalia.x509-tbs", PayloadBytes: int64(len(raw)),
		ExpiresAt: now.Add(30 * time.Second), Nonce: fmt.Sprintf("x509_nonce_%016d", nonce), X509: parsed,
		KeyFingerprint: fixture.fingerprint}
}

func x509Engine(t *testing.T, state *FileState, profile Policy, now *time.Time) *Engine {
	t.Helper()
	engine, err := New([]Policy{profile}, state, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func x509State(t *testing.T, path string) *FileState {
	t.Helper()
	state, err := OpenFileState(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	return state
}

func requireX509Decision(t *testing.T, decision Decision, code Code) {
	t.Helper()
	if decision.Code != code || decision.Allowed != (code == CodeAllowed) {
		t.Fatalf("decision = %#v, want %s", decision, code)
	}
}

func TestX509QuotaSurvivesRestartAndPreservesBoundedCRLReserve(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	now := fixture.start
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state := x509State(t, path)
	engine := x509Engine(t, state, fixture.policy(), &now)
	leafRequest := fixture.request(t, now, 1, "certificate")
	first := engine.Evaluate(context.Background(), leafRequest)
	requireX509Decision(t, first, CodeAllowed)
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state = x509State(t, path)
	engine = x509Engine(t, state, fixture.policy(), &now)
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 2, "certificate")), CodeLimitExceeded)
	crlRequest := fixture.request(t, now, 3, "crl")
	second := engine.Evaluate(context.Background(), crlRequest)
	requireX509Decision(t, second, CodeAllowed)
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 4, "crl")), CodeLimitExceeded)
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state = x509State(t, path)
	engine = x509Engine(t, state, fixture.policy(), &now)
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 5, "crl")), CodeLimitExceeded)
	events, err := readState(path)
	if err != nil || len(events) != 2 {
		t.Fatalf("journal events = %d, err = %v; refusals must not reserve", len(events), err)
	}
	for index, want := range []*SigningIntent{first.SigningIntent, second.SigningIntent} {
		if want == nil || !reflect.DeepEqual(events[index].Reservation.SigningIntent, want) {
			t.Fatalf("committed signing intent not preserved: event %d = %#v, want %#v", index,
				events[index].Reservation.SigningIntent, want)
		}
	}
	leaf, crl := events[0].Reservation, events[1].Reservation
	if leaf.SigningIntent.ArtifactKind != "certificate" || crl.SigningIntent.ArtifactKind != "crl" ||
		leaf.QuotaID != "x509-count-v1" || crl.QuotaID != leaf.QuotaID ||
		!reflect.DeepEqual(leaf.Amounts, map[string]uint64{"x509-leaf": 1}) ||
		!reflect.DeepEqual(crl.Amounts, map[string]uint64{"x509-crl": 1}) ||
		leaf.SigningIntent.ProfileID != fixture.policy().X509.ID || leaf.SigningIntent.KeyFingerprint != fixture.fingerprint ||
		leaf.SigningIntent.PayloadDigest != leafRequest.X509.Digest() || crl.SigningIntent.PayloadDigest != crlRequest.X509.Digest() ||
		leaf.Principal == "" || leaf.Nonce == "" {
		t.Fatalf("journal lost server-derived count or signing correlation: leaf=%#v crl=%#v", leaf, crl)
	}
}

func TestX509SameObjectIssuerRotationDoesNotRefillQuota(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	now := fixture.start
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state := x509State(t, path)
	engine := x509Engine(t, state, fixture.policy(), &now)
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 1, "certificate")), CodeAllowed)
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	rotated := newX509ReservationFixture(t)
	if rotated.fingerprint == fixture.fingerprint {
		t.Fatal("rotation fixture reused original issuer material")
	}
	state = x509State(t, path)
	engine = x509Engine(t, state, rotated.policy(), &now)
	requireX509Decision(t, engine.Evaluate(context.Background(), rotated.request(t, now, 2, "certificate")), CodeLimitExceeded)
	requireX509Decision(t, engine.Evaluate(context.Background(), rotated.request(t, now, 3, "crl")), CodeAllowed)
}

func TestX509OptionalReservationFieldsPreserveLegacyJournalEncoding(t *testing.T) {
	legacy := reservation("nonce_000000000001", "2026-09-03", 10, 100)
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	const previousEncoding = `{"policy_id":"cosmos-hot-wallet","object_id":"production-wallet-signer","principal":"spiffe://regalia/workload/tx-signer","nonce":"nonce_000000000001","utc_date":"2026-09-03","amounts":{"uatom":10},"daily_caps":{"uatom":100}}`
	if string(encoded) != previousEncoding {
		t.Fatalf("X.509 fields changed historical hashed reservation bytes: got %s", encoded)
	}
}

func TestX509ProfilePolicyAndPrincipalRevisionsDoNotRefillQuota(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	now := fixture.start
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state := x509State(t, path)
	engine := x509Engine(t, state, fixture.policy(), &now)
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 1, "certificate")), CodeAllowed)
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state = x509State(t, path)
	revised := fixture.policy()
	revised.ID, revised.X509.ID = "internal-ca-policy-v2", "internal-ca-profile-v2"
	engine = x509Engine(t, state, revised, &now)
	request := fixture.request(t, now, 2, "certificate")
	request.Principal = "spiffe://test.invalid/workload/pki-replacement"
	requireX509Decision(t, engine.Evaluate(context.Background(), request), CodeLimitExceeded)
	request = fixture.request(t, now, 3, "crl")
	request.Principal = "spiffe://test.invalid/workload/pki-replacement"
	requireX509Decision(t, engine.Evaluate(context.Background(), request), CodeAllowed)
}

func TestX509ConsumedNonceSurvivesPolicyAndProfileRevision(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	now := fixture.start
	profile := fixture.policy()
	profile.X509.LeafPerDay = 2
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state := x509State(t, path)
	engine := x509Engine(t, state, profile, &now)
	first := fixture.request(t, now, 1, "certificate")
	requireX509Decision(t, engine.Evaluate(context.Background(), first), CodeAllowed)
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state = x509State(t, path)
	profile.ID, profile.X509.ID = "internal-ca-policy-v2", "internal-ca-profile-v2"
	engine = x509Engine(t, state, profile, &now)
	requireX509Decision(t, engine.Evaluate(context.Background(), first), CodeReplay)
	// The duplicate must not spend the second slot, and a genuinely new nonce
	// still fits the same object budget after the revision.
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 2, "certificate")), CodeAllowed)
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 3, "certificate")), CodeLimitExceeded)
	summary, err := VerifyState(path)
	if err != nil || summary.Reservations != 2 {
		t.Fatalf("policy revision changed nonce/count history: summary=%#v err=%v", summary, err)
	}
}

func TestX509ClockRollbackIsRefusedAcrossRestartWithoutSpendingCRLReserve(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	now := fixture.start
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state := x509State(t, path)
	engine := x509Engine(t, state, fixture.policy(), &now)
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 1, "certificate")), CodeAllowed)
	now = now.Add(24 * time.Hour)
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 2, "certificate")), CodeAllowed)
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state = x509State(t, path)
	engine = x509Engine(t, state, fixture.policy(), &now)
	now = fixture.start
	request := fixture.request(t, now, 3, "crl")
	rollback := engine.Evaluate(context.Background(), request)
	if rollback.Allowed || rollback.Code != CodeDenied || rollback.Rule != "quota-date" {
		t.Fatalf("stale UTC day accepted or misclassified after reopen: %#v", rollback)
	}
	now = fixture.start.Add(24 * time.Hour)
	// The exact nonce refused under a stale clock remains usable at the current
	// day: a refusal must not consume either its nonce or its reserve.
	current := fixture.request(t, now, 3, "crl")
	requireX509Decision(t, engine.Evaluate(context.Background(), current), CodeAllowed)
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 4, "certificate")), CodeLimitExceeded)
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 5, "crl")), CodeLimitExceeded)
}

func TestX509OldJournalWithRetainedHighWaterIsRefused(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	now := fixture.start
	profile := fixture.policy()
	profile.X509.LeafPerDay = 2
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state := x509State(t, path)
	engine := x509Engine(t, state, profile, &now)
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 1, "certificate")), CodeAllowed)
	oldJournal, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 2, "certificate")), CodeAllowed)
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, oldJournal, 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenFileState(path); err == nil {
		_ = reopened.Close()
		t.Fatal("older X.509 journal opened against retained high-water: spent quota restored")
	}
	if _, err := VerifyState(path); err == nil {
		t.Fatal("older X.509 journal verified against retained high-water")
	}
}

func TestX509UnacknowledgedDurableReservationRemainsSpentAfterRestart(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	now := fixture.start
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state := x509State(t, path)
	engine := x509Engine(t, state, fixture.policy(), &now)
	// The journal append and fsync succeed, but replacing the high-water mark
	// fails. The engine must refuse execution while retaining the committed
	// reservation: uncertainty never refunds a nonce or signing capacity.
	faultPath := path + highWaterSuffix + ".tmp"
	if err := os.Mkdir(faultPath, 0o700); err != nil {
		t.Fatal(err)
	}
	request := fixture.request(t, now, 1, "certificate")
	requireX509Decision(t, engine.Evaluate(context.Background(), request), CodeStateUnavailable)
	if state.Ready(context.Background()) {
		t.Fatal("high-water write failure did not latch durable state unavailable")
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(faultPath); err != nil {
		t.Fatal(err)
	}
	state = x509State(t, path)
	engine = x509Engine(t, state, fixture.policy(), &now)
	requireX509Decision(t, engine.Evaluate(context.Background(), request), CodeReplay)
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 2, "certificate")), CodeLimitExceeded)
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 3, "crl")), CodeAllowed)
	events, err := readState(path)
	if err != nil || len(events) != 2 || events[0].Reservation.SigningIntent == nil {
		t.Fatalf("unacknowledged reservation or bounded CRL missing: events=%#v err=%v", events, err)
	}
}

func TestX509JournalRejectsCompetingWriterAndStaleEpochAfterRestart(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	now := fixture.start
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state := x509State(t, path)
	if other, err := OpenFileState(path); err == nil {
		_ = other.Close()
		t.Fatal("a competing writer opened the same X.509 journal")
	}
	engine := x509Engine(t, state, fixture.policy(), &now)
	epoch := uint64(7)
	engine.SetEpochSource(func() uint64 { return epoch })
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 1, "certificate")), CodeAllowed)
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state = x509State(t, path)
	engine = x509Engine(t, state, fixture.policy(), &now)
	engine.SetEpochSource(func() uint64 { return epoch })
	epoch = 6
	request := fixture.request(t, now, 2, "crl")
	decision := engine.Evaluate(context.Background(), request)
	if decision.Allowed || decision.Code != CodeDenied || decision.Rule != "epoch" {
		t.Fatalf("stale epoch accepted or misclassified: %#v", decision)
	}
	epoch = 7
	requireX509Decision(t, engine.Evaluate(context.Background(), request), CodeAllowed)
	summary, err := VerifyState(path)
	if err != nil || summary.Reservations != 2 || summary.HeadEpoch != 7 {
		t.Fatalf("epoch or refusal changed committed history: summary=%#v err=%v", summary, err)
	}
}

func TestX509ConcurrentLeafAndCRLReservationsRespectIndependentCaps(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	now := fixture.start
	profile := fixture.policy()
	profile.X509.LeafPerDay, profile.X509.CRLPerDay = 2, 3
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state := x509State(t, path)
	engine := x509Engine(t, state, profile, &now)
	var requests []Request
	for index := 0; index < 12; index++ {
		kind := "certificate"
		if index%2 != 0 {
			kind = "crl"
		}
		requests = append(requests, fixture.request(t, now, index+1, kind))
	}
	var leaves, crls, unexpected atomic.Int32
	var wg sync.WaitGroup
	for index, request := range requests {
		wg.Add(1)
		go func(index int, request Request) {
			defer wg.Done()
			decision := engine.Evaluate(context.Background(), request)
			if decision.Allowed {
				if index%2 == 0 {
					leaves.Add(1)
				} else {
					crls.Add(1)
				}
			} else if decision.Code != CodeLimitExceeded {
				unexpected.Add(1)
			}
		}(index, request)
	}
	wg.Wait()
	if leaves.Load() != 2 || crls.Load() != 3 || unexpected.Load() != 0 {
		t.Fatalf("accepted leaves=%d CRLs=%d unexpected=%d", leaves.Load(), crls.Load(), unexpected.Load())
	}
	summary, err := VerifyState(path)
	if err != nil || summary.Reservations != 5 {
		t.Fatalf("concurrent counts diverged from committed history: %#v, %v", summary, err)
	}
}

func TestX509SigningIntentRewriteWithHashesPreservedIsRefused(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	now := fixture.start
	path := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state := x509State(t, path)
	engine := x509Engine(t, state, fixture.policy(), &now)
	requireX509Decision(t, engine.Evaluate(context.Background(), fixture.request(t, now, 1, "certificate")), CodeAllowed)
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(contents), "internal-ca-profile-v1", "internal-ca-profile-v9", 1)
	if rewritten == string(contents) {
		t.Fatal("the committed journal carried no profile identity to rewrite")
	}
	if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenFileState(path); err == nil {
		_ = reopened.Close()
		t.Fatal("rewritten signing intent opened with original event hash preserved")
	}
}

func TestX509JournalRefusesInconsistentSigningIntentOrQuotaNamespace(t *testing.T) {
	fixture := newX509ReservationFixture(t)
	request := fixture.request(t, fixture.start, 1, "certificate")
	base := Reservation{PolicyID: fixture.policy().ID, ObjectID: request.ObjectID,
		Principal: request.Principal, Nonce: request.Nonce, UTCDate: fixture.start.Format(utcDateLayout),
		QuotaID: "x509-count-v1", Amounts: map[string]uint64{"x509-leaf": 1},
		DailyCaps: map[string]uint64{"x509-leaf": 1, "x509-crl": 1},
		SigningIntent: &SigningIntent{ProfileID: fixture.policy().X509.ID,
			PayloadDigest: request.X509.Digest(), ArtifactKind: "certificate", KeyFingerprint: fixture.fingerprint}}
	for _, test := range []struct {
		name   string
		mutate func(*Reservation)
	}{
		{"unknown quota namespace", func(r *Reservation) { r.QuotaID = "x509-count-v99" }},
		{"intent without namespace", func(r *Reservation) { r.QuotaID = "" }},
		{"namespace without intent", func(r *Reservation) { r.SigningIntent = nil }},
		{"unknown artifact", func(r *Reservation) { r.SigningIntent.ArtifactKind = "arbitrary" }},
		{"missing profile", func(r *Reservation) { r.SigningIntent.ProfileID = "" }},
		{"malformed profile", func(r *Reservation) { r.SigningIntent.ProfileID = "profile with spaces" }},
		{"missing digest", func(r *Reservation) { r.SigningIntent.PayloadDigest = "" }},
		{"malformed digest", func(r *Reservation) { r.SigningIntent.PayloadDigest = "sha256:" + strings.Repeat("z", 64) }},
		{"malformed key fingerprint", func(r *Reservation) { r.SigningIntent.KeyFingerprint = "sha256:short" }},
		{"artifact count mismatch", func(r *Reservation) { r.SigningIntent.ArtifactKind = "crl" }},
		{"more than one signing count", func(r *Reservation) { r.Amounts["x509-leaf"], r.DailyCaps["x509-leaf"] = 2, 2 }},
		{"mixed artifact counts", func(r *Reservation) { r.Amounts["x509-crl"] = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy-state.jsonl")
			state := x509State(t, path)
			reservation := base
			intent := *base.SigningIntent
			reservation.SigningIntent = &intent
			reservation.Amounts, reservation.DailyCaps = cloneAmounts(base.Amounts), cloneAmounts(base.DailyCaps)
			test.mutate(&reservation)
			if err := state.Reserve(context.Background(), reservation); err == nil {
				t.Fatalf("inconsistent X.509 reservation committed: %#v", reservation)
			}
			summary, err := VerifyState(path)
			if err != nil || summary.Reservations != 0 {
				t.Fatalf("invalid intent changed journal: summary=%#v err=%v", summary, err)
			}
			if err := state.Reserve(context.Background(), base); err != nil {
				t.Fatalf("invalid intent consumed nonce or count before refusal: %v", err)
			}
		})
	}
}
