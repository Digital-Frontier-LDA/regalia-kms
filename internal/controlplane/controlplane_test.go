package controlplane

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/fencing"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
)

// testKeys generates the custody authority's P-256 pair and returns the PEM encodings the CLI
// accepts, so every test exercises the same parse path production uses. Generated as ECDSA and
// marshalled with x509 — the parse path converts to ECDH internally, exactly as production
// parses an operator-supplied PEM.
func testKeys(t *testing.T) (publicPEM, privatePEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate authority key: %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
}

// journal fixtures built with the REAL writers, so an export fixture verifies for the same
// reason production state verifies. A hand-crafted "valid" chain could only ever prove the
// export agrees with the hand that wrote it.
type fixture struct {
	dir     string
	sources Sources
}

// discardSink is a journal-only audit host: no collector, which is a legitimate production
// configuration and the simplest fixture.
type discardSink struct{}

func (discardSink) Send(context.Context, audit.Event) error { return nil }
func (discardSink) Ready(context.Context) bool              { return true }

func writeAuditJournal(t *testing.T, path string, events int) {
	t.Helper()
	recorder, err := audit.Open(path, discardSink{})
	if err != nil {
		t.Fatalf("open audit journal: %v", err)
	}
	for i := 0; i < events; i++ {
		draft := audit.Draft{
			Timestamp:      time.Date(2026, 9, 6, 12, 0, i, 0, time.UTC),
			RequestID:      "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
			Principal:      "test-principal",
			Decision:       "allow",
			ObjectID:       "object-1",
			Purpose:        "test-purpose",
			Operation:      "release-secret",
			DeviceID:       "device-1",
			Outcome:        "ok",
			RegistryDigest: "aa" + strings.Repeat("bb", 31),
			PolicyDigest:   "cc" + strings.Repeat("dd", 31),
			RBACDigest:     "ee" + strings.Repeat("ff", 31),
		}
		if err := recorder.Record(context.Background(), draft, false); err != nil {
			t.Fatalf("record audit event %d: %v", i, err)
		}
	}
	// WAIT FOR THE SIDECARS BEFORE CLOSING. The .shipped mark is written by the shipper's own
	// goroutine after the sink acknowledges, and Close() stops the shipper "without draining it"
	// (shipper.go). So the mark is produced on a timing this test does not control: alone the
	// goroutine always won, and under `go test ./...` with every package running at once it
	// regularly lost, failing TestBuildSealsAndInspectsARoundTrip with "audit writer did not
	// create .shipped; the export contract is stale" — a message about a stale contract, when
	// what had happened was that nothing waited.
	//
	// Bounded, and a FAILURE if it never arrives: if the writer genuinely stopped producing the
	// sidecar, the constant really would be stale and that must still be caught.
	for _, suffix := range []string{highWaterSuffix, shippedSuffix} {
		deadline := time.Now().Add(10 * time.Second)
		for {
			if _, err := os.Stat(path + suffix); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("audit writer never created %s%s within 10s of recording %d events", path, suffix, events)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	if err := recorder.Close(); err != nil {
		t.Fatalf("close audit journal: %v", err)
	}
}

func writePolicyState(t *testing.T, path string, reservations int) {
	t.Helper()
	state, err := policy.OpenFileState(path)
	if err != nil {
		t.Fatalf("open policy state: %v", err)
	}
	for i := 0; i < reservations; i++ {
		reservation := policy.Reservation{
			PolicyID:  "policy-1",
			ObjectID:  "object-1",
			Principal: "test-principal",
			Nonce:     fmt.Sprintf("nonce-%08d-0123abcd", i),
			UTCDate:   "2026-09-06",
			Amounts:   map[string]uint64{"release": 1},
			DailyCaps: map[string]uint64{"release": 10},
		}
		if err := state.Reserve(context.Background(), reservation); err != nil {
			t.Fatalf("reserve %d: %v", i, err)
		}
	}
	if err := state.Close(); err != nil {
		t.Fatalf("close policy state: %v", err)
	}
}

// epochRecordMirror reproduces the on-disk epoch record shape — and its hash construction —
// exactly as internal/fencing writes it. The duplication is deliberate and is pinned from both
// sides: TestFencingFixtureVerifies requires fencing.VerifyEpochs to ACCEPT this construction,
// and the export tests require it to REJECT any tampering of it, so a formula drift in either
// place fails a test.
type epochRecordMirror struct {
	Epoch        uint64 `json:"epoch"`
	PreviousHash string `json:"previous_hash"`
	Hash         string `json:"hash"`
}

func epochMirrorHash(record epochRecordMirror) string {
	record.Hash = ""
	encoded, _ := json.Marshal(record)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func writeEpochs(t *testing.T, path string, count int) {
	t.Helper()
	previous := "sha256:" + strings.Repeat("0", 64)
	var builder strings.Builder
	for epoch := uint64(1); epoch <= uint64(count); epoch++ {
		record := epochRecordMirror{Epoch: epoch, PreviousHash: previous}
		record.Hash = epochMirrorHash(record)
		encoded, _ := json.Marshal(record)
		builder.Write(encoded)
		builder.WriteByte('\n')
		previous = record.Hash
	}
	if err := os.WriteFile(path, []byte(builder.String()), 0o600); err != nil {
		t.Fatalf("write epochs: %v", err)
	}
}

func newFixture(t *testing.T, populated bool) fixture {
	t.Helper()
	dir := t.TempDir()
	f := fixture{dir: dir, sources: Sources{
		AuditJournal: filepath.Join(dir, "audit.jsonl"),
		PolicyState:  filepath.Join(dir, "policy-state.jsonl"),
		FencingState: filepath.Join(dir, "epochs.jsonl"),
		SiteVersion:  filepath.Join(dir, "deployment-version"),
	}}
	if populated {
		writeAuditJournal(t, f.sources.AuditJournal, 3)
		writePolicyState(t, f.sources.PolicyState, 2)
		writeEpochs(t, f.sources.FencingState, 2)
		if err := os.WriteFile(f.sources.SiteVersion, []byte("regalia-kms 1.2.3 site-sitea\n"), 0o644); err != nil {
			t.Fatalf("write deployment version: %v", err)
		}
	}
	return f
}

// sealedFixture builds, seals, and returns the envelope bytes plus the authority PEMs.
func sealedFixture(t *testing.T, f fixture) (envelope, publicPEM, privatePEM []byte) {
	t.Helper()
	publicPEM, privatePEM = testKeys(t)
	export, err := Build(f.sources, "sitea", time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build export: %v", err)
	}
	payload, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}
	recipient, err := ParseRecipient(publicPEM)
	if err != nil {
		t.Fatalf("parse recipient: %v", err)
	}
	envelope, err = Seal(payload, recipient.PublicKey)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return envelope, publicPEM, privatePEM
}

func authorityKey(t *testing.T, privatePEM []byte) *ecdh.PrivateKey {
	t.Helper()
	key, err := ParseAuthorityKey(privatePEM)
	if err != nil {
		t.Fatalf("parse authority key: %v", err)
	}
	return key
}

// ------------------------------------------------------------------------------------------------
// envelope

func TestSealOpenRoundTrip(t *testing.T) {
	publicPEM, privatePEM := testKeys(t)
	recipient, err := ParseRecipient(publicPEM)
	if err != nil {
		t.Fatalf("parse recipient: %v", err)
	}
	payload := []byte("control plane payload \x00\x01 with binary bytes")
	envelope, err := Seal(payload, recipient.PublicKey)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	var decoded Envelope
	if err := json.Unmarshal(envelope, &decoded); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	if decoded.Algorithm != envelopeAlgorithm || decoded.Version != 1 {
		t.Fatalf("envelope advertises %s v%d", decoded.Algorithm, decoded.Version)
	}
	opened, err := Open(envelope, authorityKey(t, privatePEM))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(opened) != string(payload) {
		t.Fatal("round trip returned different bytes")
	}
}

func TestOpenRefusesEverythingExceptTheRightKeyAndBytes(t *testing.T) {
	publicPEM, privatePEM := testKeys(t)
	recipient, _ := ParseRecipient(publicPEM)
	envelope, err := Seal([]byte("payload"), recipient.PublicKey)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	wrongPEM, wrongPrivatePEM := testKeys(t)
	wrong, err := ParseRecipient(wrongPEM)
	if err != nil {
		t.Fatal(err)
	}
	wrongEnvelope, err := Seal([]byte("payload"), wrong.PublicKey)
	if err != nil {
		t.Fatalf("seal wrong: %v", err)
	}

	if _, err := Open(envelope, authorityKey(t, wrongPrivatePEM)); !errors.Is(err, errOpen) {
		t.Fatalf("the WRONG KEY opened the envelope (err=%v) — sealed state is readable without custody", err)
	}
	if _, err := Open(wrongEnvelope, authorityKey(t, privatePEM)); !errors.Is(err, errOpen) {
		t.Fatalf("the right key opened ANOTHER authority's envelope (err=%v)", err)
	}
	// Tamper with every field; each must fail with the same opaque error.
	for name, tamper := range map[string]func(*Envelope){
		"ciphertext":  func(e *Envelope) { e.Ciphertext = e.Ciphertext[:len(e.Ciphertext)-4] + "AAA=" },
		"nonce":       func(e *Envelope) { e.Nonce = "AAAAAAAAAAAAAAAA" },
		"ephemeral":   func(e *Envelope) { e.Ephemeral = e.Ephemeral[:len(e.Ephemeral)-4] + "AAA=" },
		"version":     func(e *Envelope) { e.Version = 2 },
		"algorithm":   func(e *Envelope) { e.Algorithm = "something-else" },
		"extra field": func(e *Envelope) { /* handled below via raw JSON */ },
	} {
		var decoded Envelope
		if err := json.Unmarshal(envelope, &decoded); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if name == "extra field" {
			reencoded, _ := json.Marshal(decoded)
			if _, err := Open(append(reencoded[:len(reencoded)-1], []byte(`,"attacker":"1"}`)...), authorityKey(t, privatePEM)); !errors.Is(err, errOpen) {
				t.Fatalf("an envelope with an UNKNOWN FIELD was accepted (err=%v)", err)
			}
			continue
		}
		tamper(&decoded)
		reencoded, _ := json.Marshal(decoded)
		if _, err := Open(reencoded, authorityKey(t, privatePEM)); !errors.Is(err, errOpen) {
			t.Fatalf("tampering with %s did not refuse (err=%v)", name, err)
		}
	}
}

// ------------------------------------------------------------------------------------------------
// scan

func TestArmedScanCleanInputReportsNoFindings(t *testing.T) {
	findings, err := armedScan(map[string][]byte{"audit.jsonl": []byte("{\"sequence\":1}\n{\"sequence\":2}\n")})
	if err != nil {
		t.Fatalf("clean input errored: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("clean input produced findings: %v", findings)
	}
}

func TestArmedScanDetectsMarkersWithoutReproducingThem(t *testing.T) {
	// Assembled from parts at runtime: the assembled markers must not exist as literals in
	// this file (the same composition discipline the secret scanner's rules require).
	privateKeyLine := strings.Join([]string{"-----BEGIN ", "PRIVATE KEY-----"}, "") + " MIIB…"
	ageLine := strings.Join([]string{"AGE-SECRET-", "KEY-1"}, "") + "K7RESTOFKEY"
	findings, err := armedScan(map[string][]byte{"epochs.jsonl": []byte("line1\n" + privateKeyLine + "\n" + ageLine + "\n")})
	if err != nil {
		t.Fatalf("scan errored: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected the two planted shapes, got %v", findings)
	}
	for _, finding := range findings {
		if strings.Contains(finding.String(), "MIIB") || strings.Contains(finding.String(), "OFKEY") {
			t.Fatalf("finding reproduces the offender: %s", finding)
		}
	}
}

func TestArmedScanWithoutShapesCannotReturnACleanVerdict(t *testing.T) {
	// The fail-closed core of the canary design: a detector with no shapes (neutered, empty
	// config, regressed constants) must NOT report "clean" — it reports that its verdict is
	// void, because it could not catch its own planted secret in the same pass.
	if _, err := armedScanWith(nil, map[string][]byte{"audit.jsonl": []byte("anything")}); !errors.Is(err, ErrScannerUnarmed) {
		t.Fatalf("an unarmed scanner returned a verdict instead of voiding it (err=%v)", err)
	}
}

func TestScanTree(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/lib/regalia-kms"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "var/lib/regalia-kms/audit.jsonl"), []byte("{\"sequence\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	findings, err := ScanTree(root)
	if err != nil {
		t.Fatalf("clean tree errored: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("clean tree produced findings: %v", findings)
	}

	// A PIN file by name, a credentials directory, and marker content in an innocent-named
	// file: three leak shapes a restored tree must not carry.
	if err := os.WriteFile(filepath.Join(root, "var/lib/regalia-kms/10-token.pin"), []byte("123456\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "run/credentials/regalia-kms.service"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/notes.txt"), []byte(strings.Join([]string{"-----BEGIN ", "PRIVATE KEY-----"}, "")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, err = ScanTree(root)
	if err != nil {
		t.Fatalf("planted tree errored: %v", err)
	}
	shapes := map[string]bool{}
	for _, finding := range findings {
		shapes[finding.Shape] = true
	}
	for _, want := range []string{"credential-file-name", "credential-directory", "pkcs-private-key-header"} {
		if !shapes[want] {
			t.Fatalf("planted shape %s not caught; got %v", want, findings)
		}
	}
}

// ------------------------------------------------------------------------------------------------
// export build

func TestFencingFixtureVerifies(t *testing.T) {
	// Pins the mirror above against the real verifier: if this fixture stops verifying, every
	// other fencing assertion below is testing the wrong thing.
	f := newFixture(t, true)
	// The epochs file is 0600 like the daemon writes it; VerifyEpochs enforces modes.
	if _, _, err := fencing.VerifyEpochs(f.sources.FencingState); err != nil {
		t.Fatalf("hand-built epoch chain does not verify: %v", err)
	}
}

func TestBuildSealsAndInspectsARoundTrip(t *testing.T) {
	f := newFixture(t, true)
	envelope, _, privatePEM := sealedFixture(t, f)
	export, err := Inspect(envelope, authorityKey(t, privatePEM))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if export.Site != "sitea" {
		t.Fatalf("unexpected export site %q", export.Site)
	}
	for _, present := range []struct {
		name  string
		entry Entry
	}{
		{"audit journal", export.AuditJournal},
		{"policy state journal", export.PolicyState},
		{"fencing epochs", export.FencingEpochs},
		{"deployment version", export.SiteVersion},
	} {
		if present.entry.Absent || present.entry.Path == "" {
			t.Fatalf("%s should be present in a populated export", present.name)
		}
	}
	// The sidecars the real writers produced must be exactly the entries the export carried:
	// this is what pins highWaterSuffix/shippedSuffix against the journals' own conventions.
	dirEntries, _ := os.ReadDir(f.dir)
	names := map[string]bool{}
	for _, entry := range dirEntries {
		names[entry.Name()] = true
	}
	for _, suffix := range []string{highWaterSuffix, shippedSuffix} {
		if !names["audit.jsonl"+suffix] {
			t.Fatalf("audit writer did not create %s; the export contract is stale", suffix)
		}
	}
}

func TestBuildAllowsAVirginSiteWithExplicitAbsentEntries(t *testing.T) {
	f := newFixture(t, false)
	envelope, _, privatePEM := sealedFixture(t, f)
	export, err := Inspect(envelope, authorityKey(t, privatePEM))
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	for _, absent := range []Entry{
		export.AuditJournal, export.AuditHighWater, export.AuditShipped,
		export.PolicyState, export.PolicyMark, export.FencingEpochs, export.SiteVersion,
	} {
		if !absent.Absent {
			t.Fatalf("virgin site exported present entry %q; absence must be explicit", absent.Path)
		}
	}
}

func TestBuildRefusesAConfigurationWithNoSources(t *testing.T) {
	// #185's lesson in this package's key: the defect lives in the configuration the code runs
	// under. An exporter whose config supplies NO paths must refuse, not emit an empty success
	// that looks like a completed export.
	if _, err := Build(Sources{}, "sitea", time.Now()); !errors.Is(err, ErrNoSources) {
		t.Fatalf("empty sources built an export (err=%v) — an empty state would ship as a complete one", err)
	}
	// A path config that is ONLY the version file (no journals) is the same hole one step in.
	if _, err := Build(Sources{SiteVersion: "/etc/regalia-kms/deployment-version"}, "sitea", time.Now()); !errors.Is(err, ErrNoSources) {
		t.Fatalf("a sources set with no journals exported only the version file (err=%v)", err)
	}
}

func TestBuildRefusesABrokenChain(t *testing.T) {
	for name, breakIt := range map[string]func(t *testing.T, f fixture){
		"audit journal": func(t *testing.T, f fixture) {
			data, _ := os.ReadFile(f.sources.AuditJournal)
			data[len(data)-8] ^= 0x01
			os.WriteFile(f.sources.AuditJournal, data, 0o600)
		},
		"policy state": func(t *testing.T, f fixture) {
			data, _ := os.ReadFile(f.sources.PolicyState)
			data[len(data)-8] ^= 0x01
			os.WriteFile(f.sources.PolicyState, data, 0o600)
		},
		"fencing epochs": func(t *testing.T, f fixture) {
			data, _ := os.ReadFile(f.sources.FencingState)
			data[len(data)-8] ^= 0x01
			os.WriteFile(f.sources.FencingState, data, 0o600)
		},
		"truncated audit journal": func(t *testing.T, f fixture) {
			data, _ := os.ReadFile(f.sources.AuditJournal)
			lines := strings.SplitAfter(string(data), "\n")
			os.WriteFile(f.sources.AuditJournal, []byte(strings.Join(lines[:len(lines)-2], "")), 0o600)
		},
	} {
		f := newFixture(t, true)
		breakIt(t, f)
		if _, err := Build(f.sources, "sitea", time.Now()); err == nil {
			t.Fatalf("%s: a tampered journal exported cleanly", name)
		}
	}
}

func TestBuildRefusesPlaintextSecretShapesInTheUnchainedEntries(t *testing.T) {
	// The journals cannot carry key material without breaking their chains, and their writers
	// refuse it at record time — the payload scan is the second net for the entries with no
	// chain, of which deployment-version is the reachable example.
	f := newFixture(t, true)
	marker := strings.Join([]string{"-----BEGIN ", "PRIVATE KEY-----"}, "")
	if err := os.WriteFile(f.sources.SiteVersion, []byte(marker+" oops\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Build(f.sources, "sitea", time.Now())
	if err == nil || !strings.Contains(err.Error(), "secret-shaped") {
		t.Fatalf("key material in the deployment-version exported (err=%v)", err)
	}
}

// ------------------------------------------------------------------------------------------------
// inspect

func sealEvilPayload(t *testing.T, publicPEM []byte, mutate func(*Export)) []byte {
	t.Helper()
	f := newFixture(t, true)
	export, err := Build(f.sources, "sitea", time.Now())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	mutate(export)
	payload, _ := json.Marshal(export)
	recipient, err := ParseRecipient(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := Seal(payload, recipient.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestInspectRefusesTamperedAndForgedPayloads(t *testing.T) {
	publicPEM, privatePEM := testKeys(t)
	key := authorityKey(t, privatePEM)
	cases := map[string]func(*Export){
		// Journal tampering is caught by the chain; this and the case below pin the
		// digest check as the SOLE detector for entries with no chain. (Its first version
		// flipped a journal byte, the chain refused it anyway, and the mutation that
		// removed the digest check stayed green — a check that never fails alone is not a
		// gate.)
		"unchained entry tampered": func(e *Export) {
			e.SiteVersion.Data[0] ^= 0x01
		},
		"journal digest mismatch": func(e *Export) {
			e.FencingEpochs.Data[0] ^= 0x01
		},
		// The amputation attack: delete the journal from the payload but keep the sidecar
		// that remembers how far the history reached. The envelope's AEAD cannot be touched
		// without the key — this is the authority-side tool lying, which is exactly what
		// the restore drill has to be able to catch.
		"journal amputated but sidecar remembers": func(e *Export) {
			e.AuditJournal.Absent = true
			e.AuditJournal.Data = nil
			e.AuditJournal.SHA256 = ""
		},
		"malformed field": func(e *Export) {
			e.SiteVersion = Entry{Path: "", SHA256: "", Data: nil, Absent: false}
		},
		"version bump": func(e *Export) { e.Version = 99 },
		"no site":      func(e *Export) { e.Site = "" },
		"planted secret": func(e *Export) {
			e.SiteVersion.Data = []byte(strings.Join([]string{"AGE-SECRET-KEY-", "1PLANTED"}, ""))
			digest := sha256.Sum256(e.SiteVersion.Data)
			e.SiteVersion.SHA256 = hex.EncodeToString(digest[:])
		},
	}
	for name, mutate := range cases {
		envelope := sealEvilPayload(t, publicPEM, mutate)
		if _, err := Inspect(envelope, key); err == nil {
			t.Fatalf("inspect accepted a %s", name)
		}
	}
	// And the forged-payload path must still refuse trailing data after the JSON document.
	recipient, err := ParseRecipient(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, true)
	export, err := Build(f.sources, "sitea", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, []byte(`{"second":"document"}`)...)
	forged, err := Seal(payload, recipient.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(forged, key); err == nil {
		t.Fatal("inspect accepted trailing data after the export document")
	}
}

// ------------------------------------------------------------------------------------------------
// report determinism and bounded reads (found in #219 review)

func TestSummaryLinesIsDeterministicAcrossRuns(t *testing.T) {
	// Measured before the fix: ranging exportEntries-as-map gave 7 distinct orderings in 300
	// calls. The report exists to be diffed line by line against the inspection output, so
	// two runs of a correct system disagreeing is the defect, not a cosmetic one.
	f := newFixture(t, true)
	export, err := Build(f.sources, "sitea", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	distinct := map[string]bool{}
	for i := 0; i < 300; i++ {
		distinct[strings.Join(SummaryLines(export), "\n")] = true
	}
	if len(distinct) != 1 {
		t.Fatalf("SummaryLines produced %d distinct orderings across 300 runs — the export and inspection reports cannot be diffed", len(distinct))
	}
}

func TestSummaryLinesSurvivesAMalformedEntry(t *testing.T) {
	// Found while measuring the ordering: a zero-valued Export panicked the printer on the
	// digest slice. A report function must not be the thing that crashes on bad input.
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("SummaryLines panicked on a malformed export: %v", recovered)
		}
	}()
	_ = SummaryLines(&Export{Site: "x"})
	_ = SummaryLines(&Export{Site: "x", SiteVersion: Entry{Path: "/v", Data: []byte("v"), SHA256: "short"}})
}

func TestBuildRefusesAnOversizedJournalBeforeReadingIt(t *testing.T) {
	f := newFixture(t, true)
	// A sparse file: the bound is refused on STAT, so the 64MiB+1 fixture costs no disk and
	// the read-then-check version would have to materialise it to notice.
	handle, err := os.Create(f.sources.FencingState)
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Truncate(maxJournalBytes + 1); err != nil {
		t.Fatal(err)
	}
	handle.Close()
	_, err = Build(f.sources, "sitea", time.Now())
	assertRefusedOnStatNotOnRead(t, err, "an oversized journal exported")
}

// assertRefusedOnStatNotOnRead is what "BEFORE READING IT" means as an assertion (#237 sweep).
//
// readBounded refuses an oversized file TWICE, and the two refusals are the whole point of its
// design being one thing rather than the other:
//
//	info.Size() > bound        "%s is %d bytes, over the %d-byte bound for its kind"   (stat)
//	int64(len(data)) > bound   "%s grew past the %d-byte bound while being read"       (read)
//
// The stat refusal is the one the function exists for: on the offline host an inspection runs on,
// materialising the file first is an OOM in the exact moment a refusal had already been decided.
// The read refusal is the backstop for a file that grows between the two.
//
// BOTH MESSAGES CONTAIN THE WORD "bound". The two tests that call this both asserted only
// `strings.Contains(err.Error(), "bound")` and both carried a header claiming they proved the
// stat path fires. Measured: with the stat operand neutralised, both stayed GREEN — the read
// backstop refused the same fixture with a message that satisfies the same assertion. A test
// whose header names a cause its assertion cannot distinguish is documentation, and this is the
// assertion that makes it a gate.
func assertRefusedOnStatNotOnRead(t *testing.T, err error, whatWouldHaveHappened string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s (err=nil)", whatWouldHaveHappened)
	}
	if strings.Contains(err.Error(), "while being read") {
		t.Fatalf("refused by the READ backstop, not by the stat check: %v\n"+
			"The bound is supposed to be decided from the file's size before any of it is "+
			"materialised; reaching the read means an oversized file was pulled into memory "+
			"on the offline host first.", err)
	}
	if !strings.Contains(err.Error(), "over the") {
		t.Fatalf("%s (err=%v) — want the stat-path refusal, which names the file's size "+
			"against the bound for its kind", whatWouldHaveHappened, err)
	}
}

func TestScanTreeFlagsOversizedFiles(t *testing.T) {
	root := t.TempDir()
	handle, err := os.Create(filepath.Join(root, "huge.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := handle.Truncate(maxTreeFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	handle.Close()
	findings, err := ScanTree(root)
	if err != nil {
		t.Fatalf("oversized tree errored: %v", err)
	}
	if len(findings) != 1 || findings[0].Shape != "oversized-file" {
		t.Fatalf("oversized file not flagged as a finding: %v", findings)
	}
}

func TestAnAbsenceMarkerIsCheckedNotObeyed(t *testing.T) {
	// Found on #219 review, third instance of verifier-dispatch-not-chosen-by-input: an
	// entry claiming Absent skipped structure, digest and secret checks, so key-shaped bytes
	// could ride through an absence marker unverified, unscanned and unreported. Both
	// directions are asserted: the forged marker must be refused, AND the same bytes must be
	// caught when presented honestly — without the second, a future change that silently
	// stops scanning absent entries is indistinguishable from this fix working.
	publicPEM, privatePEM := testKeys(t)
	key := authorityKey(t, privatePEM)
	markerBytes := []byte(strings.Join([]string{"-----BEGIN ", "PRIVATE KEY-----"}, "") + " forged-body")

	f := newFixture(t, true)
	export, err := Build(f.sources, "sitea", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Forged direction: the VERSION file's entry claims absence while carrying the bytes —
	// chosen deliberately, because it has no sidecar and no chain: with the absence check
	// removed, NOTHING else looks at an absent entry's bytes (the first version of this
	// probe targeted a journal, whose absence tripped the sidecar amputation rule first, and
	// the mutation was caught by the wrong detector — a check that is never the sole
	// detector for its own probe is not pinned).
	forged := *export
	forged.SiteVersion = Entry{Path: f.sources.SiteVersion, Data: markerBytes, SHA256: "bogus", Absent: true}
	payload, _ := json.Marshal(&forged)
	recipient, _ := ParseRecipient(publicPEM)
	envelope, err := Seal(payload, recipient.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(envelope, key); err == nil || !strings.Contains(err.Error(), "absence marker") {
		t.Fatalf("an absence marker carrying bytes was accepted (err=%v) — bytes ride past every check by claiming to be absent", err)
	}

	// Honest direction: the same bytes as a present entry are caught by the scan.
	honest := *export
	digest := sha256.Sum256(markerBytes)
	honest.SiteVersion = Entry{Path: f.sources.SiteVersion, Data: markerBytes, SHA256: hex.EncodeToString(digest[:])}
	payload, _ = json.Marshal(&honest)
	envelope, err = Seal(payload, recipient.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(envelope, key); err == nil || !strings.Contains(err.Error(), "secret-shaped") {
		t.Fatalf("the same bytes presented honestly were not caught by the scan (err=%v) — the honest direction of this fix does not hold", err)
	}
}

func TestAJournalWithContentRequiresItsTruncationMarks(t *testing.T) {
	// The fourth instance of the payload-decides-its-own-checking family (#219 review): a
	// present journal with ABSENT sidecar entries verified clean, because both mark readers
	// default a missing mark to genesis — so deleting the marks alongside the tail is a
	// verifiable truncation. The inverse-amputation rule refuses content without marks.
	publicPEM, privatePEM := testKeys(t)
	key := authorityKey(t, privatePEM)
	f := newFixture(t, true)
	export, err := Build(f.sources, "sitea", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recipient, _ := ParseRecipient(publicPEM)

	for name, mutate := range map[string]func(*Export){
		"audit marks deleted with the tail": func(e *Export) {
			e.AuditHighWater = Entry{Path: e.AuditHighWater.Path, Absent: true}
			e.AuditShipped = Entry{Path: e.AuditShipped.Path, Absent: true}
		},
		"audit high-water alone deleted": func(e *Export) {
			e.AuditHighWater = Entry{Path: e.AuditHighWater.Path, Absent: true}
		},
		// NOTE: ".shipped alone absent" is deliberately NOT a refusal case — see
		// TestAnUnreachableCollectorHostStillExports below. It was one, and the rule
		// permanently refused the host you most want an export from.
		"policy mark deleted": func(e *Export) {
			e.PolicyMark = Entry{Path: e.PolicyMark.Path, Absent: true}
		},
	} {
		forged := *export
		mutate(&forged)
		payload, _ := json.Marshal(&forged)
		envelope, err := Seal(payload, recipient.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Inspect(envelope, key); err == nil || !strings.Contains(err.Error(), "truncation") {
			t.Fatalf("a journal with content and no marks was accepted (%s): err=%v — the truncation the marks exist to detect is verifiable", name, err)
		}
	}
}

func TestAnEagerlyCreatedEmptyJournalExportsAsExplicitlyAbsent(t *testing.T) {
	// The sibling bug found in the same sweep: audit.Open creates the journal eagerly, so a
	// running daemon with nothing recorded HAS a zero-byte file and no marks. Refusing
	// "present and empty" would break the exporter on every freshly-commissioned site.
	f := newFixture(t, false)
	for _, path := range []string{f.sources.AuditJournal, f.sources.PolicyState, f.sources.FencingState} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	envelope, _, privatePEM := sealedFixture(t, f)
	export, err := Inspect(envelope, authorityKey(t, privatePEM))
	if err != nil {
		t.Fatalf("a touched-but-virgin site failed to export: %v", err)
	}
	if !export.AuditJournal.Absent {
		t.Fatal("a zero-byte journal exported as present — eager file creation would make every fresh site a refusal")
	}
}

func TestTheRealWritersProduceEveryMark(t *testing.T) {
	// The marks-required rule assumes the writers create each mark with the first durable
	// append. This pins that assumption against the real writers, so a writer change that
	// stops producing a mark fails HERE with the assumption named, not in production with
	// a refusal nobody can read.
	f := newFixture(t, true)
	// Only the TRUNCATION marks are asserted: .high-water is written on the synchronous
	// append path, so its absence beside a journal with events is not a legitimate state.
	// .shipped is written by the shipper's drain goroutine after collector acknowledgement
	// — asserting it here raced the goroutine on CI and made the test itself the flake.
	for _, name := range []string{
		"audit.jsonl" + highWaterSuffix,
		"policy-state.jsonl" + highWaterSuffix,
	} {
		if _, err := os.Stat(filepath.Join(f.dir, name)); err != nil {
			t.Fatalf("the real writers did not produce %s — the marks-required rule's assumption is false and must be re-decided: %v", name, err)
		}
	}
}

func TestAnUnreadableSidecarBesideAnAbsentJournalIsNotAnEmptyHistory(t *testing.T) {
	// The control that found the hole: the same amputated state, one character apart,
	// opposite verdicts. The numeric form was refused as amputation; the string form was
	// ACCEPTED, because `err == nil &&` made an unparseable mark skip the refusal — the
	// only place in the tree where being unparseable removed a check rather than failing
	// one (swept: every other err==nil guard is a fail-closed permission boolean).
	publicPEM, privatePEM := testKeys(t)
	key := authorityKey(t, privatePEM)
	recipient, _ := ParseRecipient(publicPEM)
	f := newFixture(t, true)
	for name, markBytes := range map[string]string{
		"numeric sequence": `{"sequence":1}`,
		"string sequence":  `{"sequence":"1"}`,
		"not JSON at all":  `,,,`,
	} {
		export, err := Build(f.sources, "sitea", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		export.AuditJournal = Entry{Path: export.AuditJournal.Path, Absent: true}
		// The SHIPPED mark is cleared too: the fixture's real one carries sequence 3, and
		// leaving it in meant the amputation refusal fired from the OTHER sidecar — the
		// mutation was red by the wrong detector and the probe proved nothing (found by
		// running the mutation before trusting it; the first version of this test passed
		// under the mutation it existed to catch).
		export.AuditShipped = Entry{Path: export.AuditShipped.Path, Absent: true}
		digest := sha256.Sum256([]byte(markBytes))
		export.AuditHighWater = Entry{Path: export.AuditHighWater.Path, Data: []byte(markBytes), SHA256: hex.EncodeToString(digest[:])}
		payload, _ := json.Marshal(export)
		envelope, err := Seal(payload, recipient.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Inspect(envelope, key); err == nil {
			t.Fatalf("an amputated journal with a %s sidecar was accepted — unreadable is not empty", name)
		}
	}
}

func TestTheExportSiteIsShapeCheckedAndBindable(t *testing.T) {
	// The seventh instance of the payload-decides family: Site is payload-controlled (anyone
	// can seal to the authority's public key), was only checked non-empty, and flows into the
	// operator report as if verified. Closed at both ends: a strict shape at Build and Inspect,
	// and an explicit binding so the inspector can refuse a file that names a different site
	// than the one being restored.
	publicPEM, privatePEM := testKeys(t)
	key := authorityKey(t, privatePEM)
	recipient, _ := ParseRecipient(publicPEM)
	f := newFixture(t, true)

	sealWithSite := func(site string) []byte {
		export, err := Build(f.sources, "sitea", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		export.Site = site // the forged field: everything else stays genuinely valid
		payload, _ := json.Marshal(export)
		envelope, err := Seal(payload, recipient.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	for _, hostile := range []string{"", "SiteA", "sitea\nsiteb  ok", "sitea; rm -rf", "site\x00x"} {
		if _, err := Inspect(sealWithSite(hostile), key); err == nil {
			t.Fatalf("a hostile site name %q reached the report — payload-controlled bytes in a trusted-looking line", hostile)
		}
	}
	// The binding: a valid export naming a DIFFERENT site is refused when the operator binds.
	if _, err := InspectForSite(sealWithSite("sitea"), key, "siteb"); err == nil {
		t.Fatal("an export naming sitea was accepted for a siteb restore — the recovery point self-declared and nobody checked")
	}
	if _, err := InspectForSite(sealWithSite("sitea"), key, "sitea"); err != nil {
		t.Fatalf("a matching site binding refused a good export: %v", err)
	}
}

// THE OTHER HALF OF THE SITE SHAPE CHECK (#237 sweep). validateSiteName is called twice — once
// by Build over the site the DAEMON is configured as, once by InspectForSite over the site a
// PAYLOAD declares. The test above covers the payload half. The Build half survived mutation:
// nothing built an export with a hostile site name.
//
// It is not defence in depth, because nothing upstream does this check. config.Validate only
// requires `site` to be non-empty — measured, it never applies the identifier shape — so the
// value comes straight out of the operator's config file and Build's call is the only guard
// between it and the export. With that operand neutralised the export is BUILT, SEALED, WRITTEN,
// and then printed: SummaryLines emits "site <value> exported <time>" as its first line, so a
// newline-bearing site forges entry lines in the report an operator reads to decide whether to
// trust the file they just produced. Same injection as the payload half, on the side that runs
// on the live guest.
func TestBuildRefusesASiteNameTheRegistryWouldNot(t *testing.T) {
	f := newFixture(t, true)

	// ANCHOR: the shape the registry accepts builds, so the refusals below are about the name
	// and not about the fixture.
	if _, err := Build(f.sources, "sitea", time.Now()); err != nil {
		t.Fatalf("anchor: a valid site name was refused: %v", err)
	}

	// BOTH SIDES OF THE LENGTH BOUND. The registry's shape is `^[a-z0-9][a-z0-9-]{2,62}$`, so
	// the accepted range is 3..63 characters — measured, not read off the export.go comment,
	// which says "62 max". A bound stated on one side only is half a bound: the long row is
	// 64 characters and the short row is 2.
	for _, hostile := range []string{"", "ab", strings.Repeat("a", 64), "SiteA", "sitea\nsiteb  ok", "sitea; rm -rf", "site\x00x"} {
		export, err := Build(f.sources, hostile, time.Now())
		if err == nil {
			lines := SummaryLines(export)
			t.Fatalf("Build accepted the site name %q and produced an export whose report "+
				"opens with %q — the exporter wrote a file naming a site it could not have "+
				"been configured as, and told the operator so in the line they read first",
				hostile, lines[0])
		}
		if !strings.Contains(err.Error(), "is not an identifier the registry would accept") {
			t.Fatalf("site %q was refused by the wrong rule: %v — this row pins the site "+
				"shape check, and a refusal from elsewhere means that check is not what "+
				"protects the report", hostile, err)
		}
	}
}

func TestMatchNameOverMatchesDeliberately(t *testing.T) {
	// Pins the measured behaviour the docstring now describes: substring-of-name, broader
	// than segment matching, in the fail-safe direction. A future "tightening" that turns
	// these into non-matches changes a documented decision and must update this test with it.
	overMatches := []struct{ name, pattern string }{
		{"my-server-keyring", "server-key"},
		{"no-credentials-here.md", "credentials"},
		{"10-token.pin", ".pin"},
	}
	for _, pair := range overMatches {
		if !matchName(pair.name, pair.pattern) {
			t.Fatalf("%q no longer matches %q — the fail-safe over-match was tightened without updating the decision", pair.name, pair.pattern)
		}
	}
	for _, clean := range []string{"unpinned.go", "spinning.txtual", "README.md"} {
		if matchName(clean, ".pin") || matchName(clean, "credentials") || matchName(clean, "server-key") {
			t.Fatalf("%q matched — the over-match is broader than documented", clean)
		}
	}
}

func TestAnUnreachableCollectorHostStillExports(t *testing.T) {
	// The marks-required rule once demanded .shipped too. The shipper writes it from its
	// drain goroutine after the collector acknowledges, and its own comment calls losing it
	// safe — so a host whose collector is unreachable NEVER produces one, and the rule
	// refused exactly the host a recovery export is most needed from (surfaced as a
	// macOS-passes/Linux-fails CI split: the drain raced Build). Absence of .shipped beside
	// a present journal with its truncation mark is a legitimate state and must verify.
	f := newFixture(t, true)
	envelope, _, privatePEM := sealedFixture(t, f)
	authority := authorityKey(t, privatePEM)
	var export Export
	payload, err := Open(envelope, authority)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &export); err != nil {
		t.Fatal(err)
	}
	export.AuditShipped = Entry{Path: export.AuditShipped.Path, Absent: true}
	resealed, err := json.Marshal(&export)
	if err != nil {
		t.Fatal(err)
	}
	// Reseal to the SAME authority the fixture used — the point is a legitimate authority
	// tool dropping one field, not a key mismatch (the first version sealed to a fresh
	// keypair and then failed on the wrong-key refusal, which proved nothing).
	envelope, err = Seal(resealed, authority.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(envelope, authorityKey(t, privatePEM)); err != nil {
		t.Fatalf("a journal-only host's export was refused: %v — the unreachable-collector case is legitimate", err)
	}
}

func TestTwoJournalsSharingABasenameAreRefused(t *testing.T) {
	// Verification materialises entries by basename in one directory; two present entries
	// with the same basename would overwrite one another and one journal would be verified
	// as the other's bytes. The configuration that produces this is pathological, and the
	// export says so instead of verifying the wrong thing.
	f := newFixture(t, true)
	// Point the policy journal at a copy of the audit journal's basename in another dir.
	elsewhere := filepath.Join(f.dir, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(f.sources.AuditJournal)
	if err := os.WriteFile(filepath.Join(elsewhere, "audit.jsonl"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mark := range []string{f.sources.PolicyState, f.sources.PolicyState + highWaterSuffix} {
		if _, err := os.Stat(mark); err == nil {
			os.Remove(mark)
		}
	}
	f.sources.PolicyState = filepath.Join(elsewhere, "audit.jsonl")
	_, err := Build(f.sources, "sitea", time.Now())
	if err == nil || !strings.Contains(err.Error(), "share the basename") {
		t.Fatalf("two journals with one basename exported (err=%v) — verification would conflate them", err)
	}
}

func TestEntryPathsCannotInjectReportLines(t *testing.T) {
	// The eighth instance, and the direct sibling of the Site fix: the sweep stopped at the
	// field that had been named and left its neighbour. A forged absent entry whose PATH
	// carries a newline rendered a fabricated "audit journal VERIFIED" line in the report —
	// measured on #219 review. Closed with the same shape rule as Site, applied to present
	// AND absent entries, plus %q in the formatter: validation is remembered per field;
	// quoting cannot be forgotten when a fifth field appears.
	publicPEM, privatePEM := testKeys(t)
	key := authorityKey(t, privatePEM)
	recipient, _ := ParseRecipient(publicPEM)
	f := newFixture(t, true)
	for _, hostile := range []string{
		"/var/lib/regalia-kms/audit.jsonl\n  audit journal   VERIFIED  sha256:0000000000",
		"relative/path.jsonl",
		"/var/lib/../etc/passwd",
		"/var/lib/x\x00y",
	} {
		export, err := Build(f.sources, "sitea", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		export.SiteVersion = Entry{Path: hostile, Absent: true} // through an absence marker…
		if hostile[0] == '/' && !containsControl(hostile) {
			export.SiteVersion = Entry{Path: hostile} // …and through a present entry where shape allows
		}
		payload, _ := json.Marshal(export)
		envelope, err := Seal(payload, recipient.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Inspect(envelope, key); err == nil {
			t.Fatalf("a hostile entry path %q passed verification — payload bytes reaching the report", hostile)
		}
	}
	// And the formatter is quoted even for clean paths: reverting %q to %s must be caught,
	// or the quoting argument ("cannot be forgotten") is decoration.
	export, err := Build(f.sources, "sitea", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(SummaryLines(export), "\n")
	if !strings.Contains(joined, `"/var/lib/regalia-kms`) && !strings.Contains(joined, `"`) {
		t.Fatal("the report is not quoting entry paths — the structural half of this fix is gone")
	}
}

func containsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func TestZeroByteSemanticsAreDecidedPerKind(t *testing.T) {
	// Each row alone passes against the wrong rule — the matrix is the test. A zero-byte
	// JOURNAL is the eager-create state every fresh site is in and exports as absent; a
	// zero-byte VERSION FILE or SIDECAR MARK is a file that exists and is empty, and the
	// guards written for exactly that state must fire. The first normalisation applied to
	// all three and silently disarmed two guards owned by other decisions.
	dir := t.TempDir()
	base := Sources{
		AuditJournal: filepath.Join(dir, "audit.jsonl"),
		PolicyState:  filepath.Join(dir, "policy-state.jsonl"),
		FencingState: filepath.Join(dir, "epochs.jsonl"),
		SiteVersion:  filepath.Join(dir, "deployment-version"),
	}

	// Row 1: zero-byte journals export as explicit absence (fresh-site state).
	for _, path := range []string{base.AuditJournal, base.PolicyState, base.FencingState} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	export, err := Build(base, "sitea", time.Now())
	if err != nil {
		t.Fatalf("zero-byte journals did not export as absent: %v", err)
	}
	if !export.AuditJournal.Absent {
		t.Fatal("zero-byte journal exported present — fresh sites would be refused")
	}

	// Row 2: zero-byte version file is REFUSED (its own guard, not disarmed).
	if err := os.WriteFile(base.SiteVersion, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(base, "sitea", time.Now()); err == nil {
		t.Fatal("a zero-byte deployment version exported — the blank-version guard was disarmed by the journal normalisation")
	}
	if err := os.WriteFile(base.SiteVersion, []byte("regalia-kms 1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Row 3: zero-byte sidecar beside a journal WITH content is REFUSED — as a present,
	// empty mark, not normalised into the marks-required refusal's blind spot.
	writeAuditJournal(t, base.AuditJournal, 1)
	if err := os.WriteFile(base.AuditJournal+highWaterSuffix, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Build(base, "sitea", time.Now())
	if err == nil {
		t.Fatal("a zero-byte high-water mark beside a journal with events exported — empty-present is a refusal, not an absence")
	}
}
