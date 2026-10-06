package audit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"
)

type reconciliationFixture struct {
	key    *ecdsa.PrivateKey
	issuer *x509.Certificate
	leaf   []byte
	crl    []byte
	config X509ReconcileConfig
	events []Event
}

func reconciliationFixtureForTest(t *testing.T) reconciliationFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic reconciliation CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: true,
		MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "web.svc.test.invalid"}, DNSNames: []string{"web.svc.test.invalid"},
		NotBefore: now, NotAfter: now.Add(5 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leaf, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(10 * time.Minute)}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	fixture := reconciliationFixture{key: key, issuer: issuer, leaf: leaf, crl: crl, config: X509ReconcileConfig{
		ProfileID: "synthetic-profile-v1", ObjectID: "synthetic-internal-ca", Purpose: "internal-pki",
		IssuerDER: issuerDER, KeyFingerprint: "sha256:" + hex.EncodeToString(fingerprint[:])}}
	leafParsed, _ := x509.ParseCertificate(leaf)
	crlParsed, _ := x509.ParseRevocationList(crl)
	for i, input := range []struct {
		kind string
		tbs  []byte
	}{{"certificate", leafParsed.RawTBSCertificate}, {"crl", crlParsed.RawTBSRevocationList}} {
		digest := sha256.Sum256(input.tbs)
		e := Event{Timestamp: now, RequestID: []string{"018f0000-0000-7000-8000-000000000001", "018f0000-0000-7000-8000-000000000002"}[i],
			Principal: "spiffe://test.invalid/workload/pki", Decision: "allow", ObjectID: fixture.config.ObjectID, Purpose: fixture.config.Purpose,
			Operation: "sign", DeviceID: "synthetic-software", Outcome: "authorized", RegistryDigest: "sha256:" + strings.Repeat("a", 64),
			PolicyDigest: "sha256:" + strings.Repeat("b", 64), RBACDigest: "sha256:" + strings.Repeat("c", 64),
			X509ProfileID: fixture.config.ProfileID, PayloadDigest: "sha256:" + hex.EncodeToString(digest[:]), ArtifactKind: input.kind, KeyFingerprint: fixture.config.KeyFingerprint}
		fixture.events = append(fixture.events, e)
		e.Outcome = "success"
		fixture.events = append(fixture.events, e)
	}
	return fixture
}

func reconciliationExport(t *testing.T, fixture reconciliationFixture, events []Event) ([]byte, X509ReconcileConfig) {
	t.Helper()
	var output bytes.Buffer
	previous := genesisHash
	for i, event := range events {
		event.Sequence = uint64(i + 1)
		event.PreviousHash = previous
		event.Hash = eventHash(event)
		if err := json.NewEncoder(&output).Encode(event); err != nil {
			t.Fatal(err)
		}
		previous = event.Hash
	}
	config := fixture.config
	config.ExpectedSequence = uint64(len(events))
	config.ExpectedHash = previous
	return output.Bytes(), config
}

func TestX509ReconciliationVerifiesSignaturesAndOrderedCollectorEvidence(t *testing.T) {
	fixture := reconciliationFixtureForTest(t)
	stream, config := reconciliationExport(t, fixture, fixture.events)
	report, err := ReconcileX509(bytes.NewReader(stream), config, [][]byte{fixture.leaf, fixture.crl})
	if err != nil {
		t.Fatal(err)
	}
	if report.Status != "consistent" || report.Events != 4 || report.AuthorizedRequests != 2 || report.SuccessfulRequests != 2 || report.MatchedArtifacts != 2 || report.Conflicts != 0 || report.IndeterminateRequests != 0 || report.UnattestedArtifacts != 0 {
		t.Fatalf("report=%#v", report)
	}
	encoded, _ := json.Marshal(report)
	for _, sensitive := range []string{"web.svc.test.invalid", fixture.events[0].RequestID, fixture.config.KeyFingerprint, fixture.events[0].PayloadDigest} {
		if bytes.Contains(encoded, []byte(sensitive)) {
			t.Fatal("report exposed input metadata")
		}
	}
}

func TestX509ReconciliationAccountsForMissingAndConflictingEvidence(t *testing.T) {
	fixture := reconciliationFixtureForTest(t)
	authorization, success := fixture.events[0], fixture.events[1]
	failed := success
	failed.Outcome = "backend-failed"
	denied := authorization
	denied.Decision, denied.Outcome = "deny", "policy-DENIED:quota"
	changed := success
	changed.Principal = "spiffe://test.invalid/workload/different"
	changedProfile := success
	changedProfile.X509ProfileID = "synthetic-profile-v2"
	secondAuth, secondSuccess := authorization, success
	secondAuth.RequestID, secondSuccess.RequestID = fixture.events[2].RequestID, fixture.events[2].RequestID
	for _, test := range []struct {
		name          string
		events        []Event
		artifacts     [][]byte
		status        string
		matched       uint64
		indeterminate uint64
		conflicts     uint64
	}{
		{"lost response", []Event{authorization, success}, nil, "indeterminate", 0, 1, 0},
		{"execution interrupted", []Event{authorization}, nil, "indeterminate", 0, 1, 0},
		{"backend failure can follow signing", []Event{authorization, failed}, nil, "indeterminate", 0, 1, 0},
		{"artifact after backend failure", []Event{authorization, failed}, [][]byte{fixture.leaf}, "indeterminate", 0, 1, 0},
		{"terminal without authorization", []Event{success}, [][]byte{fixture.leaf}, "conflict", 0, 0, 1},
		{"terminal before authorization", []Event{success, authorization}, [][]byte{fixture.leaf}, "conflict", 0, 0, 1},
		{"principal switched", []Event{authorization, changed}, [][]byte{fixture.leaf}, "conflict", 0, 0, 1},
		{"profile switched", []Event{authorization, changedProfile}, [][]byte{fixture.leaf}, "conflict", 0, 0, 1},
		{"authorization duplicated", []Event{authorization, authorization, success}, [][]byte{fixture.leaf}, "conflict", 0, 0, 1},
		{"terminal duplicated", []Event{authorization, success, success}, [][]byte{fixture.leaf}, "conflict", 0, 0, 1},
		{"denial then authorization reuses ID", []Event{denied, authorization, success}, [][]byte{fixture.leaf}, "conflict", 0, 0, 1},
		{"denial duplicated", []Event{denied, denied}, nil, "conflict", 0, 0, 1},
		{"single denial", []Event{denied}, nil, "indeterminate", 0, 0, 0},
		{"artifact duplicated", []Event{authorization, success}, [][]byte{fixture.leaf, fixture.leaf}, "conflict", 1, 0, 1},
		{"same TBS signed in two requests", []Event{authorization, success, secondAuth, secondSuccess}, [][]byte{fixture.leaf}, "indeterminate", 0, 2, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			stream, config := reconciliationExport(t, fixture, test.events)
			report, err := ReconcileX509(bytes.NewReader(stream), config, test.artifacts)
			if err != nil {
				t.Fatal(err)
			}
			if report.Status != test.status || report.MatchedArtifacts != test.matched || report.IndeterminateRequests != test.indeterminate || report.Conflicts != test.conflicts {
				t.Fatalf("report=%#v, want status=%s matched=%d indeterminate=%d conflicts=%d", report, test.status, test.matched, test.indeterminate, test.conflicts)
			}
		})
	}
}

func TestX509ReconciliationRefusesUnanchoredTruncatedOrRewrittenExports(t *testing.T) {
	fixture := reconciliationFixtureForTest(t)
	stream, config := reconciliationExport(t, fixture, fixture.events[:2])
	rewrittenEvents := append([]Event(nil), fixture.events[:2]...)
	rewrittenEvents[1].Outcome = "backend-failed"
	rewritten, _ := reconciliationExport(t, fixture, rewrittenEvents)
	for _, test := range []struct {
		name   string
		input  []byte
		mutate func(*X509ReconcileConfig)
	}{
		{"missing head", stream, func(c *X509ReconcileConfig) { c.ExpectedSequence = 0; c.ExpectedHash = "" }},
		{"wrong head", stream, func(c *X509ReconcileConfig) { c.ExpectedHash = "sha256:" + strings.Repeat("e", 64) }},
		{"wrong sequence", stream, func(c *X509ReconcileConfig) { c.ExpectedSequence++ }},
		{"truncated export", stream[:bytes.IndexByte(stream, '\n')+1], nil},
		{"self-consistent rewrite", rewritten, nil},
		{"garbage appended", append(append([]byte(nil), stream...), []byte("{}\n")...), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := config
			if test.mutate != nil {
				test.mutate(&changed)
			}
			if _, err := ReconcileX509(bytes.NewReader(test.input), changed, [][]byte{fixture.leaf}); err == nil {
				t.Fatal("unanchored or changed export accepted")
			}
		})
	}
}

func TestX509ReconciliationVerifiesArtifactSignatureIssuerAndScope(t *testing.T) {
	fixture := reconciliationFixtureForTest(t)
	stream, config := reconciliationExport(t, fixture, fixture.events[:2])
	tampered := bytes.Clone(fixture.leaf)
	tampered[len(tampered)-1] ^= 1
	wrongIssuer := reconciliationFixtureForTest(t)
	for _, test := range []struct {
		name     string
		artifact []byte
		mutate   func(*X509ReconcileConfig)
	}{
		{"altered signature", tampered, nil},
		{"trailing artifact data", append(bytes.Clone(fixture.leaf), 0), nil},
		{"wrong issuer", fixture.leaf, func(c *X509ReconcileConfig) {
			c.IssuerDER = wrongIssuer.config.IssuerDER
			c.KeyFingerprint = wrongIssuer.config.KeyFingerprint
		}},
		{"wrong independent key pin", fixture.leaf, func(c *X509ReconcileConfig) { c.KeyFingerprint = "sha256:" + strings.Repeat("e", 64) }},
		{"empty artifact", nil, nil},
		{"oversize artifact", make([]byte, MaxX509ArtifactBytes+1), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := config
			if test.mutate != nil {
				test.mutate(&changed)
			}
			if _, err := ReconcileX509(bytes.NewReader(stream), changed, [][]byte{test.artifact}); err == nil {
				t.Fatal("artifact accepted without complete pinned issuer proof")
			}
		})
	}
	for _, field := range []string{"profile", "object", "purpose"} {
		changed := config
		switch field {
		case "profile":
			changed.ProfileID += "-other"
		case "object":
			changed.ObjectID += "-other"
		case "purpose":
			changed.Purpose += "-other"
		}
		report, err := ReconcileX509(bytes.NewReader(stream), changed, [][]byte{fixture.leaf})
		if err != nil || report.Status != "unattested" || report.UnattestedArtifacts != 1 || report.MatchedArtifacts != 0 {
			t.Fatalf("scope %s falsely attested artifact: %#v err=%v", field, report, err)
		}
	}
	if _, err := ReconcileX509(bytes.NewReader(stream), config, make([][]byte, MaxX509Artifacts+1)); err == nil {
		t.Fatal("unbounded artifact inventory accepted")
	}
}

func TestX509ReconciliationAllowsSimultaneousFullAndDeltaCRLNumbers(t *testing.T) {
	fixture := reconciliationFixtureForTest(t)
	full, err := x509.ParseRevocationList(fixture.crl)
	if err != nil {
		t.Fatal(err)
	}
	base, err := asn1.Marshal(big.NewInt(0))
	if err != nil {
		t.Fatal(err)
	}
	delta, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: full.ThisUpdate, NextUpdate: full.NextUpdate,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: base}}}, fixture.issuer, fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseRevocationList(delta)
	if err != nil {
		t.Fatal(err)
	}
	authorization, success := fixture.events[2], fixture.events[3]
	authorization.RequestID = "018f0000-0000-7000-8000-000000000003"
	success.RequestID = authorization.RequestID
	authorization.PayloadDigest = reconcileDigest(parsed.RawTBSRevocationList)
	success.PayloadDigest = authorization.PayloadDigest
	events := append(append([]Event(nil), fixture.events[2:]...), authorization, success)
	stream, config := reconciliationExport(t, fixture, events)
	report, err := ReconcileX509(bytes.NewReader(stream), config, [][]byte{fixture.crl, delta})
	if err != nil || report.Status != "consistent" || report.MatchedArtifacts != 2 || report.Conflicts != 0 {
		t.Fatalf("simultaneous full/delta CRLs with valid separate attestations were refused: %#v, %v", report, err)
	}
}

func TestX509ReconciliationChecksIssuerNamesAKIAndExactTBS(t *testing.T) {
	fixture := reconciliationFixtureForTest(t)
	stream, config := reconciliationExport(t, fixture, fixture.events[:2])
	for _, test := range []struct {
		name      string
		mutate    func(*x509.Certificate, *x509.Certificate)
		wantError bool
	}{
		{"wrong issuer name with valid signature", func(_ *x509.Certificate, parent *x509.Certificate) {
			parent.RawSubject = nil
			parent.Subject = pkix.Name{CommonName: "different synthetic issuer"}
		}, true},
		{"wrong AKI with valid signature", func(_ *x509.Certificate, parent *x509.Certificate) { parent.SubjectKeyId = []byte{1, 2, 3, 4} }, true},
		{"changed TBS with valid signature", func(leaf *x509.Certificate, _ *x509.Certificate) {
			leaf.RawSubject = nil
			leaf.Subject = pkix.Name{CommonName: "other.svc.test.invalid"}
			leaf.DNSNames = []string{"other.svc.test.invalid"}
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			leaf, err := x509.ParseCertificate(fixture.leaf)
			if err != nil {
				t.Fatal(err)
			}
			parent := *fixture.issuer
			test.mutate(leaf, &parent)
			der, err := x509.CreateCertificate(rand.Reader, leaf, &parent, &fixture.key.PublicKey, fixture.key)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if err := parsed.CheckSignatureFrom(fixture.issuer); err != nil {
				t.Fatalf("negative fixture also breaks cryptographic signature: %v", err)
			}
			report, err := ReconcileX509(bytes.NewReader(stream), config, [][]byte{der})
			if test.wantError {
				if err == nil {
					t.Fatal("signed artifact bypassed exact issuer identity")
				}
				return
			}
			if err != nil || report.MatchedArtifacts != 0 || report.UnattestedArtifacts != 1 || report.IndeterminateRequests != 1 || report.Status != "unattested" {
				t.Fatalf("changed TBS matched the old digest evidence: %#v err=%v", report, err)
			}
		})
	}
}

func TestX509ReconciliationDetectsCertificateSerialCollision(t *testing.T) {
	fixture := reconciliationFixtureForTest(t)
	leaf, err := x509.ParseCertificate(fixture.leaf)
	if err != nil {
		t.Fatal(err)
	}
	leaf.RawSubject = nil
	leaf.Subject = pkix.Name{CommonName: "other.svc.test.invalid"}
	leaf.DNSNames = []string{"other.svc.test.invalid"}
	der, err := x509.CreateCertificate(rand.Reader, leaf, fixture.issuer, &fixture.key.PublicKey, fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	authorization, success := fixture.events[0], fixture.events[1]
	authorization.RequestID = fixture.events[2].RequestID
	success.RequestID = authorization.RequestID
	authorization.PayloadDigest = reconcileDigest(parsed.RawTBSCertificate)
	success.PayloadDigest = authorization.PayloadDigest
	events := append(append([]Event(nil), fixture.events[:2]...), authorization, success)
	stream, config := reconciliationExport(t, fixture, events)
	report, err := ReconcileX509(bytes.NewReader(stream), config, [][]byte{fixture.leaf, der})
	if err != nil || report.Status != "conflict" || report.Conflicts != 1 || report.MatchedArtifacts != 1 {
		t.Fatalf("duplicate issuer serial attested twice: %#v err=%v", report, err)
	}
}

func TestX509ReconciliationValidatesIntentBeyondHashIntegrity(t *testing.T) {
	fixture := reconciliationFixtureForTest(t)
	for _, test := range []struct {
		name   string
		mutate func(*Event)
	}{
		{"missing digest", func(e *Event) { e.PayloadDigest = "" }},
		{"missing artifact kind", func(e *Event) { e.ArtifactKind = "" }},
		{"invalid request identifier", func(e *Event) { e.RequestID = "not-a-request-id" }},
		{"unsafe metadata", func(e *Event) { e.Principal = "synthetic\nprincipal" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			events := append([]Event(nil), fixture.events[:2]...)
			test.mutate(&events[0])
			stream, config := reconciliationExport(t, fixture, events)
			if _, err := ReconcileX509(bytes.NewReader(stream), config, [][]byte{fixture.leaf}); err == nil {
				t.Fatal("self-consistent chain with invalid metadata was accepted")
			}
		})
	}
}

func TestX509ReconciliationRequiresCompleteAuthorizationTerminalBinding(t *testing.T) {
	fixture := reconciliationFixtureForTest(t)
	for name, mutate := range map[string]func(*Event){
		"device":    func(e *Event) { e.DeviceID = "synthetic-other-device" },
		"registry":  func(e *Event) { e.RegistryDigest = "sha256:" + strings.Repeat("e", 64) },
		"policy":    func(e *Event) { e.PolicyDigest = "sha256:" + strings.Repeat("e", 64) },
		"RBAC":      func(e *Event) { e.RBACDigest = "sha256:" + strings.Repeat("e", 64) },
		"approvers": func(e *Event) { e.VerifiedApprovers = []string{"synthetic-other-approver"} },
		"payload":   func(e *Event) { e.PayloadDigest = "sha256:" + strings.Repeat("e", 64) },
		"kind":      func(e *Event) { e.ArtifactKind = "crl" },
		"key":       func(e *Event) { e.KeyFingerprint = "sha256:" + strings.Repeat("e", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			events := append([]Event(nil), fixture.events[:2]...)
			mutate(&events[1])
			stream, config := reconciliationExport(t, fixture, events)
			report, err := ReconcileX509(bytes.NewReader(stream), config, [][]byte{fixture.leaf})
			if err != nil || report.Status != "conflict" || report.Conflicts != 1 || report.MatchedArtifacts != 0 {
				t.Fatalf("binding disagreement accepted: %#v %v", report, err)
			}
		})
	}
}

type reconcileErrorReader struct{}

func (reconcileErrorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestX509ReconciliationRetainsReaderErrorWithoutEchoingIt(t *testing.T) {
	fixture := reconciliationFixtureForTest(t)
	_, config := reconciliationExport(t, fixture, fixture.events[:2])
	_, err := ReconcileX509(reconcileErrorReader{}, config, nil)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("reader failure lost its cause: %v", err)
	}
	if strings.Contains(err.Error(), io.ErrUnexpectedEOF.Error()) {
		t.Fatal("generic error exposed reader diagnostics")
	}
}

// This reader produces finite, self-consistent audit events on demand. Their
// scope differs from the selected CA. A total byte limit must stop the reader;
// neither malformed JSON nor the final expected-head mismatch proves that bound.
type largeReconcileReader struct {
	base      Event
	remaining int
	sequence  uint64
	previous  string
	pending   []byte
	readBytes int64
}

func (reader *largeReconcileReader) Read(buffer []byte) (int, error) {
	if len(reader.pending) == 0 {
		if reader.remaining == 0 {
			return 0, io.EOF
		}
		reader.remaining--
		reader.sequence++
		event := reader.base
		event.Sequence = reader.sequence
		event.RequestID = fmt.Sprintf("018f0000-0000-7000-8000-%012x", reader.sequence)
		event.PreviousHash = reader.previous
		event.Hash = eventHash(event)
		reader.previous = event.Hash
		encoded, err := json.Marshal(event)
		if err != nil {
			return 0, err
		}
		reader.pending = append(encoded, '\n')
	}
	n := copy(buffer, reader.pending)
	reader.pending = reader.pending[n:]
	reader.readBytes += int64(n)
	return n, nil
}

func TestX509ReconciliationStopsAtTotalExportBound(t *testing.T) {
	fixture := reconciliationFixtureForTest(t)
	_, config := reconciliationExport(t, fixture, fixture.events[:2])
	base := fixture.events[0]
	base.ObjectID = "synthetic-other-object"
	base.Principal = strings.Repeat("a", 63<<10)
	reader := &largeReconcileReader{base: base, remaining: 1200, previous: genesisHash}
	config.ExpectedSequence = 1200
	if _, err := ReconcileX509(reader, config, nil); err == nil {
		t.Fatal("oversize export accepted")
	}
	if reader.readBytes != MaxX509CollectorExportBytes+1 {
		t.Fatalf("read %d bytes; bound must stop at exactly %d, independently of final head mismatch", reader.readBytes, MaxX509CollectorExportBytes+1)
	}
}
