package operations

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

type x509CoordinatorFixture struct {
	now         time.Time
	issuer      *x509.Certificate
	issuerKey   *ecdsa.PrivateKey
	leafKey     *ecdsa.PrivateKey
	profile     policy.X509Policy
	policyID    string
	state       *policy.FileState
	path        string
	router      *fakeRouter
	auditor     *fakeAudit
	hardware    *x509CoordinatorHardware
	coordinator *Coordinator
	sequence    int
}

type x509CoordinatorHardware struct {
	fakeHardware
	content string
}

func (hardware *x509CoordinatorHardware) Execute(ctx context.Context, route registry.Route, operation, format, content string, data, aad []byte) ([]byte, string, error) {
	hardware.content = content
	return hardware.fakeHardware.Execute(ctx, route, operation, format, content, data, aad)
}

func newX509CoordinatorFixture(t *testing.T) *x509CoordinatorFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key := x509CoordinatorKey(t)
	rootKey := x509CoordinatorKey(t)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-offline-root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	root = x509CoordinatorCertificate(t, root, root, rootKey, rootKey)
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "synthetic-intermediate"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(40 * time.Minute), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"svc.poc.invalid"}}
	issuer = x509CoordinatorCertificate(t, issuer, root, key, rootKey)
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(spki)
	f := &x509CoordinatorFixture{now: now, issuer: issuer, issuerKey: key, leafKey: x509CoordinatorKey(t), policyID: "synthetic-pki-policy-v1", path: filepath.Join(t.TempDir(), "policy-state.jsonl"), auditor: &fakeAudit{}, hardware: &x509CoordinatorHardware{fakeHardware: fakeHardware{output: bytes.Repeat([]byte{1}, 64)}}}
	f.profile = policy.X509Policy{ID: "synthetic-issuing-profile-v1", IssuerDER: bytes.Clone(issuer.Raw), DNSSuffixes: []string{"svc.poc.invalid"}, MaxLeafValidity: 10 * time.Minute, MaxCRLValidity: 20 * time.Minute, LeafPerDay: 1, CRLPerDay: 1}
	f.router = &fakeRouter{route: registry.Route{ObjectID: "synthetic-ca", Purpose: "internal-pki", Environment: "development", Algorithm: "p256", PolicyID: f.policyID, Binding: registry.Binding{Backend: "nitrokey-pkcs11", DeviceID: "synthetic-token", PublicKeySHA256: "sha256:" + hex.EncodeToString(digest[:])}}}
	f.open(t)
	return f
}

func (f *x509CoordinatorFixture) open(t *testing.T) {
	t.Helper()
	state, err := policy.OpenFileState(f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.state = state
	t.Cleanup(func() { state.Close() })
	semantic, err := policy.New([]policy.Policy{{ID: f.policyID, ObjectID: "synthetic-ca", Purpose: "internal-pki", Environment: "development", Operation: "sign", Algorithm: "p256", ContentTypes: []string{"application/vnd.regalia.x509-tbs"}, MaxPayloadBytes: 32 << 10, MaxFuture: 2 * time.Minute, X509: &f.profile}}, state, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	f.router.route.PolicyID = f.policyID
	f.coordinator, err = New(fakeAuthorizer{allowed: true}, f.router, semantic, f.auditor, directRunner{}, f.hardware, "sha256:synthetic-policy", nil, func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
}

func (f *x509CoordinatorFixture) request(data []byte, content string) api.Request {
	f.sequence++
	return api.Request{RequestID: fmt.Sprintf("018f0000-0000-7000-8000-%012d", f.sequence), Principal: "spiffe://regalia/workload/synthetic-pki", ObjectID: "synthetic-ca", Operation: "sign", ContentType: content, Data: bytes.Clone(data), Context: api.OperationContext{Environment: "development", Purpose: "internal-pki", ExpiresAt: f.now.Add(time.Minute), Nonce: fmt.Sprintf("nonce_%012d", f.sequence)}}
}

func (f *x509CoordinatorFixture) leaf(t *testing.T, edit func(*x509.Certificate)) []byte {
	t.Helper()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "web.svc.poc.invalid"}, DNSNames: []string{"web.svc.poc.invalid"}, NotBefore: f.now.Add(-30 * time.Second), NotAfter: f.now.Add(5 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if edit != nil {
		edit(leaf)
	}
	return x509CoordinatorCertificate(t, leaf, f.issuer, f.leafKey, f.issuerKey).RawTBSCertificate
}

func (f *x509CoordinatorFixture) crl(t *testing.T) []byte {
	t.Helper()
	encoded, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: f.now, NextUpdate: f.now.Add(10 * time.Minute), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(3), RevocationTime: f.now}}}, f.issuer, f.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return crl.RawTBSRevocationList
}

func x509CoordinatorKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func x509CoordinatorCertificate(t *testing.T, template, parent *x509.Certificate, key, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	encoded, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestCoordinatorX509InspectsFullBytesHashesOnceAndAuditsIntent(t *testing.T) {
	f := newX509CoordinatorFixture(t)
	for _, tc := range []struct {
		kind string
		data []byte
	}{{"certificate", f.leaf(t, nil)}, {"crl", f.crl(t)}} {
		t.Run(tc.kind, func(t *testing.T) {
			request := f.request(tc.data, "application/vnd.regalia.x509-tbs")
			digest := sha256.Sum256(tc.data)
			before := len(f.auditor.drafts)
			result, err := f.coordinator.Execute(context.Background(), request)
			if err != nil || len(result.Data) != 64 || !bytes.Equal(f.hardware.data, digest[:]) || f.hardware.content != "application/vnd.regalia.digest" || !bytes.Equal(request.Data, tc.data) {
				t.Fatal("inspected TBS was not hashed exactly once before signing", err)
			}
			if len(f.auditor.drafts) != before+2 {
				t.Fatal("missing authorization or terminal audit")
			}
			for _, draft := range f.auditor.drafts[before:] {
				if draft.RequestID != request.RequestID || draft.X509ProfileID != f.profile.ID || draft.PayloadDigest != "sha256:"+hex.EncodeToString(digest[:]) || draft.ArtifactKind != tc.kind || draft.KeyFingerprint != f.router.route.Binding.PublicKeySHA256 {
					t.Fatal("audit signing intent lost inspected payload, profile or trusted key binding")
				}
			}
		})
	}
}

func TestCoordinatorX509MalformedInputDoesNotSpendDurableCount(t *testing.T) {
	for _, mode := range []string{"trailing-DER", "truncated-DER", "opaque-digest"} {
		t.Run(mode, func(t *testing.T) {
			f := newX509CoordinatorFixture(t)
			data := f.leaf(t, nil)
			switch mode {
			case "trailing-DER":
				data = append(data, 0)
			case "truncated-DER":
				data = data[:len(data)-1]
			case "opaque-digest":
				digest := sha256.Sum256(data)
				data = digest[:]
			}
			refused := f.request(data, "application/vnd.regalia.x509-tbs")
			result, err := f.coordinator.Execute(context.Background(), refused)
			x509AssertCoordinatorFailure(t, result, err, "INVALID_ARGUMENT", http.StatusBadRequest, false)
			if f.hardware.calls != 0 {
				t.Fatal("malformed or opaque input reached hardware")
			}
			valid := f.request(f.leaf(t, nil), "application/vnd.regalia.x509-tbs")
			valid.Context.Nonce = refused.Context.Nonce
			if _, err := f.coordinator.Execute(context.Background(), valid); err != nil || f.hardware.calls != 1 {
				t.Fatal("malformed input consumed valid issuance capacity", err)
			}
		})
	}
}

func TestCoordinatorX509UnsupportedCallShapeDoesNotSpendDurableCount(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*api.Request)
	}{
		{"wrong-operation", func(r *api.Request) { r.Operation = "verify" }},
		{"envelope-format", func(r *api.Request) { r.Format = "regalia-envelope-v2" }},
		{"additional-authenticated-data", func(r *api.Request) { r.EnvelopeAAD = []byte("synthetic-extra-context") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newX509CoordinatorFixture(t)
			request := f.request(f.leaf(t, nil), "application/vnd.regalia.x509-tbs")
			tc.edit(&request)
			result, err := f.coordinator.Execute(context.Background(), request)
			x509AssertCoordinatorFailure(t, result, err, "INVALID_ARGUMENT", http.StatusBadRequest, false)
			if f.hardware.calls != 0 {
				t.Fatal("unsupported X.509 call shape reached the token")
			}
			if _, err := f.coordinator.Execute(context.Background(), f.request(f.leaf(t, nil), "application/vnd.regalia.x509-tbs")); err != nil || f.hardware.calls != 1 {
				t.Fatal("unsupported call shape consumed issuance capacity", err)
			}
		})
	}
}

func TestCoordinatorX509SemanticAndContentRefusalsNeverReachToken(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		edit    func(*x509.Certificate)
		pin     string
		backend string
		digest  bool
	}{
		{name: "outside-name", edit: func(c *x509.Certificate) {
			c.Subject.CommonName = "outside.invalid"
			c.DNSNames = []string{"outside.invalid"}
		}},
		{name: "long-lived", edit: func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(20 * time.Minute) }},
		{name: "CA-privilege", edit: func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }},
		{name: "wrong-key-pin", pin: "sha256:" + string(bytes.Repeat([]byte{'a'}, 64))},
		{name: "advisory-fingerprint-only", pin: "absent"},
		{name: "backend-without-enforced-pin", backend: "yubikey-piv"},
		{name: "digest-bypass", content: "application/vnd.regalia.digest", digest: true},
		{name: "content-bypass", content: "application/octet-stream"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newX509CoordinatorFixture(t)
			originalPin := f.router.route.Binding.PublicKeySHA256
			originalBackend := f.router.route.Binding.Backend
			data := f.leaf(t, tc.edit)
			if tc.digest {
				digest := sha256.Sum256(data)
				data = digest[:]
			}
			content := tc.content
			if content == "" {
				content = "application/vnd.regalia.x509-tbs"
			}
			if tc.pin != "" {
				f.router.route.Binding.PublicFingerprint = f.router.route.Binding.PublicKeySHA256
				f.router.route.Binding.PublicKeySHA256 = tc.pin
				if tc.pin == "absent" {
					f.router.route.Binding.PublicKeySHA256 = ""
				}
			}
			if tc.backend != "" {
				f.router.route.Binding.Backend = tc.backend
			}
			refused := f.request(data, content)
			result, err := f.coordinator.Execute(context.Background(), refused)
			x509AssertCoordinatorFailure(t, result, err, "DENIED", http.StatusForbidden, false)
			if f.hardware.calls != 0 || len(f.auditor.drafts) != 1 || f.auditor.drafts[0].Decision != "deny" {
				t.Fatal("semantic refusal reached hardware or lost its deny audit")
			}
			// A semantic refusal must consume neither valid issuance capacity nor its nonce.
			f.router.route.Binding.PublicKeySHA256 = originalPin
			f.router.route.Binding.Backend = originalBackend
			valid := f.request(f.leaf(t, nil), "application/vnd.regalia.x509-tbs")
			valid.Context.Nonce = refused.Context.Nonce
			if _, err := f.coordinator.Execute(context.Background(), valid); err != nil || f.hardware.calls != 1 {
				t.Fatal("profile denial consumed issuance capacity", err)
			}
		})
	}
}

func TestCoordinatorX509WrongIssuerRefusedWithoutSpendingCapacity(t *testing.T) {
	f := newX509CoordinatorFixture(t)
	originalIssuer, originalKey := f.issuer, f.issuerKey
	otherKey := x509CoordinatorKey(t)
	otherTemplate := &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "synthetic-other-issuer"}, NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(40 * time.Minute), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	f.issuer = x509CoordinatorCertificate(t, otherTemplate, otherTemplate, otherKey, otherKey)
	f.issuerKey = otherKey
	wrongIssuer := f.leaf(t, nil)
	f.issuer, f.issuerKey = originalIssuer, originalKey
	result, err := f.coordinator.Execute(context.Background(), f.request(wrongIssuer, "application/vnd.regalia.x509-tbs"))
	x509AssertCoordinatorFailure(t, result, err, "DENIED", http.StatusForbidden, false)
	if f.hardware.calls != 0 {
		t.Fatal("a certificate for another issuer reached the token")
	}
	if _, err := f.coordinator.Execute(context.Background(), f.request(f.leaf(t, nil), "application/vnd.regalia.x509-tbs")); err != nil || f.hardware.calls != 1 {
		t.Fatal("issuer denial consumed valid issuance capacity", err)
	}
}

func x509AssertCoordinatorFailure(t *testing.T, result api.Result, err error, code string, status int, retryable bool) {
	t.Helper()
	var failure *api.Failure
	if len(result.Data) != 0 || !errors.As(err, &failure) || failure.Code != code || failure.Status != status || failure.Retryable != retryable {
		t.Fatal("incorrect terminal signing failure", err)
	}
}

func TestCoordinatorX509DurableBudgetsSurvivePolicyRevisionAndKeepCRLReserve(t *testing.T) {
	f := newX509CoordinatorFixture(t)
	if _, err := f.coordinator.Execute(context.Background(), f.request(f.leaf(t, nil), "application/vnd.regalia.x509-tbs")); err != nil {
		t.Fatal(err)
	}
	if err := f.state.Close(); err != nil {
		t.Fatal(err)
	}
	f.profile.ID = "synthetic-issuing-profile-v2"
	f.policyID = "synthetic-pki-policy-v2"
	f.open(t)
	result, err := f.coordinator.Execute(context.Background(), f.request(f.leaf(t, nil), "application/vnd.regalia.x509-tbs"))
	x509AssertCoordinatorFailure(t, result, err, "RESOURCE_EXHAUSTED", http.StatusTooManyRequests, false)
	if f.hardware.calls != 1 {
		t.Fatal("restart or profile/policy revision restored issuance capacity")
	}
	if _, err := f.coordinator.Execute(context.Background(), f.request(f.crl(t), "application/vnd.regalia.x509-tbs")); err != nil || f.hardware.calls != 2 {
		t.Fatal("exhausted leaf capacity blocked the durable CRL reserve", err)
	}
	result, err = f.coordinator.Execute(context.Background(), f.request(f.crl(t), "application/vnd.regalia.x509-tbs"))
	x509AssertCoordinatorFailure(t, result, err, "RESOURCE_EXHAUSTED", http.StatusTooManyRequests, false)
	if f.hardware.calls != 2 {
		t.Fatal("CRL reserve is unbounded")
	}
}

func TestCoordinatorX509IndeterminateExecutionAndAuditFailureKeepDurableReservation(t *testing.T) {
	for _, mode := range []string{"pre-audit", "backend"} {
		t.Run(mode, func(t *testing.T) {
			f := newX509CoordinatorFixture(t)
			if mode == "pre-audit" {
				f.auditor.err = audit.ErrSinkUnavailable
			} else {
				f.hardware.err = errors.New("synthetic indeterminate token completion")
			}
			result, err := f.coordinator.Execute(context.Background(), f.request(f.leaf(t, nil), "application/vnd.regalia.x509-tbs"))
			if err == nil || len(result.Data) != 0 || (mode == "pre-audit" && f.hardware.calls != 0) || (mode == "backend" && f.hardware.calls != 1) {
				t.Fatal("failed signing attempt released output or reached the wrong boundary")
			}
			calls := f.hardware.calls
			f.state.Close()
			f.auditor.err, f.hardware.err = nil, nil
			f.open(t)
			result, err = f.coordinator.Execute(context.Background(), f.request(f.leaf(t, nil), "application/vnd.regalia.x509-tbs"))
			x509AssertCoordinatorFailure(t, result, err, "RESOURCE_EXHAUSTED", http.StatusTooManyRequests, false)
			if f.hardware.calls != calls {
				t.Fatal("failed or indeterminate completion refunded the durable signing reservation")
			}
		})
	}
}

type x509AcceptingAuditSink struct{}

func (x509AcceptingAuditSink) Send(context.Context, audit.Event) error { return nil }
func (x509AcceptingAuditSink) Ready(context.Context) bool              { return true }

type x509MutationAudit struct {
	*fakeAudit
	source []byte
}

func (sink x509MutationAudit) Record(ctx context.Context, draft audit.Draft, requireRemote bool) error {
	err := sink.fakeAudit.Record(ctx, draft, requireRemote)
	if err == nil && draft.Outcome == "authorized" {
		// Mutate the caller's buffer after inspection and reservation but before
		// hardware dispatch. The coordinator must already own its inspected bytes.
		clear(sink.source)
	}
	return err
}

func TestCoordinatorX509InspectedBytesCannotChangeBeforeHardware(t *testing.T) {
	f := newX509CoordinatorFixture(t)
	request := f.request(f.leaf(t, nil), "application/vnd.regalia.x509-tbs")
	digest := sha256.Sum256(request.Data)
	f.coordinator.audit = x509MutationAudit{fakeAudit: f.auditor, source: request.Data}
	if _, err := f.coordinator.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request.Data, make([]byte, len(request.Data))) || !bytes.Equal(f.hardware.data, digest[:]) {
		t.Fatal("caller mutation changed the bytes signed after successful inspection")
	}
	if len(f.auditor.drafts) != 2 || f.auditor.drafts[1].PayloadDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatal("caller mutation broke audit/signature payload agreement")
	}
}

func TestCoordinatorX509IntentIsDurableAndProtectedByJournalHash(t *testing.T) {
	f := newX509CoordinatorFixture(t)
	path := filepath.Join(t.TempDir(), "x509-audit.jsonl")
	// This sink acknowledges in process. It tests the real recorder's durable
	// journal and hash binding, without claiming an off-host transport drill.
	recorder, err := audit.Open(path, x509AcceptingAuditSink{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { recorder.Close() })
	f.coordinator.audit = recorder
	data := f.leaf(t, nil)
	request := f.request(data, "application/vnd.regalia.x509-tbs")
	if _, err = f.coordinator.Execute(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if err = recorder.Close(); err != nil {
		t.Fatal(err)
	}
	events, err := audit.VerifyIntegrity(path)
	if err != nil || len(events) != 2 {
		t.Fatal("signing intent journal did not verify", err)
	}
	digest := sha256.Sum256(data)
	for _, event := range events {
		if event.RequestID != request.RequestID || event.X509ProfileID != f.profile.ID || event.PayloadDigest != "sha256:"+hex.EncodeToString(digest[:]) || event.ArtifactKind != "certificate" || event.KeyFingerprint != f.router.route.Binding.PublicKeySHA256 {
			t.Fatal("durable audit lost the inspected signing intent")
		}
	}
	if events[0].Outcome != "authorized" || events[1].Outcome != "success" {
		t.Fatal("durable signing intent is not correlated across authorization and terminal success")
	}
	events[0].PayloadDigest = "sha256:" + string(bytes.Repeat([]byte{'f'}, 64))
	var tampered bytes.Buffer
	for _, event := range events {
		if err = json.NewEncoder(&tampered).Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	tamperedPath := filepath.Join(t.TempDir(), "tampered-audit.jsonl")
	if err = os.WriteFile(tamperedPath, tampered.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = audit.Verify(tamperedPath); err == nil {
		t.Fatal("payload digest tampering escaped the journal hash chain")
	}
}
