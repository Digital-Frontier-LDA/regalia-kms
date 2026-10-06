package openbaopoc

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
)

func pocData(t *testing.T, response []byte) map[string]json.RawMessage {
	t.Helper()
	var envelope struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if json.Unmarshal(response, &envelope) != nil || envelope.Data == nil {
		t.Fatal("missing synthetic response data")
	}
	return envelope.Data
}

func pocString(t *testing.T, data map[string]json.RawMessage, field string) string {
	t.Helper()
	var value string
	if json.Unmarshal(data[field], &value) != nil || value == "" {
		t.Fatal("missing synthetic response field", field)
	}
	return value
}

func pocEvidence(t *testing.T, f *signingFixture, backend *pocDaemonCA, kind string, raw []byte) {
	t.Helper()
	if len(raw) <= sha256.Size {
		t.Fatal("expected complete unhashed signing input")
	}
	want := sha256.Sum256(raw)
	token := false
	for _, record := range backend.snapshot() {
		token = token || record.Allowed && record.Kind == "digest" && record.Digest == want
	}
	if !token {
		t.Fatal("signed artifact has no matching digest-only token call", kind)
	}
	digest := "sha256:" + hex.EncodeToString(want[:])
	events := f.audit.snapshotEvents()
	for _, event := range events {
		if event.Outcome != "success" || event.X509ProfileID != f.profile.ID || event.PayloadDigest != digest || event.ArtifactKind != kind || event.KeyFingerprint != f.keyConfig["public_key_sha256"] {
			continue
		}
		authorized := false
		for _, first := range events {
			authorized = authorized || first.Outcome == "authorized" && first.RequestID == event.RequestID && first.X509ProfileID == event.X509ProfileID && first.PayloadDigest == digest && first.ArtifactKind == kind && first.KeyFingerprint == event.KeyFingerprint
		}
		if !authorized {
			t.Fatal("signature missing correlated server-owned authorization intent")
		}
		pocDurableIntent(t, f, event, kind)
		return
	}
	t.Fatal("signed artifact missing server-owned audit intent", kind)
}

func pocLeaf(t *testing.T, encoded string, root, issuer *x509.Certificate, f *signingFixture, backend *pocDaemonCA) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(encoded))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("missing leaf certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal("invalid synthetic leaf")
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	intermediates.AddCert(issuer)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: "web.svc.poc.invalid"}); err != nil {
		t.Fatal("synthetic leaf chain failed", err)
	}
	pocEvidence(t, f, backend, "certificate", leaf.RawTBSCertificate)
	f.artifacts = append(f.artifacts, append([]byte(nil), leaf.Raw...))
	return leaf
}

func TestOpenBao271PKIInspectedIssuanceAndCRL(t *testing.T) {
	binary, dir, _, digest := baoTestEnvironmentFor(t, "openbao-plugin-kms-regalia-pki-poc")
	seal := newKMSFixtureMode(t, true)
	address := freeAddress(t)
	config := baoConfig(t, dir, address, freeAddress(t), hex.EncodeToString(digest[:]), nativeFixtureConfig(seal.pki.config))
	b := baoAPI{base: "http://" + address, client: &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}}
	p := startBao(t, binary, config, dir)
	b.wait(t, false, true, p)
	share := b.initialize(t)
	b.seedSyntheticKV(t)
	caKey := testSigner(t, "p256").(*ecdsa.PrivateKey)
	issuer, root := pocIssuerChain(t, caKey)
	backend := &pocDaemonCA{key: caKey, issuer: issuer, leafCap: 3, crlCap: 16}
	collector := newPOCAuditCollector(t)
	f := newSigningFixtureWithSink(t, "p256", "sha256", caKey, backend, true, collector.sink)
	provider := externalProviderConfig(f.pki.caConfig)
	provider["plugin"] = "regalia"
	providerPath := "/v1/sys/external-keys/configs/pki"
	keyPath := providerPath + "/keys/ca"
	b.must(t, http.MethodPost, providerPath, provider)
	b.must(t, http.MethodPost, keyPath, f.keyConfig)
	if len(backend.snapshot()) != 0 {
		t.Fatal("CA mapping verification signed")
	}
	b.must(t, http.MethodPost, "/v1/sys/mounts/pki", map[string]string{"type": "pki"})
	status, _, err := b.call(http.MethodPost, "/v1/pki/keys/generate/kms", map[string]string{"external_key_ref": "pki:ca"})
	if err != nil || status < 400 || len(backend.snapshot()) != 0 {
		t.Fatal("CA mapping usable without mount grant", status)
	}
	b.must(t, http.MethodPost, keyPath+"/grants/pki", map[string]any{})
	b.must(t, http.MethodPost, "/v1/sys/mounts/ungranted", map[string]string{"type": "pki"})
	status, _, err = b.call(http.MethodPost, "/v1/ungranted/keys/generate/kms", map[string]string{"external_key_ref": "pki:ca"})
	if err != nil || status < 400 || len(backend.snapshot()) != 0 {
		t.Fatal("PKI mapping leaked to another mount")
	}
	b.must(t, http.MethodPost, "/v1/sys/namespaces/isolated", map[string]any{})
	isolated := b
	isolated.namespace = "isolated"
	isolated.must(t, http.MethodPost, "/v1/sys/mounts/pki", map[string]string{"type": "pki"})
	status, _, err = isolated.call(http.MethodPost, "/v1/pki/keys/generate/kms", map[string]string{"external_key_ref": "pki:ca"})
	if err != nil || status < 400 || len(backend.snapshot()) != 0 {
		t.Fatal("PKI mapping leaked across namespace")
	}
	b.must(t, http.MethodPost, "/v1/pki/keys/generate/kms", map[string]string{"external_key_ref": "pki:ca", "key_name": "poc-ca"})
	// The offline root private key is never mapped or imported. Only certificates
	// are imported, matching the software token's independently pinned SPKI.
	b.must(t, http.MethodPost, "/v1/pki/config/crl", map[string]any{"expiry": "10m", "disable": true})
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))
	b.must(t, http.MethodPost, "/v1/pki/intermediate/set-signed", map[string]string{"certificate": chain})
	b.must(t, http.MethodPost, "/v1/pki/issuer/default", map[string]string{"usage": "issuing-certificates,crl-signing"})
	b.must(t, http.MethodPost, "/v1/pki/config/crl", map[string]any{"expiry": "10m", "disable": false})
	role := map[string]any{"allowed_domains": []string{"svc.poc.invalid"}, "allow_subdomains": true, "key_type": "ec", "key_bits": 256, "key_usage": []string{"DigitalSignature"}, "server_flag": true, "client_flag": false, "ttl": "5m", "max_ttl": "10m", "not_before_duration": "30s", "basic_constraints_valid_for_non_ca": true}
	b.must(t, http.MethodPost, "/v1/pki/roles/poc", role)
	response := pocData(t, b.must(t, http.MethodPost, "/v1/pki/issue/poc", map[string]string{"common_name": "web.svc.poc.invalid"}))
	leaf := pocLeaf(t, pocString(t, response, "certificate"), root, issuer, f, backend)
	pocACME(t, b, root, issuer, f, backend)
	// The API and both ACME orders consumed all three leaf reservations.
	beforeExhaustion, signs := len(backend.snapshot()), f.audit.successful("sign")
	auditBefore := len(f.audit.snapshotEvents())
	status, _, err = b.call(http.MethodPost, "/v1/pki/issue/poc", map[string]string{"common_name": "web.svc.poc.invalid"})
	if err != nil || status < 400 || len(backend.snapshot()) != beforeExhaustion || f.audit.successful("sign") != signs {
		t.Fatal("leaf budget not exhausted before token execution")
	}
	denied := pocWaitCollectorAudit(t, f, auditBefore, func(event audit.Event) bool {
		return event.Decision == "deny" && event.ArtifactKind == "certificate" && event.X509ProfileID == f.profile.ID && strings.HasSuffix(event.Outcome, ":quota")
	})
	if !denied {
		t.Fatal("exhausted issuance missing durable-policy quota denial")
	}
	// Exhausted leaf issuance must still allow a bounded CRL update and revocation.
	b.must(t, http.MethodPost, "/v1/pki/revoke", map[string]string{"serial_number": pocString(t, response, "serial_number")})
	b.must(t, http.MethodGet, "/v1/pki/crl/rotate", nil)
	status, crlDER, err := b.call(http.MethodGet, "/v1/pki/crl", nil)
	crl, parseErr := x509.ParseRevocationList(crlDER)
	if err != nil || status != 200 || parseErr != nil || crl.CheckSignatureFrom(issuer) != nil {
		t.Fatal("invalid KMS-signed CRL", status)
	}
	pocEvidence(t, f, backend, "crl", crl.RawTBSRevocationList)
	f.artifacts = append(f.artifacts, append([]byte(nil), crl.Raw...))
	found := false
	for _, entry := range crl.RevokedCertificateEntries {
		found = found || entry.SerialNumber.Cmp(leaf.SerialNumber) == 0
	}
	if !found {
		t.Fatal("revoked leaf absent from CRL")
	}
	pocBaoRefusals(t, b, f, backend, role)
	before := len(backend.snapshot())
	b.must(t, http.MethodDelete, keyPath+"/grants/pki", nil)
	status, _, err = b.call(http.MethodPost, "/v1/pki/issue/poc", map[string]string{"common_name": "web.svc.poc.invalid"})
	if err != nil || status < 400 || len(backend.snapshot()) != before {
		t.Fatal("revoked PKI mount grant still reached token")
	}
	b.assertValue(t)
	pocReconcileBaoArtifacts(t, f, collector)
	p.stop(t)
	assertBaoArtifactsClean(t, dir, filepath.Join(dir, "openbao-plugin-kms-regalia-poc"), b.token, share)
	t.Log("Real OpenBao PKI: read-only CA mapping, exact mount grant and revocation, externally held intermediate, server-owned full-byte inspected leaf and CRL signatures, durable quotas and audited intent, verified chain/revoked serial after leaf budget exhaustion, EAB-gated DNS-01 ACME issuance and renewal, HTTPS certificate rotation and unsafe issuance refusals; software fixture only.")
}

func pocBaoRefusals(t *testing.T, b baoAPI, f *signingFixture, backend *pocDaemonCA, role map[string]any) {
	t.Helper()
	permissive := map[string]any{}
	for name, value := range role {
		permissive[name] = value
	}
	permissive["allow_any_name"], permissive["max_ttl"] = true, "30m"
	b.must(t, http.MethodPost, "/v1/pki/roles/permissive", permissive)
	for _, input := range []map[string]string{
		{"common_name": "outside.invalid"},
		{"common_name": "web.svc.poc.invalid", "ttl": "20m"},
	} {
		before, signs := len(backend.snapshot()), f.audit.successful("sign")
		auditBefore := len(f.audit.snapshotEvents())
		status, _, err := b.call(http.MethodPost, "/v1/pki/issue/permissive", input)
		if err != nil || status < 400 || len(backend.snapshot()) != before || f.audit.successful("sign") != signs {
			t.Fatal("permissive OpenBao role bypassed server-owned KMS profile", status)
		}
		denied := pocWaitCollectorAudit(t, f, auditBefore, func(event audit.Event) bool {
			return event.Decision == "deny" && strings.Contains(event.Outcome, "x509-")
		})
		if !denied {
			t.Fatal("unsafe OpenBao issuance did not reach server-owned profile denial")
		}
	}
	// OpenBao or the inspected KMS may refuse subordinate CA issuance first;
	// the direct KMS refusal test separately proves the server-owned CA boundary.
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "subca.svc.poc.invalid"}}, testSigner(t, "p256"))
	if err != nil {
		t.Fatal(err)
	}
	signs := f.audit.successful("sign")
	status, _, err := b.call(http.MethodPost, "/v1/pki/root/sign-intermediate", map[string]any{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "common_name": "subca.svc.poc.invalid", "ttl": "5m", "max_path_length": 0})
	if err != nil || status < 400 || f.audit.successful("sign") != signs {
		t.Fatal("intermediate issued under leaf-only CA profile")
	}
}
