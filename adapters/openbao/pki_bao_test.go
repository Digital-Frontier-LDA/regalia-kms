package openbaopoc

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"path/filepath"
	"testing"
	"time"
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

func pocEvidence(t *testing.T, backend *pocSoftwareCA, kind string, raw []byte) {
	t.Helper()
	if len(raw) <= sha256.Size {
		t.Fatal("expected complete unhashed signing input")
	}
	want := sha256.Sum256(raw)
	for _, record := range backend.snapshot() {
		if record.Allowed && record.Kind == kind && record.Digest == want {
			return
		}
	}
	t.Fatal("signed artifact has no matching inspected full-byte input", kind)
}

func pocLeaf(t *testing.T, encoded string, root, issuer *x509.Certificate, backend *pocSoftwareCA) *x509.Certificate {
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
	pocEvidence(t, backend, "certificate", leaf.RawTBSCertificate)
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
	backend := &pocSoftwareCA{key: caKey, issuer: issuer, cap: 32}
	f := newSigningFixtureWith(t, "p256", "sha256", caKey, backend, true)
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
	leaf := pocLeaf(t, pocString(t, response, "certificate"), root, issuer, backend)
	b.must(t, http.MethodPost, "/v1/pki/revoke", map[string]string{"serial_number": pocString(t, response, "serial_number")})
	b.must(t, http.MethodGet, "/v1/pki/crl/rotate", nil)
	status, crlDER, err := b.call(http.MethodGet, "/v1/pki/crl", nil)
	crl, parseErr := x509.ParseRevocationList(crlDER)
	if err != nil || status != 200 || parseErr != nil || crl.CheckSignatureFrom(issuer) != nil {
		t.Fatal("invalid KMS-signed CRL", status)
	}
	pocEvidence(t, backend, "crl", crl.RawTBSRevocationList)
	found := false
	for _, entry := range crl.RevokedCertificateEntries {
		found = found || entry.SerialNumber.Cmp(leaf.SerialNumber) == 0
	}
	if !found {
		t.Fatal("revoked leaf absent from CRL")
	}
	pocACME(t, b, root, issuer, backend)
	b.assertValue(t)
	p.stop(t)
	assertBaoArtifactsClean(t, dir, filepath.Join(dir, "openbao-plugin-kms-regalia-poc"), b.token, share)
	t.Log("Real OpenBao PKI: read-only CA mapping, exact mount grant, externally held intermediate, full-byte inspected leaf and CRL signatures, verified chain and revoked serial; software fixture only.")
}
