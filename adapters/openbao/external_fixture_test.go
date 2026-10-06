package openbaopoc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/executor"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/operations"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

type softwareSigning struct{ key crypto.Signer }

func (s softwareSigning) Execute(ctx context.Context, r registry.Route, op, format, content string, data, aad []byte) ([]byte, string, error) {
	if ctx.Err() != nil || op != "sign" || format != "" || content != "application/vnd.regalia.digest" || len(aad) != 0 {
		return nil, "", backend.ErrUnavailable
	}
	var hash crypto.Hash
	switch r.Algorithm {
	case "p256":
		hash = crypto.SHA256
	case "p384":
		hash = crypto.SHA384
	case "ed25519":
	case "rsa2048", "rsa3072", "rsa4096":
		found := false
		for h, prefix := range rsaDigestPrefix {
			if len(data) == len(prefix)+h.Size() && bytes.Equal(data[:len(prefix)], prefix) {
				hash = h
				data = data[len(prefix):]
				found = true
				break
			}
		}
		if !found {
			return nil, "", backend.ErrUnavailable
		}
	default:
		return nil, "", backend.ErrUnavailable
	}
	sig, err := s.key.Sign(rand.Reader, data, hash)
	if err != nil {
		return nil, "", err
	}
	if public, ok := s.key.Public().(*ecdsa.PublicKey); ok {
		// The fake hardware exposes the same fixed-width r||s as the KMS API.
		var values struct{ R, S *big.Int }
		if rest, e := asn1.Unmarshal(sig, &values); e != nil || len(rest) != 0 {
			return nil, "", backend.ErrUnavailable
		}
		width := (public.Params().BitSize + 7) / 8
		sig = make([]byte, width*2)
		values.R.FillBytes(sig[:width])
		values.S.FillBytes(sig[width:])
	}
	return sig, "application/octet-stream", nil
}
func (softwareSigning) Healthy(context.Context, registry.Binding) bool { return true }
func (softwareSigning) Ready(context.Context) bool                     { return true }

type signingFixture struct {
	*kmsFixture
	key             crypto.Signer
	keyConfig       kms.ConfigMap
	profile         *policy.X509Policy
	policyStatePath string
	auditPath       string
	artifacts       [][]byte
}

func newSigningFixture(t *testing.T, algorithm, hashName string, key crypto.Signer) *signingFixture {
	return newSigningFixtureWith(t, algorithm, hashName, key, softwareSigning{key}, false)
}

func newSigningFixtureWith(t *testing.T, algorithm, hashName string, key crypto.Signer, provider backend.Provider, ca bool) *signingFixture {
	return newSigningFixtureWithSink(t, algorithm, hashName, key, provider, ca, nil)
}

func newSigningFixtureWithSink(t *testing.T, algorithm, hashName string, key crypto.Signer, provider backend.Provider, ca bool, externalSink audit.Sink) *signingFixture {
	t.Helper()
	pki := newFixturePKI(t)
	objectID, purpose, content, principal, usage := "poc-signing-key", "openbao-transit", "application/vnd.regalia.digest", "spiffe://regalia/workload/openbao-keys-poc", "signing"
	if ca {
		objectID, purpose, content, principal, usage = "poc-pki-ca", "openbao-pki-poc", "application/vnd.regalia.x509-tbs", "spiffe://regalia/workload/openbao-ca-poc", "x509-ca"
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(spki)
	hardware, err := backend.New(map[string]backend.Provider{"nitrokey-pkcs11": provider, "yubikey-openpgp": provider})
	if err != nil {
		t.Fatal(err)
	}
	backendName := "nitrokey-pkcs11"
	if algorithm == "ed25519" {
		backendName = "yubikey-openpgp"
	}
	manifest := map[string]any{"schema_version": 1, "manifest_id": "synthetic-signing", "generated_at": "2026-10-03T00:00:00Z", "objects": []any{map[string]any{
		"id": objectID, "name": "Synthetic signing fixture", "kind": "asymmetric-key", "classification": "restricted", "environment": "development", "owner": "fixture", "purpose": purpose, "custody": "direct-hardware", "algorithm": algorithm, "operations": []string{"sign"}, "policy_id": "poc-transit", "bindings": []any{map[string]any{"site": "poc-site", "backend": backendName, "device_id": "software-signing", "device_serial": "synthetic", "devaut_fingerprint": "sha256:" + strings.Repeat("a", 64), "object_id": "02", "public_fingerprint": "sha256:" + hex.EncodeToString(digest[:]), "state": "active", "pin_policy": "once", "touch_policy": "never"}}, "recovery": map[string]any{}, "rotation": map[string]any{}, "migration": map[string]any{}, "verification": map[string]string{"status": "verified"}}}}
	if backendName == "nitrokey-pkcs11" {
		entry := manifest["objects"].([]any)[0].(map[string]any)["bindings"].([]any)[0].(map[string]any)
		delete(entry, "pin_policy")
		delete(entry, "touch_policy")
		if ca {
			entry["public_key_sha256"] = "sha256:" + hex.EncodeToString(digest[:])
		}
	}
	encoded, _ := json.Marshal(manifest)
	reg, err := registry.Load(bytes.NewReader(encoded), "poc-site", hardware)
	if err != nil {
		t.Fatal(err)
	}
	grants := `{"schema_version":1,"principals":[{"uri":"spiffe://regalia/workload/openbao-keys-poc","grants":[{"objects":["poc-signing-key"],"operations":["sign"],"environments":["development"]}]}]}`
	grants = strings.ReplaceAll(strings.ReplaceAll(grants, "poc-signing-key", objectID), "spiffe://regalia/workload/openbao-keys-poc", principal)
	rbac, err := auth.LoadPolicy(strings.NewReader(grants))
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(t.TempDir(), "sign-state.jsonl")
	state, err := policy.OpenFileState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Close() })
	maxPayload := int64(1024)
	if ca {
		maxPayload = 32 << 10
	}
	var profile *policy.X509Policy
	if ca {
		definition, ok := provider.(interface{ PKIProfile() *policy.X509Policy })
		if !ok {
			t.Fatal("CA fixture requires an explicit server-owned profile")
		}
		profile = definition.PKIProfile()
	}
	semantic, err := policy.New([]policy.Policy{{ID: "poc-transit", ObjectID: objectID, Purpose: purpose, Environment: "development", Operation: "sign", Algorithm: algorithm, ContentTypes: []string{content}, MaxPayloadBytes: maxPayload, MaxFuture: 2 * time.Minute, X509: profile}}, state, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	sink := &fixtureAudit{}
	var shippingSink audit.Sink = sink
	if externalSink != nil {
		shippingSink = &pocCollectorObserver{sink: externalSink, observer: sink}
	}
	auditPath := filepath.Join(t.TempDir(), "sign-audit.jsonl")
	recorder, err := audit.Open(auditPath, shippingSink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { recorder.Close() })
	coordinator, err := operations.New(rbac, reg, semantic, recorder, executor.New(1, 5*time.Second), hardware, "sha256:synthetic-transit", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.NewAuthenticator("spiffe://regalia/", nil, time.Now, time.Minute).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health/ready" {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(200)
			return
		}
		api.NewHandler(coordinator).ServeHTTP(w, r)
	}))
	f := &kmsFixture{handler: handler, pki: pki, audit: sink, t: t, hardware: hardware}
	f.start()
	for _, c := range []map[string]string{pki.config, pki.keysConfig, pki.caConfig, pki.strangerConfig} {
		c["kms_url"] = f.server.URL
	}
	t.Cleanup(func() { f.server.Close() })
	return &signingFixture{kmsFixture: f, key: key, keyConfig: kms.ConfigMap{"object_id": objectID, "purpose": purpose, "usage": usage, "algorithm": algorithm, "hash_algorithm": hashName, "public_key_sha256": "sha256:" + hex.EncodeToString(digest[:]), "public_key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))}, profile: profile, policyStatePath: statePath, auditPath: auditPath}
}

func externalProviderConfig(c map[string]string) kms.ConfigMap {
	native := nativeFixtureConfig(c)
	delete(native, "object_id")
	delete(native, "kms_purpose")
	result := kms.ConfigMap{}
	for k, v := range native {
		result[k] = v
	}
	return result
}
