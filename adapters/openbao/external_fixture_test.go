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
	key       crypto.Signer
	keyConfig kms.ConfigMap
}

func newSigningFixture(t *testing.T, algorithm, hashName string, key crypto.Signer) *signingFixture {
	t.Helper()
	pki := newFixturePKI(t)
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(spki)
	hardware, err := backend.New(map[string]backend.Provider{"nitrokey-pkcs11": softwareSigning{key}, "yubikey-openpgp": softwareSigning{key}})
	if err != nil {
		t.Fatal(err)
	}
	backendName := "nitrokey-pkcs11"
	if algorithm == "ed25519" {
		backendName = "yubikey-openpgp"
	}
	manifest := map[string]any{"schema_version": 1, "manifest_id": "synthetic-signing", "generated_at": "2026-10-03T00:00:00Z", "objects": []any{map[string]any{
		"id": "poc-signing-key", "name": "Synthetic Transit key", "kind": "asymmetric-key", "classification": "restricted", "environment": "development", "owner": "fixture", "purpose": "openbao-transit", "custody": "direct-hardware", "algorithm": algorithm, "operations": []string{"sign"}, "policy_id": "poc-transit", "bindings": []any{map[string]any{"site": "poc-site", "backend": backendName, "device_id": "software-signing", "device_serial": "synthetic", "devaut_fingerprint": "sha256:" + strings.Repeat("a", 64), "object_id": "02", "public_fingerprint": "sha256:" + hex.EncodeToString(digest[:]), "state": "active", "pin_policy": "once", "touch_policy": "never"}}, "recovery": map[string]any{}, "rotation": map[string]any{}, "migration": map[string]any{}, "verification": map[string]string{"status": "verified"}}}}
	if backendName == "nitrokey-pkcs11" {
		entry := manifest["objects"].([]any)[0].(map[string]any)["bindings"].([]any)[0].(map[string]any)
		delete(entry, "pin_policy")
		delete(entry, "touch_policy")
	}
	encoded, _ := json.Marshal(manifest)
	reg, err := registry.Load(bytes.NewReader(encoded), "poc-site", hardware)
	if err != nil {
		t.Fatal(err)
	}
	rbac, err := auth.LoadPolicy(strings.NewReader(`{"schema_version":1,"principals":[{"uri":"spiffe://regalia/workload/openbao-keys-poc","grants":[{"objects":["poc-signing-key"],"operations":["sign"],"environments":["development"]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	state, err := policy.OpenFileState(filepath.Join(t.TempDir(), "sign-state.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { state.Close() })
	semantic, err := policy.New([]policy.Policy{{ID: "poc-transit", ObjectID: "poc-signing-key", Purpose: "openbao-transit", Environment: "development", Operation: "sign", Algorithm: algorithm, ContentTypes: []string{"application/vnd.regalia.digest"}, MaxPayloadBytes: 1024, MaxFuture: 2 * time.Minute}}, state, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	sink := &fixtureAudit{}
	recorder, err := audit.Open(filepath.Join(t.TempDir(), "sign-audit.jsonl"), sink)
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
	for _, c := range []map[string]string{pki.config, pki.keysConfig, pki.strangerConfig} {
		c["kms_url"] = f.server.URL
	}
	t.Cleanup(func() { f.server.Close() })
	return &signingFixture{f, key, kms.ConfigMap{"object_id": "poc-signing-key", "purpose": "openbao-transit", "usage": "signing", "algorithm": algorithm, "hash_algorithm": hashName, "public_key_sha256": "sha256:" + hex.EncodeToString(digest[:]), "public_key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}))}}
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
