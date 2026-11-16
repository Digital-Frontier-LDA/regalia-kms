package openbaopoc

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenBao271ExternalTransitSigningAndGrants(t *testing.T) {
	binary, dir, _, digest := baoTestEnvironmentFor(t, "openbao-plugin-kms-regalia")
	seal := newKMSFixtureMode(t, true)
	address := freeAddress(t)
	config := baoConfig(t, dir, address, freeAddress(t), hex.EncodeToString(digest[:]), nativeFixtureConfig(seal.pki.config))
	b := baoAPI{base: "http://" + address, client: &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}}
	p := startBao(t, binary, config, dir)
	b.wait(t, false, true, p)
	share := b.initialize(t)
	b.seedSyntheticKV(t)
	b.must(t, http.MethodPost, "/v1/sys/mounts/transit", map[string]string{"type": "transit"})
	b.must(t, http.MethodPost, "/v1/sys/mounts/ungranted", map[string]string{"type": "transit"})
	b.must(t, http.MethodPost, "/v1/sys/namespaces/isolated", map[string]any{})
	isolated := b
	isolated.namespace = "isolated"
	isolated.must(t, http.MethodPost, "/v1/sys/mounts/transit", map[string]string{"type": "transit"})
	for _, tc := range []struct {
		algorithm, mappingHash, transitHash string
		hash                                crypto.Hash
	}{
		{"p256", "sha256", "sha2-256", crypto.SHA256}, {"p384", "sha384", "sha2-384", crypto.SHA384},
		{"rsa2048", "sha256", "sha2-256", crypto.SHA256}, {"rsa3072", "sha384", "sha2-384", crypto.SHA384}, {"rsa4096", "sha512", "sha2-512", crypto.SHA512}, {"ed25519", "none", "none", 0},
	} {
		t.Run(tc.algorithm, func(t *testing.T) {
			f := newSigningFixture(t, tc.algorithm, tc.mappingHash, testSigner(t, tc.algorithm))
			provider := externalProviderConfig(f.pki.keysConfig)
			provider["plugin"] = "regalia"
			providerPath := "/v1/sys/external-keys/configs/" + tc.algorithm
			b.must(t, http.MethodPost, providerPath, provider)
			keyPath := providerPath + "/keys/signing"
			b.must(t, http.MethodPost, keyPath, f.keyConfig)
			if f.audit.successful("sign") != 0 {
				t.Fatal("OpenBao default verification signed")
			}
			ref := tc.algorithm + ":signing"
			// Registry mount grants are a separate boundary before KMS authorization.
			status, _, err := b.call(http.MethodPost, "/v1/transit/keys/"+tc.algorithm, map[string]string{"type": "external-key", "external_key_ref": ref})
			if err != nil || status < 400 || status >= 500 {
				t.Fatal("mapping usable without mount grant", status)
			}
			b.must(t, http.MethodPost, keyPath+"/grants/transit", map[string]any{})
			b.must(t, http.MethodPost, "/v1/transit/keys/"+tc.algorithm, map[string]string{"type": "external-key", "external_key_ref": ref})
			status, _, err = b.call(http.MethodPost, "/v1/ungranted/keys/"+tc.algorithm, map[string]string{"type": "external-key", "external_key_ref": ref})
			if err != nil || status < 400 || status >= 500 {
				t.Fatal("grant leaked to another mount", status)
			}
			status, _, err = isolated.call(http.MethodPost, "/v1/transit/keys/"+tc.algorithm, map[string]string{"type": "external-key", "external_key_ref": ref})
			if err != nil || status < 400 || status >= 500 {
				t.Fatal("root mapping leaked across namespace", status)
			}
			for _, prehashed := range []bool{false, true} {
				data := []byte("synthetic OpenBao Transit payload")
				if prehashed && tc.hash != 0 {
					h := tc.hash.New()
					h.Write(data)
					data = h.Sum(nil)
				}
				input := map[string]any{"input": base64.StdEncoding.EncodeToString(data), "hash_algorithm": tc.transitHash, "prehashed": prehashed, "signature_algorithm": "pkcs1v15"}
				response := b.must(t, http.MethodPost, "/v1/transit/sign/"+tc.algorithm, input)
				var signed struct {
					Data struct {
						Signature string `json:"signature"`
					} `json:"data"`
				}
				if json.Unmarshal(response, &signed) != nil || signed.Data.Signature == "" {
					t.Fatal("no Transit signature")
				}
				input["signature"] = signed.Data.Signature
				response = b.must(t, http.MethodPost, "/v1/transit/verify/"+tc.algorithm, input)
				var verified struct {
					Data struct {
						Valid bool `json:"valid"`
					} `json:"data"`
				}
				if json.Unmarshal(response, &verified) != nil || !verified.Data.Valid {
					t.Fatal("Transit signature did not verify")
				}
				input["input"] = base64.StdEncoding.EncodeToString([]byte("different payload"))
				status, response, err = b.call(http.MethodPost, "/v1/transit/verify/"+tc.algorithm, input)
				if err != nil || (status == 200 && (json.Unmarshal(response, &verified) != nil || verified.Data.Valid)) {
					t.Fatal("Transit accepted mismatched payload")
				}
			}
			if f.audit.successful("sign") != 2 {
				t.Fatal("verification consumed KMS signing quota")
			}
			badCA := map[string]any{}
			for k, v := range f.keyConfig {
				badCA[k] = v
			}
			badCA["usage"] = "x509-ca"
			status, _, err = b.call(http.MethodPost, providerPath+"/keys/ca", badCA)
			if err != nil || status < 400 {
				t.Fatal("uninspected CA mapping accepted")
			}
			status, _, err = b.call(http.MethodPost, "/v1/transit/encrypt/"+tc.algorithm, map[string]string{"plaintext": "AQ=="})
			if err != nil || status < 400 {
				t.Fatal("external encryption unexpectedly served")
			}
			b.must(t, http.MethodDelete, keyPath+"/grants/transit", nil)
			status, _, err = b.call(http.MethodPost, "/v1/transit/sign/"+tc.algorithm, map[string]any{"input": "AQ==", "hash_algorithm": tc.transitHash, "signature_algorithm": "pkcs1v15"})
			if err != nil || status < 400 || f.audit.successful("sign") != 2 {
				t.Fatal("revoked mount grant still signed")
			}
			b.must(t, http.MethodDelete, keyPath, nil)
			_, direct := configuredExternal(t, f)
			if _, err := direct.Sign(context.Background(), &kms.SignOptions{Data: []byte{1}, SignerOpts: tc.hash}); err != nil {
				t.Fatal("mapping deletion removed custody key", err)
			}
		})
	}
	b.must(t, http.MethodDelete, "/v1/sys/mounts/transit", nil)
	b.must(t, http.MethodPost, "/v1/sys/mounts/transit", map[string]string{"type": "transit"})
	status, _, err := b.call(http.MethodPost, "/v1/transit/keys/removed", map[string]string{"type": "external-key", "external_key_ref": "p256:signing"})
	if err != nil || status < 400 {
		t.Fatal("disabled/remounted engine regained a deleted mapping")
	}
	b.assertValue(t)
	p.stop(t)
	assertBaoArtifactsClean(t, dir, filepath.Join(dir, "openbao-plugin-kms-regalia-poc"), b.token, share)
	t.Log("Real OpenBao External Keys + Transit: six algorithms, raw/prehashed calls, local verification, exact mount grants/revocation, read-only config verification and CA/encryption refusals passed; software tokens only.")
}
