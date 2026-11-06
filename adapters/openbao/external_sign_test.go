package openbaopoc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

func testSigner(t *testing.T, algorithm string) crypto.Signer {
	t.Helper()
	var key crypto.Signer
	var err error
	switch algorithm {
	case "p256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	default:
		key, err = rsa.GenerateKey(rand.Reader, map[string]int{"rsa2048": 2048, "rsa3072": 3072, "rsa4096": 4096}[algorithm])
	}
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func configuredExternal(t *testing.T, f *signingFixture) (*ExternalKMS, kms.Key) {
	t.Helper()
	p := NewExternal()
	if err := p.Open(context.Background(), &kms.OpenOptions{ConfigMap: externalProviderConfig(f.pki.keysConfig)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close(context.Background()) })
	k, err := p.GetKey(context.Background(), &kms.KeyOptions{ConfigMap: f.keyConfig})
	if err != nil {
		t.Fatal(err)
	}
	return p, k
}

func TestExternalSigningAlgorithmsAndPins(t *testing.T) {
	for _, tc := range []struct {
		algorithm, hashName string
		hash                crypto.Hash
	}{{"p256", "sha256", crypto.SHA256}, {"p384", "sha384", crypto.SHA384}, {"rsa2048", "sha256", crypto.SHA256}, {"rsa3072", "sha384", crypto.SHA384}, {"rsa4096", "sha512", crypto.SHA512}, {"ed25519", "none", 0}} {
		t.Run(tc.algorithm, func(t *testing.T) {
			f := newSigningFixture(t, tc.algorithm, tc.hashName, testSigner(t, tc.algorithm))
			p, k := configuredExternal(t, f)
			ctx := context.Background()
			if f.audit.successful("sign") != 0 {
				t.Fatal("configuration verification signed")
			}
			for _, prehashed := range []bool{false, true} {
				data := []byte("synthetic Transit message")
				if prehashed && tc.hash != 0 {
					h := tc.hash.New()
					h.Write(data)
					data = h.Sum(nil)
				}
				sig, err := k.Sign(ctx, &kms.SignOptions{Data: data, Prehashed: prehashed, SignerOpts: tc.hash})
				if err != nil {
					t.Fatal(err)
				}
				if err := k.Verify(ctx, &kms.VerifyOptions{Data: data, Signature: sig, Prehashed: prehashed, SignerOpts: tc.hash}); err != nil {
					t.Fatal("local verification failed", err)
				}
				sig[0] ^= 1
				if !errors.Is(k.Verify(ctx, &kms.VerifyOptions{Data: data, Signature: sig, Prehashed: prehashed, SignerOpts: tc.hash}), kms.ErrInvalidSignature) {
					t.Fatal("tampered signature accepted")
				}
			}
			pub, _ := k.ExportPublic(ctx)
			switch key := pub.(type) {
			case *ecdsa.PublicKey:
				key.X.SetInt64(1)
			case *rsa.PublicKey:
				key.N.SetInt64(1)
			case ed25519.PublicKey:
				key[0] ^= 1
			}
			if _, err := k.Sign(ctx, &kms.SignOptions{Data: []byte{1}, SignerOpts: tc.hash}); err != nil {
				t.Fatal("caller mutated verification pin", err)
			}
			if _, err := k.Encrypt(ctx, &kms.CipherOptions{Data: []byte{1}}); !errors.Is(err, kms.ErrNotImplemented) {
				t.Fatal("external encryption enabled")
			}
			before := f.audit.successful("sign")
			if tc.hash != 0 {
				if _, err := k.Sign(ctx, &kms.SignOptions{Data: []byte{1}, Prehashed: true, SignerOpts: tc.hash}); err == nil {
					t.Fatal("invalid digest accepted")
				}
			}
			if tc.algorithm == "ed25519" {
				if _, err := k.Sign(ctx, &kms.SignOptions{Data: bytes.Repeat([]byte{1}, 1025), SignerOpts: crypto.Hash(0)}); err == nil {
					t.Fatal("oversized Ed25519 accepted")
				}
			}
			if _, err := k.Sign(ctx, &kms.SignOptions{Data: []byte{1}, SignerOpts: &rsa.PSSOptions{Hash: tc.hash}}); err == nil {
				t.Fatal("PSS accepted")
			}
			if f.audit.successful("sign") != before {
				t.Fatal("invalid options reached KMS")
			}
			p.Close(ctx)
			if _, err := k.Sign(ctx, &kms.SignOptions{Data: []byte{1}, SignerOpts: tc.hash}); err == nil {
				t.Fatal("closed provider signed")
			}
		})
	}
}

func TestExternalConfigurationAndIdentitySeparation(t *testing.T) {
	f := newSigningFixture(t, "p256", "sha256", testSigner(t, "p256"))
	p, _ := configuredExternal(t, f)
	ctx := context.Background()
	for _, change := range []struct {
		key   string
		value any
	}{{"usage", "x509-ca"}, {"algorithm", "rsa2048"}, {"hash_algorithm", "sha384"}, {"public_key_sha256", "sha256:wrong"}, {"purpose", "bad purpose"}, {"unknown", "value"}, {"public_key", f.keyConfig["public_key"].(string) + "extra"}, {"object_id", true}} {
		c := kms.ConfigMap{}
		for k, v := range f.keyConfig {
			c[k] = v
		}
		c[change.key] = change.value
		if _, err := p.GetKey(ctx, &kms.KeyOptions{ConfigMap: c}); err == nil {
			t.Fatal("invalid mapping accepted", change.key)
		}
	}
	seal := NewExternal()
	if err := seal.Open(ctx, &kms.OpenOptions{ConfigMap: externalProviderConfig(f.pki.config), AllowEnvironment: true}); err != nil {
		t.Fatal(err)
	}
	defer seal.Close(ctx)
	k, err := seal.GetKey(ctx, &kms.KeyOptions{ConfigMap: f.keyConfig})
	if err != nil {
		t.Fatal(err)
	}
	before := f.audit.successful("sign")
	_, err = k.Sign(ctx, &kms.SignOptions{Data: []byte{1}, SignerOpts: crypto.SHA256})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "DENIED" || f.audit.successful("sign") != before {
		t.Fatal("seal identity acquired signing capability", err)
	}
}
