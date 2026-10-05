package openbaopoc

import (
	"context"
	"crypto"
	"crypto/rsa"
	"testing"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

func TestPKIPoCRefusesOpaqueInputsAndProductionFactory(t *testing.T) {
	f := newSigningFixture(t, "p256", "sha256", testSigner(t, "p256"))
	provider := NewExternalPKIPoC()
	if err := provider.Open(context.Background(), &kms.OpenOptions{ConfigMap: externalProviderConfig(f.pki.keysConfig)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { provider.Close(context.Background()) })
	config := kms.ConfigMap{}
	for name, value := range f.keyConfig {
		config[name] = value
	}
	config["usage"], config["object_id"], config["purpose"] = "x509-ca", "poc-pki-ca", "openbao-pki-poc"
	key, err := provider.GetKey(context.Background(), &kms.KeyOptions{ConfigMap: config})
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []*kms.SignOptions{nil,
		{Data: make([]byte, 32), Prehashed: true, SignerOpts: crypto.SHA256},
		{Data: []byte{1}, SignerOpts: crypto.SHA384},
		{Data: make([]byte, (32<<10)+1), SignerOpts: crypto.SHA256},
		{Data: []byte{1}, SignerOpts: &rsa.PSSOptions{Hash: crypto.SHA256}},
	} {
		if _, err := key.Sign(context.Background(), opts); err == nil {
			t.Fatal("invalid CA request reached signing")
		}
	}
	if f.audit.successful("sign") != 0 {
		t.Fatal("invalid CA requests invoked KMS")
	}
	if _, err := provider.ExternalKMS.GetKey(context.Background(), &kms.KeyOptions{ConfigMap: config}); err == nil {
		t.Fatal("normal provider accepted a CA mapping")
	}
	config["purpose"] = "openbao-transit"
	if _, err := provider.GetKey(context.Background(), &kms.KeyOptions{ConfigMap: config}); err == nil {
		t.Fatal("PKI experiment accepted another purpose")
	}
}
