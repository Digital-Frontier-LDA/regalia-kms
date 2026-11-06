package openbaopoc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"strings"

	"github.com/openbao/go-kms-wrapping/v2/kms"
)

type externalKey struct {
	kms.UnimplementedKey
	provider *ExternalKMS
	client   *versionedClient
	public   crypto.PublicKey
	spki     []byte
	hash     crypto.Hash
}

func (p *ExternalKMS) GetKey(ctx context.Context, opts *kms.KeyOptions) (kms.Key, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.opened || p.closed.Err() != nil || ctx.Err() != nil || opts == nil {
		return nil, errConfig
	}
	// PEM is public material and legitimately contains newlines. Every other
	// setting is a single explicit string; reject weakly typed config values.
	c := make(kms.ConfigMap, len(opts.ConfigMap))
	for k, v := range opts.ConfigMap {
		c[k] = v
	}
	public, ok := c["public_key"].(string)
	delete(c, "public_key")
	if !ok || len(public) > 16<<10 {
		return nil, errConfig
	}
	v, err := strictStrings(c, []string{"object_id", "purpose", "usage", "algorithm", "hash_algorithm", "public_key_sha256"})
	if err != nil || v["usage"] != "signing" || !identifier.MatchString(v["object_id"]) || !identifier.MatchString(v["purpose"]) {
		return nil, errConfig
	}
	block, rest := pem.Decode([]byte(public))
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errConfig
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errConfig
	}
	digest := sha256.Sum256(block.Bytes)
	if v["public_key_sha256"] != "sha256:"+hex.EncodeToString(digest[:]) {
		return nil, errConfig
	}
	var hash crypto.Hash
	switch v["hash_algorithm"] {
	case "sha256":
		hash = crypto.SHA256
	case "sha384":
		hash = crypto.SHA384
	case "sha512":
		hash = crypto.SHA512
	case "none":
	default:
		return nil, errConfig
	}
	valid := false
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		valid = (v["algorithm"] == "p256" && key.Curve == elliptic.P256() && hash == crypto.SHA256) || (v["algorithm"] == "p384" && key.Curve == elliptic.P384() && hash == crypto.SHA384)
	case *rsa.PublicKey:
		bits := map[string]int{"rsa2048": 2048, "rsa3072": 3072, "rsa4096": 4096}[v["algorithm"]]
		valid = bits != 0 && key.N.BitLen() == bits && key.E >= 3 && key.E%2 == 1 && hash != 0
	case ed25519.PublicKey:
		valid = v["algorithm"] == "ed25519" && hash == 0 && len(key) == ed25519.PublicKeySize
	}
	if !valid || strings.ContainsRune(public, 0) {
		return nil, errConfig
	}
	b := binding{ObjectID: v["object_id"], Purpose: v["purpose"], Environment: p.environment}
	return &externalKey{provider: p, client: &versionedClient{base: p.base, http: p.client, binding: b, native: true, logger: p.logger}, public: pub, spki: bytes.Clone(block.Bytes), hash: hash}, nil
}

func (k *externalKey) ExportPublic(ctx context.Context) (crypto.PublicKey, error) {
	call, cancel, err := k.provider.keyContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if call.Err() != nil {
		return nil, contextError(call.Err(), "")
	}
	// Callers may mutate standard-library public key structs; never expose the
	// verification pin itself.
	return x509.ParsePKIXPublicKey(bytes.Clone(k.spki))
}
