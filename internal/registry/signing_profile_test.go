package registry

import (
	"strings"
	"testing"
)

// THE SIGNING PROFILE (#432; the owner: the KMS is a blockchain user, not a validator). A secp256k1 key signs as
// cosmos-account unless its manifest says otherwise; cosmos-validator is refused until validator signing (with its
// height and round high-water marks) exists; a profile on any other key is refused, as is an unknown one.
func TestTheSigningProfileOfAKey(t *testing.T) {
	pinned := `,"device_serial":"test-serial","public_key_sha256":"sha256:` + strings.Repeat("c", 64) + `"`
	sibling := `,"device_serial":"sibling-serial","public_key_sha256":"sha256:` + strings.Repeat("e", 64) + `"`
	load := func(algorithm, profile string) (*Registry, error) {
		document := object("wallet-key", "cosmos-transaction", algorithm, "sign",
			nitrokeyBinding("sitea", "local-hsm", pinned)+","+nitrokeyBinding("siteb", "remote-hsm", sibling))
		if profile != "" {
			document = strings.Replace(document, `"verification":`, `"signing_profile":`+profile+`,"verification":`, 1)
		}
		return Load(strings.NewReader(manifest(document)), "sitea", &healthMap{states: map[string]bool{}})
	}
	for _, c := range []struct {
		name, algorithm, profile, want, refused string
	}{
		{"a secp256k1 key with no profile is an account key", "secp256k1", "", ProfileCosmosAccount, ""},
		{"an explicit account key", "secp256k1", `"cosmos-account"`, ProfileCosmosAccount, ""},
		{"a validator key is refused", "secp256k1", `"cosmos-validator"`, "", "this KMS signs no validator votes"},
		{"an unknown profile is refused", "secp256k1", `"cosmos-relayer"`, "", `signing_profile "cosmos-relayer" is not cosmos-account`},
		{"a profile on an ed25519 key is refused", "ed25519", `"cosmos-account"`, "", "is for a secp256k1 (Cosmos) key, not ed25519"},
		{"an ed25519 key has none", "ed25519", "", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			registry, err := load(c.algorithm, c.profile)
			if c.refused != "" {
				if err == nil || !strings.Contains(err.Error(), c.refused) {
					t.Fatalf("loaded, or refused for another reason: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := registry.entries["wallet-key"].route.SigningProfile; got != c.want {
				t.Fatalf("profile %q, want %q", got, c.want)
			}
		})
	}
}

// The key's pinned Cosmos public key: a compressed secp256k1 point, on a secp256k1 key only.
func TestTheCosmosPublicKeyOfAKey(t *testing.T) {
	pinned := `,"device_serial":"test-serial","public_key_sha256":"sha256:` + strings.Repeat("c", 64) + `"`
	sibling := `,"device_serial":"sibling-serial","public_key_sha256":"sha256:` + strings.Repeat("e", 64) + `"`
	const g = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	load := func(algorithm, key string) (*Registry, error) {
		document := object("wallet-key", "cosmos-transaction", algorithm, "sign",
			nitrokeyBinding("sitea", "local-hsm", pinned)+","+nitrokeyBinding("siteb", "remote-hsm", sibling))
		document = strings.Replace(document, `"verification":`, `"cosmos_public_key":`+key+`,"verification":`, 1)
		return Load(strings.NewReader(manifest(document)), "sitea", &healthMap{states: map[string]bool{}})
	}
	registry, err := load("secp256k1", `"`+g+`"`)
	if err != nil {
		t.Fatal(err)
	}
	if got := registry.entries["wallet-key"].route.CosmosPublicKey; len(got) != 33 || got[0] != 2 {
		t.Fatalf("pinned key %x", got)
	}
	for _, c := range []struct{ algorithm, key, want string }{
		{"secp256k1", `"` + strings.ToUpper(g) + `"`, "66 lowercase hex"},
		{"secp256k1", `"04` + g[2:] + `"`, "02 or 03 first"},
		{"secp256k1", `"` + g[:64] + `"`, "compressed secp256k1"},
		{"secp256k1", `"zz` + g[2:] + `"`, "compressed secp256k1"},
		{"ed25519", `"` + g + `"`, "is for a secp256k1 (Cosmos) key, not ed25519"},
	} {
		if _, err := load(c.algorithm, c.key); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %s: %v, not %q", c.algorithm, c.key, err, c.want)
		}
	}
}
