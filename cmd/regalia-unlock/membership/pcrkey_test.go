package membership

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tests/vectors/pcr-key-policy-v1.json: for each fixed system-phase PCR public key, the TPM Name it loads
// under and the PolicyAuthorize digest, made by signkey.py and checked against a real TPM (swtpm:
// TPM2_LoadExternal's Name and a policyauthorize trial session) before they were written. Go computes the
// same from the PEM alone.
func TestEveryPCRKeyGivesTheTPMsNameAndPolicy(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "pcr-key-policy-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct{ Name, PEM, TPMName, Policy string } `json:"cases"`
	}
	if err := json.Unmarshal([]byte(strings.ReplaceAll(string(raw), `"tpm_name"`, `"tpmname"`)), &vectors); err != nil {
		t.Fatal(err)
	}
	for _, c := range vectors.Cases {
		name, policy, err := PCRKeyPolicy([]byte(c.PEM))
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		if hex.EncodeToString(name) != c.TPMName || hex.EncodeToString(policy) != c.Policy {
			t.Errorf("%s: Name %x policy %x, not %s %s", c.Name, name, policy, c.TPMName, c.Policy)
		}
	}
	if len(vectors.Cases) < 3 {
		t.Fatalf("only %d keys", len(vectors.Cases))
	}
}

// Only an RSA-2048 key with exponent 65537 in one PEM "PUBLIC KEY" block: anything else is refused, never
// read as some other key (a TPM refuses another exponent at LoadExternal, so no policy could be made of it).
func TestOnlyOneRSA2048KeyIsTaken(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "pcr-keys", "system-1.pub.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := PCRKeyPolicy(raw); err != nil {
		t.Fatalf("the fixture is refused: %v", err)
	}
	block, _ := pem.Decode(raw)
	parsed, _ := x509.ParsePKIXPublicKey(block.Bytes)
	key := parsed.(*rsa.PublicKey)
	encode := func(public any) []byte {
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, data := range map[string][]byte{
		"exponent 3":          encode(&rsa.PublicKey{N: key.N, E: 3}),
		"1024 bits":           encode(&small.PublicKey),
		"a P-256 key":         encode(&ec.PublicKey),
		"two keys":            append(append([]byte{}, raw...), raw...),
		"text after the key":  append(append([]byte{}, raw...), "x"...),
		"an RSA PUBLIC KEY":   pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(key)}),
		"a header in the PEM": pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Headers: map[string]string{"a": "b"}, Bytes: block.Bytes}),
		"not PEM":             []byte("not a key"),
		"empty":               nil,
		"garbage DER":         pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x01}}),
	} {
		if _, _, err := PCRKeyPolicy(data); err == nil {
			t.Errorf("%s: taken", name)
		} else if _, ok := err.(*Refused); !ok {
			t.Errorf("%s: %v is not a refusal", name, err)
		}
	}
}
