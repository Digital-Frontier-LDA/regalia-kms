package membership

import (
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tests/vectors/root-card-chain-v3.json (3e's, #298): a v3 chain whose root is a P-256 key generated on a
// Nitrokey HSM 2 (DENK0404380, staging, deleted after), both epochs signed on the card. The initrd's verifier
// accepts it from the root, and refuses each signature altered or turned high-S.
func cardChain(t *testing.T) (root any, envelopes []any, expected int64) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "vectors", "root-card-chain-v3.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := Load(raw, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	v := restoreTyped(document).(map[string]any)
	for _, value := range v["chain"].([]any) {
		e := value.(map[string]any)
		signature := map[string]any{"key": e["signature_public"]}
		for k, x := range e["signature"].(map[string]any) {
			signature[k] = x
		}
		envelopes = append(envelopes, map[string]any{"manifest": e["manifest"], "signature": signature})
	}
	epoch, _ := integer(v["expected_epoch"])
	return v["root_public"], envelopes, epoch.Int64()
}

func TestACardSignedChainIsAcceptedFromItsRoot(t *testing.T) {
	root, envelopes, expected := cardChain(t)
	entries, err := RootEntries(root, "the root key")
	if err != nil || len(entries) != 1 || entries[0].Alg != "ecdsa-p256" {
		t.Fatalf("the card's root: %v, %v", entries, err)
	}
	current, err := AcceptChain(nil, envelopes, root)
	if err != nil {
		t.Fatalf("the card-signed chain is refused: %v", err)
	}
	if epoch, _ := integer(current["epoch"]); epoch.Int64() != expected || current["schema"] != SchemaV3 {
		t.Errorf("accepted at epoch %v, schema %v; expected %d under v3", current["epoch"], current["schema"], expected)
	}
	typed := 0
	for _, entry := range current["revocation_keys"].([]any) {
		if alg, _, err := revocationEntry(entry, "x"); err == nil && alg == "ecdsa-p256" {
			typed++
		}
	}
	if typed == 0 {
		t.Error("the chain names no typed revocation key")
	}
}

func TestEachCardSignatureAlteredOrHighSIsRefused(t *testing.T) {
	_, all, expected := cardChain(t)
	if int64(len(all)) != expected {
		t.Fatalf("%d envelopes for an expected epoch of %d", len(all), expected)
	}
	for i := range all {
		for name, change := range map[string]func([]byte){
			"a flipped byte": func(sig []byte) { sig[10] ^= 1 },
			// the same signature with s replaced by n - s: valid ECDSA, and refused (low-S only)
			"high-S": func(sig []byte) {
				s := new(big.Int).SetBytes(sig[32:])
				new(big.Int).Sub(p256Order, s).FillBytes(sig[32:])
			},
		} {
			root, envelopes, _ := cardChain(t)
			signature := envelopes[i].(map[string]any)["signature"].(map[string]any)
			sig, _ := hex.DecodeString(signature["sig"].(string))
			change(sig)
			signature["sig"] = hex.EncodeToString(sig)
			// the signature check itself refuses both (low-S is part of it), not an earlier shape error
			if _, err := AcceptChain(nil, envelopes, root); err == nil || !strings.Contains(err.Error(), "the manifest signature does not verify") {
				t.Errorf("epoch %d, %s: %v", i+1, name, err)
			}
		}
	}
}
