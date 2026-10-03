package membership

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"regexp"
	"strings"
)

// Typed keys (#156, #199), as membership.py has them: a key entry is a bare 64-hex Ed25519 public key, or
// {"alg": "ecdsa-p256", "key": "<130 hex: 04 || X || Y>"} (the Nitrokey's: its PKCS#11 has no EdDSA). Typed
// entries are valid only under schema v3. The algorithm comes from the entry only, never from a signature.

var (
	signatureKeyPattern = regexp.MustCompile(`^(?:[0-9a-f]{64}|[0-9a-f]{130})$`)
	p256Order           = elliptic.P256().Params().N
	p256HalfOrder       = new(big.Int).Rsh(p256Order, 1)
	typedAlgorithms     = []string{"ecdsa-p256"} // membership.REVOCATION_ALGS[1:]
)

// KeyEntry is one key as an entry names it: its algorithm, and its public key in hex.
type KeyEntry struct{ Alg, Key string }

// revocationEntry is membership.revocation_entry: (alg, key hex) of one entry, or Refused.
func revocationEntry(entry any, label string) (string, string, error) {
	if bare, ok := entry.(string); ok {
		if err := hexField(bare, 64, label); err != nil {
			return "", "", err
		}
		return "ed25519", bare, nil
	}
	typed, err := exact(entry, []string{"alg", "key"}, label)
	if err != nil {
		return "", "", err
	}
	alg, _ := typed["alg"].(string)
	known := false
	for _, a := range typedAlgorithms {
		known = known || alg == a
	}
	if !known {
		return "", "", refuse("%s: alg must be one of %s", label, strings.Join(typedAlgorithms, ", "))
	}
	if err := hexField(typed["key"], 130, label+": an ecdsa-p256 key (04 || X || Y)"); err != nil {
		return "", "", err
	}
	key := typed["key"].(string)
	if !strings.HasPrefix(key, "04") {
		return "", "", refuse("%s: an ecdsa-p256 key must be an uncompressed point", label)
	}
	point, _ := hex.DecodeString(key)
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point); err != nil {
		return "", "", refuse("%s: not a point on P-256", label)
	}
	return alg, key, nil
}

// RootEntries is membership.root_entries: the pinned root, one entry or a list of one to eight, each a bare
// 64-hex Ed25519 key or a typed entry (#156: the root on an offline Nitrokey). It takes the root as JSON
// gives it (a string, an object or a list), as node.py's root_key and rollout's --root-key do.
func RootEntries(root any, label string) ([]KeyEntry, error) {
	entries, isList := root.([]any)
	if !isList {
		entries = []any{root}
	}
	if len(entries) == 0 || len(entries) > 8 {
		return nil, refuse("the root is one key or a list of one to eight")
	}
	out, seen := make([]KeyEntry, 0, len(entries)), map[string]bool{}
	for _, entry := range entries {
		alg, key, err := revocationEntry(entry, label)
		if err != nil {
			return nil, err
		}
		out = append(out, KeyEntry{alg, key})
		seen[key] = true
	}
	if len(seen) != len(out) {
		return nil, refuse("the root keys must be distinct")
	}
	return out, nil
}

// revocationAlg is membership.revocation_alg: the algorithm the manifest's revocation_keys give for a key
// (its hex), or "" if it names none.
func revocationAlg(manifest map[string]any, key string) string {
	entries, _ := manifest["revocation_keys"].([]any)
	for _, entry := range entries {
		alg, hexKey, err := revocationEntry(entry, "a revocation key")
		if err == nil && hexKey == key {
			return alg
		}
	}
	return ""
}
