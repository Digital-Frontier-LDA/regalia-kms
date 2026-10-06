package membership

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// Schema v4 (#199), as membership.py has it ("Schema v4" in its docstring): no revocation keys and no
// authority host. Each node has a signing_key in its own TPM (ecdsa-p256), the owner has one to eight
// owner_keys (ed25519 or ecdsa-p256, together ONE party, "owner"), and the manifest names the signer rules:
// heartbeat_signers, activation_signers and revocation_signers. A restrictive change is signed by a quorum
// that meets one revocation_signers rule of the CURRENT manifest, every signature verified by the key that
// manifest gives its party, the algorithm from that key's entry. The floors are the format's.

const (
	SchemaV4          = "regalia.membership/v4"
	ownerHeartbeatMin = 300
	ownerParty        = "owner" // the owner's party name in a signer rule (never a node_id)
	heartbeatFloor    = 2       // no single party keeps a cluster alive, or (naming a node) revokes, alone
	nodeRuleFloor     = 2
	maxOwnerKeys      = 8
	maxRules          = 4
	maxSignatures     = 16
)

var (
	signingKeyAlgs = []string{"ecdsa-p256"}            // a TPM has no Ed25519
	ownerKeyAlgs   = []string{"ed25519", "ecdsa-p256"} // the approval YubiKeys' OpenPGP applet (#126), or P-256
	signerFields   = []string{"owner_heartbeat_lifetime_s", "owner_keys", "heartbeat_signers", "activation_signers", "revocation_signers"}
	singleRules    = []string{"heartbeat_signers", "activation_signers"} // one rule each; revocation_signers is a list
	v4ManifestKeys = append(without(v2ManifestKeys, "revocation_keys"), signerFields...)
	v4NodeKeys     = append(append([]string(nil), v2NodeKeys...), "signing_key")
	// what only the root may change: a quorum (or a v1-v3 revocation key) leaves every one as it was
	rootFields = append([]string{"policy_version", "revocation_keys", "heartbeat_max_lifetime_s"}, signerFields...)
	// named in a signer rule, but not counting
	notCounting = map[string]bool{"RETIRED": true, "REVOKED_STOLEN": true, "QUARANTINED": true}
)

func without(keys []string, drop string) []string {
	out := []string{}
	for _, k := range keys {
		if k != drop {
			out = append(out, k)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// typedKey is membership.typed_key: (alg, key hex) of a TYPED entry ({"alg", "key"}) whose alg is one of
// algs. Never a bare string: the algorithm is always written beside the key.
func typedKey(entry any, label string, algs []string) (string, string, error) {
	if _, ok := entry.(map[string]any); !ok {
		return "", "", refuse("%s must be a typed key {\"alg\", \"key\"}", label)
	}
	typed, err := exact(entry, []string{"alg", "key"}, label)
	if err != nil {
		return "", "", err
	}
	alg, _ := typed["alg"].(string)
	if !contains(algs, alg) {
		return "", "", refuse("%s: alg must be one of %s", label, strings.Join(algs, ", "))
	}
	if alg != "ed25519" {
		return revocationEntry(entry, label)
	}
	if err := hexField(typed["key"], 64, label+": an ed25519 key"); err != nil {
		return "", "", err
	}
	return "ed25519", typed["key"].(string), nil
}

// signerRules is membership._signer_rules: a v4 manifest's owner keys, the owner's heartbeat bound and the
// rules. `seen` is Validate's: an owner key is no node's identity, nor another owner key.
func signerRules(manifest map[string]any, byID map[string]map[string]any, seen map[string]string) error {
	owners, ok := manifest["owner_keys"].([]any)
	if !ok || len(owners) < 1 || len(owners) > maxOwnerKeys {
		return refuse("owner_keys must be a list of one to %d keys", maxOwnerKeys)
	}
	for i, entry := range owners {
		label := fmt.Sprintf("owner_keys[%d]", i)
		_, key, err := typedKey(entry, label, ownerKeyAlgs)
		if err != nil {
			return err
		}
		if owner, used := seen[key]; used {
			return refuse("%s is already used (%s)", label, owner)
		}
		seen[key] = label
	}
	life, isInt := integer(manifest["owner_heartbeat_lifetime_s"])
	most, _ := integer(manifest["heartbeat_max_lifetime_s"])
	if !isInt || most == nil || life.Cmp(big.NewInt(ownerHeartbeatMin)) < 0 || life.Cmp(most) > 0 {
		return refuse("owner_heartbeat_lifetime_s must be an integer from %d to heartbeat_max_lifetime_s", ownerHeartbeatMin)
	}
	rule := func(value any, label string, ownerAlone bool) error {
		object, err := exact(value, []string{"threshold", "parties"}, label)
		if err != nil {
			return err
		}
		list, ok := object["parties"].([]any)
		parties := make([]string, 0, len(list))
		for _, p := range list {
			if name, isString := p.(string); isString {
				parties = append(parties, name)
			}
		}
		if !ok || len(list) == 0 || len(parties) != len(list) {
			return refuse("%s.parties must be a non-empty list of names", label)
		}
		distinct := map[string]bool{}
		for _, p := range parties {
			distinct[p] = true
		}
		if len(distinct) != len(parties) {
			return refuse("%s.parties must be distinct", label)
		}
		for _, p := range parties {
			if _, node := byID[p]; p != ownerParty && !node {
				return refuse("%s names %q, which is neither a node of this manifest nor %s", label, p, ownerParty)
			}
		}
		threshold, isInt := integer(object["threshold"])
		if !isInt {
			return refuse("%s.threshold must be an integer", label)
		}
		least := int64(heartbeatFloor)
		if ownerAlone {
			least = nodeRuleFloor
			if len(parties) == 1 && parties[0] == ownerParty {
				least = 1
			}
		}
		if threshold.Cmp(big.NewInt(least)) < 0 || threshold.Cmp(big.NewInt(int64(len(parties)))) > 0 {
			return refuse("%s.threshold must be from %d to the number of its parties (%d)", label, least, len(parties))
		}
		return nil
	}
	for _, name := range singleRules {
		if err := rule(manifest[name], name, false); err != nil {
			return err
		}
	}
	rules, ok := manifest["revocation_signers"].([]any)
	if !ok || len(rules) < 1 || len(rules) > maxRules {
		return refuse("revocation_signers must be a list of one to %d rules", maxRules)
	}
	for i, r := range rules {
		if err := rule(r, fmt.Sprintf("revocation_signers[%d]", i), true); err != nil {
			return err
		}
	}
	return nil
}

// apartFromRoot is membership._apart_from_root: a v4 manifest's party keys (owner_keys, every signing_key)
// are none of the pinned root's. One device is never both the payload root and a quorum party (D28).
func apartFromRoot(manifest map[string]any, root any) error {
	if manifest["schema"] != SchemaV4 {
		return nil
	}
	entries, err := RootEntries(root, "the root key")
	if err != nil {
		return err
	}
	roots := map[string]bool{}
	for _, e := range entries {
		roots[e.Key] = true
	}
	type labelled struct{ label, key string }
	var keys []labelled
	for i, entry := range manifest["owner_keys"].([]any) {
		keys = append(keys, labelled{fmt.Sprintf("owner_keys[%d]", i), entry.(map[string]any)["key"].(string)})
	}
	for _, value := range manifest["nodes"].([]any) {
		node := value.(map[string]any)
		if signing, has := node["signing_key"]; has {
			keys = append(keys, labelled{"signing_key of " + node["node_id"].(string), signing.(map[string]any)["key"].(string)})
		}
	}
	for _, k := range keys {
		if roots[k.key] {
			return refuse("%s is a pinned root key: the payload root is never a quorum party", k.label)
		}
	}
	return nil
}

// countingParties is membership.counting_parties: the parties whose signatures over message count under the
// CURRENT v4 manifest. Every signature names a party of that manifest with the key it gives that party and
// verifies the way that key's entry says; a party named twice is refused; a RETIRED, REVOKED_STOLEN or
// QUARANTINED node's signature must verify all the same, and does not count.
func countingParties(current map[string]any, message []byte, signatures any, what string) (map[string]bool, error) {
	if current == nil || current["schema"] != SchemaV4 {
		return nil, refuse("a %s signed by a quorum needs a current %s manifest naming its signers", what, SchemaV4)
	}
	list, ok := signatures.([]any)
	if !ok || len(list) < 1 || len(list) > maxSignatures {
		return nil, refuse("signatures must be a list of one to %d signatures", maxSignatures)
	}
	nodes, err := Validate(current)
	if err != nil {
		return nil, err
	}
	owners := map[string]string{}
	for _, entry := range current["owner_keys"].([]any) {
		alg, key, err := typedKey(entry, "owner_keys", ownerKeyAlgs)
		if err != nil {
			return nil, err
		}
		owners[key] = alg
	}
	named, counting := map[string]bool{}, map[string]bool{}
	for i, value := range list {
		sig, err := exact(value, []string{"party", "key", "sig"}, fmt.Sprintf("signatures[%d]", i))
		if err != nil {
			return nil, err
		}
		party, isString := sig["party"].(string)
		if !isString || named[party] {
			return nil, refuse("signatures[%d]: party %s is named twice or is not a name", i, repr(sig["party"]))
		}
		named[party] = true
		key, isString := sig["key"].(string)
		if !isString || !signatureKeyPattern.MatchString(key) {
			return nil, refuse("signatures[%d].key must be 64 or 130 lowercase hex", i)
		}
		var alg string
		if party == ownerParty {
			if alg = owners[key]; alg == "" {
				return nil, refuse("signatures[%d]: the key is not one of the current manifest's owner_keys", i)
			}
		} else {
			node, has := nodes[party]
			signing, hasKey := node["signing_key"].(map[string]any)
			if !has || !hasKey {
				return nil, refuse("signatures[%d]: %q is not a node of the current manifest with a signing_key", i, party)
			}
			if key != signing["key"] {
				return nil, refuse("signatures[%d]: the key is not %s's signing_key", i, party)
			}
			alg = signing["alg"].(string) // from the manifest's entry, never from the signature
		}
		if err := verifyTyped(alg, key, message, sig["sig"], fmt.Sprintf("%s (signatures[%d], %s)", what, i, party)); err != nil {
			return nil, err
		}
		if party == ownerParty || !notCounting[nodes[party]["state"].(string)] {
			counting[party] = true
		}
	}
	return counting, nil
}

// meets is membership.meets: whether the counting parties meet one signer rule.
func meets(rule any, parties map[string]bool) bool {
	object, _ := rule.(map[string]any)
	list, _ := object["parties"].([]any)
	n := int64(0)
	for _, p := range list {
		if name, ok := p.(string); ok && parties[name] {
			n++
		}
	}
	threshold, ok := integer(object["threshold"])
	return ok && big.NewInt(n).Cmp(threshold) >= 0
}

// verifyTyped is membership.verify_revocation: a signature over message by key, the way its entry's alg
// says. Ed25519, or ECDSA P-256 over SHA-256 with r || s and only the low-S form. `what` names it in the
// refusal.
func verifyTyped(alg, key string, message []byte, sigValue any, what string) error {
	if err := hexField(sigValue, 128, what+" signature"); err != nil {
		return err
	}
	sig, _ := hex.DecodeString(sigValue.(string))
	public, err := hex.DecodeString(key)
	fails := refuse("the %s signature does not verify", what)
	if err != nil {
		return fails
	}
	switch alg {
	case "ed25519":
		if len(public) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(public), message, sig) {
			return fails
		}
		return nil
	case "ecdsa-p256":
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if r.Sign() <= 0 || r.Cmp(p256Order) >= 0 || s.Sign() <= 0 || s.Cmp(p256HalfOrder) > 0 {
			return refuse("the %s signature is not a low-S P-256 signature", what)
		}
		point, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), public)
		if err != nil {
			return fails
		}
		digest := sha256.Sum256(message)
		if !ecdsa.Verify(point, digest[:], r, s) {
			return fails
		}
		return nil
	}
	return refuse("unknown revocation key algorithm %s", repr(alg))
}

// repr is Python's %r for the values a refusal names: a string quoted (sameReason reads "x" as 'x'), else the
// value as JSON would write it.
func repr(value any) string {
	if s, ok := value.(string); ok {
		return fmt.Sprintf("%q", s)
	}
	return string(Canonical(value))
}

// NodeSigningKey is opstate._signing_key: the node's signing_key in `manifest` (validated here) as (alg, key
// hex); ok is false when the manifest names no such node or it has no signing_key.
func NodeSigningKey(manifest map[string]any, nodeID string) (alg, key string, ok bool, err error) {
	nodes, err := Validate(manifest)
	if err != nil {
		return "", "", false, err
	}
	node, named := nodes[nodeID]
	if !named || node["signing_key"] == nil {
		return "", "", false, nil
	}
	alg, key, err = typedKey(node["signing_key"], nodeID+"'s signing_key", signingKeyAlgs)
	return alg, key, err == nil, err
}

// VerifyTypedSignature is membership.verify_revocation: `message` signed by (alg, key), `sig` the hex signature
// (Ed25519, or P-256 r||s low-S). `what` names it in the refusal ("the <what> signature does not verify").
func VerifyTypedSignature(alg, key string, message []byte, sig any, what string) error {
	return verifyTyped(alg, key, message, sig, what)
}
