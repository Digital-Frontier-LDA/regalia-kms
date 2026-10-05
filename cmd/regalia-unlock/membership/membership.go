package membership

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// The constants of membership.py.
const (
	SchemaV1         = "regalia.membership/v1"
	SchemaV2         = "regalia.membership/v2"
	SchemaV3         = "regalia.membership/v3" // v2 with typed keys ({"alg": ...}): only here (#156, #199)
	heartbeatMin     = 3600
	heartbeatHardMax = 7 * 24 * 3600
	domain           = "regalia-membership/v1\x00"
)

var (
	schemas      = []string{SchemaV1, SchemaV2, SchemaV3, SchemaV4} // in order: a chain never goes back
	capabilities = map[string][]string{"ACTIVE": {"authorize", "request", "serve"}, "MAINTENANCE": {"request"}, "DRAINING": {"serve"},
		"QUARANTINED": {}, "RETIRED": {}, "REVOKED_STOLEN": {}}
	terminal       = map[string]bool{"RETIRED": true, "REVOKED_STOLEN": true}
	manifestKeys   = []string{"schema", "epoch", "prev_digest", "policy_version", "issued_at", "revocation_keys", "nodes"}
	nodeKeys       = []string{"node_id", "state", "ek_name", "ak_name", "wg_boot_pub", "wg_service_pub", "hsm_serials"}
	identityKeys   = []string{"ek_name", "ak_name", "wg_boot_pub", "wg_service_pub"}
	v2ManifestKeys = append(append([]string(nil), manifestKeys...), "heartbeat_max_lifetime_s")
	v2NodeKeys     = append(append([]string(nil), nodeKeys...), "ssh_host_pub")
	v2IdentityKeys = append(append([]string(nil), identityKeys...), "ssh_host_pub")
	nodeIDPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	policyPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
	serialPattern  = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)
	// membership.UTC_TIME: ASCII digits, every field at full width, uppercase T and Z (#254)
	issuedAtPattern = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$`)
)

// Refused is membership.Refused: a decision not to accept, with its reason.
type Refused struct{ Reason string }

func (r *Refused) Error() string { return r.Reason }

func refuse(format string, args ...any) error { return &Refused{Reason: fmt.Sprintf(format, args...)} }

func require(condition bool, format string, args ...any) error {
	if condition {
		return nil
	}
	return refuse(format, args...)
}

// Digest is membership.digest: SHA-256 of the canonical manifest, in hex.
func Digest(manifest map[string]any) string {
	sum := sha256.Sum256(Canonical(manifest))
	return hex.EncodeToString(sum[:])
}

func exact(value any, keys []string, label string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, refuse("%s must be an object", label)
	}
	for _, key := range keys {
		if _, has := object[key]; !has {
			return nil, refuse("%s fields mismatch", label)
		}
	}
	if len(object) != len(keys) {
		return nil, refuse("%s fields mismatch", label)
	}
	return object, nil
}

func hexField(value any, n int, label string) error {
	text, ok := value.(string)
	if !ok || len(text) != n || strings.ToLower(text) != text {
		return refuse("%s must be %d lowercase hex", label, n)
	}
	if _, err := hex.DecodeString(text); err != nil {
		return refuse("%s must be %d lowercase hex", label, n)
	}
	return nil
}

// integer is a JSON integer (never a bool): as Python's isinstance(e, int) and not isinstance(e, bool).
func integer(value any) (*big.Int, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return nil, false
	}
	n, ok := new(big.Int).SetString(string(number), 10)
	return n, ok
}

// identityKeysOf is membership.identity_keys: v1's four, ssh_host_pub from v2, and signing_key from v4.
func identityKeysOf(node map[string]any) []string {
	keys := identityKeys
	if _, has := node["ssh_host_pub"]; has {
		keys = v2IdentityKeys
	}
	if _, has := node["signing_key"]; has {
		keys = append(append([]string(nil), keys...), "signing_key")
	}
	return keys
}

// identityValue is membership.identity_value: the field itself, or a typed key's hex (signing_key).
func identityValue(node map[string]any, key string) string {
	if key == "signing_key" {
		return node[key].(map[string]any)["key"].(string)
	}
	return node[key].(string)
}

func sameKeySet(object map[string]any, keys []string) bool {
	if len(object) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, has := object[k]; !has {
			return false
		}
	}
	return true
}

// issuedAt is datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ"): four digits of year, one or two of every other
// field, a day that exists. With ASCII digits only, where Python's \d would also take other scripts' digits:
// stricter, so the initrd refuses such a manifest and the console asks (fail closed).
func issuedAt(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	m := issuedAtPattern.FindStringSubmatch(text)
	if m == nil {
		return false
	}
	f := make([]int, 6)
	for i := range f {
		f[i], _ = strconv.Atoi(m[i+1])
	}
	// strptime takes seconds up to 61, and datetime then refuses 60 and 61: 59 is the last
	if f[1] < 1 || f[1] > 12 || f[2] < 1 || f[2] > 31 || f[3] > 23 || f[4] > 59 || f[5] > 59 {
		return false
	}
	// the day must exist in that month (strptime refuses 2026-02-30)
	t := time.Date(f[0], time.Month(f[1]), f[2], 0, 0, 0, 0, time.UTC)
	return t.Day() == f[2] && f[0] >= 1
}

// Validate is membership.validate: schema and uniqueness. Returns the nodes by ID.
func Validate(value any) (map[string]map[string]any, error) {
	manifest, ok := value.(map[string]any)
	if !ok {
		return nil, refuse("manifest must be an object")
	}
	schema, _ := manifest["schema"].(string)
	if schemaIndex(schema) < 0 {
		return nil, refuse("schema must be %s", strings.Join(schemas, " or "))
	}
	fourth := schema == SchemaV4
	second := schema == SchemaV2 || schema == SchemaV3 || fourth // v3 and v4 have v2's fields
	keys, nodeKeySet := manifestKeys, nodeKeys
	if fourth {
		keys, nodeKeySet = v4ManifestKeys, v4NodeKeys
	} else if second {
		keys, nodeKeySet = v2ManifestKeys, v2NodeKeys
	}
	// A tombstone keeps exactly the fields it had: one retired under an earlier schema may lack what later
	// schemas added (ssh_host_pub from v2, signing_key from v4), and nothing is invented for it.
	shapes := [][]string{v4NodeKeys, v2NodeKeys, nodeKeys}
	for len(shapes) > 0 && len(shapes[0]) != len(nodeKeySet) {
		shapes = shapes[1:]
	}
	if _, err := exact(manifest, keys, "manifest"); err != nil {
		return nil, err
	}
	if second {
		// isinstance(life, int): a bool would pass the type test, and its value (0 or 1) fails the range
		life, isInt := integer(manifest["heartbeat_max_lifetime_s"])
		if b, isBool := manifest["heartbeat_max_lifetime_s"].(bool); isBool {
			life, isInt = big.NewInt(0), true
			if b {
				life = big.NewInt(1)
			}
		}
		if !isInt || life.Cmp(big.NewInt(heartbeatMin)) < 0 || life.Cmp(big.NewInt(heartbeatHardMax)) > 0 {
			return nil, refuse("heartbeat_max_lifetime_s must be an integer from %d to %d", heartbeatMin, heartbeatHardMax)
		}
	}
	epoch, ok := integer(manifest["epoch"])
	if !ok || epoch.Sign() < 1 {
		return nil, refuse("epoch must be an integer >= 1")
	}
	if epoch.Cmp(big.NewInt(1)) == 0 {
		if manifest["prev_digest"] != "" {
			return nil, refuse("epoch 1 has no previous manifest (prev_digest \"\")")
		}
	} else if err := hexField(manifest["prev_digest"], 64, "prev_digest"); err != nil {
		return nil, err
	}
	if policy, ok := manifest["policy_version"].(string); !ok || !policyPattern.MatchString(policy) {
		return nil, refuse("policy_version must be a short name")
	}
	if !issuedAt(manifest["issued_at"]) {
		return nil, refuse("issued_at must be UTC, YYYY-MM-DDTHH:MM:SSZ")
	}
	if !fourth {
		revocation, ok := manifest["revocation_keys"].([]any)
		if !ok {
			return nil, refuse("revocation_keys must be a list")
		}
		distinct, typed := map[string]bool{}, false
		for i, entry := range revocation {
			_, key, err := revocationEntry(entry, fmt.Sprintf("revocation_keys[%d]", i))
			if err != nil {
				return nil, err
			}
			distinct[key] = true
			if _, bare := entry.(string); !bare {
				typed = true
			}
		}
		if len(distinct) != len(revocation) {
			return nil, refuse("revocation_keys must be distinct")
		}
		if typed && schema != SchemaV3 {
			return nil, refuse("a typed revocation key ({\"alg\": ...}) needs schema %s", SchemaV3)
		}
	}
	nodes, ok := manifest["nodes"].([]any)
	if !ok || len(nodes) == 0 {
		return nil, refuse("nodes must be a non-empty list")
	}
	byID, seen := map[string]map[string]any{}, map[string]string{}
	for i, value := range nodes {
		label := fmt.Sprintf("nodes[%d]", i)
		keys := nodeKeySet
		if object, isObject := value.(map[string]any); isObject {
			state, _ := object["state"].(string)
			for _, shape := range shapes {
				if terminal[state] && sameKeySet(object, shape) {
					keys = shape // a tombstone keeps the fields it had
					break
				}
			}
		}
		node, err := exact(value, keys, label)
		if err != nil {
			return nil, err
		}
		id, ok := node["node_id"].(string)
		if !ok || !nodeIDPattern.MatchString(id) {
			return nil, refuse("%s.node_id must be a short lowercase name", label)
		}
		if fourth && id == ownerParty {
			return nil, refuse("%s: %q is the owner's party name under %s, never a node_id", label, ownerParty, SchemaV4)
		}
		if _, dup := byID[id]; dup {
			return nil, refuse("duplicate node_id %q", id)
		}
		state, ok := node["state"].(string)
		if _, known := capabilities[state]; !ok || !known {
			return nil, refuse("%s.state is not a known state", label)
		}
		for _, field := range []struct {
			key string
			n   int
		}{{"ek_name", 68}, {"ak_name", 68}, {"wg_boot_pub", 64}, {"wg_service_pub", 64}} {
			if err := hexField(node[field.key], field.n, label+"."+field.key); err != nil {
				return nil, err
			}
		}
		if _, has := node["ssh_host_pub"]; has {
			if err := hexField(node["ssh_host_pub"], 64, label+".ssh_host_pub"); err != nil {
				return nil, err
			}
		}
		if _, has := node["signing_key"]; has {
			if _, _, err := typedKey(node["signing_key"], label+".signing_key", signingKeyAlgs); err != nil {
				return nil, err
			}
		}
		serials, ok := node["hsm_serials"].([]any)
		if !ok {
			return nil, refuse("%s.hsm_serials", label)
		}
		for _, serial := range serials {
			s, isString := serial.(string)
			if !isString || !serialPattern.MatchString(s) {
				return nil, refuse("%s.hsm_serials", label)
			}
		}
		// No identity may belong to two nodes, compared by value across roles.
		for _, key := range identityKeysOf(node) {
			value := identityValue(node, key)
			if owner, used := seen[value]; used {
				return nil, refuse("%s of %s is already used (%s)", key, id, owner)
			}
			seen[value] = key + " of " + id
		}
		for _, serial := range serials {
			key := "\x00hsm\x00" + serial.(string) // never equal to an identity value (hex)
			if _, used := seen[key]; used {
				return nil, refuse("HSM %s is listed twice", serial)
			}
			seen[key] = id
		}
		byID[id] = node
	}
	if fourth {
		if err := signerRules(manifest, byID, seen); err != nil {
			return nil, err
		}
	}
	return byID, nil
}

// VerifyEnvelope is membership.verify_envelope: the manifest inside, if its signature is by the pinned root
// key or by a revocation key named in the CURRENT manifest, or, under v4, by a quorum of the parties the
// CURRENT manifest names (one of its revocation_signers rules met). Returns the manifest and the signer,
// "root", "revocation" or "quorum". A current
// manifest that does not validate is refused here, before Accept reads its fields: only what Accept or
// AcceptChain returned should be passed.
func VerifyEnvelope(value any, root any, current map[string]any) (map[string]any, string, error) {
	if current != nil {
		if _, err := Validate(current); err != nil {
			return nil, "", refuse("the current manifest is not valid: %v", err)
		}
	}
	if object, ok := value.(map[string]any); ok {
		if _, quorum := object["signatures"]; quorum {
			return verifyQuorum(object, root, current)
		}
	}
	envelope, err := exact(value, []string{"manifest", "signature"}, "envelope")
	if err != nil {
		return nil, "", err
	}
	signature, err := exact(envelope["signature"], []string{"signer", "key", "sig"}, "signature")
	if err != nil {
		return nil, "", err
	}
	signer, _ := signature["signer"].(string)
	if signer != "root" && signer != "revocation" {
		return nil, "", refuse("signer must be root or revocation")
	}
	if k, ok := signature["key"].(string); !ok || !signatureKeyPattern.MatchString(k) {
		return nil, "", refuse("signature.key must be 64 or 130 lowercase hex")
	}
	if err := hexField(signature["sig"], 128, "signature.sig"); err != nil {
		return nil, "", err
	}
	// the algorithm comes from the pinned root entry or the current manifest's entry for the key, never
	// from the signature
	key, algorithm := signature["key"].(string), ""
	if signer == "root" {
		entries, err := RootEntries(root, "the root key")
		if err != nil {
			return nil, "", err
		}
		for _, entry := range entries {
			if entry.Key == key {
				algorithm = entry.Alg
				break
			}
		}
		if algorithm == "" {
			return nil, "", refuse("the signature names a root key that is not the pinned root")
		}
	} else {
		if current != nil {
			algorithm = revocationAlg(current, key)
		}
		if algorithm == "" {
			return nil, "", refuse("the signing revocation key is not named by the current manifest")
		}
	}
	if _, err := Validate(envelope["manifest"]); err != nil {
		return nil, "", err
	}
	manifest := envelope["manifest"].(map[string]any)
	if err := apartFromRoot(manifest, root); err != nil {
		return nil, "", err
	}
	if algorithm != "ed25519" && manifest["schema"] != SchemaV3 && manifest["schema"] != SchemaV4 {
		return nil, "", refuse("a manifest signed by a typed (%s) key needs schema %s or %s", algorithm, SchemaV3, SchemaV4)
	}
	sig, _ := hex.DecodeString(signature["sig"].(string))
	if !verifySignature(algorithm, key, sig, append([]byte(domain), Canonical(manifest)...)) {
		return nil, "", refuse("the manifest signature does not verify")
	}
	return manifest, signer, nil
}

// verifyQuorum is verify_envelope's v4 path: {"manifest", "signatures"}, the counting parties meeting one
// revocation_signers rule of the CURRENT manifest.
func verifyQuorum(object map[string]any, root any, current map[string]any) (map[string]any, string, error) {
	envelope, err := exact(object, []string{"manifest", "signatures"}, "envelope")
	if err != nil {
		return nil, "", err
	}
	if _, err := Validate(envelope["manifest"]); err != nil {
		return nil, "", err
	}
	manifest := envelope["manifest"].(map[string]any)
	if err := apartFromRoot(manifest, root); err != nil {
		return nil, "", err
	}
	parties, err := countingParties(current, append([]byte(domain), Canonical(manifest)...), envelope["signatures"], "manifest")
	if err != nil {
		return nil, "", err
	}
	for _, rule := range current["revocation_signers"].([]any) {
		if meets(rule, parties) {
			return manifest, "quorum", nil
		}
	}
	counting := make([]string, 0, len(parties))
	for p := range parties {
		counting = append(counting, p)
	}
	sort.Strings(counting)
	named := strings.Join(counting, ", ")
	if named == "" {
		named = "none"
	}
	return nil, "", refuse("the manifest's signatures meet no revocation_signers rule of the current manifest (counting: %s)", named)
}

// verifySignature is verifyTyped as a yes or no.
func verifySignature(algorithm, key string, sig, message []byte) bool {
	return verifyTyped(algorithm, key, message, hex.EncodeToString(sig), "a") == nil
}

func subset(a, b []string) bool {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	for _, x := range a {
		if !in[x] {
			return false
		}
	}
	return true
}

func sameKeys(a, b map[string]any) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, has := b[k]; !has {
			return false
		}
	}
	return true
}

func equal(a, b any) bool { return string(Canonical(a)) == string(Canonical(b)) }

// restrictive is membership._restrictive: a revocation-signed (v1-v3) or quorum-signed (v4) change only
// narrows: identities, policy, keys and signer rules unchanged; capabilities only shrink.
func restrictive(current, candidate map[string]any, signer string) error {
	who := "a revocation key"
	if signer != "revocation" {
		who = "a revocation quorum"
	}
	names := map[string]string{"policy_version": "the policy version", "revocation_keys": "the revocation keys"}
	for _, k := range rootFields {
		if k == "recovery_ends_by" && candidate[k] == nil {
			continue // clearing it is not a widening: a recovery's end is stated again by the root
		}
		if !equal(candidate[k], current[k]) {
			name := names[k]
			if name == "" {
				name = k
			}
			return refuse("%s cannot change %s", who, name)
		}
	}
	old, err := Validate(current)
	if err != nil {
		return err
	}
	fresh, err := Validate(candidate)
	if err != nil {
		return err
	}
	if len(old) != len(fresh) {
		return refuse("%s cannot add or remove nodes", who)
	}
	for id := range old {
		if _, has := fresh[id]; !has {
			return refuse("%s cannot add or remove nodes", who)
		}
	}
	for _, id := range listedIDs(candidate) {
		node := fresh[id]
		if !sameKeys(node, old[id]) {
			return refuse("%s cannot add or drop fields of %s", who, id)
		}
		for _, key := range append(append([]string(nil), identityKeysOf(node)...), "hsm_serials") {
			if !equal(node[key], old[id][key]) {
				return refuse("%s cannot change %s of %s", who, key, id)
			}
		}
		if !subset(capabilities[node["state"].(string)], capabilities[old[id]["state"].(string)]) {
			return refuse("%s: %s -> %s widens capabilities; only the root can do that", id, old[id]["state"], node["state"])
		}
	}
	return nil
}

// listedIDs are a validated manifest's node IDs in its own order, as Python iterates validate()'s dict: where
// more than one node breaks a rule, the refusal names the same one.
func listedIDs(manifest map[string]any) []string {
	nodes := manifest["nodes"].([]any)
	ids := make([]string, 0, len(nodes))
	for _, value := range nodes {
		ids = append(ids, value.(map[string]any)["node_id"].(string))
	}
	return ids
}

func sortedIDs(nodes map[string]map[string]any) []string {
	ids := make([]string, 0, len(nodes))
	for id := range nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// tombstones is membership._tombstones: no node leaves, and retirement is terminal, for every signer.
func tombstones(current, candidate map[string]any) error {
	old, err := Validate(current)
	if err != nil {
		return err
	}
	fresh, err := Validate(candidate)
	if err != nil {
		return err
	}
	for _, id := range listedIDs(current) {
		node := old[id]
		state := node["state"].(string)
		next, present := fresh[id]
		if !terminal[state] {
			if !present {
				return refuse("tombstone: %s cannot be removed; retire it instead", id)
			}
			if terminal[next["state"].(string)] {
				if !sameKeys(next, node) {
					return refuse("tombstone: %s becomes %s and its fields cannot change in the same manifest "+
						"(ssh_host_pub is neither added nor dropped)", id, next["state"])
				}
				for _, key := range append(append([]string(nil), identityKeysOf(node)...), "hsm_serials") {
					if !equal(next[key], node[key]) {
						return refuse("tombstone: %s becomes %s and its %s cannot change in the same manifest", id, next["state"], key)
					}
				}
			}
			continue
		}
		if !present {
			return refuse("tombstone: %s is %s and must stay in every later manifest (its identities are never reused)", id, state)
		}
		if !sameKeys(next, node) {
			return refuse("tombstone: %s is %s and its fields cannot change (ssh_host_pub is neither added nor dropped)", id, state)
		}
		for _, key := range append(append([]string(nil), identityKeysOf(node)...), "hsm_serials") {
			if !equal(next[key], node[key]) {
				return refuse("tombstone: %s is %s and its %s cannot change", id, state, key)
			}
		}
		nextState := next["state"].(string)
		if nextState != state && !(state == "RETIRED" && nextState == "REVOKED_STOLEN") {
			return refuse("tombstone: %s is %s, which is terminal for every signer (%s refused); hardware that may return "+
				"belongs in MAINTENANCE or QUARANTINED", id, state, nextState)
		}
	}
	return nil
}

func schemaIndex(schema string) int {
	for i, s := range schemas {
		if s == schema {
			return i
		}
	}
	return -1
}

// Accept is membership.accept: the next manifest, if `envelope` may follow `current` (nil at enrolment,
// where only a root-signed epoch-1 manifest is accepted).
func Accept(current map[string]any, envelope any, root any) (map[string]any, error) {
	candidate, signer, err := VerifyEnvelope(envelope, root, current)
	if err != nil {
		return nil, err
	}
	epoch, _ := integer(candidate["epoch"])
	if current == nil {
		if signer != "root" || epoch.Cmp(big.NewInt(1)) != 0 {
			return nil, refuse("the first manifest must be the root-signed epoch 1")
		}
		return candidate, nil
	}
	have, _ := integer(current["epoch"])
	if epoch.Cmp(have) == 0 {
		if Digest(candidate) == Digest(current) {
			return current, nil
		}
		return nil, refuse("CONFLICT: a different manifest at epoch %s: record an incident", epoch)
	}
	if epoch.Cmp(new(big.Int).Add(have, big.NewInt(1))) != 0 {
		return nil, refuse("epoch %s does not follow %s (fetch the missing manifests and accept them in order)", epoch, have)
	}
	if candidate["prev_digest"] != Digest(current) {
		return nil, refuse("prev_digest does not chain to the current manifest")
	}
	if candidate["schema"] != current["schema"] {
		if schemaIndex(candidate["schema"].(string)) <= schemaIndex(current["schema"].(string)) {
			return nil, refuse("schema %s cannot follow %s: the schema only moves forward", candidate["schema"], current["schema"])
		}
		if signer != "root" {
			return nil, refuse("only the root can change the schema (%s to %s)", current["schema"], candidate["schema"])
		}
	}
	if err := tombstones(current, candidate); err != nil {
		return nil, err
	}
	bothV4 := current["schema"] == SchemaV4 && candidate["schema"] == SchemaV4
	// K_A is named by every node's TPM objects (#361): no signer changes it; a new K_A is a new genesis. (v3 -> v4,
	// root-signed, is where it is first set.)
	if bothV4 && !equal(candidate["anchor_policy_key"], current["anchor_policy_key"]) {
		return nil, refuse("anchor_policy_key is set at genesis and never changes, for any signer: every node's TPM objects " +
			"are defined under it (a new one is a new genesis)")
	}
	if bothV4 && !belowQuorum(current) && belowQuorum(candidate) && candidate["recovery_ends_by"] != nil {
		return nil, refuse("this epoch drops the counting nodes below the activation threshold: recovery_ends_by must be " +
			"null (an earlier recovery's end does not carry over)")
	}
	if signer != "root" {
		if err := restrictive(current, candidate, signer); err != nil {
			return nil, err
		}
	} else if bothV4 {
		if err := cardRecordRules(current, candidate); err != nil {
			return nil, err
		}
		if err := recoveryEndRules(current, candidate); err != nil {
			return nil, err
		}
	}
	return candidate, nil
}

// AcceptChain is membership.accept_chain: each envelope in order.
func AcceptChain(current map[string]any, envelopes []any, root any) (map[string]any, error) {
	for _, envelope := range envelopes {
		next, err := Accept(current, envelope, root)
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

// LoadManifestOrEnvelope reads a document (Load) after refusing bytes that are not UTF-8, as Python's
// json.loads of bytes does.
func LoadDocument(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("not valid JSON: not UTF-8")
	}
	return Load(raw, MaxBytes)
}

// May is membership.may: whether node may `serve`, `request` (be unlocked) or `authorize` (give a
// contribution) under a manifest; false for a node it does not name. One difference: Python's may() RAISES
// for a manifest that does not validate, and May returns false. Call it only on a manifest Validate (or
// Accept) has passed, as bootcfg does; never rely on it to refuse one.
func May(manifest map[string]any, node, action string) bool {
	nodes, err := Validate(manifest)
	if err != nil {
		return false
	}
	entry, named := nodes[node]
	if !named {
		return false
	}
	state, _ := entry["state"].(string)
	for _, allowed := range capabilities[state] {
		if allowed == action {
			return true
		}
	}
	return false
}
