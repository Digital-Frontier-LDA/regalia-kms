package membership

import (
	"crypto/ed25519"
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
	heartbeatMin     = 3600
	heartbeatHardMax = 7 * 24 * 3600
	domain           = "regalia-membership/v1\x00"
)

var (
	schemas      = []string{SchemaV1, SchemaV2} // in order: a chain never goes back
	capabilities = map[string][]string{"ACTIVE": {"authorize", "request", "serve"}, "MAINTENANCE": {"request"}, "DRAINING": {"serve"},
		"QUARANTINED": {}, "RETIRED": {}, "REVOKED_STOLEN": {}}
	terminal        = map[string]bool{"RETIRED": true, "REVOKED_STOLEN": true}
	manifestKeys    = []string{"schema", "epoch", "prev_digest", "policy_version", "issued_at", "revocation_keys", "nodes"}
	nodeKeys        = []string{"node_id", "state", "ek_name", "ak_name", "wg_boot_pub", "wg_service_pub", "hsm_serials"}
	identityKeys    = []string{"ek_name", "ak_name", "wg_boot_pub", "wg_service_pub"}
	v2ManifestKeys  = append(append([]string(nil), manifestKeys...), "heartbeat_max_lifetime_s")
	v2NodeKeys      = append(append([]string(nil), nodeKeys...), "ssh_host_pub")
	v2IdentityKeys  = append(append([]string(nil), identityKeys...), "ssh_host_pub")
	nodeIDPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	policyPattern   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
	serialPattern   = regexp.MustCompile(`^[A-Za-z0-9]{1,32}$`)
	issuedAtPattern = regexp.MustCompile(`^([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})T([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2})Z$`)
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

func identityKeysOf(node map[string]any) []string {
	if _, has := node["ssh_host_pub"]; has {
		return v2IdentityKeys
	}
	return identityKeys
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
	if schema != SchemaV1 && schema != SchemaV2 {
		return nil, refuse("schema must be %s or %s", SchemaV1, SchemaV2)
	}
	second := schema == SchemaV2
	keys, nodeKeySet := manifestKeys, nodeKeys
	if second {
		keys, nodeKeySet = v2ManifestKeys, v2NodeKeys
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
	revocation, ok := manifest["revocation_keys"].([]any)
	if !ok {
		return nil, refuse("revocation_keys must be a list")
	}
	distinct := map[string]bool{}
	for _, key := range revocation {
		if err := hexField(key, 64, "a revocation key"); err != nil {
			return nil, err
		}
		distinct[key.(string)] = true
	}
	if len(distinct) != len(revocation) {
		return nil, refuse("revocation_keys must be distinct")
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
			_, hasSSH := object["ssh_host_pub"]
			state, _ := object["state"].(string)
			if !hasSSH && terminal[state] {
				keys = nodeKeys // a tombstone keeps the fields it had
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
			value := node[key].(string)
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
	return byID, nil
}

// VerifyEnvelope is membership.verify_envelope: the manifest inside, if its signature is by the pinned root
// key or by a revocation key named in the CURRENT manifest. Returns the manifest and the signer.
func VerifyEnvelope(value any, rootKey string, current map[string]any) (map[string]any, string, error) {
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
	if err := hexField(signature["key"], 64, "signature.key"); err != nil {
		return nil, "", err
	}
	if err := hexField(signature["sig"], 128, "signature.sig"); err != nil {
		return nil, "", err
	}
	key := signature["key"].(string)
	if signer == "root" {
		if key != rootKey {
			return nil, "", refuse("the signature names a root key that is not the pinned root")
		}
	} else {
		named := false
		if current != nil {
			for _, k := range current["revocation_keys"].([]any) {
				if k == key {
					named = true
				}
			}
		}
		if !named {
			return nil, "", refuse("the signing revocation key is not named by the current manifest")
		}
	}
	if _, err := Validate(envelope["manifest"]); err != nil {
		return nil, "", err
	}
	manifest := envelope["manifest"].(map[string]any)
	sig, _ := hex.DecodeString(signature["sig"].(string))
	if !verifySignature(algorithmOf(key), key, sig, append([]byte(domain), Canonical(manifest)...)) {
		return nil, "", refuse("the manifest signature does not verify")
	}
	return manifest, signer, nil
}

// algorithmOf is the signature algorithm of a key as the manifest names it. Today every key is a bare 64-hex
// Ed25519 public key (the root's, and every revocation key's). Typed revocation keys (an ECDSA P-256 key of a
// Nitrokey, #66) will be named by their manifest entry; the algorithm is taken from that entry and from
// nothing else, so a signature can never choose how it is checked.
func algorithmOf(key string) string { return "ed25519" }

// verifySignature checks a signature under the algorithm the manifest named for its key.
func verifySignature(algorithm, key string, sig, message []byte) bool {
	switch algorithm {
	case "ed25519":
		public, err := hex.DecodeString(key)
		if err != nil || len(public) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(public), message, sig)
	}
	return false
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

// restrictive is membership._restrictive: a revocation-signed change only narrows.
func restrictive(current, candidate map[string]any) error {
	if !equal(candidate["policy_version"], current["policy_version"]) {
		return refuse("a revocation key cannot change the policy version")
	}
	if !equal(candidate["revocation_keys"], current["revocation_keys"]) {
		return refuse("a revocation key cannot change the revocation keys")
	}
	if !equal(candidate["heartbeat_max_lifetime_s"], current["heartbeat_max_lifetime_s"]) {
		return refuse("a revocation key cannot change heartbeat_max_lifetime_s")
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
		return refuse("a revocation key cannot add or remove nodes")
	}
	for id := range old {
		if _, has := fresh[id]; !has {
			return refuse("a revocation key cannot add or remove nodes")
		}
	}
	for _, id := range sortedIDs(fresh) {
		node := fresh[id]
		for _, key := range append(append([]string(nil), identityKeysOf(node)...), "hsm_serials") {
			if !equal(node[key], old[id][key]) {
				return refuse("a revocation key cannot change %s of %s", key, id)
			}
		}
		if !subset(capabilities[node["state"].(string)], capabilities[old[id]["state"].(string)]) {
			return refuse("%s: %s -> %s widens capabilities; only the root can do that", id, old[id]["state"], node["state"])
		}
	}
	return nil
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
	for _, id := range sortedIDs(old) {
		node := old[id]
		state := node["state"].(string)
		next, present := fresh[id]
		if !terminal[state] {
			if !present {
				return refuse("tombstone: %s cannot be removed; retire it instead", id)
			}
			if terminal[next["state"].(string)] {
				if !sameKeys(next, node) {
					return refuse("tombstone: %s becomes %s and its fields cannot change in the same manifest", id, next["state"])
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
			return refuse("tombstone: %s is %s and must stay in every later manifest", id, state)
		}
		if !sameKeys(next, node) {
			return refuse("tombstone: %s is %s and its fields cannot change", id, state)
		}
		for _, key := range append(append([]string(nil), identityKeysOf(node)...), "hsm_serials") {
			if !equal(next[key], node[key]) {
				return refuse("tombstone: %s is %s and its %s cannot change", id, state, key)
			}
		}
		nextState := next["state"].(string)
		if nextState != state && !(state == "RETIRED" && nextState == "REVOKED_STOLEN") {
			return refuse("tombstone: %s is %s, which is terminal for every signer", id, state)
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
func Accept(current map[string]any, envelope any, rootKey string) (map[string]any, error) {
	candidate, signer, err := VerifyEnvelope(envelope, rootKey, current)
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
		return nil, refuse("epoch %s does not follow %s", epoch, have)
	}
	if candidate["prev_digest"] != Digest(current) {
		return nil, refuse("prev_digest does not chain to the current manifest")
	}
	if candidate["schema"] != current["schema"] {
		if schemaIndex(candidate["schema"].(string)) <= schemaIndex(current["schema"].(string)) {
			return nil, refuse("schema %s cannot follow %s: the schema only moves forward", candidate["schema"], current["schema"])
		}
		if signer != "root" {
			return nil, refuse("only the root can change the schema")
		}
	}
	if err := tombstones(current, candidate); err != nil {
		return nil, err
	}
	if signer == "revocation" {
		if err := restrictive(current, candidate); err != nil {
			return nil, err
		}
	}
	return candidate, nil
}

// AcceptChain is membership.accept_chain: each envelope in order.
func AcceptChain(current map[string]any, envelopes []any, rootKey string) (map[string]any, error) {
	for _, envelope := range envelopes {
		next, err := Accept(current, envelope, rootKey)
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
