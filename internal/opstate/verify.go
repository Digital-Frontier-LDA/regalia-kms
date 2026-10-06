package opstate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

// THE ENTRY FORMAT (opstate-v1, deploy/baremetal/opstate.py, regalia-kms-48). Every value under Prefix is
// {"entry": …, "signatures": […]}, signed over EntryDomain + canonical(entry), and every server verifies it
// before acting on it. This is opstate.py's verify(), transition() and batch(), decision for decision; the
// shared vector tests/vectors/opstate-v1.json holds them alike.
const (
	EntrySchema   = "regalia.opstate/v1"
	EntryDomain   = "regalia-opstate/v1\x00"
	MaxBatch      = 64
	MaxEntryBytes = 4096
	MaxApprovers  = 64
	// MaxRequestLifeS is opstate.MAX_REQUEST_LIFE_S: the longest a request may stay spendable after it is spent.
	// A lone survivor's full scope waits it out, so it is a cap the spend enforces (1e).
	MaxRequestLifeS = 900
)

var (
	entryKinds  = []string{"spend", "sequence", "quota", "key-state"}
	keyStates   = []string{"enabled", "disabled", "destroyed"}
	nodeSigned  = map[string]bool{"spend": true, "sequence": true, "quota": true}
	namePattern = regexp.MustCompile(`^[\x21-\x7e]{1,256}$`)
	datePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	timePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	nodePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	hexPattern  = map[int]*regexp.Regexp{16: regexp.MustCompile(`^[0-9a-f]{16}$`), 64: regexp.MustCompile(`^[0-9a-f]{64}$`), 128: regexp.MustCompile(`^[0-9a-f]{128}$`)}
	countLimit  = new(big.Int).Lsh(big.NewInt(1), 63)
	// a key's signing profile: cosmos-account, cosmos-validator, ... fixed at the key's creation
	profilePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	common         = []string{"schema", "kind", "at"}
	entryFields    = map[string][]string{
		"spend": append(append([]string(nil), common...), "nonce_digest", "principal", "object_id", "purpose", "environment", "payload_sha256",
			"approvers", "approver_set", "approvals_sha256", "node_id", "boot_id", "lease_digest", "lease_expires_at", "expires_at"),
		"sequence":  append(append([]string(nil), common...), "sequence_key", "value", "nonce_digest", "node_id", "boot_id"),
		"quota":     append(append([]string(nil), common...), "principal", "utc_date", "counter", "total", "cap", "nonce_digest", "node_id", "boot_id"),
		"key-state": append(append([]string(nil), common...), "object_id", "state", "version", "prev_digest", "approver_set", "signing_profile"),
	}
)

// Refused is a decision not to accept an entry, with opstate.py's reason.
type Refused struct{ Reason string }

func (r *Refused) Error() string { return r.Reason }

func refuse(format string, args ...any) error { return &Refused{Reason: fmt.Sprintf(format, args...)} }

// pyList is Python's repr of a sorted list of strings, as membership.exact names fields.
func pyList(names []string) string {
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = "'" + n + "'"
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func exactFields(value any, keys []string, label string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, refuse("%s must be an object", label)
	}
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	var missing, unknown []string
	for _, k := range keys {
		if _, has := object[k]; !has {
			missing = append(missing, k)
		}
	}
	for k := range object {
		if !want[k] {
			unknown = append(unknown, k)
		}
	}
	if len(missing) > 0 || len(unknown) > 0 {
		sort.Strings(missing)
		sort.Strings(unknown)
		return nil, refuse("%s fields mismatch: missing=%s unknown=%s", label, pyList(missing), pyList(unknown))
	}
	return object, nil
}

func hexOf(value any, n int, label string) error {
	if s, ok := value.(string); !ok || !hexPattern[n].MatchString(s) {
		return refuse("%s must be %d lowercase hex", label, n)
	}
	return nil
}

func nameOf(value any, label string) error {
	if s, ok := value.(string); !ok || !namePattern.MatchString(s) {
		return refuse("%s must be 1 to 256 printable characters, no space", label)
	}
	return nil
}

func countOf(value any, label string) (int64, error) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, refuse("%s must be an integer from 0", label)
	}
	n, ok := new(big.Int).SetString(string(number), 10)
	if !ok || n.Sign() < 0 || n.Cmp(countLimit) >= 0 {
		return 0, refuse("%s must be an integer from 0", label)
	}
	return n.Int64(), nil
}

// timeOf is heartbeat.parse_time: exactly YYYY-MM-DDTHH:MM:SSZ and a real date, as unix seconds.
func timeOf(value any, label string) (int64, error) {
	text, ok := value.(string)
	if !ok || !timePattern.MatchString(text) {
		return 0, refuse("%s must be UTC, YYYY-MM-DDTHH:MM:SSZ", label)
	}
	t, err := time.Parse("2006-01-02T15:04:05Z", text)
	if err != nil {
		return 0, refuse("%s is not a real date", label)
	}
	return t.Unix(), nil
}

func oneOf(value any, list []string) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	for _, l := range list {
		if s == l {
			return true
		}
	}
	return false
}

// ValidateEntry is opstate.validate: the schema only. Returns the entry and its kind.
func ValidateEntry(value any) (map[string]any, string, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, "", refuse("the entry must be an object")
	}
	if !oneOf(object["kind"], entryKinds) {
		return nil, "", refuse("kind must be one of %s", strings.Join(entryKinds, ", "))
	}
	kind := object["kind"].(string)
	entry, err := exactFields(object, entryFields[kind], "the "+kind+" entry")
	if err != nil {
		return nil, "", err
	}
	if entry["schema"] != EntrySchema {
		return nil, "", refuse("schema must be %s", EntrySchema)
	}
	at, err := timeOf(entry["at"], "at")
	if err != nil {
		return nil, "", err
	}
	if len(membership.Canonical(entry)) > MaxEntryBytes {
		return nil, "", refuse("the entry is over %d bytes", MaxEntryBytes)
	}
	if nodeSigned[kind] {
		if s, ok := entry["node_id"].(string); !ok || !nodePattern.MatchString(s) {
			return nil, "", refuse("node_id must be a node ID")
		}
		if s, ok := entry["boot_id"].(string); !ok || !bootIDPattern.MatchString(s) {
			return nil, "", refuse("boot_id must be a boot UUID")
		}
		if err := hexOf(entry["nonce_digest"], 64, "nonce_digest"); err != nil {
			return nil, "", err
		}
	}
	switch kind {
	case "spend":
		for _, k := range []string{"principal", "object_id", "purpose", "environment"} {
			if err := nameOf(entry[k], k); err != nil {
				return nil, "", err
			}
		}
		for _, k := range []string{"payload_sha256", "lease_digest", "approver_set", "approvals_sha256"} {
			if err := hexOf(entry[k], 64, k); err != nil {
				return nil, "", err
			}
		}
		list, ok := entry["approvers"].([]any)
		if !ok || len(list) > MaxApprovers {
			return nil, "", refuse("approvers must be a list of at most %d", MaxApprovers)
		}
		names := make([]string, len(list))
		for i, a := range list {
			if err := nameOf(a, "an approver ID"); err != nil {
				return nil, "", err
			}
			names[i] = a.(string)
		}
		for i := 1; i < len(names); i++ {
			if names[i-1] >= names[i] {
				return nil, "", refuse("approvers must be sorted, each once")
			}
		}
		leaseEnd, err := timeOf(entry["lease_expires_at"], "lease_expires_at")
		if err != nil {
			return nil, "", err
		}
		if leaseEnd <= at {
			return nil, "", refuse("the signing node's lease had run out when it spent")
		}
		expires, err := timeOf(entry["expires_at"], "expires_at")
		if err != nil {
			return nil, "", err
		}
		if expires <= at {
			return nil, "", refuse("the request had expired when it was spent")
		}
		if expires-at > MaxRequestLifeS {
			return nil, "", refuse("the request stays spendable %d s after it is spent, more than %d s: refused (a lone survivor's wait is bounded by this)", expires-at, MaxRequestLifeS)
		}
	case "sequence":
		if err := nameOf(entry["sequence_key"], "sequence_key"); err != nil {
			return nil, "", err
		}
		if _, err := countOf(entry["value"], "value"); err != nil {
			return nil, "", err
		}
	case "quota":
		if err := nameOf(entry["principal"], "principal"); err != nil {
			return nil, "", err
		}
		date, ok := entry["utc_date"].(string)
		if !ok || !datePattern.MatchString(date) {
			return nil, "", refuse("utc_date must be YYYY-MM-DD")
		}
		if _, err := timeOf(date+"T00:00:00Z", "utc_date"); err != nil {
			return nil, "", err
		}
		if err := nameOf(entry["counter"], "counter"); err != nil {
			return nil, "", err
		}
		total, err := countOf(entry["total"], "total")
		if err != nil {
			return nil, "", err
		}
		limit, err := countOf(entry["cap"], "cap")
		if err != nil {
			return nil, "", err
		}
		if total > limit {
			return nil, "", refuse("the total %d is over the cap %d", total, limit)
		}
	default:
		if err := nameOf(entry["object_id"], "object_id"); err != nil {
			return nil, "", err
		}
		if !oneOf(entry["state"], keyStates) {
			return nil, "", refuse("state must be one of %s", strings.Join(keyStates, ", "))
		}
		version, err := countOf(entry["version"], "version")
		if err != nil || version < 1 {
			return nil, "", refuse("version must be an integer from 1")
		}
		if version == 1 {
			if entry["prev_digest"] != "" {
				return nil, "", refuse("the first state of a key replaces nothing (prev_digest \"\")")
			}
		} else if err := hexOf(entry["prev_digest"], 64, "prev_digest"); err != nil {
			return nil, "", err
		}
		if err := hexOf(entry["approver_set"], 64, "approver_set"); err != nil {
			return nil, "", err
		}
		if text, ok := entry["signing_profile"].(string); !ok || !profilePattern.MatchString(text) {
			return nil, "", refuse("signing_profile must be a profile name")
		}
	}
	return entry, kind, nil
}

func hashName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return hex.EncodeToString(sum[:])
}

// KeyFor is opstate.key_for: the etcd key an entry lives under.
func KeyFor(value any) (string, error) {
	entry, kind, err := ValidateEntry(value)
	if err != nil {
		return "", err
	}
	switch kind {
	case "spend":
		return Prefix + "nonces/" + entry["nonce_digest"].(string), nil
	case "sequence":
		return Prefix + "seq/" + hashName(entry["sequence_key"].(string)), nil
	case "quota":
		return Prefix + "quota/" + hashName(entry["principal"].(string)) + "/" + entry["utc_date"].(string) + "/" + hashName(entry["counter"].(string)), nil
	}
	return Prefix + "keys/" + hashName(entry["object_id"].(string)) + "/state", nil
}

func verifyEd25519(keyHex, sigValue any, raw []byte, label string) error {
	if err := hexOf(keyHex, 64, label+" key"); err != nil {
		return err
	}
	if err := hexOf(sigValue, 128, label+" signature"); err != nil {
		return err
	}
	key, _ := hex.DecodeString(keyHex.(string))
	sig, _ := hex.DecodeString(sigValue.(string))
	if !ed25519.Verify(ed25519.PublicKey(key), raw, sig) {
		return refuse("%s signature does not verify", label)
	}
	return nil
}

// printableName is membership.printable: one line of printable ASCII, for a name a writer chose.
func printableName(value any) string {
	text := fmt.Sprint(value)
	var b strings.Builder
	for _, r := range text {
		if r >= ' ' && r <= '~' {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	out := b.String()
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// ApproverSet is one D25 approver set a key-state entry may name: {approver ID: Ed25519 key hex} and the
// threshold. A verifier keeps every set the policy has had, by digest, as it keeps manifests: an entry signed
// under an earlier set still verifies after the set is rotated.
type ApproverSet struct {
	Approvers map[string]string
	Required  int
}

// Digest is opstate.approver_set_digest: SHA-256 of canonical({"approvers": …, "required": n}).
func (set ApproverSet) Digest() string {
	approvers := make(map[string]any, len(set.Approvers))
	for id, key := range set.Approvers {
		approvers[id] = key
	}
	sum := sha256.Sum256(membership.Canonical(map[string]any{"approvers": approvers, "required": json.Number(strconv.Itoa(set.Required))}))
	return hex.EncodeToString(sum[:])
}

// EntryDigest is opstate.entry_digest: what the next key-state entry names as prev_digest.
func EntryDigest(entry map[string]any) string {
	sum := sha256.Sum256(membership.Canonical(entry))
	return hex.EncodeToString(sum[:])
}

// Sessions says whether a verified session entry (VerifySession) names `key` (64 hex) for that node and boot,
// and `at` (the entry's) lies in its window: from its issued_at, before its valid_until. A daemon start makes a
// key, so one boot may have several.
type Sessions func(nodeID, bootID, key, at string) bool

// VerifyValue is opstate.verify: the entry stored at `key` as `value`, if it verifies. Node-signed kinds are
// signed by the node's session key; a key-state change by the approver set it names, which must be one of
// `approverSets` (by digest).
func VerifyValue(key string, value any, sessions Sessions, approverSets map[string]ApproverSet) (map[string]any, error) {
	stored, err := exactFields(value, []string{"entry", "signatures"}, "the opstate value")
	if err != nil {
		return nil, err
	}
	want, err := KeyFor(stored["entry"])
	if err != nil {
		return nil, err
	}
	if key != want {
		return nil, refuse("the entry belongs under %s, not %s", want, key)
	}
	entry, kind, _ := ValidateEntry(stored["entry"])
	raw := append([]byte(EntryDomain), membership.Canonical(entry)...)
	signatures, ok := stored["signatures"].([]any)
	if !ok || len(signatures) == 0 {
		return nil, refuse("the entry carries no signature")
	}
	if nodeSigned[kind] {
		if len(signatures) != 1 {
			return nil, refuse("a node's entry carries exactly one signature")
		}
		sig, err := exactFields(signatures[0], []string{"party", "boot_id", "session_key", "sig"}, "the node's signature")
		if err != nil {
			return nil, err
		}
		if sig["party"] != entry["node_id"] || sig["boot_id"] != entry["boot_id"] {
			return nil, refuse("the entry is signed as %s, boot %s; it names %s, boot %s", sig["party"], sig["boot_id"], entry["node_id"], entry["boot_id"])
		}
		if err := hexOf(sig["session_key"], 64, "the signature's session_key"); err != nil {
			return nil, err
		}
		node, boot, session := entry["node_id"].(string), entry["boot_id"].(string), sig["session_key"].(string)
		if !sessions(node, boot, session, entry["at"].(string)) {
			return nil, refuse("no verified session entry names that key for %s in boot %s at %s", node, boot, entry["at"])
		}
		if err := verifyEd25519(session, sig["sig"], raw, node+"'s session"); err != nil {
			return nil, err
		}
		return entry, nil
	}
	setDigest := entry["approver_set"].(string)
	named, known := approverSets[setDigest]
	if !known {
		return nil, refuse("the approver set %s is not one this verifier knows", setDigest[:16])
	}
	if named.Digest() != setDigest {
		return nil, refuse("the approver set held under %s is not that set", setDigest[:16])
	}
	approvers, required := named.Approvers, named.Required
	if required < 1 || len(approvers) == 0 {
		return nil, refuse("a key-state change needs an approver set and a threshold")
	}
	if len(signatures) > MaxApprovers {
		return nil, refuse("at most %d approvals", MaxApprovers)
	}
	counted := map[string]bool{}
	for _, value := range signatures {
		sig, err := exactFields(value, []string{"party", "sig"}, "an approval")
		if err != nil {
			return nil, err
		}
		party, isText := sig["party"].(string)
		approverKey, known := approvers[party]
		if !isText || !known {
			return nil, refuse("%s is not an approver", printableName(sig["party"]))
		}
		if counted[party] {
			return nil, refuse("%s approved twice", party)
		}
		if err := verifyEd25519(approverKey, sig["sig"], raw, party+"'s approval"); err != nil {
			return nil, err
		}
		counted[party] = true
	}
	if len(counted) < required {
		return nil, refuse("%d of %d required approvals", len(counted), required)
	}
	return entry, nil
}

// Transition is opstate.transition: whether `entry` may replace `previous` (nil: the key does not exist),
// both verified. What etcd's compare cannot say.
func Transition(previous, entry map[string]any) error {
	kind := entry["kind"].(string)
	if previous == nil {
		if kind == "key-state" && string(entry["version"].(json.Number)) != "1" {
			return refuse("the key %s has no state on record; version %s replaces one", entry["object_id"], entry["version"])
		}
		return nil
	}
	if previous["kind"] != kind {
		return refuse("a %s entry cannot replace a %s entry", kind, previous["kind"])
	}
	switch kind {
	case "spend":
		return refuse("SPENT: the nonce %s was spent by %s at %s", entry["nonce_digest"].(string)[:16], previous["node_id"], previous["at"])
	case "sequence":
		was, _ := strconv.ParseInt(string(previous["value"].(json.Number)), 10, 64)
		now, _ := strconv.ParseInt(string(entry["value"].(json.Number)), 10, 64)
		if now <= was {
			return refuse("the sequence %s is at %d; %d is not above it", entry["sequence_key"], was, now)
		}
	case "quota":
		was, _ := strconv.ParseInt(string(previous["total"].(json.Number)), 10, 64)
		now, _ := strconv.ParseInt(string(entry["total"].(json.Number)), 10, 64)
		if now <= was {
			return refuse("a quota total only grows within its day (%d, then %d)", was, now)
		}
	default:
		if previous["state"] == "destroyed" {
			return refuse("the key %s is destroyed: its state is final", entry["object_id"])
		}
		if entry["signing_profile"] != previous["signing_profile"] {
			return refuse("the key %s's signing profile is %s from its creation; %s is refused", entry["object_id"], previous["signing_profile"], entry["signing_profile"])
		}
		was, _ := strconv.ParseInt(string(previous["version"].(json.Number)), 10, 64)
		now, _ := strconv.ParseInt(string(entry["version"].(json.Number)), 10, 64)
		if now != was+1 || entry["prev_digest"] != EntryDigest(previous) {
			return refuse("REPLAY: the key %s is at version %d; this entry is version %d over another state", entry["object_id"], was, now)
		}
	}
	return nil
}

// Write is one entry of a Reserve's transaction: its key, its verified value's entry, and the entry it
// replaces (nil when the key is new).
type Write struct {
	Key      string
	Entry    map[string]any
	Previous map[string]any
}

// Batch is opstate.batch: one Reserve's transaction, every entry already verified. At most MaxBatch, each key
// once, exactly one spend, and every other entry naming the spend's nonce and node. Returns the nonce digest.
func Batch(writes []Write) (string, error) {
	if len(writes) == 0 || len(writes) > MaxBatch {
		return "", refuse("a transaction holds 1 to %d entries", MaxBatch)
	}
	seen := map[string]bool{}
	for _, w := range writes {
		if seen[w.Key] {
			return "", refuse("a transaction writes each key once")
		}
		seen[w.Key] = true
	}
	var spends []map[string]any
	for _, w := range writes {
		if w.Entry["kind"] == "spend" {
			spends = append(spends, w.Entry)
		}
	}
	if len(spends) != 1 {
		return "", refuse("a transaction holds exactly one spend (%d here)", len(spends))
	}
	digest, node := spends[0]["nonce_digest"], spends[0]["node_id"]
	for _, w := range writes {
		if w.Entry["kind"] == "key-state" {
			return "", refuse("a key-state change is its own transaction, never part of a Reserve")
		}
		if w.Entry["nonce_digest"] != digest || w.Entry["node_id"] != node {
			return "", refuse("every entry of a Reserve names its spend's nonce and node")
		}
		if err := Transition(w.Previous, w.Entry); err != nil {
			return "", err
		}
	}
	return digest.(string), nil
}
