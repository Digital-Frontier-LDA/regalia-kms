package opstate

import (
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

// THE STATE EPOCH (#432 item (e), D32): which history the operational state holds. A lone survivor under the owner's
// "full" authorization takes etcd over with --force-new-cluster, which keeps the cluster ID and the revision, so its
// first write is /regalia/v1/state-epoch: the epoch N its authorization was given at, the owner's signed survivor
// authorization inside, signed by the node's signing_key in force when it is dated. This is
// deploy/baremetal/opstate.verify_state_epoch (and survivor.verify_authorization, which it needs) in Go, held to the
// same vector (tests/vectors/opstate-v1.json, state_epoch_checks) with the same refusals. The cache verifies the entry
// before applied.json reports its epoch; it is self-authorizing like every opstate value, so a server that rejoins
// after a wipe verifies it from etcd and the chain alone.

const (
	StateEpochSchema = "regalia.opstate-state-epoch/v1"
	StateEpochDomain = "regalia-opstate-state-epoch/v1\x00"
	StateEpochKey    = Prefix + "state-epoch"

	survivorAuthSchema  = "regalia.survivor-authorization/v1"
	survivorAuthDomain  = "regalia-survivor-authorization/v1\x00"
	survivorRequestLife = 900 // survivor.REQUEST_LIFE_S (opstate.MAX_REQUEST_LIFE_S)
	survivorSkew        = 60
	survivorFallback    = 600 // FALLBACK_EXTRA_S: a fence only attested, not read over iLO
	survivorMaxLife     = 7 * 24 * 3600
	survivorMaxFenced   = 512
)

var (
	stateEpochFields = []string{"schema", "state_epoch", "node_id", "authorization", "cluster_id", "revision_before", "issued_at"}
	survivorAuthKeys = []string{"schema", "node_id", "quarantine_epoch", "quarantine_digest", "not_before", "expires_at", "fenced", "scope", "fence"}
	nodeIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
)

// StoreRef is where a state-epoch entry was read: the etcd cluster (16 hex) and the entry's mod_revision.
type StoreRef struct {
	ClusterID   string
	ModRevision int64
}

// StateEpochMessage is opstate.state_epoch_message: the entry's form, then what its node signs.
func StateEpochMessage(value any) ([]byte, map[string]any, error) {
	entry, err := exactFields(value, stateEpochFields, "the state-epoch entry")
	if err != nil {
		return nil, nil, err
	}
	if entry["schema"] != StateEpochSchema {
		return nil, nil, refuse("schema must be %s", StateEpochSchema)
	}
	epoch, err := countOf(entry["state_epoch"], "state_epoch")
	if err != nil {
		return nil, nil, err
	}
	if epoch < 1 {
		return nil, nil, refuse("state_epoch is a manifest epoch, 1 or more")
	}
	if id, ok := entry["node_id"].(string); !ok || !nodeIDPattern.MatchString(id) {
		return nil, nil, refuse("node_id must be a node ID")
	}
	if err := hexOf(entry["cluster_id"], 16, "cluster_id"); err != nil {
		return nil, nil, err
	}
	if _, err := countOf(entry["revision_before"], "revision_before"); err != nil {
		return nil, nil, err
	}
	if _, err := timeOf(entry["issued_at"], "issued_at"); err != nil {
		return nil, nil, err
	}
	if _, ok := entry["authorization"].(map[string]any); !ok {
		return nil, nil, refuse("the state-epoch entry carries the owner's survivor authorization")
	}
	return append([]byte(StateEpochDomain), membership.Canonical(entry)...), entry, nil
}

// VerifyStateEpoch is opstate.verify_state_epoch: the entry at `key`, if it holds, else a Refused naming why.
// `chain` is the verified membership chain, oldest first; `previous` the verified entry it replaces, or nil;
// `store` where it was read, or nil before it is written.
func VerifyStateEpoch(key string, value any, chain []map[string]any, previous map[string]any, store *StoreRef) (map[string]any, error) {
	stored, err := exactFields(value, []string{"entry", "signature"}, "the state-epoch value")
	if err != nil {
		return nil, err
	}
	raw, entry, err := StateEpochMessage(stored["entry"])
	if err != nil {
		return nil, err
	}
	if key != StateEpochKey {
		return nil, refuse("the state-epoch entry belongs under %s, not %s", StateEpochKey, key)
	}
	if len(chain) == 0 {
		return nil, refuse("a state epoch is judged against the membership chain")
	}
	n, _ := countOf(entry["state_epoch"], "state_epoch")
	var atN map[string]any
	for _, manifest := range chain {
		if epoch, err := countOf(manifest["epoch"], "epoch"); err == nil && epoch == n {
			atN = manifest
			break
		}
	}
	if atN == nil {
		return nil, refuse("the chain holds no manifest at epoch %d", n)
	}
	node := entry["node_id"].(string)
	auth, err := verifySurvivorAuthorization(entry["authorization"], atN, node)
	if err != nil {
		return nil, err
	}
	if auth["scope"] != "full" {
		return nil, refuse("a take-over needs the owner's \"full\" authorization; this one is %s", auth["scope"])
	}
	issued, _ := timeOf(entry["issued_at"], "issued_at")
	_, expires, _ := validateSurvivorAuthorization(auth)
	if from := survivorFullFrom(auth); !(from <= issued && issued < expires) {
		return nil, refuse("the state epoch is dated %s, outside the authorization's full scope", entry["issued_at"])
	}
	var inForce map[string]any
	for _, manifest := range chain {
		at, err := timeOf(manifest["issued_at"], "a manifest's issued_at")
		if err != nil {
			return nil, err
		}
		if at <= issued {
			inForce = manifest
		}
	}
	var alg, publicKey string
	ok := false
	if inForce != nil {
		if alg, publicKey, ok, err = membership.NodeSigningKey(inForce, node); err != nil {
			return nil, asRefused(err)
		}
	}
	if !ok {
		return nil, refuse("%s had no signing key when its state epoch is dated", node)
	}
	if err := membership.VerifyTypedSignature(alg, publicKey, raw, stored["signature"], node+"'s state-epoch entry"); err != nil {
		return nil, asRefused(err)
	}
	if store != nil {
		if entry["cluster_id"] != store.ClusterID {
			return nil, refuse("the state-epoch entry names cluster %s; it is stored in cluster %s", entry["cluster_id"], store.ClusterID)
		}
		before, _ := countOf(entry["revision_before"], "revision_before")
		if store.ModRevision <= before {
			return nil, refuse("the state-epoch entry is stored at revision %d, not after the %d its take-over named", store.ModRevision, before)
		}
	}
	if previous != nil {
		held, err := countOf(previous["state_epoch"], "the previous state_epoch")
		if err != nil {
			return nil, err
		}
		if n <= held {
			return nil, refuse("the store holds state epoch %d; %d is not above it", held, n)
		}
	}
	return entry, nil
}

// validateSurvivorAuthorization is survivor.validate_authorization (form only): (not_before, expires_at) seconds.
func validateSurvivorAuthorization(value any) (int64, int64, error) {
	auth, err := exactFields(value, survivorAuthKeys, "the survivor authorization")
	if err != nil {
		return 0, 0, err
	}
	if auth["schema"] != survivorAuthSchema {
		return 0, 0, refuse("schema must be %s", survivorAuthSchema)
	}
	if id, ok := auth["node_id"].(string); !ok || !nodeIDPattern.MatchString(id) {
		return 0, 0, refuse("node_id must be a node ID")
	}
	if epoch, err := countOf(auth["quarantine_epoch"], "quarantine_epoch"); err != nil || epoch < 1 {
		return 0, 0, refuse("the authorization's quarantine_epoch must be an integer >= 1")
	}
	if err := hexOf(auth["quarantine_digest"], 64, "the authorization's quarantine_digest"); err != nil {
		return 0, 0, err
	}
	if !printableText(auth["fenced"], survivorMaxFenced) {
		return 0, 0, refuse("fenced must be printable text of at most %d bytes", survivorMaxFenced)
	}
	if !oneOf(auth["scope"], []string{"stateless", "full"}) {
		return 0, 0, refuse("scope must be one of stateless, full")
	}
	fence, err := exactFields(auth["fence"], []string{"method", "nodes"}, "the fence evidence")
	if err != nil {
		return 0, 0, err
	}
	if !oneOf(fence["method"], []string{"redfish", "attested"}) {
		return 0, 0, refuse("the fence method must be one of redfish, attested")
	}
	fenced, ok := fence["nodes"].(map[string]any)
	if !ok || len(fenced) == 0 {
		return 0, 0, refuse("the fence evidence names the fenced nodes")
	}
	want := "unreachable"
	if fence["method"] == "redfish" {
		want = "Off"
	}
	ids := make([]string, 0, len(fenced))
	for id := range fenced {
		ids = append(ids, id)
	}
	sort.Strings(ids) // Python walks the JSON's own order; one refusal among several may be named differently
	for _, id := range ids {
		if !nodeIDPattern.MatchString(id) {
			return 0, 0, refuse("the fence evidence names node IDs")
		}
		seen, err := exactFields(fenced[id], []string{"power_state", "read_at"}, "the fence evidence for "+id)
		if err != nil {
			return 0, 0, err
		}
		if _, err := timeOf(seen["read_at"], "the fence evidence's read_at"); err != nil {
			return 0, 0, err
		}
		if seen["power_state"] != want {
			return 0, 0, refuse("a %s fence reads %s for every fenced node; %s's is %s", fence["method"], want, id, pyRepr(seen["power_state"]))
		}
	}
	start, err := timeOf(auth["not_before"], "not_before")
	if err != nil {
		return 0, 0, err
	}
	expires, err := timeOf(auth["expires_at"], "expires_at")
	if err != nil {
		return 0, 0, err
	}
	if start >= expires {
		return 0, 0, refuse("the authorization's expires_at must be after its not_before")
	}
	if expires-start > survivorMaxLife {
		return 0, 0, refuse("a survivor authorization lives at most %d s (this one: %d)", survivorMaxLife, expires-start)
	}
	return start, expires, nil
}

// verifySurvivorAuthorization is survivor.verify_authorization against the manifest it was given at (`current`).
func verifySurvivorAuthorization(value any, current map[string]any, nodeID string) (map[string]any, error) {
	signed, err := exactFields(value, []string{"authorization", "signature"}, "the signed survivor authorization")
	if err != nil {
		return nil, err
	}
	auth, _ := signed["authorization"].(map[string]any)
	if _, _, err := validateSurvivorAuthorization(signed["authorization"]); err != nil {
		return nil, err
	}
	message := append([]byte(survivorAuthDomain), membership.Canonical(auth)...)
	parties, err := membership.CountingParties(current, message, []any{signed["signature"]}, "survivor authorization")
	if err != nil {
		return nil, asRefused(err)
	}
	if len(parties) != 1 || !parties[membership.OwnerParty] {
		return nil, refuse("the survivor authorization is not the owner's")
	}
	epoch, _ := countOf(current["epoch"], "epoch")
	quarantine, _ := countOf(auth["quarantine_epoch"], "quarantine_epoch")
	if epoch != quarantine || membership.Digest(current) != auth["quarantine_digest"] {
		return nil, refuse("the survivor authorization is for epoch %d's manifest; this node's is epoch %d: a new epoch ends it", quarantine, epoch)
	}
	nodes, err := membership.Validate(current)
	if err != nil {
		return nil, asRefused(err)
	}
	survivor := auth["node_id"].(string)
	if node, has := nodes[survivor]; !has || membership.NotCounting(fmt.Sprint(node["state"])) {
		return nil, refuse("%s does not count under epoch %d: it is no survivor", survivor, epoch)
	}
	var loose, others []string
	for id, node := range nodes {
		if id == survivor {
			continue
		}
		others = append(others, id)
		if !membership.NotCounting(fmt.Sprint(node["state"])) {
			loose = append(loose, id)
		}
	}
	sort.Strings(loose)
	sort.Strings(others)
	if len(loose) > 0 {
		verb := "are"
		if len(loose) == 1 {
			verb = "is"
		}
		return nil, refuse("a lone survivor needs every other node quarantined, revoked or retired under epoch %d; %s %s not", epoch, strings.Join(loose, ", "), verb)
	}
	var named []string
	for id := range auth["fence"].(map[string]any)["nodes"].(map[string]any) {
		named = append(named, id)
	}
	sort.Strings(named)
	if strings.Join(named, ",") != strings.Join(others, ",") {
		return nil, refuse("the fence evidence names %s; the other nodes are %s", pyList(named), pyList(others))
	}
	if survivor != nodeID {
		return nil, refuse("the survivor authorization is for %s, not %s", survivor, nodeID)
	}
	return auth, nil
}

// survivorFullFrom is survivor.full_from: when a "full" authorization's stateful scope begins.
func survivorFullFrom(auth map[string]any) int64 {
	start, _, _ := validateSurvivorAuthorization(auth)
	extra := int64(0)
	if auth["fence"].(map[string]any)["method"] == "attested" {
		extra = survivorFallback
	}
	return start + survivorRequestLife + survivorSkew + extra
}

// printableText is survivor._text: printable, not blank, at most `limit` bytes (Python's str.isprintable is Go's
// unicode.IsPrint: letters, marks, numbers, punctuation, symbols and the ASCII space).
func printableText(value any, limit int) bool {
	text, ok := value.(string)
	if !ok || strings.TrimSpace(text) == "" || len(text) > limit {
		return false
	}
	for _, r := range text {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// pyRepr is Python's %r of a JSON value as a refusal names it: a string in single quotes, else its JSON.
func pyRepr(value any) string {
	if s, ok := value.(string); ok {
		return "'" + s + "'"
	}
	if n, ok := value.(interface{ String() string }); ok {
		if _, isBig := new(big.Int).SetString(n.String(), 10); isBig {
			return n.String()
		}
	}
	return string(membership.Canonical(value))
}
