package membership

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Activation by quorum (#432): the v2 activation lease and the owner's recovery authorization, verified under
// the verifier's CURRENT manifest. This is deploy/baremetal/activation.py's verify(), decision for decision
// (tests/vectors/activation-v2.json holds every call the Python tests make); the Gate (internal/fencing)
// adds the file, the chain, this node's identity and the time window.
const (
	ActivationSchema   = "regalia.activation/v2"
	ActivationDomain   = "regalia-activation/v2\x00"
	recoveryAuthSchema = "regalia.activation-recovery/v1"
	recoveryAuthDomain = "regalia-activation-recovery/v1\x00"
	// MaxActivationLeaseS is activation.MAX_LEASE_S, and internal/fencing.MaxLeaseDuration: one bound.
	MaxActivationLeaseS = 600
	maxFencedBytes      = 512
)

var (
	leaseKeys     = []string{"schema", "node_id", "site", "registry_digest", "activation_epoch", "manifest_epoch", "manifest_digest", "not_before", "expires_at"}
	authKeys      = []string{"schema", "node_id", "site", "registry_digest", "quarantine_epoch", "quarantine_digest", "not_before", "expires_at", "fenced"}
	sitePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`) // a registry site (>= 3 characters), not a node_id
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	epochLimit    = new(big.Int).Lsh(big.NewInt(1), 63)
)

// parseTime is heartbeat.parse_time: exactly YYYY-MM-DDTHH:MM:SSZ, a real date, as unix seconds. Seconds 60
// and 61 are refused here where Python's strptime takes them: stricter, so fail closed.
func parseTime(value any, label string) (int64, error) {
	if text, ok := value.(string); !ok || !issuedAtPattern.MatchString(text) {
		return 0, refuse("%s must be UTC, YYYY-MM-DDTHH:MM:SSZ", label)
	}
	if !issuedAt(value) {
		return 0, refuse("%s is not a real date", label)
	}
	t, err := time.Parse("2006-01-02T15:04:05Z", value.(string))
	if err != nil {
		return 0, refuse("%s is not a real date", label)
	}
	return t.Unix(), nil
}

func activationEpoch(value any, label string) (int64, error) {
	n, ok := integer(value)
	if !ok || n.Sign() < 1 || n.Cmp(epochLimit) >= 0 {
		return 0, refuse("%s must be an integer >= 1", label)
	}
	return n.Int64(), nil
}

func matches(value any, pattern *regexp.Regexp) bool {
	text, ok := value.(string)
	return ok && pattern.MatchString(text)
}

// validateLease is activation.validate: the schema only. Returns (not_before, expires).
func validateLease(value any) (map[string]any, int64, int64, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, 0, 0, refuse("the activation lease is an object")
	}
	keys := leaseKeys
	if _, has := object["recovery"]; has {
		keys = append(append([]string(nil), leaseKeys...), "recovery")
	}
	lease, err := exact(object, keys, "the activation lease")
	if err != nil {
		return nil, 0, 0, err
	}
	checks := []struct {
		ok   bool
		text string
	}{
		{lease["schema"] == ActivationSchema, "schema must be " + ActivationSchema},
		{matches(lease["node_id"], nodeIDPattern), "node_id must be a node ID"},
		{matches(lease["site"], sitePattern), "site must be a registry site name"},
		{matches(lease["registry_digest"], digestPattern), "registry_digest must be sha256:<64 hex>"},
	}
	for _, c := range checks {
		if !c.ok {
			return nil, 0, 0, refuse("%s", c.text)
		}
	}
	if _, err := activationEpoch(lease["activation_epoch"], "activation_epoch"); err != nil {
		return nil, 0, 0, err
	}
	manifestEpoch, err := activationEpoch(lease["manifest_epoch"], "manifest_epoch")
	if err != nil {
		return nil, 0, 0, err
	}
	if err := hexField(lease["manifest_digest"], 64, "manifest_digest"); err != nil {
		return nil, 0, 0, err
	}
	start, err := parseTime(lease["not_before"], "not_before")
	if err != nil {
		return nil, 0, 0, err
	}
	expires, err := parseTime(lease["expires_at"], "expires_at")
	if err != nil {
		return nil, 0, 0, err
	}
	if start >= expires {
		return nil, 0, 0, refuse("expires_at must be after not_before")
	}
	if expires-start > MaxActivationLeaseS {
		return nil, 0, 0, refuse("an activation lease lives at most %d s (this one: %d)", MaxActivationLeaseS, expires-start)
	}
	if _, has := lease["recovery"]; has {
		block, err := exact(lease["recovery"], []string{"authorization", "signature"}, "the recovery block")
		if err != nil {
			return nil, 0, 0, err
		}
		auth, _, _, err := validateAuthorization(block["authorization"])
		if err != nil {
			return nil, 0, 0, err
		}
		quarantine, _ := activationEpoch(auth["quarantine_epoch"], "quarantine_epoch")
		if manifestEpoch != quarantine {
			return nil, 0, 0, refuse("a recovery lease names the quarantine manifest, epoch %d", quarantine)
		}
	}
	return lease, start, expires, nil
}

// printable is Python's str.isprintable for the text a recovery authorization attests.
func printable(text string) bool {
	for _, r := range text {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// validateAuthorization is activation.validate_authorization: the owner's recovery authorization, schema only.
func validateAuthorization(value any) (map[string]any, int64, int64, error) {
	auth, err := exact(value, authKeys, "the recovery authorization")
	if err != nil {
		return nil, 0, 0, err
	}
	fenced, isText := auth["fenced"].(string)
	checks := []struct {
		ok   bool
		text string
	}{
		{auth["schema"] == recoveryAuthSchema, "schema must be " + recoveryAuthSchema},
		{matches(auth["node_id"], nodeIDPattern), "node_id must be a node ID"},
		{matches(auth["site"], sitePattern), "site must be a registry site name"},
		{matches(auth["registry_digest"], digestPattern), "registry_digest must be sha256:<64 hex>"},
	}
	for _, c := range checks {
		if !c.ok {
			return nil, 0, 0, refuse("%s", c.text)
		}
	}
	if _, err := activationEpoch(auth["quarantine_epoch"], "quarantine_epoch"); err != nil {
		return nil, 0, 0, err
	}
	if err := hexField(auth["quarantine_digest"], 64, "quarantine_digest"); err != nil {
		return nil, 0, 0, err
	}
	if !isText || strings.TrimSpace(fenced) == "" || len(fenced) > maxFencedBytes || !printable(fenced) {
		return nil, 0, 0, refuse("fenced must be printable text of at most %d bytes", maxFencedBytes)
	}
	start, err := parseTime(auth["not_before"], "not_before")
	if err != nil {
		return nil, 0, 0, err
	}
	expires, err := parseTime(auth["expires_at"], "expires_at")
	if err != nil {
		return nil, 0, 0, err
	}
	if start >= expires {
		return nil, 0, 0, refuse("the authorization's expires_at must be after its not_before")
	}
	return auth, start, expires, nil
}

func sortedParties(parties map[string]bool) string {
	names := make([]string, 0, len(parties))
	for p := range parties {
		names = append(names, p)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func ruleParties(current map[string]any) ([]string, int64) {
	rule := current["activation_signers"].(map[string]any)
	var parties []string
	for _, p := range rule["parties"].([]any) {
		parties = append(parties, p.(string))
	}
	threshold, _ := integer(rule["threshold"])
	return parties, threshold.Int64()
}

// authorizationHolds is activation._authorization_holds: the owner's authorization checked against the
// CURRENT manifest. The current manifest has passed Validate.
func authorizationHolds(value any, current map[string]any) (map[string]any, error) {
	signed, err := exact(value, []string{"authorization", "signature"}, "the signed recovery authorization")
	if err != nil {
		return nil, err
	}
	auth, start, expires, err := validateAuthorization(signed["authorization"])
	if err != nil {
		return nil, err
	}
	message := append([]byte(recoveryAuthDomain), Canonical(auth)...)
	parties, err := countingParties(current, message, []any{signed["signature"]}, "recovery authorization")
	if err != nil {
		return nil, err
	}
	if len(parties) != 1 || !parties[ownerParty] {
		return nil, refuse("the recovery authorization is not the owner's")
	}
	quarantine, _ := activationEpoch(auth["quarantine_epoch"], "quarantine_epoch")
	epoch, _ := integer(current["epoch"])
	if epoch.Cmp(big.NewInt(quarantine)) != 0 || Digest(current) != auth["quarantine_digest"] {
		return nil, refuse("the recovery authorization is for epoch %d's manifest; this node's is epoch %s: a new epoch ends it", quarantine, epoch)
	}
	maxLife, _ := integer(current["recovery_authorization_max_s"])
	if big.NewInt(expires-start).Cmp(maxLife) > 0 {
		return nil, refuse("the recovery authorization lives %d s, more than the manifest's recovery_authorization_max_s (%s)", expires-start, maxLife)
	}
	nodes, _ := Validate(current)
	rule, _ := ruleParties(current)
	survivor := auth["node_id"].(string)
	counts := func(p string) bool {
		node, named := nodes[p]
		return named && !notCounting[node["state"].(string)]
	}
	if !contains(rule, survivor) || !counts(survivor) {
		return nil, refuse("%s does not count toward activation under epoch %s", survivor, epoch)
	}
	var loose []string
	for _, p := range rule {
		if p != ownerParty && p != survivor && counts(p) {
			loose = append(loose, p)
		}
	}
	if len(loose) > 0 {
		verb := "are"
		if len(loose) == 1 {
			verb = "is"
		}
		return nil, refuse("the recovery path needs every other node party quarantined or revoked under epoch %s; %s %s not", epoch, strings.Join(loose, ", "), verb)
	}
	return auth, nil
}

// VerifyActivation is activation.verify: the lease of `envelope` if its signatures meet the CURRENT manifest's
// activation rule, else a *Refused. The lease may name an older manifest (no serving gap at an epoch change),
// never a newer one, and is counted under the current signers and keys. NORMAL: the threshold of node parties,
// the owner never. RECOVERY (#432 amendment 5): the survivor alone, carrying the owner's authorization, while
// the current manifest is its quarantine manifest. Time is the caller's. Returns the lease and the hex SHA-256
// of its signed message (ActivationDomain + canonical lease), which names it.
func VerifyActivation(value any, current map[string]any) (map[string]any, string, error) {
	envelope, err := exact(value, []string{"lease", "signatures"}, "the activation envelope")
	if err != nil {
		return nil, "", err
	}
	lease, start, end, err := validateLease(envelope["lease"])
	if err != nil {
		return nil, "", err
	}
	message := append([]byte(ActivationDomain), Canonical(lease)...)
	if current == nil || current["schema"] != SchemaV4 {
		return nil, "", refuse("activation by quorum needs a %s manifest", SchemaV4)
	}
	nodes, err := Validate(current)
	if err != nil {
		return nil, "", err
	}
	epoch, _ := integer(current["epoch"])
	named, _ := activationEpoch(lease["manifest_epoch"], "manifest_epoch")
	if big.NewInt(named).Cmp(epoch) > 0 {
		return nil, "", refuse("the lease names manifest epoch %d, newer than this node's %s", named, epoch)
	}
	if big.NewInt(named).Cmp(epoch) == 0 && lease["manifest_digest"] != Digest(current) {
		return nil, "", refuse("the lease names another manifest at epoch %s", epoch)
	}
	node := lease["node_id"].(string)
	if _, has := nodes[node]; !has {
		return nil, "", refuse("%s is not a node of the current manifest", node)
	}
	if !May(current, node, "serve") {
		return nil, "", refuse("%s may not serve under epoch %s", node, epoch)
	}
	rule, threshold := ruleParties(current)
	signers, err := countingParties(current, message, envelope["signatures"], "activation lease")
	if err != nil {
		return nil, "", err
	}
	counted, nodeParties := map[string]bool{}, map[string]bool{}
	for p := range signers {
		if contains(rule, p) {
			counted[p] = true
			if p != ownerParty {
				nodeParties[p] = true
			}
		}
	}
	if counted[ownerParty] {
		return nil, "", refuse("the owner signs a recovery authorization, never a lease")
	}
	named2 := sortedParties(nodeParties)
	if _, recovery := lease["recovery"]; !recovery {
		if int64(len(nodeParties)) < threshold {
			if named2 == "" {
				named2 = "none"
			}
			return nil, "", refuse("%d of the nodes signed (%s); activation needs %d", len(nodeParties), named2, threshold)
		}
		return lease, digestOf(message), nil
	}
	auth, err := authorizationHolds(lease["recovery"], current)
	if err != nil {
		return nil, "", err
	}
	if lease["node_id"] != auth["node_id"] || lease["site"] != auth["site"] || lease["registry_digest"] != auth["registry_digest"] {
		return nil, "", refuse("the recovery authorization is for %s, site %s; the lease names %s, site %s", auth["node_id"], auth["site"], lease["node_id"], lease["site"])
	}
	aStart, _ := parseTime(auth["not_before"], "not_before")
	aEnd, _ := parseTime(auth["expires_at"], "expires_at")
	if !(aStart <= start && end <= aEnd) {
		return nil, "", refuse("the lease's window is not inside the recovery authorization's")
	}
	survivor := auth["node_id"].(string)
	if len(nodeParties) != 1 || !nodeParties[survivor] {
		if named2 == "" {
			named2 = "nobody"
		}
		return nil, "", refuse("a recovery lease is signed by the survivor %s (signed by: %s)", survivor, named2)
	}
	if int64(len(nodeParties))+1 < threshold {
		return nil, "", refuse("the survivor and the owner's authorization are below the threshold %d", threshold)
	}
	return lease, digestOf(message), nil
}

func digestOf(message []byte) string {
	sum := sha256.Sum256(message)
	return hex.EncodeToString(sum[:])
}
