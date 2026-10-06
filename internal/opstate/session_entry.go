package opstate

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

// THE SESSION ENTRY, THE APPROVALS BEHIND A SPEND, AND THE CHECK AT SIGN (opstate.py, 48 and 1e on #492).
const (
	SessionSchema = "regalia.opstate-session/v1"
	SessionDomain = "regalia-opstate-session/v1\x00"
	// SkewS is opstate.SKEW_S: between a signer's authenticated clock and etcd's leader.
	SkewS = 60
)

var (
	sessionFields  = []string{"schema", "node_id", "boot_id", "session_key", "issued_at"}
	approvalFields = []string{"approver_id", "nonce", "expires_at", "payload_digest", "signature"}
	// UngatedSet is opstate.UNGATED_SET: the approver set of a purpose no approval gates.
	UngatedSet = ApproverSet{Approvers: map[string]string{}, Required: 0}.Digest()
)

// SessionKeyPath is opstate.session_key_path: where a session entry lives, one per daemon start.
func SessionKeyPath(value any) (map[string]any, string, error) {
	entry, err := exactFields(value, sessionFields, "the session entry")
	if err != nil {
		return nil, "", err
	}
	if entry["schema"] != SessionSchema {
		return nil, "", refuse("schema must be %s", SessionSchema)
	}
	if s, ok := entry["node_id"].(string); !ok || !nodePattern.MatchString(s) {
		return nil, "", refuse("node_id must be a node ID")
	}
	if s, ok := entry["boot_id"].(string); !ok || !bootIDPattern.MatchString(s) {
		return nil, "", refuse("boot_id must be a boot UUID")
	}
	if err := hexOf(entry["session_key"], 64, "session_key"); err != nil {
		return nil, "", err
	}
	if _, err := timeOf(entry["issued_at"], "issued_at"); err != nil {
		return nil, "", err
	}
	return entry, Prefix + "sessions/" + entry["node_id"].(string) + "/" + entry["boot_id"].(string) + "/" + entry["session_key"].(string), nil
}

// VerifySession is opstate.verify_session: the session at `key`, if the signing_key its node held WHEN IT WAS
// ISSUED signed it. `chain` is the verified membership chain, oldest first: the key in force is the newest
// manifest's issued at or before the session's issued_at (a key rotated later must not make that node's earlier
// spends unverifiable). Returns the entry and valid_until: the issued_at of the first later manifest naming
// another key for the node, "" when none does (a key replaced because it leaked vouches for nothing after).
// The node's state is not judged: a node revoked later keeps its earlier spends verifiable.
func VerifySession(key string, value any, chain []map[string]any) (map[string]any, string, error) {
	stored, err := exactFields(value, []string{"entry", "signature"}, "the session value")
	if err != nil {
		return nil, "", err
	}
	entry, want, err := SessionKeyPath(stored["entry"])
	if err != nil {
		return nil, "", err
	}
	if key != want {
		return nil, "", refuse("the session entry belongs under %s, not %s", want, key)
	}
	if len(chain) == 0 {
		return nil, "", refuse("a session is judged against the membership chain")
	}
	node := entry["node_id"].(string)
	issued, _ := timeOf(entry["issued_at"], "issued_at")
	index := -1
	for i, manifest := range chain {
		at, err := timeOf(manifest["issued_at"], "a manifest's issued_at")
		if err != nil {
			return nil, "", err
		}
		if at <= issued {
			index = i
		}
	}
	if index < 0 {
		return nil, "", refuse("%s's session is dated before the first manifest", node)
	}
	signingKey := func(manifest map[string]any) (string, bool, error) {
		alg, k, ok, err := membership.NodeSigningKey(manifest, node)
		return alg + ":" + k, ok, err
	}
	inForce, ok, err := signingKey(chain[index])
	if err != nil {
		return nil, "", asRefused(err)
	}
	if !ok {
		return nil, "", refuse("%s had no signing key at epoch %s, when its session is dated", node, chain[index]["epoch"])
	}
	alg, publicKey, _ := strings.Cut(inForce, ":")
	message := append([]byte(SessionDomain), membership.Canonical(entry)...)
	if err := membership.VerifyTypedSignature(alg, publicKey, message, stored["signature"], node+"'s session entry"); err != nil {
		return nil, "", asRefused(err)
	}
	for _, later := range chain[index+1:] {
		held, ok, err := signingKey(later)
		if err != nil {
			return nil, "", asRefused(err)
		}
		if !ok || held != inForce {
			return entry, later["issued_at"].(string), nil
		}
	}
	return entry, "", nil
}

func asRefused(err error) error {
	if r, ok := err.(*membership.Refused); ok {
		return &Refused{Reason: r.Reason}
	}
	return err
}

// ApprovalsDigest is opstate.approvals_digest: SHA-256 of the canonical list of approvals, by approver ID.
func ApprovalsDigest(approvals []any) string {
	sorted := append([]any(nil), approvals...)
	id := func(a any) string {
		if m, ok := a.(map[string]any); ok {
			if s, ok := m["approver_id"].(string); ok {
				return s
			}
		}
		return ""
	}
	sort.SliceStable(sorted, func(i, j int) bool { return id(sorted[i]) < id(sorted[j]) })
	sum := sha256.Sum256(membership.Canonical(sorted))
	return hex.EncodeToString(sum[:])
}

// bindingBytes is opstate.binding_bytes: internal/approval.Binding.CanonicalBytes for the request the spend
// consumed, from its payload's digest.
func bindingBytes(spend map[string]any, nonce string) []byte {
	out := []byte("regalia-approval-v2\n")
	for _, field := range []string{spend["object_id"].(string), spend["purpose"].(string), spend["environment"].(string), nonce,
		spend["expires_at"].(string), spend["payload_sha256"].(string)} {
		out = append(out, strconv.Itoa(len(field))+":"+field+"\n"...)
	}
	return out
}

// CheckApprovals is opstate.check_approvals: the approvals a spend counted (from the signer's audit line)
// existed. Returns the approver IDs.
func CheckApprovals(spend any, approvals any, sets map[string]ApproverSet) ([]string, error) {
	entry, kind, err := ValidateEntry(spend)
	if err != nil {
		return nil, err
	}
	if kind != "spend" {
		return nil, refuse("only a spend has approvals")
	}
	list, ok := approvals.([]any)
	if !ok || len(list) > MaxApprovers {
		return nil, refuse("approvals must be a list of at most %d", MaxApprovers)
	}
	if ApprovalsDigest(list) != entry["approvals_sha256"] {
		return nil, refuse("these are not the approvals the spend counted (approvals_sha256)")
	}
	setDigest := entry["approver_set"].(string)
	named, known := sets[setDigest]
	if !known || named.Digest() != setDigest {
		return nil, refuse("the approver set %s is not one this verifier knows", setDigest[:16])
	}
	spendExpires, _ := timeOf(entry["expires_at"], "expires_at")
	spendAt, _ := timeOf(entry["at"], "at")
	counted := []string{}
	seen := map[string]bool{}
	for _, value := range list {
		a, err := exactFields(value, approvalFields, "an approval")
		if err != nil {
			return nil, err
		}
		who, isText := a["approver_id"].(string)
		key, member := named.Approvers[who]
		if !isText || !member || seen[who] {
			return nil, refuse("%s is not an approver of the set, or counted twice", printableName(a["approver_id"]))
		}
		nonce, isText := a["nonce"].(string)
		if !isText || hashName(nonce) != entry["nonce_digest"] {
			return nil, refuse("%s approved another request's nonce", who)
		}
		if a["payload_digest"] != entry["payload_sha256"] {
			return nil, refuse("%s approved another payload", who)
		}
		expires, err := timeOf(a["expires_at"], "an approval's expires_at")
		if err != nil {
			return nil, err
		}
		if expires > spendExpires {
			return nil, refuse("%s's approval outlives the request", who)
		}
		if expires <= spendAt {
			return nil, refuse("%s's approval had expired when the request was spent", who)
		}
		text, _ := a["signature"].(string)
		sig, err := base64.StdEncoding.Strict().DecodeString(text)
		public, _ := hex.DecodeString(key)
		if err != nil || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, bindingBytes(entry, nonce), sig) {
			return nil, refuse("%s's approval does not verify over the request's binding", who)
		}
		seen[who] = true
		counted = append(counted, who)
	}
	if len(counted) < named.Required {
		return nil, refuse("%d of %d required approvals", len(counted), named.Required)
	}
	sort.Strings(counted)
	names := make([]string, 0)
	for _, a := range entry["approvers"].([]any) {
		names = append(names, a.(string))
	}
	if joinList(counted) != joinList(names) {
		return nil, refuse("the spend names %s; the approvals are %s's", pyList(names), pyList(counted))
	}
	return counted, nil
}

func joinList(list []string) string {
	encoded, _ := json.Marshal(list)
	return string(encoded)
}

// MaySign is opstate.may_sign: after the spend committed and before the HSM, the node still holds the very lease
// the spend names, unlapsed at `now` (authenticated unix seconds), and the request expires more than SkewS from
// now. Refused otherwise: the spend is burned.
func MaySign(spend any, now int64, heldLeaseDigest, heldLeaseExpiresAt string) error {
	entry, kind, err := ValidateEntry(spend)
	if err != nil {
		return err
	}
	if kind != "spend" {
		return refuse("only a spend is signed under")
	}
	if heldLeaseDigest != entry["lease_digest"] || heldLeaseExpiresAt != entry["lease_expires_at"] {
		return refuse("BURNED: this node no longer holds the lease the spend was committed under")
	}
	leaseEnd, _ := timeOf(entry["lease_expires_at"], "lease_expires_at")
	if now >= leaseEnd {
		return refuse("BURNED: the lease the spend names has lapsed")
	}
	expires, _ := timeOf(entry["expires_at"], "expires_at")
	if now+SkewS >= expires {
		return refuse("BURNED: the request expires within %d s: its spend's key might be collected before it", SkewS)
	}
	return nil
}

// GCTTL is opstate.gc_ttl: the etcd lease a spend's key is written with, in seconds.
func GCTTL(spend any) (int64, error) {
	entry, _, err := ValidateEntry(spend)
	if err != nil {
		return 0, err
	}
	at, _ := timeOf(entry["at"], "at")
	expires, _ := timeOf(entry["expires_at"], "expires_at")
	return expires - at + SkewS, nil
}

// Fresh is opstate.fresh: when a reader observes an entry's creation, its `at` must lie within SkewS of the
// reader's authenticated `now` (unix seconds). The session window bounds `at`, but `at` is signed by the session
// key itself: judged on arrival, the window bounds real time, not claimed time.
func Fresh(entry any, now int64) error {
	valid, _, err := ValidateEntry(entry)
	if err != nil {
		return err
	}
	at, _ := timeOf(valid["at"], "at")
	if now-at > SkewS || at-now > SkewS {
		return refuse("the entry is dated %s, %d s from this reader's clock when it arrived (more than %d s): refused", valid["at"], now-at, SkewS)
	}
	return nil
}

// FreshAt is a Cache's Fresh on the reader's authenticated clock.
func FreshAt(now func() time.Time) func(key string, parsed any) error {
	return func(_ string, parsed any) error { return Fresh(parsed, now().Unix()) }
}
