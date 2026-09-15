// Package approval turns client-presented approval evidence into a set of approver
// identities the policy engine may count.
//
// THE FIELD IS CALLED VerifiedApprovers AND THE VERIFICATION HAS TO BE REAL.
//
// The first attempt at satisfying policy.RequiredApprovals bridged an
// X-Verified-Approvers header of comma-separated SPIFFE IDs straight into
// policy.Request.VerifiedApprovers. It was withdrawn before it was pushed, because a
// client that can reach the endpoint could satisfy any approval requirement by naming
// approvers from the policy's own list. A control whose value is a client assertion is
// decoration, and this one would have been worse than the dead code it replaced: the
// unsatisfiable version denies every approval-bearing request, which is useless but never
// wrongly authorizes. The bridge would have allowed every one of them.
//
// So the header carries evidence rather than claims: detached ed25519 signatures over a
// canonical binding of the request, verified here against an operator-managed key set
// before any identity is counted.
//
// AN APPROVAL THAT FAILS ANY CHECK IS NOT AN ERROR. It is simply not an approver. The
// count then fails the policy on its own if it is short. This matters because the
// alternative -- rejecting the request when an approval does not verify -- lets anyone who
// can reach the endpoint turn a valid two-of-two request into a denial by appending one
// piece of garbage.
package approval

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// HeaderName carries base64(JSON []Approval). It is deliberately not the withdrawn
// X-Verified-Approvers: a header of that name promised something it did not do, and
// reusing it would let an old client's claims arrive at a server that now expects evidence.
const HeaderName = "X-Verified-Approvals"

// MaxHeaderBytes bounds the base64 payload. Each approval is a few hundred bytes and
// RequiredApprovals is bounded by the size of the policy's approver list, so this is
// generous. It exists because signature verification is not free and the header is
// attacker-controlled: without a bound, one request can ask the daemon to perform
// unlimited ed25519 verifications.
const MaxHeaderBytes = 16 << 10

// MaxApprovals bounds the decoded list for the same reason.
const MaxApprovals = 64

// Approval is one approver's detached signature over a request.
type Approval struct {
	ApproverID    string `json:"approver_id"`
	Nonce         string `json:"nonce"`
	ExpiresAt     string `json:"expires_at"`
	PayloadDigest string `json:"payload_digest"`
	Signature     string `json:"signature"`
}

// Binding is the part of a request an approval is bound to. Every field is load-bearing:
// object and purpose and environment say what is being authorized, nonce stops the
// approval being replayed onto another request, expiry stops it being kept, and the
// payload digest stops an approver's signature from covering bytes they never saw.
type Binding struct {
	ObjectID    string
	Purpose     string
	Environment string
	Nonce       string
	ExpiresAt   time.Time
	Payload     []byte
}

// CanonicalBytes is what an approver signs.
//
// EVERY FIELD CARRIES ITS BYTE LENGTH, BECAUSE A NEWLINE-JOINED BINDING IS NOT UNAMBIGUOUS.
//
// The v1 form joined the fields with "\n" and claimed that two different requests could not
// produce the same bytes by shifting content across a field boundary. That was false, and a
// signature really did transfer:
//
//	{ObjectID: "prod-signer",         Purpose: "release\nescrow"}
//	{ObjectID: "prod-signer\nrelease", Purpose: "escrow"}
//
// both serialize to ...\nprod-signer\nrelease\nescrow\n..., so one approver's signature over
// the first counted, unmodified, on the second. Nothing in this package prevented it. The
// property held in production only because api.validateRequest happens to constrain all four
// string fields to charsets with no newline -- a regex three packages away that this file
// neither references nor pins, and that a second entry point (a CLI, a batch path, a new
// field that is not identifier-shaped) would not inherit.
//
// A length prefix makes the framing self-delimiting: shifting a byte across a boundary
// changes a declared length, so the bytes differ. The guarantee is now local to this
// function and provable from it alone.
//
// The length is len(field) -- the number of bytes in the string as stored. A Go string is an
// arbitrary byte sequence, not a guaranteed-valid UTF-8 one, so nothing is encoded or
// validated here; the count is of whatever bytes the field holds. API.md states the external
// contract in the form an outside signer needs it -- the byte count of the field's UTF-8
// encoding -- which is the same number for any value that arrived as JSON.
//
// It counts the field only: not the "<len>:" prefix, and not the "\n" that terminates the
// line. An implementation that counted UTF-16 code units, runes, or included the newline
// would produce different signed bytes, and its approvals would silently not count.
//
// The domain separator moves to v2 with the framing. The bytes an approver signs have
// changed, and two incompatible serializations must not share a label -- that is the
// confusion the label exists to prevent. See TestShiftingContentAcrossAFieldBoundaryIsNotTheSameBinding.
//
// The payload appears as a hex digest rather than inline so that signing does not require
// the approver to hold the plaintext, and so a large payload does not make a large binding:
// the payload's contribution is 64 hex characters whatever the payload weighs. The binding
// as a whole is NOT fixed-size -- it varies with the object, purpose, nonce and environment,
// which is precisely why the fields need explicit lengths.
func (binding Binding) CanonicalBytes() []byte {
	digest := sha256.Sum256(binding.Payload)
	canonical := strings.Builder{}
	canonical.WriteString("regalia-approval-v2\n")
	for _, field := range []string{
		binding.ObjectID,
		binding.Purpose,
		binding.Environment,
		binding.Nonce,
		binding.ExpiresAt.UTC().Format(time.RFC3339Nano),
		hex.EncodeToString(digest[:]),
	} {
		canonical.WriteString(strconv.Itoa(len(field)))
		canonical.WriteString(":")
		canonical.WriteString(field)
		canonical.WriteString("\n")
	}
	return []byte(canonical.String())
}

// PayloadDigest is the hex digest an approval must carry to be counted for this binding.
func (binding Binding) PayloadDigest() string {
	digest := sha256.Sum256(binding.Payload)
	return hex.EncodeToString(digest[:])
}

// KeySet maps an approver's SPIFFE ID to the public key that speaks for it. It is
// operator-managed configuration loaded at startup, never anything the request supplies.
type KeySet struct {
	keys   map[string]ed25519.PublicKey
	digest string
}

// Digest identifies the loaded key set so a decision can be tied to the keys that made it.
func (set *KeySet) Digest() string {
	if set == nil {
		return ""
	}
	return set.digest
}

// Len reports how many approver keys are configured.
func (set *KeySet) Len() int {
	if set == nil {
		return 0
	}
	return len(set.keys)
}

type keyDocument struct {
	Approvers map[string]string `json:"approvers"`
}

// LoadKeySet reads the operator-managed approver keys.
//
// An empty file is refused rather than treated as "no approvers configured". A key set
// that silently loads as empty turns every RequiredApprovals policy into a permanent
// denial, which looks exactly like the dead-code posture this replaces -- the daemon would
// start, serve, and refuse every dual-control operation with nothing in the logs saying
// why. If approvals are not in use, do not configure the path.
func LoadKeySet(path string) (*KeySet, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read approver keys: %w", err)
	}
	var document keyDocument
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("approver keys must be a JSON object with an approvers map: %w", err)
	}
	// One document, nothing after it. Decode stops at the end of the first JSON value, so
	// without this a file of `{"approvers":{...}} {"approvers":{...}}` loads the first and
	// silently ignores the second -- an operator who appended a key would believe it was
	// configured and it would never count. This is the same check loadConfig, readLease and
	// decodeRequest already make; the key set was the one place that skipped it.
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("approver keys must contain exactly one JSON document")
	}
	if len(document.Approvers) == 0 {
		return nil, errors.New("approver key set is empty: every dual-control policy would deny for a reason nothing reports")
	}
	set := &KeySet{keys: make(map[string]ed25519.PublicKey, len(document.Approvers))}
	for id, encoded := range document.Approvers {
		if strings.TrimSpace(id) == "" {
			return nil, errors.New("approver key set contains an empty approver id")
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("approver %q must carry a base64 ed25519 public key of %d bytes", id, ed25519.PublicKeySize)
		}
		set.keys[id] = ed25519.PublicKey(decoded)
	}
	sum := sha256.Sum256(contents)
	set.digest = "sha256:" + hex.EncodeToString(sum[:])
	return set, nil
}

// NewKeySet builds a key set directly, for callers that already hold the keys.
func NewKeySet(keys map[string]ed25519.PublicKey) *KeySet {
	set := &KeySet{keys: make(map[string]ed25519.PublicKey, len(keys))}
	canonical := make([]string, 0, len(keys))
	for id, key := range keys {
		set.keys[id] = key
		canonical = append(canonical, id+":"+base64.StdEncoding.EncodeToString(key))
	}
	sortStrings(canonical)
	sum := sha256.Sum256([]byte(strings.Join(canonical, "\n")))
	set.digest = "sha256:" + hex.EncodeToString(sum[:])
	return set
}

// Verify returns the deduplicated set of approver identities whose evidence holds for this
// binding, in a deterministic order.
//
// It never returns an error for bad evidence. A malformed header, an unknown approver, a
// replayed nonce, a stale expiry, a digest over different bytes or a signature that does
// not verify all produce the same outcome: that approver is not counted. Only the count
// decides, and the policy engine owns the count.
func (set *KeySet) Verify(header string, binding Binding) []string {
	if set == nil || header == "" || len(header) > MaxHeaderBytes {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil
	}
	var approvals []Approval
	decoder := json.NewDecoder(strings.NewReader(string(decoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&approvals); err != nil || len(approvals) > MaxApprovals {
		return nil
	}
	// ONE DOCUMENT, NOTHING AFTER IT -- the same check LoadKeySet makes twenty lines up, which
	// this decoder skipped. Measured: a 392-byte header and a 420-byte header differing only
	// by an appended `{"attacker":"rider"}` both counted the same approver. No approver is
	// gained -- every approval is signature-verified against the binding -- so the exposure is
	// identity: an audit record naming an approval header by digest no longer names the
	// evidence that was counted, and MaxHeaderBytes bounds the padding without forbidding it.
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil
	}
	signed := binding.CanonicalBytes()
	expectedDigest := binding.PayloadDigest()
	seen := make(map[string]struct{}, len(approvals))
	verified := make([]string, 0, len(approvals))
	for _, approval := range approvals {
		if !set.counts(approval, binding, signed, expectedDigest) {
			continue
		}
		if _, already := seen[approval.ApproverID]; already {
			// The same approver twice is one approver. Two signatures from one key must
			// not satisfy RequiredApprovals: 2 -- that is the whole point of dual control.
			continue
		}
		seen[approval.ApproverID] = struct{}{}
		verified = append(verified, approval.ApproverID)
	}
	sortStrings(verified)
	return verified
}

func (set *KeySet) counts(approval Approval, binding Binding, signed []byte, expectedDigest string) bool {
	key, configured := set.keys[approval.ApproverID]
	if !configured {
		return false
	}
	if approval.Nonce != binding.Nonce || approval.PayloadDigest != expectedDigest {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, approval.ExpiresAt)
	if err != nil || expires.After(binding.ExpiresAt) {
		// An approval may expire before the request does; it may not outlive it. Allowing
		// a later expiry would let an approver issue evidence that stays valid across
		// future requests that reuse the nonce window.
		return false
	}
	signature, err := base64.StdEncoding.DecodeString(approval.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(key, signed, signature)
}

func sortStrings(values []string) {
	for outer := 1; outer < len(values); outer++ {
		for inner := outer; inner > 0 && values[inner] < values[inner-1]; inner-- {
			values[inner], values[inner-1] = values[inner-1], values[inner]
		}
	}
}
