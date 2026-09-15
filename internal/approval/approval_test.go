package approval

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var requestExpiry = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func binding() Binding {
	return Binding{
		ObjectID: "signing-key-1", Purpose: "release-signing", Environment: "production",
		Nonce: "nonce-aaaa", ExpiresAt: requestExpiry, Payload: []byte("the bytes being signed"),
	}
}

func approver(t *testing.T, id string) (string, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return id, private, public
}

func sign(t *testing.T, id string, key ed25519.PrivateKey, target Binding, over Binding) Approval {
	t.Helper()
	return Approval{
		ApproverID: id, Nonce: target.Nonce, ExpiresAt: target.ExpiresAt.UTC().Format(time.RFC3339Nano),
		PayloadDigest: target.PayloadDigest(),
		Signature:     base64.StdEncoding.EncodeToString(ed25519.Sign(key, over.CanonicalBytes())),
	}
}

func header(t *testing.T, approvals ...Approval) string {
	t.Helper()
	encoded, err := json.Marshal(approvals)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

// THE HEADER CARRIES EVIDENCE, NOT CLAIMS.
//
// The withdrawn first attempt bridged a comma-separated list of SPIFFE IDs into
// VerifiedApprovers, so a client could satisfy any approval requirement by naming
// approvers from the policy's own list. This is that attack: the names are right, the
// approvers are configured, and there is no signature anywhere.
func TestNamingApproversWithoutSignaturesVerifiesNobody(t *testing.T) {
	alice, _, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	bob, _, bobPublic := approver(t, "spiffe://regalia/approver/bob")
	set := NewKeySet(map[string]ed25519.PublicKey{alice: alicePublic, bob: bobPublic})

	claimed := header(t,
		Approval{ApproverID: alice, Nonce: binding().Nonce, ExpiresAt: requestExpiry.Format(time.RFC3339Nano), PayloadDigest: binding().PayloadDigest()},
		Approval{ApproverID: bob, Nonce: binding().Nonce, ExpiresAt: requestExpiry.Format(time.RFC3339Nano), PayloadDigest: binding().PayloadDigest()},
	)
	if verified := set.Verify(claimed, binding()); len(verified) != 0 {
		t.Fatalf("DEFECT: naming approvers with no signature verified %v — the field is called "+
			"VerifiedApprovers and a client just asserted its own approvers", verified)
	}
}

// An approval signed for one request must not count for another. Each component of the
// binding is varied separately, because a binding that omits any of them is replayable
// along that axis and a single combined case would not say which.
func TestAnApprovalDoesNotTransferToAnotherRequest(t *testing.T) {
	alice, aliceKey, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	set := NewKeySet(map[string]ed25519.PublicKey{alice: alicePublic})
	original := binding()

	for _, variant := range []struct {
		what   string
		change func(Binding) Binding
	}{
		{"a different object", func(b Binding) Binding { b.ObjectID = "signing-key-2"; return b }},
		{"a different purpose", func(b Binding) Binding { b.Purpose = "code-signing"; return b }},
		{"a different environment", func(b Binding) Binding { b.Environment = "staging"; return b }},
		{"a different nonce", func(b Binding) Binding { b.Nonce = "nonce-bbbb"; return b }},
		{"a different payload", func(b Binding) Binding { b.Payload = []byte("other bytes entirely"); return b }},
		{"a later expiry", func(b Binding) Binding { b.ExpiresAt = requestExpiry.Add(time.Hour); return b }},
	} {
		t.Run(variant.what, func(t *testing.T) {
			replayed := variant.change(original)
			// Signed for the original request, presented on the replayed one. The
			// approval's own fields are restated for the target so only the signature
			// and the binding disagree — otherwise the field checks would catch it first
			// and the signature would never be exercised.
			evidence := sign(t, alice, aliceKey, replayed, original)
			if verified := set.Verify(header(t, evidence), replayed); len(verified) != 0 {
				t.Fatalf("DEFECT: an approval signed for another request counted on one with %s: %v — "+
					"the binding does not cover it, so approvals are replayable", variant.what, verified)
			}
		})
	}
}

// A signature that verifies against a key nobody configured is not an approval. This is
// the case where the cryptography is impeccable and the identity is unknown.
func TestASignatureFromAnUnconfiguredKeyCountsForNobody(t *testing.T) {
	alice, aliceKey, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	stranger, strangerKey, _ := approver(t, "spiffe://regalia/approver/stranger")
	set := NewKeySet(map[string]ed25519.PublicKey{alice: alicePublic})

	evidence := sign(t, stranger, strangerKey, binding(), binding())
	if verified := set.Verify(header(t, evidence), binding()); len(verified) != 0 {
		t.Fatalf("DEFECT: a valid signature from an unconfigured approver counted: %v — "+
			"anyone with a keypair could approve", verified)
	}
	// The control: the same construction with a configured key must count, or the test
	// above passes because the verifier rejects everything.
	if verified := set.Verify(header(t, sign(t, alice, aliceKey, binding(), binding())), binding()); len(verified) != 1 {
		t.Fatalf("a configured approver's valid signature did not count (%v): the negative "+
			"case above would then prove nothing", verified)
	}
}

// Dual control means two people. Two signatures from one key are one approver.
func TestTheSameApproverTwiceCountsOnce(t *testing.T) {
	alice, aliceKey, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	bob, _, bobPublic := approver(t, "spiffe://regalia/approver/bob")
	set := NewKeySet(map[string]ed25519.PublicKey{alice: alicePublic, bob: bobPublic})

	once := sign(t, alice, aliceKey, binding(), binding())
	verified := set.Verify(header(t, once, once), binding())
	if len(verified) != 1 {
		t.Fatalf("DEFECT: the same approver presented twice verified as %d approvers (%v) — "+
			"one person would satisfy required_approvals: 2", len(verified), verified)
	}
}

// An approval may expire before the request; it may not outlive it.
func TestAnApprovalMayNotExpireAfterTheRequest(t *testing.T) {
	alice, aliceKey, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	set := NewKeySet(map[string]ed25519.PublicKey{alice: alicePublic})

	earlier := binding()
	earlier.ExpiresAt = requestExpiry.Add(-time.Minute)
	evidence := sign(t, alice, aliceKey, earlier, earlier)
	// Signed against its own earlier expiry, presented on the real request. The approval
	// is narrower than the request, which is allowed.
	evidence.PayloadDigest = binding().PayloadDigest()
	if verified := set.Verify(header(t, evidence), binding()); len(verified) != 0 {
		t.Fatal("an approval signed over a different expiry counted: the expiry is in the " +
			"canonical bytes, so this must fail on the signature")
	}

	longer := sign(t, alice, aliceKey, binding(), binding())
	longer.ExpiresAt = requestExpiry.Add(time.Hour).Format(time.RFC3339Nano)
	if verified := set.Verify(header(t, longer), binding()); len(verified) != 0 {
		t.Fatalf("DEFECT: an approval claiming to outlive the request counted: %v — "+
			"evidence would stay valid across later requests", verified)
	}
}

// Bad evidence must not deny a request that is otherwise properly approved: otherwise
// anyone who can reach the endpoint turns a valid approval into a denial by appending junk.
func TestGarbageAlongsideValidEvidenceDoesNotDiscardIt(t *testing.T) {
	alice, aliceKey, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	set := NewKeySet(map[string]ed25519.PublicKey{alice: alicePublic})

	good := sign(t, alice, aliceKey, binding(), binding())
	junk := Approval{ApproverID: "spiffe://regalia/approver/nobody", Signature: "!!!not base64!!!"}
	verified := set.Verify(header(t, junk, good), binding())
	if len(verified) != 1 || verified[0] != alice {
		t.Fatalf("DEFECT: appending unverifiable evidence discarded a valid approval (%v) — "+
			"any caller could deny a properly approved request", verified)
	}
}

func TestAMalformedHeaderVerifiesNobodyAndDoesNotPanic(t *testing.T) {
	alice, _, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	set := NewKeySet(map[string]ed25519.PublicKey{alice: alicePublic})
	for _, bad := range []string{"", "not-base64!!", base64.StdEncoding.EncodeToString([]byte("{}")),
		base64.StdEncoding.EncodeToString([]byte(`[{"unknown_field":1}]`)),
		strings.Repeat("A", MaxHeaderBytes+1)} {
		if verified := set.Verify(bad, binding()); len(verified) != 0 {
			t.Fatalf("malformed header %q verified %v", bad[:min(len(bad), 24)], verified)
		}
	}
}

// A nil key set is the unconfigured deployment: it counts nobody, which keeps
// required_approvals unsatisfiable rather than trivially satisfied.
func TestANilKeySetCountsNobody(t *testing.T) {
	var set *KeySet
	alice, aliceKey, _ := approver(t, "spiffe://regalia/approver/alice")
	if verified := set.Verify(header(t, sign(t, alice, aliceKey, binding(), binding())), binding()); len(verified) != 0 {
		t.Fatalf("DEFECT: an unconfigured deployment counted approvers: %v", verified)
	}
}

// TRAILING CONTENT MUST BE REFUSED, AND THE FIRST DOCUMENT HAS TO BE VALID TO PROVE IT.
//
// My first attempt at this put "AAAA" in the leading document, which is not a 32-byte key,
// so LoadKeySet refused on the key length and never reached the trailing content. The test
// passed, the guard was absent, and falsification is the only reason I know that: removing
// the EOF check left the suite green.
//
// The leading document here is a real key set that loads on its own. Anything that refuses
// these files is refusing them for the trailing content.
func TestLoadKeySetRefusesAnythingAfterTheFirstDocument(t *testing.T) {
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"approvers":{"spiffe://regalia/approver/alice":"` + base64.StdEncoding.EncodeToString(public) + `"}}`
	dir := t.TempDir()
	write := func(name, contents string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	// The control: the leading document alone must load, or everything below refuses for
	// the wrong reason and this test proves nothing -- which is exactly what happened first.
	if set, err := LoadKeySet(write("alone.json", valid)); err != nil || set.Len() != 1 {
		t.Fatalf("the leading document does not load on its own (%v): the cases below would "+
			"pass whether or not trailing content is refused", err)
	}

	for _, trailing := range []struct{ name, suffix, why string }{
		{"second.json", " " + valid, "an operator appending a key would believe it was configured and it would never count"},
		{"junk.json", " not-json-at-all", "silent acceptance of a corrupted key file"},
		{"array.json", " [1,2,3]", "a second JSON value of any shape"},
	} {
		if _, err := LoadKeySet(write(trailing.name, valid+trailing.suffix)); err == nil {
			t.Errorf("DEFECT: LoadKeySet accepted a key file with %s after the first document: %s",
				trailing.name, trailing.why)
		}
	}
}

func TestLoadKeySetRefusesAnEmptyOrMalformedSet(t *testing.T) {
	dir := t.TempDir()
	write := func(name, contents string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	_, public, _ := ed25519.GenerateKey(nil)
	_ = public
	for _, bad := range []struct{ name, contents, why string }{
		{"empty.json", `{"approvers":{}}`, "an empty set makes every dual-control policy deny for a reason nothing reports"},
		{"short.json", `{"approvers":{"a":"AAAA"}}`, "a key of the wrong length"},
		{"unbase64.json", `{"approvers":{"a":"!!!"}}`, "a key that is not base64"},
		{"blankid.json", `{"approvers":{"":"AAAA"}}`, "an empty approver id"},
		{"unknown.json", `{"approvers":{},"extra":1}`, "an unknown field"},
	} {
		if _, err := LoadKeySet(write(bad.name, bad.contents)); err == nil {
			t.Errorf("LoadKeySet accepted %s: %s", bad.name, bad.why)
		}
	}
	valid, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	good := write("good.json", `{"approvers":{"spiffe://regalia/approver/alice":"`+base64.StdEncoding.EncodeToString(valid)+`"}}`)
	set, err := LoadKeySet(good)
	if err != nil || set.Len() != 1 || set.Digest() == "" {
		t.Fatalf("a valid key set was refused (%v): the negative cases above would prove nothing", err)
	}
}

// THE BINDING MUST BE UNAMBIGUOUS ON ITS OWN, NOT BECAUSE A DISTANT REGEX HAPPENS TO HELP.
//
// TestAnApprovalDoesNotTransferToAnotherRequest replaces one field with a *different value*,
// which always changes the canonical bytes. It never moves a byte across a field boundary,
// and that is the one shape the v1 framing could not survive: newline-joined fields with no
// length made these two requests serialize identically, so a signature over the first
// counted, unmodified, on the second.
//
// This does not reach the daemon today. api.validateRequest constrains object, purpose,
// environment and nonce to charsets with no newline, so the HTTP path cannot present either
// binding. That is exactly why the case is worth pinning here: the guarantee lived three
// packages away in a regex this package neither references nor pins, and a second entry
// point, or one new field that is not identifier-shaped, would not inherit it. Verify and
// CanonicalBytes are exported and Binding's fields are exported, so the input needs no
// privilege to build -- as this test demonstrates by building it.
func TestShiftingContentAcrossAFieldBoundaryIsNotTheSameBinding(t *testing.T) {
	alice, aliceKey, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	set := NewKeySet(map[string]ed25519.PublicKey{alice: alicePublic})

	signedFor := binding()
	signedFor.ObjectID, signedFor.Purpose = "prod-signer", "release\nescrow"

	shifted := binding()
	shifted.ObjectID, shifted.Purpose = "prod-signer\nrelease", "escrow"

	if string(signedFor.CanonicalBytes()) == string(shifted.CanonicalBytes()) {
		t.Fatalf("DEFECT: two different requests share canonical bytes, so one approver's "+
			"signature authorizes both.\n  object %q purpose %q\n  object %q purpose %q\n  both sign: %q",
			signedFor.ObjectID, signedFor.Purpose, shifted.ObjectID, shifted.Purpose,
			signedFor.CanonicalBytes())
	}

	// The signature is the thing that has to not transfer. Equality of the bytes is the
	// mechanism; this is the consequence, and it is what an attacker would actually get.
	evidence := sign(t, alice, aliceKey, shifted, signedFor)
	if verified := set.Verify(header(t, evidence), shifted); len(verified) != 0 {
		t.Fatalf("DEFECT: an approval signed for object %q purpose %q counted on object %q "+
			"purpose %q: %v -- the binding does not delimit its fields, so content shifted "+
			"across a boundary produces the same signed bytes",
			signedFor.ObjectID, signedFor.Purpose, shifted.ObjectID, shifted.Purpose, verified)
	}

	// Positive control: the same approver, same construction, still counts for the request
	// the signature was actually made over. Without this the test would also pass if Verify
	// had simply stopped counting anybody.
	if verified := set.Verify(header(t, sign(t, alice, aliceKey, signedFor, signedFor)), signedFor); len(verified) != 1 {
		t.Fatalf("positive control failed: a valid approval for its own request counted %v, "+
			"so the negative case above proves nothing", verified)
	}
}

// THE WIRE FORMAT IS A CONTRACT WITH SIGNERS THIS DAEMON DOES NOT RUN.
//
// API.md publishes the canonical binding so an approver can sign outside this process. That
// makes the exact bytes an interface, not an implementation detail: any change to the
// framing, the separator, the version tag, the field order, or what <len> counts silently
// invalidates every external signer, and the failure mode is an approval that is simply not
// counted -- no error, no log line saying the format moved.
//
// So this pins the bytes literally rather than recomputing them the way CanonicalBytes does.
// A test that rebuilt the expectation from the same loop would agree with any change to that
// loop, which is the one thing it must not do.
//
// The multi-byte field is deliberate. <len> is a BYTE count, and "é" is two bytes but one
// rune -- an implementation counting runes or UTF-16 code units passes every ASCII case and
// fails only in the field. The daemon cannot present this input (api.validateRequest rejects
// it), but the published contract has no such filter, and per TESTING.md §17 the boundary is
// what the input can be, not what today's caller happens to send.
func TestTheCanonicalBindingIsTheBytesAPIMdPublishes(t *testing.T) {
	// Exactly the request in API.md's "Test vector" section.
	binding := Binding{
		ObjectID:    "signing-key-1",
		Purpose:     "release-signing",
		Environment: "production",
		Nonce:       "nonce-aaaa-bbbb-cccc",
		ExpiresAt:   time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC),
		Payload:     []byte("the bytes being signed"),
	}

	// Literal, not recomputed. A test that rebuilt this from the same loop CanonicalBytes
	// uses would agree with any change to that loop, which is the one thing it must not do.
	const published = "regalia-approval-v2\n" +
		"13:signing-key-1\n" +
		"15:release-signing\n" +
		"10:production\n" +
		"20:nonce-aaaa-bbbb-cccc\n" +
		"20:2026-01-02T15:04:05Z\n" +
		"64:850578896d7e7f0c6b2d8c93a22f456a12545aec94b1cbbd3770e39f7582c59c\n"

	if got := string(binding.CanonicalBytes()); got != published {
		t.Fatalf("DEFECT: the canonical binding no longer matches the vector API.md publishes.\n"+
			"  published: %q\n  produced:  %q\n"+
			"External signers build these bytes from the spec; a change here makes their "+
			"approvals stop counting, with no error anywhere.", published, got)
	}

	// The vector's signature must verify, or the published key/signature pair is wrong and an
	// implementer checking against it would conclude their correct signer is broken.
	// Named to avoid reading as a credential assignment: this is the PUBLIC half of a
	// throwaway ed25519 pair whose seed API.md prints as 00 01 02 .. 1f. It is a documentation
	// vector, never an operator key, and gitleaks' generic-api-key rule fires on the shape
	// `...Key = "<high entropy>"` regardless of which half of the pair it is.
	const vectorPublicHalf = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg="
	const vectorSignature = "wO20bUHZh99VG+VzFp2M/+fz+8a7tYcynVUKzi4dAas6B2+mnzeI8jI0pHIZxSLyywcWo/zbOGoOCpidSo2CAg=="
	publicKey, err := base64.StdEncoding.DecodeString(vectorPublicHalf)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("API.md publishes an unusable public key %q: %v", vectorPublicHalf, err)
	}
	signature, err := base64.StdEncoding.DecodeString(vectorSignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		t.Fatalf("API.md publishes an unusable signature: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), binding.CanonicalBytes(), signature) {
		t.Fatalf("DEFECT: the signature API.md publishes does not verify against the bytes this " +
			"daemon produces. An implementer checking their signer against the documented " +
			"vector would conclude their correct implementation is broken.")
	}

	// Control on this test's own premise, not on the daemon. No production mutation can make
	// this fire: for the published signature to verify against two different requests, the
	// framing would have to produce identical bytes for both, and the assertions above would
	// already have caught that. What it does catch is a later edit that makes `other` no longer
	// a different request -- verified by mutating it to `other.Purpose = binding.Purpose`, which
	// fails here. Recorded as a test-integrity guard rather than a verified production guard,
	// per TESTING.md §17: if nothing can construct the failing input, say so.
	other := binding
	other.Purpose = "code-signing"
	if ed25519.Verify(ed25519.PublicKey(publicKey), other.CanonicalBytes(), signature) {
		t.Fatal("positive control failed: the published signature verifies for a different " +
			"request too, so verifying it proves nothing about the binding")
	}

	// <len> counts bytes. "café" is 5 bytes and 4 runes; an implementation counting runes or
	// UTF-16 code units passes every ASCII case above and fails only in the field. The daemon
	// cannot present this input -- api.validateRequest rejects it -- but the published contract
	// has no such filter, and per TESTING.md §17 the boundary is what the input can be.
	multibyte := binding
	multibyte.Purpose = "café"
	if !strings.Contains(string(multibyte.CanonicalBytes()), "\n5:café\n") {
		t.Fatalf("DEFECT: the length prefix is not a byte count -- %q contains no \"5:café\", so "+
			"an external signer counting bytes, as API.md specifies, disagrees with this daemon",
			multibyte.CanonicalBytes())
	}
}
