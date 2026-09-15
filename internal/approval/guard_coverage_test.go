package approval

// Refusal guards in this package that a mutation sweep proved no test detected. Each test
// below was written against an observed mutant: the comment on each says, concretely, what
// the package returns when the named guard is removed, so a later reader deciding the test
// is redundant has the counterexample in front of them.
//
// TWO KINDS OF REFUSAL LIVE HERE, AND THEY ARE ASSERTED DIFFERENTLY.
//
// LoadKeySet refuses with an error, so those tests assert the exact message -- a key file is
// walked by four sequential refusals (unknown field, trailing document, empty set, empty id,
// bad key) and almost any malformed file errors for some reason other than the one named.
//
// Verify deliberately refuses with no message at all: per this package's doc comment, an
// approval that fails any check is not an error, it is simply not an approver, because
// erroring would let anyone append garbage to a properly approved request and turn it into a
// denial. There is no message to assert. What distinguishes each Verify case instead is the
// pair: the malformed evidence counts nobody, and a control differing in exactly one respect
// counts exactly the approver who signed. The control is placed after the refusal assertion,
// per TESTING.md §18 -- an anchor that fatals first forecloses the falsification below it.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// keyFile writes one approver key document into a fresh temp directory and returns its path.
func keyFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "approvers.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// realApproverKey returns the base64 of a genuine 32-byte ed25519 public key. Every LoadKeySet
// fixture below carries one, because the key-length guard is the last refusal in the loop and
// a placeholder like "AAAA" is refused there before the guard under test is ever reached --
// which is exactly how the suite's existing blankid.json case fails to cover the id guard.
func realApproverKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(public)
}

// AN UNKNOWN TOP-LEVEL FIELD IS A KEY FILE THAT DOES NOT MEAN WHAT IT SAYS.
//
// Without the Decode error guard in LoadKeySet, `{"approvers":{...},"revoked":[...]}` loads
// and the revocation list is silently discarded -- observed returning a live *KeySet with
// Len=1. Worse, `{"aprovers":{"alice":K1},"approvers":{"bob":K2}}` loads holding only bob:
// an operator who typoed the map name would see a daemon that starts, serves, and counts a
// set of approvers they never wrote, with nothing anywhere saying a key was dropped.
//
// The suite's existing unknown.json case (`{"approvers":{},"extra":1}`) does not cover this:
// with the Decode guard removed it is still refused, by the empty-set guard further down
// ("approver key set is empty: every dual-control policy would deny for a reason nothing
// reports"). Both fixtures here carry a real key in a real approvers map, so the empty-set
// guard, the id guard and the key-length guard all pass and the Decode error is the only
// thing left that can refuse them.
func TestLoadKeySetRefusesAKeyFileWithAnUnknownTopLevelField(t *testing.T) {
	const alice = "spiffe://regalia/approver/alice"
	const bob = "spiffe://regalia/approver/bob"
	aliceKey, bobKey := realApproverKey(t), realApproverKey(t)

	for _, unknown := range []struct{ what, contents, field, why string }{
		{
			"a field this version does not implement",
			`{"approvers":{"` + alice + `":"` + aliceKey + `"},"revoked":["` + alice + `"]}`,
			`"revoked"`,
			"a revocation list that loads and is discarded is worse than one that is refused: " +
				"the operator believes a key is revoked and it still counts",
		},
		{
			"a typo in the map name, beside a correctly spelled one",
			`{"aprovers":{"` + alice + `":"` + aliceKey + `"},"approvers":{"` + bob + `":"` + bobKey + `"}}`,
			`"aprovers"`,
			"the typoed map is dropped and the daemon serves a key set the operator never wrote",
		},
	} {
		t.Run(unknown.what, func(t *testing.T) {
			set, err := LoadKeySet(keyFile(t, unknown.contents))
			if err == nil {
				t.Fatalf("DEFECT: LoadKeySet accepted a key file carrying %s and returned a key set of "+
					"Len=%d: %s", unknown.field, set.Len(), unknown.why)
			}
			// The message, not merely an error: this file is walked by four other refusals and
			// any of them matching would leave the Decode guard unproven.
			const wrapper = "approver keys must be a JSON object with an approvers map"
			if !strings.Contains(err.Error(), wrapper) || !strings.Contains(err.Error(), "unknown field "+unknown.field) {
				t.Fatalf("LoadKeySet() error = %q, want it to mention %q and %q — a refusal for a "+
					"different reason (empty set, trailing document, key length) would leave this "+
					"guard unproven", err, wrapper, "unknown field "+unknown.field)
			}
		})
	}

	// ANCHOR, after the refusals: the same approvers map with no unknown field beside it must
	// LOAD. Without it every assertion above is equally consistent with a LoadKeySet that
	// refuses every file, and the fixtures would prove nothing about unknown fields.
	set, err := LoadKeySet(keyFile(t, `{"approvers":{"`+alice+`":"`+aliceKey+`"}}`))
	if err != nil || set.Len() != 1 {
		t.Fatalf("anchor failed: the same approvers map without the unknown field was refused "+
			"(%v, Len=%d), so the cases above are not evidence about unknown fields", err, set.Len())
	}
}

// AN EMPTY APPROVER ID IS AN IDENTITY NOTHING SPEAKS FOR, AND IT IS COUNTABLE.
//
// Without the TrimSpace guard, `{"approvers":{"":"<real key>"}}` loads with Len=1 and an id of
// "" -- and the downstream consequence was observed: a header naming approver_id "" verifies
// as `[""]`, so a request supplying the empty string counts toward RequiredApprovals. The
// whitespace form is the same hole with a value that looks like a typo rather than a blank.
//
// The suite's existing blankid.json case (`{"approvers":{"":"AAAA"}}`) does not cover this:
// "AAAA" decodes to 3 bytes, so the key-length guard refuses it and the id guard is never
// reached -- with the id guard removed, blankid.json is still refused, by
// `approver "" must carry a base64 ed25519 public key of 32 bytes`. Both fixtures here carry a
// genuine 32-byte key so that the loop reaches the id guard and nothing else can refuse them.
func TestLoadKeySetRefusesAnEmptyOrWhitespaceApproverIDCarryingAValidKey(t *testing.T) {
	key := realApproverKey(t)

	for _, blank := range []struct{ what, id string }{
		{"the empty string", ""},
		{"an id that is only whitespace", "   "},
	} {
		t.Run(blank.what, func(t *testing.T) {
			set, err := LoadKeySet(keyFile(t, `{"approvers":{"`+blank.id+`":"`+key+`"}}`))
			if err == nil {
				t.Fatalf("DEFECT: LoadKeySet accepted approver id %q with a valid key (Len=%d) — a "+
					"header naming approver_id %q then verifies as that approver and counts toward "+
					"required_approvals", blank.id, set.Len(), blank.id)
			}
			const wants = "approver key set contains an empty approver id"
			if !strings.Contains(err.Error(), wants) {
				t.Fatalf("LoadKeySet() error = %q, want it to mention %q — the key is genuine, so a "+
					"refusal naming the key length would mean the fixture, not the guard, did the work",
					err, wants)
			}
		})
	}

	// ANCHOR, after the refusals: the identical file with a real id and the same key must LOAD.
	// It is what makes the difference between the cases exactly one thing — the id.
	set, err := LoadKeySet(keyFile(t, `{"approvers":{"spiffe://regalia/approver/alice":"`+key+`"}}`))
	if err != nil || set.Len() != 1 {
		t.Fatalf("anchor failed: the same key under a real approver id was refused (%v, Len=%d), so "+
			"the cases above do not isolate the id", err, set.Len())
	}
}

// A BASE64 ERROR AND A LENGTH MISMATCH ARE TWO DIFFERENT FACTS, AND THEY CAN DISAGREE.
//
// LoadKeySet refuses on `err != nil || len(decoded) != ed25519.PublicKeySize`. The suite's
// existing unbase64.json value ("!!!") makes both operands true at once, so the length operand
// alone is enough to refuse it and the error operand is never the sole refuser.
//
// A real key with "!!!" appended separates them: base64.StdEncoding.DecodeString reports
// `illegal base64 data at input byte 44` AND returns the 32 decoded bytes of the valid prefix.
// The length operand is therefore false. With the error operand removed, this file was
// observed loading with Len=1 -- a key file an operator corrupted by appending characters
// loads as though it were clean, and the daemon counts approvals against a key the file no
// longer unambiguously contains.
func TestLoadKeySetRefusesAKeyWhoseBase64IsMalformedEvenWhenItsPrefixDecodesTo32Bytes(t *testing.T) {
	const alice = "spiffe://regalia/approver/alice"
	key := realApproverKey(t)
	corrupted := key + "!!!"

	// The fixture's premise, checked against the primitive rather than assumed: the decode
	// errors and still yields exactly 32 bytes. If this ever stops holding, the length operand
	// is what refuses the file below and the test silently stops covering the error operand.
	decoded, decodeErr := base64.StdEncoding.DecodeString(corrupted)
	if decodeErr == nil || len(decoded) != ed25519.PublicKeySize {
		t.Fatalf("fixture premise broken: DecodeString(%q...) err=%v len=%d, want an error with a "+
			"32-byte prefix — otherwise the length operand refuses this file and the error operand "+
			"stays uncovered", corrupted[:8], decodeErr, len(decoded))
	}

	set, err := LoadKeySet(keyFile(t, `{"approvers":{"`+alice+`":"`+corrupted+`"}}`))
	if err == nil {
		t.Fatalf("DEFECT: LoadKeySet accepted a key whose base64 is malformed (Len=%d) because its "+
			"first 44 characters happen to decode to 32 bytes — appended junk in a key file loads "+
			"silently", set.Len())
	}
	wants := fmt.Sprintf("approver %q must carry a base64 ed25519 public key of %d bytes", alice, ed25519.PublicKeySize)
	if !strings.Contains(err.Error(), wants) {
		t.Fatalf("LoadKeySet() error = %q, want it to mention %q — a refusal from the unknown-field, "+
			"trailing-document, empty-set or id guard would leave the base64 error operand unproven",
			err, wants)
	}

	// ANCHOR, after the refusal: the same file with the "!!!" removed must LOAD. Without it the
	// refusal above is consistent with a LoadKeySet that rejects this whole shape of document.
	clean, err := LoadKeySet(keyFile(t, `{"approvers":{"`+alice+`":"`+key+`"}}`))
	if err != nil || clean.Len() != 1 {
		t.Fatalf("anchor failed: the same key without the trailing %q was refused (%v, Len=%d), so "+
			"the case above does not isolate the base64 error", "!!!", err, clean.Len())
	}
}

// AN UNCONFIGURED DEPLOYMENT HAS NO KEY SET, AND SOMETHING ASKS IT FOR ITS DIGEST.
//
// (*KeySet)(nil) is the value this package hands out when no approver key path is configured:
// cmd/regalia-kms's preflight leaves the field nil, and operations' seal-separation test passes
// `(*approval.KeySet)(nil)` explicitly. Without the nil check, Digest dereferences it --
// observed as `PANIC runtime error: invalid memory address or nil pointer dereference` at the
// `return set.digest` line, which in the daemon is a crash on the path that records which keys
// made a decision.
//
// TestANilKeySetCountsNobody covers Verify's nil check, not this one, and the daemon's only
// Digest call sits inside the arm where the key set is never nil -- so nothing in the module
// went red when this guard was removed. Not TESTING.md §17: the input needs no privilege, and
// this test constructs it.
func TestANilKeySetHasAnEmptyDigestAndDoesNotPanic(t *testing.T) {
	var unconfigured *KeySet

	var digest string
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("DEFECT: (*KeySet)(nil).Digest() panicked: %v — an unconfigured deployment "+
					"crashes the daemon wherever a decision records the key set that made it", recovered)
			}
		}()
		digest = unconfigured.Digest()
	}()
	if digest != "" {
		t.Fatalf("(*KeySet)(nil).Digest() = %q, want %q: a nil key set identifies no keys", digest, "")
	}

	// ANCHOR, after the assertion: a configured key set reports a real digest. Without it, the
	// empty string above is equally consistent with a Digest that always returns "" — which
	// would make the nil answer meaningless rather than deliberate.
	alice, _, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	configured := NewKeySet(map[string]ed25519.PublicKey{alice: alicePublic})
	if !strings.HasPrefix(configured.Digest(), "sha256:") {
		t.Fatalf("anchor failed: a configured key set reported digest %q, so the empty digest above "+
			"says nothing about the nil receiver", configured.Digest())
	}
}

// A HEADER WHOSE BASE64 IS MALFORMED IS NOT EVIDENCE, EVEN IF THE BYTES BEFORE THE FAULT PARSE.
//
// base64.StdEncoding.DecodeString returns both an error and whatever it decoded before the
// fault. If the JSON list is padded to a length divisible by three there is no '=' in the
// encoding, so a single appended character faults only at the very end and the complete,
// valid approval list survives in the returned bytes. With Verify's decode-error check
// removed, this header was observed verifying as `[spiffe://regalia/approver/alice]`: a
// truncated or corrupted header -- the exact thing a proxy, a copy-paste, or a length limit
// produces -- counts as a full approval.
//
// The suite's existing "not-base64!!" case does not cover this: it faults at input byte 3 with
// an empty partial decode, so the JSON decode guard below is what refuses it, not this one.
func TestVerifyRefusesAHeaderWhoseBase64IsMalformedEvenWhenItsPrefixDecodesToAValidList(t *testing.T) {
	alice, aliceKey, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	set := NewKeySet(map[string]ed25519.PublicKey{alice: alicePublic})

	list, err := json.Marshal([]Approval{sign(t, alice, aliceKey, binding(), binding())})
	if err != nil {
		t.Fatal(err)
	}
	// Left-padded with JSON whitespace to a multiple of three so the encoding carries no '='
	// padding; the trailing "!" is then the first and only illegal byte, after a complete value.
	padded := strings.Repeat(" ", (3-len(list)%3)%3) + string(list)
	malformed := base64.StdEncoding.EncodeToString([]byte(padded)) + "!"

	// The fixture's premise, checked against the primitive: the decode errors and still yields
	// the whole JSON document. If that stops holding, the JSON decode guard is what refuses the
	// header and this test quietly stops covering the base64 guard.
	decoded, decodeErr := base64.StdEncoding.DecodeString(malformed)
	if decodeErr == nil || string(decoded) != padded {
		t.Fatalf("fixture premise broken: DecodeString err=%v, recovered %d of %d bytes — the partial "+
			"decode must be the complete list, or a later guard refuses this header", decodeErr,
			len(decoded), len(padded))
	}
	if len(malformed) > MaxHeaderBytes {
		t.Fatalf("fixture premise broken: header is %d bytes, over MaxHeaderBytes=%d, so the size "+
			"guard refuses it first", len(malformed), MaxHeaderBytes)
	}

	// Verify reports no message for bad evidence by design (see this file's header comment), so
	// the assertion is the count: nobody.
	if verified := set.Verify(malformed, binding()); len(verified) != 0 {
		t.Fatalf("DEFECT: a header whose base64 does not decode verified %v — base64 hands back the "+
			"bytes it read before the fault, so corrupted or truncated evidence counts as whole", verified)
	}

	// ANCHOR, after the refusal: the identical bytes without the trailing "!" must verify alice.
	// The two headers differ in exactly one character, so the refusal above is attributable to
	// the base64 fault and not to anything about the approval it carries.
	clean := base64.StdEncoding.EncodeToString([]byte(padded))
	if verified := set.Verify(clean, binding()); len(verified) != 1 || verified[0] != alice {
		t.Fatalf("anchor failed: the same list without the trailing %q verified %v, want [%s] — the "+
			"refusal above would then prove nothing about the base64 fault", "!", verified, alice)
	}
}

// AN APPROVAL CARRYING A FIELD THIS DAEMON DOES NOT UNDERSTAND IS NOT EVIDENCE IT CAN JUDGE.
//
// Verify refuses on `err != nil || len(approvals) > MaxApprovals`. This test covers the first
// operand; TestVerifyRefusesAnApprovalsListLongerThanMaxApprovals covers the second. They need
// separate fixtures -- one is a decode failure over a short list, the other a clean decode over
// a long one -- so neither can stand in for the other, though a mutation of the whole guard
// reds both.
//
// With the decode-error operand removed, a valid approval with `,"bogus":1` spliced in was
// observed verifying as `[spiffe://regalia/approver/alice]`. That is the shape of a downgrade:
// a signer emitting a newer approval format -- one carrying a field that constrains what the
// approval means, a scope, a quorum tag, a second binding -- would have that field silently
// dropped and the approval counted anyway, against a binding the extra field was meant to narrow.
//
// The suite's existing `[{"unknown_field":1}]` case does not cover this: with the operand
// removed it decodes to a single zero-valued Approval whose empty ApproverID is in no key set,
// so counts() refuses it and Verify still returns []. That case passes whatever this guard does.
func TestVerifyRefusesAnApprovalsListCarryingAnUnknownField(t *testing.T) {
	alice, aliceKey, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	set := NewKeySet(map[string]ed25519.PublicKey{alice: alicePublic})

	one, err := json.Marshal(sign(t, alice, aliceKey, binding(), binding()))
	if err != nil {
		t.Fatal(err)
	}
	spliced := "[" + strings.TrimSuffix(string(one), "}") + `,"bogus":1}]`
	if !strings.Contains(spliced, `,"bogus":1}]`) {
		t.Fatalf("fixture premise broken: the unknown field was not spliced into the approval: %q", spliced)
	}

	if verified := set.Verify(base64.StdEncoding.EncodeToString([]byte(spliced)), binding()); len(verified) != 0 {
		t.Fatalf("DEFECT: an approval carrying an unrecognised field verified %v — a field that was "+
			"meant to narrow what the approval authorizes is dropped and the approval counts in full",
			verified)
	}

	// ANCHOR, after the refusal: the identical approval without the spliced field must verify
	// alice. The two headers differ in exactly the eleven characters of the unknown field, which
	// is what attributes the refusal above to the field rather than to the signature or binding.
	clean := "[" + string(one) + "]"
	if verified := set.Verify(base64.StdEncoding.EncodeToString([]byte(clean)), binding()); len(verified) != 1 || verified[0] != alice {
		t.Fatalf("anchor failed: the same approval without the unknown field verified %v, want [%s] — "+
			"the refusal above would then prove nothing about the field", verified, alice)
	}
}

// THE APPROVAL COUNT IS BOUNDED BECAUSE SIGNATURE VERIFICATION IS NOT FREE.
//
// MaxApprovals is the second operand of the same guard as the test above. MaxHeaderBytes bounds
// the bytes; MaxApprovals bounds the ed25519 verifications one request can ask for, and the two
// are not the same bound -- a list of 65 minimal entries is far under the byte limit. With the
// cap removed, a 65-entry list was observed verifying its valid members instead of nothing, so
// nothing but the byte limit stands between a caller and as many verifications as fit in 16 KiB.
//
// The fixture keeps 8 real approvers and pads with zero-valued entries: the padding cannot be
// counted (its empty ApproverID is in no key set) so it changes only the length, which is the
// one thing under test.
func TestVerifyRefusesAnApprovalsListLongerThanMaxApprovals(t *testing.T) {
	const realApprovers = 8
	keys := make(map[string]ed25519.PublicKey, realApprovers)
	valid := make([]Approval, 0, realApprovers)
	for index := 0; index < realApprovers; index++ {
		id, private, public := approver(t, fmt.Sprintf("spiffe://regalia/approver/a%d", index))
		keys[id] = public
		valid = append(valid, sign(t, id, private, binding(), binding()))
	}
	set := NewKeySet(keys)

	list := func(entries int) string {
		approvals := append([]Approval{}, valid...)
		for len(approvals) < entries {
			approvals = append(approvals, Approval{})
		}
		return header(t, approvals...)
	}

	over := list(MaxApprovals + 1)
	// The fixture's premise: the over-cap list is still inside the byte limit. Without this the
	// refusal below could come from Verify's MaxHeaderBytes check and the cap stays uncovered.
	if len(over) > MaxHeaderBytes {
		t.Fatalf("fixture premise broken: a %d-entry list encodes to %d bytes, over MaxHeaderBytes=%d "+
			"— the size guard would refuse it and the cap would stay untested",
			MaxApprovals+1, len(over), MaxHeaderBytes)
	}

	if verified := set.Verify(over, binding()); len(verified) != 0 {
		t.Fatalf("DEFECT: a %d-entry approvals list verified %v — MaxApprovals=%d does not bound the "+
			"list, so one request can ask the daemon for as many ed25519 verifications as fit in "+
			"MaxHeaderBytes", MaxApprovals+1, verified, MaxApprovals)
	}

	// ANCHOR, after the refusal: one entry fewer -- exactly at the cap -- must verify all eight
	// real approvers. It is what proves the refusal above came from the cap and not from the byte
	// limit, the JSON decode, or the padding entries.
	if verified := set.Verify(list(MaxApprovals), binding()); len(verified) != realApprovers {
		t.Fatalf("anchor failed: a %d-entry list at the cap verified %d approvers (%v), want %d — the "+
			"refusal above is then attributable to something other than the cap",
			MaxApprovals, len(verified), verified, realApprovers)
	}
}

// AN EXPIRY THAT DOES NOT PARSE IS NOT AN EXPIRY IN THE PAST.
//
// counts() refuses on `err != nil || expires.After(binding.ExpiresAt)`. The second operand is
// covered by TestAnApprovalMayNotExpireAfterTheRequest, whose approval carries a well-formed
// RFC3339 time an hour later. The first operand cannot be reached by that fixture, and removing
// it left the module green.
//
// The failure it admits is quiet and the wrong way round: time.Parse returns the ZERO time on
// error, and the zero time is not After anything, so a malformed expiry falls straight through
// the freshness check into ed25519.Verify. Both `expires_at:""` and `expires_at:"not-a-time"`
// were observed verifying as `[spiffe://regalia/approver/alice]` with the operand removed --
// an approval with no usable expiry at all is treated as one that expires no later than the
// request, which is the most permissive reading available.
//
// The approval's own ExpiresAt is not part of CanonicalBytes -- the BINDING's expiry is -- so
// overwriting it after signing leaves a signature that still verifies. That is what makes this
// operand the only thing left that can refuse the evidence.
func TestAnApprovalWhoseExpiryDoesNotParseCountsForNobody(t *testing.T) {
	alice, aliceKey, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	set := NewKeySet(map[string]ed25519.PublicKey{alice: alicePublic})

	for _, unparseable := range []struct{ what, expiresAt string }{
		{"an absent expiry", ""},
		{"an expiry that is not a time at all", "not-a-time"},
		{"a date with no time, which RFC3339 does not accept", "2026-09-05"},
	} {
		t.Run(unparseable.what, func(t *testing.T) {
			evidence := sign(t, alice, aliceKey, binding(), binding())
			evidence.ExpiresAt = unparseable.expiresAt
			// Verify reports no message for bad evidence by design; the count is the assertion.
			if verified := set.Verify(header(t, evidence), binding()); len(verified) != 0 {
				t.Fatalf("DEFECT: an approval whose expires_at is %q verified %v — time.Parse returns "+
					"the zero time on failure and the zero time outlives nothing, so an approval with "+
					"no usable expiry reads as one that expires before the request",
					unparseable.expiresAt, verified)
			}
		})
	}

	// ANCHOR, after the refusals: the identical approval with a well-formed expiry must verify
	// alice. It differs from each case above in exactly the expires_at string, which is what
	// attributes those refusals to the parse and not to the signature, the nonce or the digest.
	wellFormed := sign(t, alice, aliceKey, binding(), binding())
	if verified := set.Verify(header(t, wellFormed), binding()); len(verified) != 1 || verified[0] != alice {
		t.Fatalf("anchor failed: the same approval with expires_at=%q verified %v, want [%s] — the "+
			"refusals above would then prove nothing about the parse",
			wellFormed.ExpiresAt, verified, alice)
	}
	if _, err := time.Parse(time.RFC3339Nano, wellFormed.ExpiresAt); err != nil {
		t.Fatalf("anchor failed: the control's own expires_at %q does not parse (%v), so it is not a "+
			"control for a parse failure", wellFormed.ExpiresAt, err)
	}
}
