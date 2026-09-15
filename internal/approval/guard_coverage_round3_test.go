package approval

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Two of the six operands #237's sweep found undetected in this package. The other four are
// recorded at the bottom of this file as defense-in-depth that cannot fail alone — measured,
// not assumed, because a test for a guard nothing can make the sole refuser is documentation
// wearing a gate's name.

// TestAnApprovalWhoseOwnClaimsDisagreeWithWhatItSignedIsNotCounted pins both operands of
// approval.go's `approval.Nonce != binding.Nonce || approval.PayloadDigest != expectedDigest`.
//
// BE PRECISE ABOUT WHAT THIS DOES NOT PROTECT. It is not the replay defence, and reading it
// as one would leave a real gap looking covered. An approval is counted only if
// ed25519.Verify succeeds over binding.CanonicalBytes(), which length-prefixes the object,
// purpose, environment, nonce, expiry and payload digest of the request being served. A
// signature made over request A therefore does not verify against request B, and that — not
// this guard — is what stops an approval being moved between requests.
//
// What this guard enforces is narrower and still worth keeping: `approval.Nonce` and
// `approval.PayloadDigest` are fields the CLIENT writes and nobody signs. They carry no
// authority. Without this check the daemon accepts an approval whose own statement of what
// it authorizes contradicts what it proves — evidence that disagrees with itself. Measured:
// with the nonce operand defeated, an approval declaring `nonce-zzzz-a-different-request`
// while carrying a valid signature over the real binding is counted, and Verify returns the
// approver as having approved a request their own evidence names differently.
//
// Nothing downstream reads those two fields today — Verify returns approver IDs and only the
// count reaches the policy engine — so the consequence is confined to admitting
// self-contradictory evidence. That is the honest scope of it.
//
// The subtests are separate because the two operands are separately defeatable and each must
// be attributable on its own; a single row would go red for either mutation and pin neither.
func TestAnApprovalWhoseOwnClaimsDisagreeWithWhatItSignedIsNotCounted(t *testing.T) {
	alice, alicePrivate, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	set := NewKeySet(map[string]ed25519.PublicKey{alice: alicePublic})
	request := binding()

	// THE CONTROL, in the same run. Without it every assertion below passes against a
	// counts() that refuses everything, and none of them is evidence. It also proves the
	// fixture reaches the signature check alive: the approver is configured, the expiry
	// parses and does not outlive the request, and the signature decodes to 64 bytes.
	honest := sign(t, alice, alicePrivate, request, request)
	if !set.counts(honest, request, request.CanonicalBytes(), request.PayloadDigest()) {
		t.Fatal("control: an approval that agrees with the request in every field and carries a " +
			"valid signature was not counted — every assertion below would pass against a " +
			"counts() that returns false unconditionally")
	}

	for _, row := range []struct {
		name string
		lie  func(Binding) Binding
		what string
	}{
		{
			name: "nonce",
			lie:  func(b Binding) Binding { b.Nonce = "nonce-zzzz-a-different-request"; return b },
			what: "declares a different nonce than the request it is being counted for",
		},
		{
			name: "payload digest",
			lie:  func(b Binding) Binding { b.Payload = []byte("bytes this approver never saw"); return b },
			what: "declares a digest over different bytes than the request it is being counted for",
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			// sign() takes the claimed binding and the signed binding separately, which is
			// what makes this input constructible: the approval's self-reported fields come
			// from the lie, the signature is over the REAL request and genuinely verifies.
			// Only the operand under test can refuse it.
			lying := sign(t, alice, alicePrivate, row.lie(request), request)

			if set.counts(lying, request, request.CanonicalBytes(), request.PayloadDigest()) {
				t.Fatalf("an approval that %s was counted — its signature is honest, so this is not "+
					"a forged approval; it is evidence whose own account of what it authorizes "+
					"contradicts what it proves, and the daemon accepted it", row.what)
			}
			if got := set.Verify(header(t, lying), request); len(got) != 0 {
				t.Fatalf("Verify returned %v for an approval that %s; the count is what reaches the "+
					"policy engine, so a self-contradictory approval satisfying RequiredApprovals "+
					"is the outcome that matters", got, row.what)
			}
		})
	}
}

// TestAMissingOrUnreadableApproverKeyFileSaysSoRatherThanBlamingItsContents pins the
// os.ReadFile error check in LoadKeySet.
//
// Defeated, `contents` is nil, the decoder is handed an empty reader, and the NEXT guard
// refuses with "approver keys must be a JSON object with an approvers map: EOF". So a path
// that does not exist, and a file the daemon may not read, both report as a malformed key
// file. The single caller (cmd/regalia-kms/preflight.go) treats every error from here as
// fatal, so no control flow changes — what changes is what an operator is told to go and fix,
// and preflight exists to tell them exactly that. A typo in ApproverKeysPath would send them
// to inspect JSON that is either fine or absent.
//
// The error identity is asserted, not the message text. errors.Is is what a future caller
// would branch on to tell "approvals are not configured" from "approvals are configured and
// broken", and it is the thing the wrapping preserves and the fall-through destroys.
func TestAMissingOrUnreadableApproverKeyFileSaysSoRatherThanBlamingItsContents(t *testing.T) {
	directory := t.TempDir()

	// THE CONTROL: a well-formed key set at a readable path must load, so a LoadKeySet that
	// refused everything cannot pass the rows below.
	alice, _, alicePublic := approver(t, "spiffe://regalia/approver/alice")
	good := filepath.Join(directory, "good.json")
	contents := `{"approvers":{"` + alice + `":"` + base64.StdEncoding.EncodeToString(alicePublic) + `"}}`
	if err := os.WriteFile(good, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if set, err := LoadKeySet(good); err != nil || set.Len() != 1 {
		t.Fatalf("control: a well-formed key set did not load (%v) — the assertions below would "+
			"pass against a LoadKeySet that refuses everything", err)
	}

	if _, err := LoadKeySet(filepath.Join(directory, "absent.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a key set path that does not exist reported %v, which does not carry os.ErrNotExist "+
			"— an operator who mistyped ApproverKeysPath is told their JSON is malformed and sent "+
			"to inspect a file that is not there", err)
	}

	// Root ignores mode bits, so this row can only be built as an ordinary user. CI's test
	// step runs as `runner`; the one root step runs a single named test in another package.
	if os.Geteuid() == 0 {
		t.Log("running as root: skipping the unreadable-file row, since root reads a 0000 file " +
			"and the fixture cannot build the state it needs")
		return
	}
	locked := filepath.Join(directory, "locked.json")
	if err := os.WriteFile(locked, []byte(`{"approvers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	// PROVE THE FIXTURE. If the file is readable after all, the row below tests nothing and
	// would fail blaming the guard rather than the fixture.
	if _, err := os.ReadFile(locked); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("fixture: the 0000 file is still readable (%v), so the row below would assert "+
			"nothing about an unreadable key set", err)
	}
	if _, err := LoadKeySet(locked); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("a key set the daemon may not read reported %v, which does not carry "+
			"os.ErrPermission — a permissions problem is reported as malformed JSON", err)
	}
}

// MEASURED AND DELIBERATELY NOT TESTED — the other four survivors in this package.
//
// Each was defeated and its input built; none can be made the sole refuser, so a test for it
// would be green today and green under the mutation it claims to catch.
//
//   approval.go, Verify, `header == ""`
//     Defeated, Verify("") still returns nil: base64 decoding "" yields no bytes and the JSON
//     decode of nothing fails at the next guard. The empty check is an early exit.
//
//   approval.go, counts, `err != nil` and `len(signature) != ed25519.SignatureSize`
//     Defeated TOGETHER — not one at a time, since each is otherwise the other's sibling —
//     a garbage-base64 signature, a 5-byte signature and a 65-byte signature are all still
//     refused. ed25519.Verify rejects a signature that is not SignatureSize bytes, so both
//     operands are a cheaper path to an answer the primitive already gives.
