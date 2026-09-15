package operations

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/approval"
)

// AN APPROVAL MUST COMMIT TO THE BYTES BEING SEALED.
//
// The approval binding took `request.Data` directly. Five operations carry their body there and
// seal-envelope does not -- its parts arrive in SealCiphertext/SealNonce/SealDataKey -- so every
// seal-envelope approval committed to sha256 of nothing, and one issued for a given ciphertext
// counted for ANY other under the same object, purpose, environment, nonce and expiry.
//
// The nonce is single-use, so this is not "one approval seals anything forever". It is that
// within a nonce's life the approver's signature stopped saying WHICH ciphertext they approved:
// they believed they had authorised sealing particular bytes and had authorised sealing
// anything. For a dual-control gate on a custody system that is the property the gate is for.
//
// Written against the binding rather than through the coordinator on purpose: the defect is in
// what the signature covers, and a test that drove the whole stack could pass or fail for a
// dozen unrelated reasons.
func TestASealApprovalDoesNotCarryToADifferentCiphertext(t *testing.T) {
	now := time.Date(2026, 9, 5, 7, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	const approver = "spiffe://regalia/approver/treasury"
	keys := approval.NewKeySet(map[string]ed25519.PublicKey{approver: public})

	binding := func(request api.Request) approval.Binding {
		return approval.Binding{
			ObjectID: request.ObjectID, Purpose: request.Context.Purpose,
			Environment: request.Context.Environment, Nonce: request.Context.Nonce,
			ExpiresAt: request.Context.ExpiresAt, Payload: approvalPayload(request),
		}
	}
	seal := func(ciphertext string) api.Request {
		return api.Request{
			ObjectID: "opaque-secret", Operation: "seal-envelope",
			Principal: "spiffe://regalia/workload/deployer",
			Context: api.OperationContext{
				Environment: "production", Purpose: "release-secret",
				ExpiresAt: now.Add(time.Minute), Nonce: "nonce_0123456789abcd1",
			},
			SealCiphertext: []byte(ciphertext),
			SealNonce:      []byte("012345678901"),
			SealDataKey:    bytes.Repeat([]byte{7}, 32),
		}
	}

	approved := seal("the ciphertext the approver was shown")
	substituted := seal("entirely different bytes, same everything else")

	// The precondition the whole test rests on: the two requests differ ONLY in the sealed
	// bytes. Without this the second could be refused for an unrelated reason and the test
	// would pass while proving nothing.
	if approved.ObjectID != substituted.ObjectID ||
		approved.Context != substituted.Context ||
		!bytes.Equal(approved.SealNonce, substituted.SealNonce) {
		t.Fatal("the two requests differ in more than the ciphertext: the substitution is not the variable")
	}
	if bytes.Equal(approved.SealCiphertext, substituted.SealCiphertext) {
		t.Fatal("the two ciphertexts are identical: nothing is being substituted")
	}

	header := approvalsHeader(t, binding(approved), map[string]ed25519.PrivateKey{approver: private}, approver)

	if got := keys.Verify(header, binding(approved)); len(got) != 1 || got[0] != approver {
		t.Fatalf("the approval did not count for the ciphertext it was signed over: %v", got)
	}
	if got := keys.Verify(header, binding(substituted)); len(got) != 0 {
		t.Fatalf("an approval issued for one ciphertext counted for another: %v", got)
	}
}

// The nonce is part of what is sealed and must be covered too, for the same reason.
func TestASealApprovalDoesNotCarryToADifferentNonceField(t *testing.T) {
	now := time.Date(2026, 9, 5, 7, 0, 0, 0, time.UTC)
	base := api.Request{
		ObjectID: "opaque-secret", Operation: "seal-envelope",
		Context: api.OperationContext{
			Environment: "production", Purpose: "release-secret",
			ExpiresAt: now.Add(time.Minute), Nonce: "nonce_0123456789abcd1",
		},
		SealCiphertext: []byte("same ciphertext"),
		SealNonce:      []byte("012345678901"),
	}
	other := base
	other.SealNonce = []byte("210987654321")

	if bytes.Equal(approvalPayload(base), approvalPayload(other)) {
		t.Fatal("two seals differing in their AEAD nonce produce the same approval payload")
	}
}

// The framing has to be unambiguous: a shifted boundary between the two parts must not produce
// the same bytes, or an approval for (nonce N, ciphertext C) would also cover a different split
// of the same concatenation.
func TestTheSealApprovalPayloadIsUnambiguouslyFramed(t *testing.T) {
	left := api.Request{Operation: "seal-envelope", SealNonce: []byte("AAAA"), SealCiphertext: []byte("BBBBBB")}
	right := api.Request{Operation: "seal-envelope", SealNonce: []byte("AAAAB"), SealCiphertext: []byte("BBBBB")}
	if bytes.Equal(approvalPayload(left), approvalPayload(right)) {
		t.Fatal("moving the boundary between nonce and ciphertext produced the same payload")
	}
}

// Every other operation must keep committing to Data, or this fix would quietly stop the five
// working operations' approvals covering anything.
func TestApprovalPayloadIsStillTheDataForEveryOtherOperation(t *testing.T) {
	for _, operation := range []string{"sign", "unwrap", "wrap", "key-agreement", "certificate-sign", "release-secret"} {
		t.Run(operation, func(t *testing.T) {
			request := api.Request{Operation: operation, Data: []byte("the body")}
			if !bytes.Equal(approvalPayload(request), []byte("the body")) {
				t.Fatalf("%s no longer commits to Data: %q", operation, approvalPayload(request))
			}
		})
	}
}
