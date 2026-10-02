package gpgsign

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// THE BINDING IS THE DAEMON'S. internal/approval serializes it in the parent module and this adapter
// serializes it again, across a module boundary neither can import over. API.md publishes one test
// vector for outside signers; the daemon's TestTheCanonicalBindingIsTheBytesAPIMdPublishes holds its
// side to it, and this holds ours. If the two ever disagree, approvals made here silently stop
// counting — the KMS treats evidence that does not verify as absent, not as an error.
func TestTheBindingIsTheBytesAPIMdPublishes(t *testing.T) {
	payload := sha256.Sum256([]byte("the bytes being signed"))
	pending := Pending{Version: 1, Mode: ModeDetach, ObjectID: "signing-key-1", Purpose: "release-signing", Environment: "production",
		Nonce: "nonce-aaaa-bbbb-cccc", ExpiresAt: "2026-01-02T15:04:05Z", Created: "2026-01-02T15:00:00Z", PayloadSHA256: hex.EncodeToString(payload[:]),
		// Not part of the binding: the record's own statement of which file it is for.
		DocumentSHA256: documentHash([]byte("the file")), RequestID: "0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b"}
	binding, err := pending.Binding()
	if err != nil {
		t.Fatal(err)
	}
	const published = "regalia-approval-v2\n13:signing-key-1\n15:release-signing\n10:production\n20:nonce-aaaa-bbbb-cccc\n20:2026-01-02T15:04:05Z\n64:850578896d7e7f0c6b2d8c93a22f456a12545aec94b1cbbd3770e39f7582c59c\n"
	if string(binding) != published {
		t.Fatalf("the binding is not the published one:\n%q\n%q", binding, published)
	}
	// The documentation key: seed 00 01 02 … 1f. Never an approver anywhere.
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	documentation := ed25519.NewKeyFromSeed(seed)
	if base64.StdEncoding.EncodeToString(documentation.Public().(ed25519.PublicKey)) != "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=" {
		t.Fatal("the documentation key is not the one API.md names")
	}
	approval, err := Approve(pending, "spiffe://regalia/approver/release", documentation, time.Date(2026, 1, 2, 15, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if approval.Signature != "wO20bUHZh99VG+VzFp2M/+fz+8a7tYcynVUKzi4dAas6B2+mnzeI8jI0pHIZxSLyywcWo/zbOGoOCpidSo2CAg==" {
		t.Fatalf("the approval signature is not API.md's: %s", approval.Signature)
	}
	if approval.Nonce != pending.Nonce || approval.ExpiresAt != pending.ExpiresAt || approval.PayloadDigest != pending.PayloadSHA256 {
		t.Fatalf("the approval does not carry the request's own nonce, expiry and digest: %#v", approval)
	}
}

// approvingKMS is the fake KMS with an approval policy in front of it: a request counts only if it
// carries an approval by the configured approver over the binding of THIS request, verified the way
// internal/approval verifies one. Anything else is DENIED, and nothing is signed.
type approvingKMS struct {
	*fakeKMS
	approverID string
	approver   ed25519.PublicKey
	denied     int
}

func newApprovingKMS(t *testing.T, tc keyCase, approverID string, approver ed25519.PublicKey) *approvingKMS {
	t.Helper()
	kms := &approvingKMS{fakeKMS: newFakeKMS(t, tc.key), approverID: approverID, approver: approver}
	kms.respond = func(writer http.ResponseWriter, seen seenRequest, signature []byte) {
		if !kms.approved(seen) {
			kms.mu.Lock()
			kms.denied++
			kms.mu.Unlock()
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(writer).Encode(map[string]any{"request_id": seen.requestID, "code": "DENIED", "message": "request failed", "retryable": false})
			return
		}
		writeResult(writer, seen.requestID, seen.document.ObjectID, signature)
	}
	return kms
}

func (kms *approvingKMS) approved(seen seenRequest) bool {
	decoded, err := base64.StdEncoding.DecodeString(seen.approvals)
	if err != nil {
		return false
	}
	var approvals []Approval
	if json.Unmarshal(decoded, &approvals) != nil {
		return false
	}
	digest := sha256.Sum256(seen.payload)
	binding, err := Pending{Version: 1, ObjectID: seen.document.ObjectID, Purpose: seen.document.Context.Purpose,
		Environment: seen.document.Context.Environment, Nonce: seen.document.Context.Nonce, ExpiresAt: seen.document.Context.ExpiresAt,
		Created: "2026-01-01T00:00:00Z", PayloadSHA256: hex.EncodeToString(digest[:])}.Binding()
	if err != nil {
		return false
	}
	for _, approval := range approvals {
		signature, err := base64.StdEncoding.DecodeString(approval.Signature)
		if err == nil && approval.ApproverID == kms.approverID && approval.Nonce == seen.document.Context.Nonce &&
			approval.ExpiresAt == seen.document.Context.ExpiresAt && approval.PayloadDigest == hex.EncodeToString(digest[:]) &&
			ed25519.Verify(kms.approver, binding, signature) {
			return true
		}
	}
	return false
}

const releaseApprover = "spiffe://regalia/approver/release"

// THE FLOW, FOR EVERY KEY TYPE AND EVERY MODE: prepare without contacting the KMS, approve, complete
// — and the result is an ordinary signature that go-crypto verifies against the exported key. The
// same request without the approval is denied.
func TestPrepareApproveCompleteProducesAnOrdinarySignature(t *testing.T) {
	approverPublic, approverPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range keyCases() {
		t.Run(tc.name, func(t *testing.T) {
			kms := newApprovingKMS(t, tc, releaseApprover, approverPublic)
			key := kms.key4(t, tc.key.Public())
			document := []byte(releaseFile)

			// Without approval, the policy denies; nothing is written.
			var denied bytes.Buffer
			if _, err := key.DetachSign(context.Background(), &denied, bytes.NewReader(document), fixedNow, true); err == nil || denied.Len() != 0 {
				t.Fatalf("an unapproved request was signed (%v, %d bytes)", err, denied.Len())
			}

			outputs := map[Mode]*bytes.Buffer{}
			for _, mode := range []Mode{ModeExportKey, ModeDetach, ModeDetachBinary, ModeClearSign} {
				before := len(kms.seen())
				pending, err := key.Prepare(context.Background(), mode, bytes.NewReader(document), fixedNow, 5*time.Minute)
				if err != nil {
					t.Fatalf("%s: prepare: %v", mode, err)
				}
				if len(kms.seen()) != before {
					t.Fatalf("%s: prepare contacted the KMS", mode)
				}
				if pending.ObjectID != target.ObjectID || pending.Fingerprint != key.Fingerprint() || len(pending.PayloadSHA256) != 64 || pending.Nonce == "" {
					t.Fatalf("%s: the pending record is incomplete: %#v", mode, pending)
				}
				approval, err := Approve(pending, releaseApprover, approverPrivate, fixedNow)
				if err != nil {
					t.Fatalf("%s: approve: %v", mode, err)
				}
				out := &bytes.Buffer{}
				if _, err := key.Complete(context.Background(), out, bytes.NewReader(document), pending, []Approval{approval}, fixedNow); err != nil {
					t.Fatalf("%s: complete: %v", mode, err)
				}
				// Exactly one request, carrying the prepared nonce, request ID and expiry.
				requests := kms.seen()[before:]
				if len(requests) != 1 || requests[0].document.Context.Nonce != pending.Nonce || requests[0].requestID != pending.RequestID ||
					requests[0].document.Context.ExpiresAt != pending.ExpiresAt {
					t.Fatalf("%s: complete did not send the prepared request once: %#v", mode, requests)
				}
				outputs[mode] = out
			}

			keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(outputs[ModeExportKey].Bytes()))
			if err != nil || len(keyring) != 1 {
				t.Fatalf("the approved key export does not parse: %v", err)
			}
			if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(document), bytes.NewReader(outputs[ModeDetach].Bytes()), nil); err != nil {
				t.Fatalf("the approved detached signature does not verify: %v", err)
			}
			if _, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(document), bytes.NewReader(outputs[ModeDetachBinary].Bytes()), nil); err != nil {
				t.Fatalf("the approved binary signature does not verify: %v", err)
			}
			if err := key.verifyClearSigned(outputs[ModeClearSign].Bytes()); err != nil {
				t.Fatalf("the approved cleartext signature does not verify: %v", err)
			}
		})
	}
}

// What Complete refuses BEFORE the KMS is asked, and what the KMS refuses when asked. In every case
// nothing is written.
func TestCompleteRefusesWhatWasNotPreparedAndApproved(t *testing.T) {
	approverPublic, approverPrivate, _ := ed25519.GenerateKey(nil)
	_, stranger, _ := ed25519.GenerateKey(nil)
	tc := keyCases()[1]
	kms := newApprovingKMS(t, tc, releaseApprover, approverPublic)
	key := kms.key4(t, tc.key.Public())
	document := []byte(releaseFile)
	prepare := func() (Pending, Approval) {
		t.Helper()
		pending, err := key.Prepare(context.Background(), ModeDetach, bytes.NewReader(document), fixedNow, 5*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		approval, err := Approve(pending, releaseApprover, approverPrivate, fixedNow)
		if err != nil {
			t.Fatal(err)
		}
		return pending, approval
	}
	otherPending, otherApproval := prepare()
	_ = otherPending

	for name, test := range map[string]struct {
		edit       func(*Pending, *[]Approval, *[]byte, *time.Time)
		want       string
		reachesKMS bool
	}{
		"the file changed after approval": {func(_ *Pending, _ *[]Approval, doc *[]byte, _ *time.Time) {
			*doc = bytes.Replace(*doc, []byte("stable"), []byte("sid   "), 1)
		}, "not what was prepared and approved", false},
		"no approval": {func(_ *Pending, approvals *[]Approval, _ *[]byte, _ *time.Time) { *approvals = nil }, "no approval", false},
		"an approval for another request": {func(_ *Pending, approvals *[]Approval, _ *[]byte, _ *time.Time) {
			*approvals = []Approval{otherApproval}
		}, "for another request", false},
		"the record expired": {func(_ *Pending, _ *[]Approval, _ *[]byte, now *time.Time) { *now = now.Add(6 * time.Minute) }, "expired", false},
		"a record for another object": {func(pending *Pending, _ *[]Approval, _ *[]byte, _ *time.Time) {
			pending.ObjectID = "another-key"
		}, "another key or target", false},
		"a record for another key": {func(pending *Pending, _ *[]Approval, _ *[]byte, _ *time.Time) {
			pending.Fingerprint = strings.Repeat("0", 40)
		}, "another key or target", false},
		"an approval by a key the KMS does not know": {func(pending *Pending, approvals *[]Approval, _ *[]byte, _ *time.Time) {
			forged, _ := Approve(*pending, releaseApprover, stranger, fixedNow)
			*approvals = []Approval{forged}
		}, "DENIED", true},
		"an approval under an identity the KMS does not know": {func(pending *Pending, approvals *[]Approval, _ *[]byte, _ *time.Time) {
			renamed, _ := Approve(*pending, "spiffe://regalia/approver/someone-else", approverPrivate, fixedNow)
			*approvals = []Approval{renamed}
		}, "DENIED", true},
		"a signature creation time moved after approval": {func(pending *Pending, _ *[]Approval, _ *[]byte, _ *time.Time) {
			pending.Created = fixedNow.Add(time.Second).Format(time.RFC3339)
		}, "not what was prepared and approved", false},
	} {
		t.Run(name, func(t *testing.T) {
			pending, approval := prepare()
			approvals, doc, now := []Approval{approval}, append([]byte(nil), document...), fixedNow
			test.edit(&pending, &approvals, &doc, &now)
			before := len(kms.seen())
			var out bytes.Buffer
			_, err := key.Complete(context.Background(), &out, bytes.NewReader(doc), pending, approvals, now)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected a refusal containing %q, got %v", test.want, err)
			}
			if out.Len() != 0 {
				t.Fatalf("%d bytes were written by a refused completion", out.Len())
			}
			if reached := len(kms.seen()) != before; reached != test.reachesKMS {
				t.Fatalf("the KMS was contacted: %v, want %v", reached, test.reachesKMS)
			}
		})
	}

	// An approval is spent with its request: the same record cannot be completed twice, because the
	// KMS has reserved the nonce. The fake does not model that, so this asserts what the client
	// controls — the nonce and request ID are the prepared ones, never fresh.
	pending, approval := prepare()
	var first bytes.Buffer
	if _, err := key.Complete(context.Background(), &first, bytes.NewReader(document), pending, []Approval{approval}, fixedNow); err != nil {
		t.Fatal(err)
	}
	last := kms.seen()[len(kms.seen())-1]
	if last.document.Context.Nonce != pending.Nonce || last.idempotencyKey != pending.Nonce {
		t.Fatal("complete sent a nonce other than the approved one")
	}
}

func TestApproveAndPrepareRefuseWhatCannotCount(t *testing.T) {
	_, approver, _ := ed25519.GenerateKey(nil)
	tc := keyCases()[0]
	kms := newFakeKMS(t, tc.key)
	key := kms.key4(t, tc.key.Public())
	pending, err := key.Prepare(context.Background(), ModeDetach, strings.NewReader("document"), fixedNow, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Approve(pending, releaseApprover, approver, fixedNow.Add(5*time.Minute)); err == nil {
		t.Error("an expired record was approved")
	}
	// Dated a year ahead, consistently: an approval of it now could be stockpiled.
	future := pending
	future.Created = fixedNow.AddDate(1, 0, 0).Format(time.RFC3339)
	future.ExpiresAt = fixedNow.AddDate(1, 0, 0).Add(5 * time.Minute).Format(time.RFC3339Nano)
	if _, err := Approve(future, releaseApprover, approver, fixedNow); err == nil || !strings.Contains(err.Error(), "dated in the future") {
		t.Errorf("a record dated next year was approved today: %v", err)
	}
	// Dated now (within the allowed skew) and expiring just over one window from the approver's
	// clock: the date check passes, and the expiry check is what refuses it.
	late := pending
	late.Created = fixedNow.Add(time.Minute).Format(time.RFC3339)
	late.ExpiresAt = fixedNow.Add(time.Hour + time.Minute).Format(time.RFC3339Nano)
	if _, err := Approve(late, releaseApprover, approver, fixedNow); err == nil || !strings.Contains(err.Error(), "too far in the future") {
		t.Errorf("a record expiring more than a window ahead was approved: %v", err)
	}
	if _, err := Approve(pending, "", approver, fixedNow); err == nil {
		t.Error("an approval without an approver ID was made")
	}
	if _, err := Approve(pending, releaseApprover, tc.key, fixedNow); err == nil {
		t.Error("a non-Ed25519 key approved")
	}
	tampered := pending
	tampered.ExpiresAt = "2026-10-01T12:05:00+00:00" // not the canonical form the KMS will rebuild
	if _, err := Approve(tampered, releaseApprover, approver, fixedNow); err == nil {
		t.Error("a record with a non-canonical expiry was approved; its approval could never count")
	}
	exported, err := key.Prepare(context.Background(), ModeExportKey, nil, fixedNow, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	exported.DocumentSHA256 = pending.DocumentSHA256
	if _, err := Approve(exported, releaseApprover, approver, fixedNow); err == nil {
		t.Error("a key export that names a file was approved")
	}
	for _, window := range []time.Duration{30 * time.Second, 2 * time.Hour} {
		if _, err := key.Prepare(context.Background(), ModeDetach, strings.NewReader("document"), fixedNow, window); err == nil {
			t.Errorf("a window of %v was accepted", window)
		}
	}
	if _, err := key.Prepare(context.Background(), Mode("inline"), strings.NewReader("document"), fixedNow, 5*time.Minute); err == nil {
		t.Error("an unknown mode was prepared")
	}
	// The record round-trips through its file form, strictly.
	encoded, _ := json.Marshal(pending)
	if read, err := ReadPending(encoded); err != nil || read != pending {
		t.Errorf("the pending record does not round-trip: %v", err)
	}
	if _, err := ReadPending(append(encoded, []byte(` {"x":1}`)...)); err == nil {
		t.Error("a pending file with a second document was accepted")
	}
	if _, err := ReadPending([]byte(strings.Replace(string(encoded), `"version":1`, `"version":1,"slot":2`, 1))); err == nil {
		t.Error("a pending file with an unknown field was accepted")
	}
}
