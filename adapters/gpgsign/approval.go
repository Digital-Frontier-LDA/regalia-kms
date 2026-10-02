package gpgsign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// SIGNING UNDER A POLICY THAT REQUIRES APPROVAL (regalia#530).
//
// A purpose policy with required_approvals does not admit a request on the caller's identity alone:
// it wants an approver's Ed25519 signature over a binding of that exact request — object, purpose,
// environment, nonce, expiry and the SHA-256 of the payload (API.md). For an OpenPGP signature the
// payload is the signature digest, which covers the signature's own creation time. So the signature
// has to be PREPARED before anyone can approve it, and COMPLETED afterwards, unchanged:
//
//	Prepare   decides the creation time, nonce, request ID and expiry, computes the payload the KMS
//	          would be sent, and returns a Pending record. The KMS is not contacted.
//	Approve   an approver reads the Pending record and signs its binding with their own key.
//	Complete  rebuilds the same signature, checks that its payload is the one that was approved,
//	          sends it with the approvals, and writes the result.
//
// Nothing here weakens the policy: the KMS verifies each approval against its own key set, and a
// request whose evidence does not count is denied exactly as before.

// Mode is what is being signed.
type Mode string

const (
	ModeDetach       Mode = "detach"        // an armored detached signature
	ModeDetachBinary Mode = "detach-binary" // a binary detached signature
	ModeClearSign    Mode = "clearsign"     // a cleartext-signed document
	ModeExportKey    Mode = "export-key"    // the public key with its self-certification
)

// Pending is a prepared signature waiting for approval. It holds nothing secret. Every field is
// either shown to the approver or needed to rebuild the identical request.
type Pending struct {
	Version     int    `json:"version"`
	Mode        Mode   `json:"mode"`
	Fingerprint string `json:"key_fingerprint"`
	ObjectID    string `json:"object_id"`
	Purpose     string `json:"purpose"`
	Environment string `json:"environment"`
	// Created is the OpenPGP signature's creation time. It is part of what is signed, so Complete
	// uses it instead of the clock.
	Created   string `json:"signature_created"`
	Nonce     string `json:"nonce"`
	RequestID string `json:"request_id"`
	ExpiresAt string `json:"expires_at"`
	// DocumentSHA256 is the SHA-256 of the file being signed (empty for a key export): what a
	// human approver compares with the artifact. PayloadSHA256 is the SHA-256 of the bytes the KMS
	// will be sent, which is what the approval binding carries.
	DocumentSHA256 string `json:"document_sha256,omitempty"`
	PayloadSHA256  string `json:"payload_sha256"`
}

// Approval is one approver's evidence, in the form the KMS reads (API.md).
type Approval struct {
	ApproverID    string `json:"approver_id"`
	Nonce         string `json:"nonce"`
	ExpiresAt     string `json:"expires_at"`
	PayloadDigest string `json:"payload_digest"`
	Signature     string `json:"signature"`
}

var errPrepared = errors.New("prepared: the payload was observed and nothing was sent")

// withCall returns the same key with a different KMS call behind it.
func (key *Key) withCall(call signCall) *Key {
	signer := *key.signer
	signer.call = call
	replaced := *key
	replaced.signer = &signer
	return &replaced
}

// run performs one mode against w. It is the single path Prepare, Complete and the unapproved
// commands share, so what is prepared is exactly what is later completed.
func (key *Key) run(ctx context.Context, mode Mode, w io.Writer, message io.Reader, at time.Time) (Signed, error) {
	switch mode {
	case ModeDetach:
		return key.DetachSign(ctx, w, message, at, true)
	case ModeDetachBinary:
		return key.DetachSign(ctx, w, message, at, false)
	case ModeClearSign:
		return key.ClearSign(ctx, w, message, at)
	case ModeExportKey:
		return Signed{Created: key.created}, key.ExportPublic(ctx, w)
	}
	return Signed{}, errors.New("unknown signing mode")
}

// Payload computes the bytes the KMS would be sent for this signature, and sends nothing. created
// is the signature's creation time (ignored for a key export, whose time is the key's).
func (key *Key) Payload(ctx context.Context, mode Mode, message io.Reader, created time.Time) ([]byte, error) {
	var payload []byte
	observed := 0
	probe := key.withCall(func(_ context.Context, sent []byte, _ string) ([]byte, error) {
		observed++
		payload = append([]byte(nil), sent...)
		return nil, errPrepared
	})
	_, err := probe.run(ctx, mode, io.Discard, message, created.UTC().Truncate(time.Second))
	if !errors.Is(err, errPrepared) || observed != 1 || len(payload) == 0 {
		if err == nil || errors.Is(err, errPrepared) {
			err = errors.New("the signature could not be prepared")
		}
		return nil, err
	}
	return payload, nil
}

// Prepare computes what Complete will send, without sending it, and fixes the request's nonce, ID
// and expiry (validFor from the client's clock). now becomes the signature's creation time.
func (key *Key) Prepare(ctx context.Context, mode Mode, message io.Reader, now time.Time, validFor time.Duration) (Pending, error) {
	if key.signer.client == nil {
		return Pending{}, errors.New("this key has no KMS client")
	}
	if validFor < time.Minute || validFor > time.Hour {
		return Pending{}, errors.New("an approval window is between 1 minute and 1 hour")
	}
	now = now.UTC().Truncate(time.Second)
	payload, err := key.Payload(ctx, mode, message, now)
	if err != nil {
		return Pending{}, err
	}
	fixed, err := key.signer.client.Fresh(validFor)
	if err != nil {
		return Pending{}, err
	}
	payloadHash := sha256.Sum256(payload)
	created := now
	if mode == ModeExportKey {
		created = key.created
	}
	return Pending{
		Version: 1, Mode: mode, Fingerprint: key.Fingerprint(),
		ObjectID: key.signer.target.ObjectID, Purpose: key.signer.target.Purpose, Environment: key.signer.target.Environment,
		Created: created.Format(time.RFC3339), Nonce: fixed.Nonce, RequestID: fixed.RequestID,
		ExpiresAt: fixed.ExpiresAt.Format(time.RFC3339Nano), PayloadSHA256: hex.EncodeToString(payloadHash[:]),
	}, nil
}

// Covers says whether the pending signature is this key's signature over message: the approver's
// own check that the digest they are asked to sign is the digest of the file in front of them, and
// not merely a file hash the preparer wrote into the record. key may be offline.
//
// It recomputes the payload from the approver's copy of the file, this key and the record's
// creation time, and compares its SHA-256 with the one the approval binding carries.
func (key *Key) Covers(ctx context.Context, pending Pending, message io.Reader) error {
	created, _, err := pending.times()
	if err != nil {
		return err
	}
	target := key.signer.target
	if pending.Fingerprint != key.Fingerprint() || pending.ObjectID != target.ObjectID ||
		pending.Purpose != target.Purpose || pending.Environment != target.Environment {
		return errors.New("the pending signature is for another key or target than the one this approver approves for")
	}
	payload, err := key.Payload(ctx, pending.Mode, message, created)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != pending.PayloadSHA256 {
		return errors.New("the pending signature is not a signature over this file")
	}
	return nil
}

// SetDocument records the SHA-256 of the file being signed, for the approver to compare.
func (pending *Pending) SetDocument(document []byte) {
	sum := sha256.Sum256(document)
	pending.DocumentSHA256 = hex.EncodeToString(sum[:])
}

// times parses the record's two times, refusing a record that is not exactly what Prepare writes.
func (pending Pending) times() (created, expires time.Time, err error) {
	if pending.Version != 1 {
		return created, expires, errors.New("unknown pending-signature version")
	}
	if created, err = time.Parse(time.RFC3339, pending.Created); err != nil {
		return created, expires, errors.New("the pending signature's creation time is not readable")
	}
	if expires, err = time.Parse(time.RFC3339Nano, pending.ExpiresAt); err != nil || expires.UTC().Format(time.RFC3339Nano) != pending.ExpiresAt {
		return created, expires, errors.New("the pending signature's expiry is not in canonical form")
	}
	if decoded, decodeErr := hex.DecodeString(pending.PayloadSHA256); decodeErr != nil || len(decoded) != sha256.Size {
		return created, expires, errors.New("the pending signature's payload digest is not a SHA-256")
	}
	return created, expires, nil
}

// Binding is the bytes an approver signs: the KMS's approval binding, version 2 (API.md). A version
// line, then six records, each "<length>:<field>\n" with the length in bytes.
//
// The same serialization is implemented in the daemon (internal/approval). The two cannot share
// code across the module boundary, so TestTheBindingIsTheBytesAPIMdPublishes holds this one to the
// vector API.md publishes, the same vector the daemon's test holds.
func (pending Pending) Binding() ([]byte, error) {
	if _, _, err := pending.times(); err != nil {
		return nil, err
	}
	var canonical strings.Builder
	canonical.WriteString("regalia-approval-v2\n")
	for _, field := range []string{pending.ObjectID, pending.Purpose, pending.Environment, pending.Nonce, pending.ExpiresAt, pending.PayloadSHA256} {
		canonical.WriteString(strconv.Itoa(len(field)))
		canonical.WriteString(":")
		canonical.WriteString(field)
		canonical.WriteString("\n")
	}
	return []byte(canonical.String()), nil
}

// Approve signs the pending signature's binding as approverID. signer must be an Ed25519 key: the
// KMS verifies approvals with Ed25519 and nothing else. now is the approver's clock; an expired
// record is refused, because its approval could never count.
func Approve(pending Pending, approverID string, signer crypto.Signer, now time.Time) (Approval, error) {
	_, expires, err := pending.times()
	if err != nil {
		return Approval{}, err
	}
	if !now.Before(expires) {
		return Approval{}, errors.New("the pending signature has expired; prepare it again")
	}
	public, ok := signer.Public().(ed25519.PublicKey)
	if !ok || strings.TrimSpace(approverID) == "" {
		return Approval{}, errors.New("an approval needs an approver ID and an Ed25519 key")
	}
	binding, err := pending.Binding()
	if err != nil {
		return Approval{}, err
	}
	// crypto.Hash(0): Ed25519 signs the message itself, not a digest of it.
	signature, err := signer.Sign(nil, binding, crypto.Hash(0))
	if err != nil {
		return Approval{}, fmt.Errorf("sign the approval: %w", err)
	}
	if !ed25519.Verify(public, binding, signature) {
		return Approval{}, errors.New("the approval signature does not verify against the approver's own key")
	}
	return Approval{ApproverID: approverID, Nonce: pending.Nonce, ExpiresAt: pending.ExpiresAt,
		PayloadDigest: pending.PayloadSHA256, Signature: base64.StdEncoding.EncodeToString(signature)}, nil
}

// Complete rebuilds the prepared signature, sends it with the approvals, and writes the result to w.
//
// It refuses, before contacting the KMS, when the record is for another key or target, has expired,
// carries no approval, or carries one that was made for another request. And when the payload it
// rebuilds is not the one that was prepared — the file changed, or the key did — nothing is sent:
// an approval is for the bytes the approver was shown.
func (key *Key) Complete(ctx context.Context, w io.Writer, message io.Reader, pending Pending, approvals []Approval, now time.Time) (Signed, error) {
	created, expires, err := pending.times()
	if err != nil {
		return Signed{}, err
	}
	target := key.signer.target
	if key.signer.client == nil || pending.Fingerprint != key.Fingerprint() || pending.ObjectID != target.ObjectID ||
		pending.Purpose != target.Purpose || pending.Environment != target.Environment {
		return Signed{}, errors.New("the pending signature was prepared for another key or target")
	}
	if !now.Before(expires) {
		return Signed{}, errors.New("the pending signature has expired; prepare it again")
	}
	if len(approvals) == 0 {
		return Signed{}, errors.New("no approval was given")
	}
	for _, approval := range approvals {
		if approval.Nonce != pending.Nonce || approval.ExpiresAt != pending.ExpiresAt || approval.PayloadDigest != pending.PayloadSHA256 {
			return Signed{}, fmt.Errorf("the approval from %s is for another request", approval.ApproverID)
		}
	}
	fixed := Fixed{Nonce: pending.Nonce, RequestID: pending.RequestID, ExpiresAt: expires}
	calls := 0
	sender := key.withCall(func(ctx context.Context, payload []byte, subject string) ([]byte, error) {
		calls++
		sum := sha256.Sum256(payload)
		if calls != 1 || hex.EncodeToString(sum[:]) != pending.PayloadSHA256 {
			return nil, errors.New("what would be signed now is not what was prepared and approved: the file or the key changed")
		}
		return key.signer.client.SignFixed(ctx, target, payload, subject, fixed, approvals)
	})
	var out bytes.Buffer
	signed, err := sender.run(ctx, pending.Mode, &out, message, created)
	if err != nil {
		return Signed{}, err
	}
	if _, err := w.Write(out.Bytes()); err != nil {
		return Signed{}, err
	}
	return signed, nil
}

// ReadPending and ReadApproval parse the two records strictly: one JSON document, no unknown field.
func ReadPending(contents []byte) (Pending, error) {
	var pending Pending
	if err := decodeOne(contents, &pending); err != nil {
		return Pending{}, errors.New("the pending-signature file is not the expected JSON document")
	}
	if _, _, err := pending.times(); err != nil {
		return Pending{}, err
	}
	return pending, nil
}

func ReadApproval(contents []byte) (Approval, error) {
	var approval Approval
	if err := decodeOne(contents, &approval); err != nil || approval.ApproverID == "" || approval.Signature == "" {
		return Approval{}, errors.New("the approval file is not the expected JSON document")
	}
	return approval, nil
}

func decodeOne(contents []byte, into any) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("more than one JSON document")
	}
	return nil
}
