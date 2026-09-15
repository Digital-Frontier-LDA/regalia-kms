// Package controlplane exports and inspects the durable, reconstructable KMS control-plane
// state (#49).
//
// WHY THIS PACKAGE EXISTS. Proxmox VM backups, snapshots and replication are forbidden for the
// KMS guest (the policy guard quarantines the VM over them) because a machine image captures
// memory-resident credentials and runtime state that has no business leaving the custody
// boundary. But "no backups" cannot be the whole answer: the guest also accumulates state a
// rebuilt site cannot reconstruct on its own — the audit journal, the policy reservation state,
// the fencing epoch history — and a site that cannot recover that state after a loss is a site
// that loses its own history. So the durable state is exported SEPARATELY, as an encrypted,
// integrity-checked application artifact carried out through the custody procedure, and the
// machine image stays forbidden. deploy/proxmox/README.md states the contract this package
// implements: runtime credentials, vTPM state, memory, swap, core dumps, PINs, plaintext
// outputs and token state are excluded; rebuild recovers operational authority through the
// witnessed custody procedure, never by restoring an image.
//
// The envelope is sealed to the CUSTODY AUTHORITY's P-256 public key — the same offline-authority
// pattern verify.py uses for commissioning evidence. The guest holds only the public half, so an
// export file found on a compromised guest disk helps nobody read past exports. The authority
// signs the carried-out FILE outside the guest (the guest has no signing key, by design), exactly
// as it signs commissioning transcripts.
package controlplane

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// envelopeAlgorithm binds every field of this envelope format to a name the inspector can
// refuse on. A future algorithm change must not silently accept old envelopes.
const envelopeAlgorithm = "ecdh-p256+hkdf-sha256+aes-256-gcm"

// envelopeInfo is the HKDF info string AND the AES-GCM associated data: key derivation and
// AEAD authentication are both bound to purpose and version, so a sealed blob from any other
// subsystem cannot be opened as a control-plane export, and an envelope field cannot be swapped
// between the two.
const envelopeInfo = "regalia-control-plane-export-v1"

// Envelope is the on-disk format: everything except v/alg is opaque base64. There is no
// plaintext metadata on purpose — even the site name and entry list travel inside the
// ciphertext, so an export file found on a backup share says nothing about the deployment.
type Envelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	Ephemeral  string `json:"ephemeral"` // base64, uncompressed P-256 point (65 bytes)
	Nonce      string `json:"nonce"`     // base64, 12 bytes
	Ciphertext string `json:"ciphertext"`
}

// Seal encrypts payload to the custody authority's public key and returns the serialized
// envelope. The whole payload is one AES-GCM plaintext, so tampering with any envelope field
// fails at open rather than at parse.
func Seal(payload []byte, recipient *ecdh.PublicKey) ([]byte, error) {
	if recipient == nil || recipient.Curve() != ecdh.P256() {
		return nil, errors.New("controlplane: recipient key must be P-256")
	}
	ephemeral, err := generateEphemeralKey(entropyReader)
	if err != nil {
		return nil, fmt.Errorf("controlplane: generate ephemeral key: %w", err)
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return nil, fmt.Errorf("controlplane: ephemeral ECDH: %w", err)
	}
	key, err := deriveKey(shared, ephemeral.PublicKey().Bytes(), recipient.Bytes())
	if err != nil {
		return nil, fmt.Errorf("controlplane: derive key: %w", err)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, fmt.Errorf("controlplane: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(entropyReader, nonce); err != nil {
		return nil, fmt.Errorf("controlplane: nonce: %w", err)
	}
	envelope := Envelope{
		Version:    1,
		Algorithm:  envelopeAlgorithm,
		Ephemeral:  base64.StdEncoding.EncodeToString(ephemeral.PublicKey().Bytes()),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, payload, []byte(envelopeInfo))),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("controlplane: marshal envelope: %w", err)
	}
	return encoded, nil
}

var generateEphemeralKey = ecdh.P256().GenerateKey

var errOpen = errors.New("controlplane: envelope could not be opened with this key")

// Open decrypts an envelope with the custody authority's private key. Every failure is the
// same error: open is the one place where "which field was wrong" is a hint to an attacker
// holding a file they cannot read, and it tells a legitimate operator nothing they can act on.
func Open(encoded []byte, recipient *ecdh.PrivateKey) ([]byte, error) {
	if recipient == nil || recipient.Curve() != ecdh.P256() {
		return nil, errOpen
	}
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, errOpen
	}
	// ONE DOCUMENT, NOTHING AFTER IT. Decode stops at the end of the first JSON value, so
	// without this an export and the same bytes with anything appended open to the SAME
	// payload -- measured, 255 and 275 bytes, identical result. Nothing records a digest of
	// this file today, so the exposure is identity rather than content: the payload is
	// GCM-authenticated and the inner entries carry their own digests. But this is the
	// artifact operators carry offline, and RUNBOOK-DISASTER-RECOVERY.md already asks them to
	// record its hash -- at which point "we verified sha256:X" stops naming what was verified.
	// Fifteen of the other sixteen decoders in this module already make this check.
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errOpen
	}
	if envelope.Version != 1 || envelope.Algorithm != envelopeAlgorithm {
		return nil, errOpen
	}
	ephemeralBytes, err := base64.StdEncoding.Strict().DecodeString(envelope.Ephemeral)
	if err != nil {
		return nil, errOpen
	}
	ephemeral, err := ecdh.P256().NewPublicKey(ephemeralBytes)
	if err != nil {
		return nil, errOpen
	}
	shared, err := recipient.ECDH(ephemeral)
	if err != nil {
		return nil, errOpen
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(envelope.Nonce)
	if err != nil || len(nonce) != gcmNonceSize {
		return nil, errOpen
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, errOpen
	}
	key, err := deriveKey(shared, ephemeral.Bytes(), recipient.PublicKey().Bytes())
	if err != nil {
		return nil, errOpen
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, errOpen
	}
	payload, err := gcm.Open(nil, nonce, ciphertext, []byte(envelopeInfo))
	if err != nil {
		return nil, errOpen
	}
	return payload, nil
}

const gcmNonceSize = 12

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// deriveKey mixes the ECDH shared secret with BOTH public keys. ECDH output alone does not
// bind which keys produced it; adding both points makes the derived key specific to this pair
// and this exchange, which is the standard ECIES shape (RFC 9180 uses the same contributor
// inputs for the same reason).
func deriveKey(shared, ephemeralPublic, recipientPublic []byte) ([]byte, error) {
	salt := append(append([]byte(envelopeInfo), ephemeralPublic...), recipientPublic...)
	return hkdf.Key(sha256.New, shared, salt, envelopeInfo, 32)
}

// Recipient is a parsed custody-authority public key: the ECDH half for sealing, plus the
// digest an operator transcribes into the custody record — the same fingerprint discipline as
// the commissioning evidence key in deploy/proxmox.
type Recipient struct {
	PublicKey *ecdh.PublicKey
	// Digest is the lowercase hex SHA-256 of the key's DER encoding.
	Digest string
}

// ParseRecipient reads a PEM "PUBLIC KEY" (PKIX, P-256) — the custody authority's public half,
// distributed with the site configuration exactly like the commissioning evidence key.
func ParseRecipient(pemBytes []byte) (*Recipient, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("controlplane: recipient key must be a PEM PUBLIC KEY")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("controlplane: parse recipient key: %w", err)
	}
	public, ok := parsed.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return nil, errors.New("controlplane: recipient key must be ECDSA P-256")
	}
	ecdhPublic, err := public.ECDH()
	if err != nil {
		return nil, fmt.Errorf("controlplane: recipient key: %w", err)
	}
	digest := sha256.Sum256(block.Bytes)
	return &Recipient{PublicKey: ecdhPublic, Digest: fmt.Sprintf("%x", digest[:])}, nil
}

// ParseAuthorityKey reads a PEM "PRIVATE KEY" (PKCS#8, P-256) — the custody authority's private
// half, which exists only in the authority's offline custody and never on the guest.
func ParseAuthorityKey(pemBytes []byte) (*ecdh.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("controlplane: authority key must be a PEM PRIVATE KEY")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("controlplane: parse authority key: %w", err)
	}
	private, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || private.Curve != elliptic.P256() {
		return nil, errors.New("controlplane: authority key must be ECDSA P-256")
	}
	return private.ECDH()
}

// Ed25519 is intentionally unsupported as an envelope recipient: it signs and verifies but
// cannot do key agreement, and inventing a wrapper would be new cryptography. This constant
// exists only so the doc can point at what the authority DOES use Ed25519 for.
const authoritySignsEnvelopesWith = "P-256 ECDSA (same key class as commissioning evidence)"

var _ = ed25519.PublicKey(nil)
