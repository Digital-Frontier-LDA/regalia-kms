// Package envelope protects bounded opaque secrets with ephemeral AES data
// keys whose wrapping key operations are provided only by hardware backends.
package envelope

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"time"
)

const (
	Version           = 2
	MaxPlaintextBytes = 1 << 20
	maxContextBytes   = 64 << 10
	maxEnvelopeBytes  = 2 << 20
)

var (
	ErrInvalidEnvelope    = errors.New("invalid secret envelope")
	ErrBackendUnavailable = errors.New("hardware wrapping backend unavailable")
	objectIDPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
	keyVersionPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
)

type KeyRef struct {
	Backend string `json:"backend"`
	ID      string `json:"id"`
	Version string `json:"version"`
}

type Wrapper interface {
	Backend() string
	WrapKey(context.Context, KeyRef, []byte, []byte) ([]byte, error)
	UnwrapKey(context.Context, KeyRef, []byte, []byte) ([]byte, error)
}

type Envelope struct {
	Version        int       `json:"version"`
	ObjectID       string    `json:"object_id"`
	KEK            KeyRef    `json:"kek"`
	Algorithm      string    `json:"algorithm"`
	ContextDigest  string    `json:"context_digest"`
	CreatedAt      time.Time `json:"created_at"`
	Nonce          []byte    `json:"nonce_base64"`
	Ciphertext     []byte    `json:"ciphertext_base64"`
	WrappedDataKey []byte    `json:"wrapped_data_key_base64"`
}

func Seal(ctx context.Context, wrapper Wrapper, kek KeyRef, objectID string, bindingContext, plaintext []byte, random io.Reader, createdAt time.Time) (Envelope, error) {
	// The `createdAt.IsZero()` operand here is the FIRST refusal. The same property is
	// checked downstream at validateEnvelopeMetadata:326[4] and would catch any input
	// this guard misses. The metadata layer is the test pin — see
	// TestParseRefusesAnEnvelopeNamingACreatedAtBeforeTheClockStarted — because Parse,
	// Open, Rewrap and Marshal reach validateEnvelopeMetadata directly with pre-existing
	// envelopes, where the entry-point guard is not in the call path.
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintextBytes || len(bindingContext) > maxContextBytes || random == nil || createdAt.IsZero() {
		return Envelope{}, ErrInvalidEnvelope
	}
	envelope := Envelope{
		Version: Version, ObjectID: objectID, KEK: kek, Algorithm: "AES-256-GCM",
		ContextDigest: contextDigest(bindingContext), CreatedAt: createdAt.UTC(),
	}
	if err := validateEnvelopeMetadata(envelope, wrapper); err != nil {
		return Envelope{}, err
	}
	dataKey := make([]byte, 32)
	defer zero(dataKey)
	if _, err := io.ReadFull(random, dataKey); err != nil {
		return Envelope{}, ErrInvalidEnvelope
	}
	aead, err := newAEAD(dataKey)
	if err != nil {
		return Envelope{}, ErrInvalidEnvelope
	}
	envelope.Nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(random, envelope.Nonce); err != nil {
		return Envelope{}, ErrInvalidEnvelope
	}
	envelope.Ciphertext = aead.Seal(nil, envelope.Nonce, plaintext, envelope.contentAAD())
	envelope.WrappedDataKey, err = wrapper.WrapKey(ctx, kek, dataKey, envelope.wrapAAD(kek))
	if err != nil {
		return Envelope{}, ErrBackendUnavailable
	}
	if len(envelope.WrappedDataKey) == 0 {
		return Envelope{}, ErrBackendUnavailable
	}
	return envelope, nil
}

// SealAssembled is the sibling of Seal for the offline-CLI flow: the client has already
// run AES-GCM locally with (dataKey, nonce) and sends the resulting ciphertext along
// with the two inputs. The KMS validates the binding, runs a local AEAD round-trip to
// prove the caller really held the data key (a random 32-byte slice + 12-byte nonce +
// random ciphertext would not authenticate), then asks the hardware to wrap the data
// key. The only server-stamped field is createdAt.
//
// The caller passes the bindingContext (objectID, purpose, environment digest) explicitly
// because the sealer passes the server-derived route.ObjectID/Purpose/Environment into
// envelope.ReleaseContext upstream; both seal and release must derive the canonical
// bytes the same way.
//
// PLAINTEXT IN DAEMON MEMORY.
//
// The local round-trip is necessary (see below) and produces plaintext in KMS memory for
// the duration of aead.Open plus the deferred zero call. ADR-0001 §3 already accepts this
// pattern for the *release* path (Envelope.Open, where plaintext is the consumer's
// product); SealAssembled extends the same bounded-interval exposure to the *seal* path,
// where plaintext is not the product. The exposure is bounded by the size cap
// (MaxPlaintextBytes), the deferred zero of the slice, and the absence of any string,
// JSON, log, error-path, or audit emission that contains the buffer. Replacing the
// round-trip with a challenge-MAC protocol would remove the exposure at the cost of a
// second client round-trip; see #84 PR-A follow-up for that discussion.
//
// CALLER CONTRACT.
//
// dataKey is a parameter (not a local like Seal's), so defer zero(dataKey) overwrites the
// caller's slice. Callers that need to retain the data key must copy it before the call.
// nonce and ciphertext are copied locally; the caller's slices are left intact.
//
// WHY THE LOCAL ROUND-TRIP.
//
// Without it, any random 32-byte slice + 12-byte nonce + random bytes would pass the
// length check and reach the hardware wrap. The GCM tag under contentAAD is the only way
// the KMS can tell that the caller actually knew the data key -- the AEAD tag is at once
// the authentication of the plaintext and the proof of possession of the data key, and
// verifying the tag is what produces plaintext briefly in memory.
func SealAssembled(ctx context.Context, wrapper Wrapper, kek KeyRef, objectID string, bindingContext, ciphertext, nonce, dataKey []byte, createdAt time.Time) (Envelope, error) {
	// Empty plaintext is rejected here to match Seal in this file (which refuses
	// len(plaintext) == 0). The two seal entry points must agree about whether an empty secret
	// is sealable, and the answer we pick is no: a 16-byte ciphertext is exactly a GCM tag
	// over zero bytes, and wrapping that against a KEK only spends wrap capacity on a no-op
	// envelope. The minimum non-empty ciphertext is 17 bytes (1 byte of plaintext plus the
	// 16-byte tag).
	// The `createdAt.IsZero()` operand here is the FIRST refusal. The same property is
	// checked downstream at validateEnvelopeMetadata:326[4] and would catch any input
	// this guard misses — see the comment at Seal:62 and the test pinning the metadata
	// layer.
	if len(dataKey) != 32 || len(nonce) != 12 || len(ciphertext) < 17 || len(ciphertext) > MaxPlaintextBytes+16 || len(bindingContext) > maxContextBytes || createdAt.IsZero() {
		return Envelope{}, ErrInvalidEnvelope
	}
	// Register the caller's dataKey zeroing BEFORE any subsequent return path. Error paths
	// (validateEnvelopeMetadata, newAEAD, aead.Open) are exactly where a rejected key needs
	// to vanish rather than linger -- the failed-authentication path is also the one an
	// attacker drives, since a valid GCM tag under a known key is what proves possession.
	// plaintext is created further down and registered at the same time it appears.
	defer zero(dataKey)
	envelope := Envelope{
		Version: Version, ObjectID: objectID, KEK: kek, Algorithm: "AES-256-GCM",
		ContextDigest: contextDigest(bindingContext), CreatedAt: createdAt.UTC(),
		Nonce: append([]byte(nil), nonce...), Ciphertext: append([]byte(nil), ciphertext...),
	}
	if err := validateEnvelopeMetadata(envelope, wrapper); err != nil {
		return Envelope{}, err
	}
	// Local AEAD round-trip -- prove the supplied (dataKey, nonce, ciphertext) authenticate
	// under contentAAD. The GCM tag here is the only way the KMS can tell the caller knew the
	// data key; see "WHY THE LOCAL ROUND-TRIP" in the function comment.
	aead, err := newAEAD(dataKey)
	if err != nil {
		return Envelope{}, ErrInvalidEnvelope
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, envelope.contentAAD())
	if err != nil {
		return Envelope{}, ErrInvalidEnvelope
	}
	defer zero(plaintext)
	wrapped, err := wrapper.WrapKey(ctx, kek, dataKey, envelope.wrapAAD(kek))
	if err != nil || len(wrapped) == 0 {
		return Envelope{}, ErrBackendUnavailable
	}
	envelope.WrappedDataKey = wrapped
	return envelope, nil
}

func Parse(encoded []byte) (Envelope, error) {
	if len(encoded) == 0 || len(encoded) > maxEnvelopeBytes {
		return Envelope{}, ErrInvalidEnvelope
	}
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return Envelope{}, ErrInvalidEnvelope
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Envelope{}, ErrInvalidEnvelope
	}
	if err := validateEnvelope(envelope, nil); err != nil {
		return Envelope{}, err
	}
	return envelope, nil
}

func (envelope Envelope) Marshal() ([]byte, error) {
	if err := validateEnvelope(envelope, nil); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) > maxEnvelopeBytes {
		return nil, ErrInvalidEnvelope
	}
	return append(encoded, '\n'), nil
}

func (envelope Envelope) Open(ctx context.Context, wrapper Wrapper, bindingContext []byte, use func([]byte) error) error {
	if use == nil || len(bindingContext) > maxContextBytes || validateEnvelope(envelope, wrapper) != nil {
		return ErrInvalidEnvelope
	}
	if subtle.ConstantTimeCompare([]byte(envelope.ContextDigest), []byte(contextDigest(bindingContext))) != 1 {
		return ErrInvalidEnvelope
	}
	dataKey, err := wrapper.UnwrapKey(ctx, envelope.KEK, envelope.WrappedDataKey, envelope.wrapAAD(envelope.KEK))
	if err != nil {
		return ErrBackendUnavailable
	}
	defer zero(dataKey)
	if len(dataKey) != 32 {
		return ErrInvalidEnvelope
	}
	aead, err := newAEAD(dataKey)
	if err != nil {
		return ErrInvalidEnvelope
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, envelope.contentAAD())
	if err != nil {
		return ErrInvalidEnvelope
	}
	defer zero(plaintext)
	return use(plaintext)
}

// Peek reads the header fields a caller must know BEFORE it can verify anything: which KEK
// generation opens the envelope, and when it was sealed.
//
// The release path cannot check the AEAD until it has the data key, and it cannot get the data key
// without first reaching the right card — so the routing decision and the age check both happen on
// unverified bytes. That is not a weakness here. The version only selects among bindings already
// commissioned for the same object at the same site, and the age bound can only be moved in the
// direction of refusal: an attacker who backdates created_at makes their own envelope expire, and
// one who post-dates it produces a header the wrap AAD no longer authenticates, so the unwrap
// fails. Nothing is trusted on the strength of this call; the envelope is parsed and validated in
// full further down.
func Peek(encoded []byte) (KeyRef, time.Time, error) {
	parsed, err := Parse(encoded)
	if err != nil {
		return KeyRef{}, time.Time{}, err
	}
	if parsed.KEK.Version == "" {
		return KeyRef{}, time.Time{}, fmt.Errorf("%w: envelope names no KEK version", ErrInvalidEnvelope)
	}
	return parsed.KEK, parsed.CreatedAt, nil
}

// Rewrap authenticates the existing content, unwraps only the data key, and
// binds it to a new hardware KEK without changing content ciphertext.
func (envelope *Envelope) Rewrap(ctx context.Context, oldWrapper, newWrapper Wrapper, newKEK KeyRef, bindingContext []byte) error {
	if envelope == nil || len(bindingContext) > maxContextBytes || validateEnvelope(*envelope, oldWrapper) != nil || validateKeyRef(newKEK, newWrapper) != nil {
		return ErrInvalidEnvelope
	}
	if subtle.ConstantTimeCompare([]byte(envelope.ContextDigest), []byte(contextDigest(bindingContext))) != 1 {
		return ErrInvalidEnvelope
	}
	dataKey, err := oldWrapper.UnwrapKey(ctx, envelope.KEK, envelope.WrappedDataKey, envelope.wrapAAD(envelope.KEK))
	if err != nil {
		return ErrBackendUnavailable
	}
	defer zero(dataKey)
	if len(dataKey) != 32 {
		return ErrInvalidEnvelope
	}
	aead, err := newAEAD(dataKey)
	if err != nil {
		return ErrInvalidEnvelope
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, envelope.contentAAD())
	if err != nil {
		return ErrInvalidEnvelope
	}
	zero(plaintext)
	wrapped, err := newWrapper.WrapKey(ctx, newKEK, dataKey, envelope.wrapAAD(newKEK))
	if err != nil || len(wrapped) == 0 {
		return ErrBackendUnavailable
	}
	envelope.KEK = newKEK
	envelope.WrappedDataKey = wrapped
	return nil
}

func (envelope Envelope) Clone() Envelope {
	envelope.Nonce = append([]byte(nil), envelope.Nonce...)
	envelope.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	envelope.WrappedDataKey = append([]byte(nil), envelope.WrappedDataKey...)
	return envelope
}

func validateEnvelope(envelope Envelope, wrapper Wrapper) error {
	if err := validateEnvelopeMetadata(envelope, wrapper); err != nil {
		return err
	}
	// SIXTEEN IS DELIBERATE HERE AND SEVENTEEN IS DELIBERATE IN THE SEAL PATHS, and the asymmetry
	// is not an oversight — it was nearly "fixed" into a regression, so the reason lives here now.
	//
	// Both seal entry points refuse a ciphertext under 17 bytes: 16 is exactly a GCM tag over zero
	// bytes and an empty secret is not sealable. Raising this floor to match looks like tightening
	// a parser to accept only what the writers produce. It is not. An empty-plaintext envelope is
	// already refused, one layer up, by `Releaser.Execute` with "envelope released an empty secret"
	// — and that error's IDENTITY is load-bearing: Coordinator.Execute branches on
	// errors.Is(err, ErrInvalidEnvelope) to answer INVALID_ARGUMENT and to record the audit outcome
	// "integrity-failed". Refusing it here would relabel a well-formed, authentic envelope that
	// happens to hold nothing as an integrity failure, and cost the operator the one error that
	// says what actually happened.
	//
	// So the split is: this function is the SYNTACTIC floor (a token that cannot be opened at all),
	// and "no empty secrets" is a SEMANTIC rule enforced where it can be named.
	// internal/secrets/guard_coverage_test.go pins both halves.
	if len(envelope.Nonce) != 12 || len(envelope.Ciphertext) < 16 || len(envelope.Ciphertext) > MaxPlaintextBytes+16 || len(envelope.WrappedDataKey) == 0 || len(envelope.WrappedDataKey) > 64<<10 {
		return ErrInvalidEnvelope
	}
	return nil
}

func validateEnvelopeMetadata(envelope Envelope, wrapper Wrapper) error {
	if envelope.Version != Version || !objectIDPattern.MatchString(envelope.ObjectID) || envelope.Algorithm != "AES-256-GCM" || envelope.CreatedAt.IsZero() {
		return ErrInvalidEnvelope
	}
	// The `< 7` conjunct that used to sit here could never fire -- an exact length of 71 already
	// implies it -- and an unreachable operand beside a live one READS AS THE GUARD, which is how
	// a later editor deletes the wrong half. 71 is "sha256:" plus 64 hex characters, and it is
	// what makes the [:7] and [7:] slices below safe.
	if len(envelope.ContextDigest) != 71 || envelope.ContextDigest[:7] != "sha256:" {
		return ErrInvalidEnvelope
	}
	if _, err := hex.DecodeString(envelope.ContextDigest[7:]); err != nil {
		return ErrInvalidEnvelope
	}
	return validateKeyRef(envelope.KEK, wrapper)
}

func validateKeyRef(ref KeyRef, wrapper Wrapper) error {
	if !objectIDPattern.MatchString(ref.ID) || !keyVersionPattern.MatchString(ref.Version) || !hardwareBackend(ref.Backend) {
		return ErrInvalidEnvelope
	}
	if wrapper != nil && wrapper.Backend() != ref.Backend {
		return ErrInvalidEnvelope
	}
	return nil
}

func hardwareBackend(value string) bool {
	return value == "nitrokey-pkcs11" || value == "yubikey-piv" || value == "yubikey-openpgp"
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ReleaseContext is the canonical binding context for a released secret, and the ONE place its
// shape is decided.
//
// ENVELOPE.md requires that the context "be independently reconstructed by the KMS" and "not be
// accepted as an unverified opaque client assertion". It was accepted as exactly that: the caller
// sent it, the handler decoded it, the coordinator passed it through, and nothing compared it to
// the authorization that had just been granted. The digest then proved only that the presenter knew
// the string the envelope was sealed with.
//
// Every field here comes from the route, which comes from the custody manifest: the registry refuses
// a request whose purpose is not the object's, and the environment is the manifest's, never the
// caller's. Sealing and releasing must derive the context the same way, so both call this.
//
// The fields cannot contain NUL -- object and purpose match ^[a-z0-9][a-z0-9-]{2,62}$ and the
// environment is an enum -- so NUL separation is unambiguous and the version tag makes a future
// shape change a different context rather than a silent reinterpretation.
func ReleaseContext(objectID, purpose, environment string) []byte {
	return []byte("regalia-release-v1\x00" + objectID + "\x00" + purpose + "\x00" + environment)
}

func contextDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// contentAAD is the Additional Authenticated Data AEAD binds content to.
//
// It deliberately OMITS CreatedAt: the offline CLI cannot know the server's stamp before
// sealing, so binding the AEAD to a timestamp the client did not provide would force the
// server to either re-stamp (admits a re-stamp attack) or refuse (closes the offline
// path). The server-stamped createdAt enters wrapAAD below, where the hardware wrap
// binds temporal provenance independently. This split makes content integrity verifiable
// end-to-end without requiring a synchronous round-trip to obtain a timestamp.
//
// The four fields are the same between client and server because both derive them from
// (Version, ObjectID, Algorithm, ContextDigest) and the digest is independently
// reconstructed from the authorized route.
//
// WHY Version BUMPED FROM 1 TO 2 IN #206.
//
// The data-key frame wire encoding changed in #206 (RGK\x01 → RGK\x02, with a 4-byte
// big-endian length field) to be self-delimiting against PKCS#11 modules whose
// C_UnwrapKey does not strip RFC 5649 padding (measured on SoftHSM 2.6.1; see
// keywrap.OpenFrame for the consumer side). That change is wire-incompatible: a frame
// built by the prior code cannot be opened by this code, and a frame built by this code
// cannot be opened by the prior code. The wire-incompatible change is the reason to
// bump the version now.
//
// Bumping the format string alone would leave operators reading a "v2" API label against
// an envelope JSON that says "version: 1"; both labels track the same wire encoding, so
// both bump together. Blast radius measured empty by peer review of #206 (#11 OPEN,
// #22 OPEN, no committed SOPS file names regalia, no .sops.yaml at root). Same posture
// as regalia-approval-v1 → v2 in #210: a wire-incompatible bump when nothing in the
// wild uses the prior encoding.
func (envelope Envelope) contentAAD() []byte {
	return []byte(fmt.Sprintf("regalia-envelope-v%d\x00%s\x00%s\x00%s", envelope.Version, envelope.ObjectID, envelope.Algorithm, envelope.ContextDigest))
}

// wrapAAD is what the hardware wrap binds: contentAAD, then the KEK identity
// (Backend, ID, Version), then the server-stamped CreatedAt. The shape of this AAD is
// internal to the wire between this KMS and the hardware, so reordering CreatedAt here
// does not interact with the envelope structure on disk or on the wire. The version
// bump above applies here too: a wrapAAD built by sealed fixtures under Version=1 will
// not match the wrapAAD this code computes, and the hardware wrap will refuse at the
// AAD check.
func (envelope Envelope) wrapAAD(ref KeyRef) []byte {
	return append(envelope.contentAAD(), []byte("\x00"+ref.Backend+"\x00"+ref.ID+"\x00"+ref.Version+"\x00"+envelope.CreatedAt.Format(time.RFC3339Nano))...)
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

// Compile-time check that crypto/rand.Reader remains an acceptable default RNG.
var _ io.Reader = rand.Reader
