package gpgsign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	pgpecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Key is an OpenPGP (version 4) signing key whose private half is a KMS object.
//
// Its fingerprint is a hash of the public key AND the creation time, so the creation time is part of
// the key's identity: it is fixed once, in the configuration, and must never follow the clock. A
// key exported twice with two creation times is two keys to every verifier.
type Key struct {
	signer  *Signer
	public  *packet.PublicKey
	created time.Time
	userID  string
}

// NewKey frames signer's public key as an OpenPGP key created at created, claiming userID
// (by convention "Name <email>").
func NewKey(signer *Signer, created time.Time, userID string) (*Key, error) {
	if signer == nil || created.IsZero() || created.Unix() < 0 || created.Unix() > 0xffffffff {
		return nil, errors.New("an OpenPGP key needs a signer and a creation time")
	}
	if strings.TrimSpace(userID) == "" || len(userID) > 255 || strings.ContainsAny(userID, "\r\n\x00") {
		return nil, errors.New("the user ID must be one line of at most 255 bytes")
	}
	created = created.UTC().Truncate(time.Second)
	var public *packet.PublicKey
	switch key := signer.public.(type) {
	case *rsa.PublicKey:
		public = packet.NewRSAPublicKey(created, key)
	case *ecdsa.PublicKey:
		var err error
		if public, err = ecdsaPublicKey(created, key); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported release key")
	}
	return &Key{signer: signer, public: public, created: created, userID: userID}, nil
}

// ecdsaPublicKey frames a standard-library ECDSA public key as an OpenPGP one.
//
// go-crypto's ECDSA key type carries its curve as a value of an INTERNAL package, so it cannot be
// built from outside the library. The curve is therefore taken from a key the library generates
// itself, and only the point is replaced. The alternative is to write the public-key packet by hand
// and parse it back, which is one more encoder in a repository that has learned to distrust its
// own. The throwaway private key is discarded with the entity; nothing of it reaches the result.
func ecdsaPublicKey(created time.Time, key *ecdsa.PublicKey) (*packet.PublicKey, error) {
	var curve packet.Curve
	switch key.Curve {
	case elliptic.P256():
		curve = packet.CurveNistP256
	case elliptic.P384():
		curve = packet.CurveNistP384
	default:
		return nil, errors.New("the release key must be on P-256 or P-384")
	}
	template, err := openpgp.NewEntity("curve template", "", "", &packet.Config{Algorithm: packet.PubKeyAlgoECDSA, Curve: curve})
	if err != nil {
		return nil, fmt.Errorf("prepare the OpenPGP curve: %w", err)
	}
	generated, ok := template.PrimaryKey.PublicKey.(*pgpecdsa.PublicKey)
	if !ok {
		return nil, errors.New("prepare the OpenPGP curve: unexpected key type")
	}
	point, err := key.Bytes() // 0x04 || X || Y
	if err != nil || len(point)%2 != 1 || point[0] != 4 {
		return nil, errors.New("the release public key is not a valid curve point")
	}
	half := (len(point) - 1) / 2
	framed := *generated
	framed.X, framed.Y = new(big.Int).SetBytes(point[1:1+half]), new(big.Int).SetBytes(point[1+half:])
	return packet.NewECDSAPublicKey(created, &framed), nil
}

// Fingerprint is the key's version-4 fingerprint, 40 upper-case hex digits.
func (key *Key) Fingerprint() string {
	return strings.ToUpper(hex.EncodeToString(key.public.Fingerprint))
}

// KeyID is the long key ID: the last 16 hex digits of the fingerprint.
func (key *Key) KeyID() string { return key.Fingerprint()[24:] }

// UserID is the identity the key claims.
func (key *Key) UserID() string { return key.userID }

// Matches reports whether selector — what `gpg -u` or git's user.signingkey would carry — names
// this key: its fingerprint or key ID (with or without 0x, any case), or a substring of its user
// ID, which is how GnuPG reads a name or an e-mail address.
func (key *Key) Matches(selector string) bool {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return false
	}
	hexSelector := strings.ToUpper(strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(selector, "0x"), "0X"), "!"))
	if hexSelector == key.Fingerprint() || hexSelector == key.KeyID() {
		return true
	}
	return strings.Contains(strings.ToLower(key.userID), strings.ToLower(selector))
}

// sign runs one go-crypto signing step with the private half bound to this operation, and returns
// the signer's own error when there was one (see bound).
func (key *Key) sign(ctx context.Context, subject string, step func(*packet.PrivateKey) error) error {
	operation := &bound{signer: key.signer, ctx: ctx, subject: subject}
	err := step(&packet.PrivateKey{PublicKey: *key.public, PrivateKey: operation})
	if operation.failure != nil {
		return operation.failure
	}
	return err
}

// config is what go-crypto signs with. The salt notation it would add by default to a version-4
// signature is switched off: the signatures here are what `gpg --detach-sign` makes, with no
// library-specific notation for a verifier to print, and an RSA key certification is then the same
// bytes on every export. What the salt defends (a fault during an EdDSA signature, a chosen-prefix
// attack on the hash) does not apply to RSA or ECDSA computed inside the token over SHA-2.
func (key *Key) config(now time.Time) *packet.Config {
	salted := false
	return &packet.Config{DefaultHash: key.signer.hash, Time: func() time.Time { return now }, NonDeterministicSignaturesViaNotation: &salted}
}

// Signed describes a signature that was made, for the status line a caller may have to print.
type Signed struct {
	Created      time.Time
	PubKeyAlgo   uint8
	HashAlgo     uint8
	DocumentHash string // SHA-256 of the signed bytes, hex
}

// DetachSign writes a detached binary-document signature over message to w: what `gpg --detach-sign`
// makes, ASCII-armored when armored is set. It costs exactly one KMS operation, whose subject names
// the SHA-256 of the document so the KMS's audit record can be matched to an artifact.
func (key *Key) DetachSign(ctx context.Context, w io.Writer, message io.Reader, now time.Time, armored bool) (Signed, error) {
	now = now.UTC().Truncate(time.Second)
	signature := &packet.Signature{
		Version: key.public.Version, SigType: packet.SigTypeBinary, PubKeyAlgo: key.public.PubKeyAlgo,
		Hash: key.signer.hash, CreationTime: now, IssuerKeyId: &key.public.KeyId, IssuerFingerprint: key.public.Fingerprint,
	}
	config := key.config(now)
	hasher, err := signature.PrepareSign(config)
	if err != nil {
		return Signed{}, err
	}
	document := sha256.New()
	if _, err := io.Copy(io.MultiWriter(hasher, document), message); err != nil {
		return Signed{}, errors.New("read the document to sign")
	}
	documentHash := hex.EncodeToString(document.Sum(nil))
	if err := key.sign(ctx, "openpgp-detached sha256:"+documentHash, func(private *packet.PrivateKey) error {
		return signature.Sign(hasher, private, config)
	}); err != nil {
		return Signed{}, err
	}
	// Serialized to memory first: w receives a whole signature or nothing.
	var framed bytes.Buffer
	if err := serialize(&framed, openpgp.SignatureType, armored, signature.Serialize); err != nil {
		return Signed{}, err
	}
	if _, err := w.Write(framed.Bytes()); err != nil {
		return Signed{}, err
	}
	hashID := hashIDs[key.signer.hash]
	return Signed{Created: now, PubKeyAlgo: uint8(key.public.PubKeyAlgo), HashAlgo: hashID, DocumentHash: documentHash}, nil
}

// hashIDs are the OpenPGP hash algorithm numbers (RFC 9580 §9.5), for the status line only.
var hashIDs = map[crypto.Hash]uint8{crypto.SHA256: 8, crypto.SHA384: 9, crypto.SHA512: 10}

// ExportPublic writes the ASCII-armored public key: the key packet, its user ID and the
// self-signature that binds them and marks the key as one that signs. A verifier imports this once.
//
// The self-signature is itself a signature by the key, so exporting costs one KMS operation. It is
// dated at the key's creation time, not at the clock, so an RSA key exports to the same bytes every
// time and nothing about the export depends on when it was run.
func (key *Key) ExportPublic(ctx context.Context, w io.Writer) error {
	primary := true
	selfSignature := &packet.Signature{
		Version: key.public.Version, SigType: packet.SigTypePositiveCert, PubKeyAlgo: key.public.PubKeyAlgo,
		Hash: key.signer.hash, CreationTime: key.created, IssuerKeyId: &key.public.KeyId, IssuerFingerprint: key.public.Fingerprint,
		FlagsValid: true, FlagSign: true, FlagCertify: true, IsPrimaryId: &primary,
	}
	// The configured line IS the identity ("Name (comment) <address>"), so it is set whole.
	// packet.NewUserId builds one from three parts and refuses the brackets a whole line contains.
	userID := &packet.UserId{Id: key.userID}
	if err := key.sign(ctx, "openpgp-key-certification "+key.Fingerprint(), func(private *packet.PrivateKey) error {
		return selfSignature.SignUserId(userID.Id, key.public, private, key.config(key.created))
	}); err != nil {
		return err
	}
	entity := &openpgp.Entity{
		PrimaryKey: key.public,
		Identities: map[string]*openpgp.Identity{userID.Id: {
			Name: userID.Id, UserId: userID, SelfSignature: selfSignature, Signatures: []*packet.Signature{selfSignature},
		}},
	}
	// Serialized to memory first: w receives a whole key or nothing.
	var exported bytes.Buffer
	if err := serialize(&exported, openpgp.PublicKeyType, true, entity.Serialize); err != nil {
		return err
	}
	_, err := w.Write(exported.Bytes())
	return err
}

func serialize(w io.Writer, blockType string, armored bool, write func(io.Writer) error) error {
	if !armored {
		return write(w)
	}
	encoder, err := armor.Encode(w, blockType, nil)
	if err != nil {
		return err
	}
	if err := write(encoder); err != nil {
		return err
	}
	if err := encoder.Close(); err != nil {
		return err
	}
	_, err = io.WriteString(w, "\n")
	return err
}
