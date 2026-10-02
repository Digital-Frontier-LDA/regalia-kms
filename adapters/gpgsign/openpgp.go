package gpgsign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	pgpecdsa "github.com/ProtonMail/go-crypto/openpgp/ecdsa"
	pgpeddsa "github.com/ProtonMail/go-crypto/openpgp/eddsa"
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
	// throwaway is set for an Ed25519 key only: the dummy private key go-crypto signs with before
	// the KMS's signature replaces its own (eddsa.go). It never signs anything that is written.
	throwaway *pgpeddsa.PrivateKey
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
	var throwaway *pgpeddsa.PrivateKey
	switch key := signer.public.(type) {
	case *rsa.PublicKey:
		public = packet.NewRSAPublicKey(created, key)
	case *ecdsa.PublicKey:
		var err error
		if public, err = ecdsaPublicKey(created, key); err != nil {
			return nil, err
		}
	case ed25519.PublicKey:
		var err error
		if public, throwaway, err = eddsaPublicKey(created, key); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unsupported release key")
	}
	return &Key{signer: signer, public: public, created: created, userID: userID, throwaway: throwaway}, nil
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

// begin starts a signature: the hash go-crypto will sign, and a second hash of the same input that
// finish verifies the result against. Everything to be signed is written to the returned writer.
func (key *Key) begin(signature *packet.Signature, config *packet.Config) (hash.Hash, hash.Hash, io.Writer, error) {
	hasher, err := signature.PrepareSign(config)
	if err != nil {
		return nil, nil, nil, err
	}
	check := key.signer.hash.New()
	return hasher, check, io.MultiWriter(hasher, check), nil
}

// finish signs the fed signature through the KMS and returns the serialized packet — after parsing
// it back and verifying it against the KMS public key. NOTHING THIS ADAPTER WRITES SKIPS THIS: the
// Signer already checks the raw signature against the pinned key, and this checks the finished
// OpenPGP packet, hashed subpackets and all, the way a verifier will. For Ed25519 it is also what
// guarantees the throwaway signature of eddsa.go can never leave.
func (key *Key) finish(ctx context.Context, signature *packet.Signature, config *packet.Config, hasher, check hash.Hash, subject string) ([]byte, error) {
	var err error
	if key.throwaway != nil {
		err = key.signEdDSA(ctx, signature, hasher, config, subject)
	} else {
		err = key.sign(ctx, subject, func(private *packet.PrivateKey) error { return signature.Sign(hasher, private, config) })
	}
	if err != nil {
		return nil, err
	}
	var serialized bytes.Buffer
	if err := signature.Serialize(&serialized); err != nil {
		return nil, err
	}
	if err := key.verifyPacket(serialized.Bytes(), check); err != nil {
		return nil, err
	}
	return serialized.Bytes(), nil
}

// verifyPacket parses one serialized signature packet and verifies it over signed, a hash that has
// been fed exactly what the signature covers, against this key.
func (key *Key) verifyPacket(serialized []byte, signed hash.Hash) error {
	parsed, err := packet.Read(bytes.NewReader(serialized))
	if err != nil {
		return errors.New("the finished signature is not a readable OpenPGP packet")
	}
	signature, ok := parsed.(*packet.Signature)
	if !ok || signature.IssuerKeyId == nil || *signature.IssuerKeyId != key.public.KeyId || !bytes.Equal(signature.IssuerFingerprint, key.public.Fingerprint) {
		return errors.New("the finished signature does not name this key as its issuer")
	}
	if err := key.public.VerifySignature(signed, signature); err != nil {
		return errors.New("the finished signature does not verify against the KMS public key")
	}
	return nil
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
	hasher, check, signedInput, err := key.begin(signature, config)
	if err != nil {
		return Signed{}, err
	}
	document := sha256.New()
	if _, err := io.Copy(io.MultiWriter(signedInput, document), message); err != nil {
		return Signed{}, errors.New("read the document to sign")
	}
	documentHash := hex.EncodeToString(document.Sum(nil))
	serialized, err := key.finish(ctx, signature, config, hasher, check, "openpgp-detached sha256:"+documentHash)
	if err != nil {
		return Signed{}, err
	}
	// Serialized to memory first: w receives a whole signature or nothing.
	var framed bytes.Buffer
	if err := serialize(&framed, openpgp.SignatureType, armored, func(w io.Writer) error {
		_, err := w.Write(serialized)
		return err
	}); err != nil {
		return Signed{}, err
	}
	if _, err := w.Write(framed.Bytes()); err != nil {
		return Signed{}, err
	}
	hashID := hashIDs[key.signer.hash]
	return Signed{Created: now, PubKeyAlgo: uint8(key.public.PubKeyAlgo), HashAlgo: hashID, DocumentHash: documentHash}, nil
}

// ClearSign writes message to w as a cleartext-signed document (RFC 9580 §7): the text itself,
// readable, followed by an armored signature over its canonical form — what `gpg --clearsign` makes,
// and what an apt repository serves as InRelease. It costs exactly one KMS operation.
//
// The signature covers the text with line endings canonicalised and trailing whitespace removed from
// each line; that is the framework's rule, not a choice here. A document that must be reproduced
// byte for byte belongs under a detached signature instead.
func (key *Key) ClearSign(ctx context.Context, w io.Writer, message io.Reader, now time.Time) (Signed, error) {
	now = now.UTC().Truncate(time.Second)
	text, err := io.ReadAll(message)
	if err != nil {
		return Signed{}, errors.New("read the document to sign")
	}
	documentHash := sha256.Sum256(text)
	subject := "openpgp-cleartext sha256:" + hex.EncodeToString(documentHash[:])
	// The line ending before the signature armor is a separator, not part of the signed text
	// (RFC 9580 §7.1), and the encoder writes that separator itself. So the text's own final line
	// ending is dropped here, exactly as `gpg --clearsign` does: handing it over would sign an
	// extra empty line, and every verifier would then extract the text with a blank line added.
	body := text
	if bytes.HasSuffix(body, []byte("\r\n")) {
		body = body[:len(body)-2]
	} else if bytes.HasSuffix(body, []byte("\n")) {
		body = body[:len(body)-1]
	}
	// Framed in memory: w receives a whole signed document or nothing.
	var framed bytes.Buffer
	config := key.config(now)
	frame := func(private *packet.PrivateKey) error {
		plaintext, err := clearsign.Encode(&framed, private, config)
		if err != nil {
			return err
		}
		if _, err := plaintext.Write(body); err != nil {
			return err
		}
		return plaintext.Close() // go-crypto signs here
	}
	var document []byte
	if key.throwaway == nil {
		if err := key.sign(ctx, subject, frame); err != nil {
			return Signed{}, err
		}
		if document, err = withArmorChecksum(framed.Bytes()); err != nil {
			return Signed{}, err
		}
	} else {
		// Ed25519 (eddsa.go). clearsign frames the text and signs with the throwaway key; that
		// signature block is then REPLACED by one made over the same canonical text through
		// begin/finish, which signs via the KMS and verifies the result.
		if err := frame(&packet.PrivateKey{PublicKey: *key.public, PrivateKey: key.throwaway}); err != nil {
			return Signed{}, err
		}
		block, _ := clearsign.Decode(framed.Bytes())
		if block == nil {
			return Signed{}, errors.New("the cleartext-signed document could not be read back")
		}
		signature := &packet.Signature{
			Version: key.public.Version, SigType: packet.SigTypeText, PubKeyAlgo: key.public.PubKeyAlgo,
			Hash: key.signer.hash, CreationTime: now, IssuerKeyId: &key.public.KeyId, IssuerFingerprint: key.public.Fingerprint,
		}
		hasher, check, signedInput, err := key.begin(signature, config)
		if err != nil {
			return Signed{}, err
		}
		if _, err := signedInput.Write(block.Bytes); err != nil {
			return Signed{}, err
		}
		serialized, err := key.finish(ctx, signature, config, hasher, check, subject)
		if err != nil {
			return Signed{}, err
		}
		if document, err = replaceSignatureBlock(framed.Bytes(), serialized); err != nil {
			return Signed{}, err
		}
	}
	// Whatever the path, the document that leaves is read back as a verifier reads it and checked
	// against the KMS public key.
	if err := key.verifyClearSigned(document); err != nil {
		return Signed{}, err
	}
	if _, err := w.Write(document); err != nil {
		return Signed{}, err
	}
	return Signed{Created: now, PubKeyAlgo: uint8(key.public.PubKeyAlgo), HashAlgo: hashIDs[key.signer.hash], DocumentHash: hex.EncodeToString(documentHash[:])}, nil
}

// withArmorChecksum re-armors the signature block of a cleartext-signed document WITH its CRC-24
// line, and ends the document with a newline.
//
// go-crypto's clearsign leaves the checksum out, as RFC 9580 now recommends. GnuPG 2.4 (gpg and
// gpgv, so every apt before 3.0) then cannot find the end of the armor when the base64 happens to
// need no padding: it reports "no valid OpenPGP data found" and exits 2, although it also prints
// "Good signature". Whether a signature needs padding depends on its length — measured here: every
// RSA-3072 signature failed, the ECDSA ones passed. With the checksum line GnuPG reads all of them,
// and the verifiers that ignore the checksum (Sequoia, go-crypto) are unaffected.
//
// Both steps use the library's own armor reader and writer; nothing is encoded by hand.
func withArmorChecksum(document []byte) ([]byte, error) {
	_, signature, err := signatureBlock(document)
	if err != nil {
		return nil, err
	}
	return replaceSignatureBlock(document, signature)
}

// signatureBlock finds a cleartext-signed document's signature armor and returns where it starts
// and the packet bytes inside it.
func signatureBlock(document []byte) (int, []byte, error) {
	const begin = "\n-----BEGIN PGP SIGNATURE-----"
	at := bytes.LastIndex(document, []byte(begin))
	if at < 0 {
		return 0, nil, errors.New("the cleartext-signed document has no signature block")
	}
	block, err := armor.Decode(bytes.NewReader(document[at+1:]))
	if err != nil || block.Type != openpgp.SignatureType {
		return 0, nil, errors.New("the cleartext-signed document's signature block is not readable")
	}
	signature, err := io.ReadAll(block.Body)
	if err != nil || len(signature) == 0 {
		return 0, nil, errors.New("the cleartext-signed document's signature block is not readable")
	}
	return at, signature, nil
}

// replaceSignatureBlock returns document with its signature armor replaced by signature, armored
// with its checksum line and followed by a newline.
func replaceSignatureBlock(document, signature []byte) ([]byte, error) {
	at, _, err := signatureBlock(document)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.Write(document[:at+1])
	if err := serialize(&out, openpgp.SignatureType, true, func(w io.Writer) error {
		_, err := w.Write(signature)
		return err
	}); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// verifyClearSigned reads a cleartext-signed document the way a verifier does and checks its
// signature against this key.
func (key *Key) verifyClearSigned(document []byte) error {
	block, rest := clearsign.Decode(document)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("the cleartext-signed document could not be read back")
	}
	_, signature, err := signatureBlock(document)
	if err != nil {
		return err
	}
	signed := key.signer.hash.New()
	signed.Write(block.Bytes)
	return key.verifyPacket(signature, signed)
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
	subject, config := "openpgp-key-certification "+key.Fingerprint(), key.config(key.created)
	if key.throwaway == nil {
		if err := key.sign(ctx, subject, func(private *packet.PrivateKey) error {
			return selfSignature.SignUserId(userID.Id, key.public, private, config)
		}); err != nil {
			return err
		}
	} else {
		// Ed25519 (eddsa.go): SignUserId hashes and signs in one step, with no place to observe
		// the digest, so the certification's input is fed here: the key as it is hashed for a
		// signature, then 0xB4, the user ID's length and the user ID (RFC 9580 §5.2.4). The
		// library's own VerifyUserIdSignature, below, is the check that this is the right input.
		hasher, check, signedInput, err := key.begin(selfSignature, config)
		if err != nil {
			return err
		}
		if err := key.public.SerializeForHash(signedInput); err != nil {
			return err
		}
		length := len(userID.Id)
		if _, err := signedInput.Write(append([]byte{0xb4, byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)}, userID.Id...)); err != nil {
			return err
		}
		if _, err := key.finish(ctx, selfSignature, config, hasher, check, subject); err != nil {
			return err
		}
	}
	// For every key type: the certification must verify as the library verifies one.
	if err := key.public.VerifyUserIdSignature(userID.Id, key.public, selfSignature); err != nil {
		return errors.New("the key certification does not verify against the KMS public key")
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
