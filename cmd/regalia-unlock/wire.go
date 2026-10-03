package main

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
)

// The formats below are those of deploy/baremetal/unlock.py and attest.py, which define them. Both
// sides are held to tests/vectors/unlock-v1.json.
const (
	wireVersion = 1 // the LUKS2 token's version
	// the exchange's version: 2 adds the PCR values read beside the quote (evidence.pcr_values), so that a
	// peer can name the PCR that differs. A peer accepts 1 and 2; peers are upgraded before nodes.
	exchangeVersion   = 2
	responseSchema    = "regalia.unlock-response/v1"
	responseDomain    = "regalia-unlock/v1/response\x00"
	contributionLabel = "regalia-unlock/v1/contribution\x00"
	transcriptLabel   = "regalia-kms/attest/v1"
	hkdfInfoFormat    = "regalia/luks/v1/%s/%s/%d"
	secretBytes       = 32
	keyBits           = 3072
	maxMessage        = 64 * 1024
	maxEpoch          = 1<<63 - 1
)

var (
	nodeIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	hex64Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	namePattern   = regexp.MustCompile(`^000b[0-9a-f]{64}$`)
)

// transcript is attest.transcript: every field length-prefixed under a fixed label, so no two
// different field tuples encode to the same bytes. The TPM quote's qualifying data is its SHA-256.
func transcript(nodeID string, epoch uint64, sessionID, ephemeralPublic, nonce []byte) []byte {
	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], epoch)
	var out bytes.Buffer
	for _, field := range [][]byte{[]byte(transcriptLabel), []byte(nodeID), epochBytes[:], sessionID, ephemeralPublic, nonce} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		out.Write(size[:])
		out.Write(field)
	}
	return out.Bytes()
}

// credential is the keyslot passphrase of path peer -> target: both halves, or nothing.
func credential(local, contribution []byte, target, peer string, pathEpoch uint64) ([]byte, error) {
	if len(local) != secretBytes || len(contribution) != secretBytes {
		return nil, errors.New("a contribution is not 32 bytes")
	}
	ikm := append(append(make([]byte, 0, 2*secretBytes), local...), contribution...)
	defer wipe(ikm)
	key, err := hkdf.Key(sha256.New, ikm, nil, fmt.Sprintf(hkdfInfoFormat, target, peer, pathEpoch), 32)
	if err != nil {
		return nil, err
	}
	defer wipe(key)
	out := make([]byte, base64.StdEncoding.EncodedLen(len(key)))
	base64.StdEncoding.Encode(out, key)
	return out, nil
}

func wipe(secret []byte) {
	for i := range secret {
		secret[i] = 0
	}
}

type helloReply struct {
	V      int    `json:"v"`
	PeerID string `json:"peer_id"`
	Epoch  uint64 `json:"epoch"`
	Nonce  string `json:"nonce"`
	Error  string `json:"error"`
}

type evidence struct {
	EphemeralPublic string            `json:"ephemeral_public"`
	Nonce           string            `json:"nonce"`
	Quote           string            `json:"quote"`
	Signature       string            `json:"signature"`
	PCRValues       map[string]string `json:"pcr_values"`
}

type unlockRequest struct {
	V         int      `json:"v"`
	Op        string   `json:"op"`
	NodeID    string   `json:"node_id"`
	SessionID string   `json:"session_id"`
	PathEpoch uint64   `json:"path_epoch"`
	Evidence  evidence `json:"evidence"`
}

type response struct {
	Schema           string `json:"schema"`
	PeerID           string `json:"peer_id"`
	NodeID           string `json:"node_id"`
	Epoch            uint64 `json:"epoch"`
	ManifestDigest   string `json:"manifest_digest"`
	SessionID        string `json:"session_id"`
	TranscriptSHA256 string `json:"transcript_sha256"`
	PathEpoch        uint64 `json:"path_epoch"`
	Ciphertext       string `json:"ciphertext"`
}

type peerSignature struct {
	AKPublic string `json:"ak_public"`
	Quote    string `json:"quote"`
	Sig      string `json:"sig"`
}

type unlockReply struct {
	V         int            `json:"v"`
	Error     string         `json:"error"`
	Response  *response      `json:"response"`
	Signature *peerSignature `json:"signature"`
}

// decodeReply parses one reply strictly: one JSON object, no unknown field, nothing after it.
func decodeReply(raw []byte, into any) error {
	if len(raw) > maxMessage {
		return errors.New("the reply is too long")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return errors.New("the reply is not the expected JSON object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("the reply has trailing data")
	}
	return nil
}

func refusal(code string) error {
	if code != "DENIED" && code != "INVALID_REQUEST" {
		code = "?"
	}
	return fmt.Errorf("the peer refused (%s)", code)
}

// validate checks every field's grammar. canonical() relies on it: after it, no field holds a
// character that JSON would escape.
func (r *response) validate() error {
	switch {
	case r.Schema != responseSchema:
		return errors.New("the response has another schema")
	case !nodeIDPattern.MatchString(r.PeerID) || !nodeIDPattern.MatchString(r.NodeID):
		return errors.New("the response names something that is not a node ID")
	case r.Epoch < 1 || r.Epoch > maxEpoch || r.PathEpoch < 1 || r.PathEpoch > maxEpoch:
		return errors.New("the response's epochs must be integers >= 1")
	case !hex64Pattern.MatchString(r.ManifestDigest) || !hex64Pattern.MatchString(r.SessionID) || !hex64Pattern.MatchString(r.TranscriptSHA256):
		return errors.New("the response's digests must be 64 lowercase hex")
	}
	if len(r.Ciphertext) != keyBits/4 {
		return errors.New("the response's ciphertext is not one RSA-3072 block")
	}
	if _, err := lowerHex(r.Ciphertext); err != nil {
		return errors.New("the response's ciphertext is not lowercase hex")
	}
	return nil
}

// canonical is membership.canonical of the response: sorted keys, no spaces. It is what the peer
// signed; it is rebuilt here from the parsed values, so what is verified is what is used.
func (r *response) canonical() []byte {
	return []byte(`{"ciphertext":"` + r.Ciphertext + `","epoch":` + strconv.FormatUint(r.Epoch, 10) +
		`,"manifest_digest":"` + r.ManifestDigest + `","node_id":"` + r.NodeID + `","path_epoch":` + strconv.FormatUint(r.PathEpoch, 10) +
		`,"peer_id":"` + r.PeerID + `","schema":"` + r.Schema + `","session_id":"` + r.SessionID +
		`","transcript_sha256":"` + r.TranscriptSHA256 + `"}`)
}

func (r *response) signedDigest() []byte {
	digest := sha256.Sum256(append([]byte(responseDomain), r.canonical()...))
	return digest[:]
}

func lowerHex(value string) ([]byte, error) {
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, errors.New("not lowercase hex")
		}
	}
	return hex.DecodeString(value)
}
