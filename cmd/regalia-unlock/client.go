package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// transport carries one request to a peer and returns its reply.
type transport func(request []byte) ([]byte, error)

// quoter returns the TPM's quote over 32 bytes of qualifying data: the TPMS_ATTEST and its signature.
type quoter func(qualifying []byte) (attest, signature []byte, values map[string]string, err error)

// session is what one boot holds in memory: a session ID and an RSA key, both made here and never
// stored. It opens one response, the first valid one, and is then spent.
type session struct {
	nodeID          string
	id              []byte
	key             *rsa.PrivateKey
	ephemeralPublic []byte
	consumed        bool
	spokeVersion1   bool // a peer answered only version 1 (said once in the diagnostics)
	unsteadyPCRs    bool // a quote went without values: its PCRs kept moving (said once in the diagnostics)
}

func newSession(nodeID string) (*session, error) {
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &session{nodeID: nodeID, id: id, key: key, ephemeralPublic: spki}, nil
}

// ask is unlock.ask: the node asks one peer for its contribution at one path epoch. The session is
// spent only by a valid response; every other outcome is an error that leaves it usable.
func (s *session) ask(peer pin, pathEpoch uint64, send transport, quote quoter) ([]byte, error) {
	if s.consumed {
		return nil, errors.New("this boot session has already accepted a response")
	}
	// Version 2 first. A peer that does not speak it yet answers the hello INVALID_REQUEST, and is asked again in
	// version 1 (no PCR values: they only name a PCR in its audit, and decide nothing).
	version := exchangeVersion
	var hello helloReply
	for {
		request, _ := json.Marshal(map[string]any{"v": version, "op": "hello", "node_id": s.nodeID})
		raw, err := send(request)
		if err != nil {
			return nil, fmt.Errorf("hello: the transport failed (%w)", err)
		}
		hello = helloReply{}
		if err := decodeReply(raw, &hello); err != nil {
			return nil, fmt.Errorf("hello: %w", err)
		}
		if hello.Error == "INVALID_REQUEST" && version == exchangeVersion {
			version, s.spokeVersion1 = 1, true
			continue
		}
		break
	}
	if hello.Error != "" {
		return nil, fmt.Errorf("hello: %w", refusal(hello.Error))
	}
	if hello.V != version || hello.PeerID != peer.NodeID {
		return nil, errors.New("hello: the peer that answered is not " + peer.NodeID)
	}
	if hello.Epoch < 1 || hello.Epoch > maxEpoch || !hex64Pattern.MatchString(hello.Nonce) {
		return nil, errors.New("hello: the peer's epoch or nonce is malformed")
	}
	nonce, _ := hex.DecodeString(hello.Nonce)
	// The epoch is the one the peer states. Every decision about membership is the peer's, under its own
	// manifest; the node holds none before root. A reply changed on the way makes a quote the peer refuses.
	expected := sha256.Sum256(transcript(s.nodeID, hello.Epoch, s.id, s.ephemeralPublic, nonce))
	attest, signature, values, err := quote(expected[:])
	if err != nil {
		return nil, fmt.Errorf("quote: %w", err)
	}
	if version == exchangeVersion && values == nil {
		s.unsteadyPCRs = true
	}
	if version == 1 || values == nil {
		version, values = 1, nil // version 1 carries no values (and a quote whose PCRs would not hold still goes)
	}
	request, _ := json.Marshal(unlockRequest{V: version, Op: "unlock", NodeID: s.nodeID, SessionID: hex.EncodeToString(s.id), PathEpoch: pathEpoch,
		Evidence: evidence{EphemeralPublic: hex.EncodeToString(s.ephemeralPublic), Nonce: hello.Nonce,
			Quote: hex.EncodeToString(attest), Signature: hex.EncodeToString(signature), PCRValues: values}})
	raw, err := send(request)
	if err != nil {
		return nil, fmt.Errorf("unlock: the transport failed (%w)", err)
	}
	var reply unlockReply
	if err := decodeReply(raw, &reply); err != nil {
		return nil, fmt.Errorf("unlock: %w", err)
	}
	if reply.Error != "" {
		return nil, fmt.Errorf("unlock: %w", refusal(reply.Error))
	}
	if reply.Response == nil || reply.Signature == nil {
		return nil, errors.New("unlock: the reply holds no signed response")
	}
	return s.open(peer, reply.Response, reply.Signature, pathEpoch, hello.Epoch, expected[:])
}

// open is unlock.BootSession.open: the contribution, if the response is the peer's valid answer to
// exactly what this boot session asked.
func (s *session) open(peer pin, r *response, signature *peerSignature, pathEpoch, stated uint64, expected []byte) ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	switch {
	case r.PeerID != peer.NodeID:
		return nil, errors.New("the response is not from " + peer.NodeID + ", the peer that was asked")
	case r.PathEpoch != pathEpoch:
		// not in the quote, so the request's can be changed on the way: this must not spend the session
		return nil, fmt.Errorf("the peer answered for path epoch %d, not %d", r.PathEpoch, pathEpoch)
	case r.NodeID != s.nodeID || r.SessionID != hex.EncodeToString(s.id):
		return nil, errors.New("the response is for another node or another boot session")
	case subtle.ConstantTimeCompare([]byte(r.TranscriptSHA256), []byte(hex.EncodeToString(expected))) != 1:
		return nil, errors.New("the response does not answer the request this boot session sent")
	case r.Epoch != stated:
		return nil, fmt.Errorf("the response was decided under epoch %d, not the epoch %d the peer's hello stated", r.Epoch, stated)
	}
	if err := verifyPeerSignature(signature, peer, r.signedDigest()); err != nil {
		return nil, err
	}
	ciphertext, _ := hex.DecodeString(r.Ciphertext)
	secret, err := rsa.DecryptOAEP(sha256.New(), nil, s.key, ciphertext, append([]byte(contributionLabel), expected...))
	if err != nil || len(secret) != secretBytes {
		return nil, errors.New("the contribution does not decrypt: it was not encrypted to this key for this exchange")
	}
	s.consumed = true
	return secret, nil
}
