package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/askpass"
)

// The TPM structures the fake peer sends are built here byte by byte, from the TPM 2.0 Library's
// layout (Part 2), as deploy/baremetal/attest.py reads them: an independent check of what go-tpm parses.
const (
	tpmGenerated  = 0xFF544347
	stAttestQuote = 0x8018
	algSHA256     = 0x000B
	algNull       = 0x0010
	algECDSA      = 0x0018
	algECC        = 0x0023
	curveP256     = 0x0003
	rawAttributes = 0x00050072 // fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | restricted | sign
)

func sized(data []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(data))), data...)
}

// fakePeer is a peer as deploy/baremetal/unlock.py's Peer answers, with a software P-256 key standing
// for its TPM attestation key. It verifies nothing: what is under test is what the client accepts.
type fakePeer struct {
	id           string
	epoch        uint64
	ak           *ecdsa.PrivateKey
	akPublic     []byte
	ekName       []byte
	contribution []byte
	nonce        []byte
	hello        func(*helloReply)                  // changes the hello reply
	edit         func(*response)                    // changes the response before it is signed
	forge        func(*unlockReply)                 // changes the reply after it is signed
	requests     []map[string]any                   // every request received
	deny         string                             // answer every request with this error
	refuse       string                             // answer the unlock request with this error: the quote was seen, nothing is given
	onlyV1       bool                               // a peer not yet upgraded: a version 2 request is INVALID_REQUEST
	signWith     func(digest []byte) *peerSignature // another signer
}

func newFakePeer(t *testing.T, id string) *fakePeer {
	t.Helper()
	ak, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, _ := ak.PublicKey.Bytes()
	area := binary.BigEndian.AppendUint16(nil, algECC)
	area = binary.BigEndian.AppendUint16(area, algSHA256)
	area = binary.BigEndian.AppendUint32(area, rawAttributes)
	area = append(area, sized(nil)...)
	for _, v := range []uint16{algNull, algECDSA, algSHA256, curveP256, algNull} {
		area = binary.BigEndian.AppendUint16(area, v)
	}
	area = append(append(area, sized(point[1:33])...), sized(point[33:])...)
	ekName := append([]byte{0x00, 0x0b}, bytes.Repeat([]byte{id[0]}, 32)...)
	return &fakePeer{id: id, epoch: 7, ak: ak, akPublic: sized(area), ekName: ekName,
		contribution: bytes.Repeat([]byte{0x42}, 32), nonce: bytes.Repeat([]byte{0xa7}, 32)}
}

func (p *fakePeer) pin() pin {
	name, _, _ := akIdentity(p.akPublic)
	return pin{NodeID: p.id, Endpoint: "192.0.2.1:7443", EKName: hex.EncodeToString(p.ekName), AKName: hex.EncodeToString(name)}
}

// sign is what lease.TpmSigner returns: a TPMS_ATTEST whose qualifying data is the digest, signed by the AK.
func (p *fakePeer) sign(digest []byte) *peerSignature {
	name, _, _ := akIdentity(p.akPublic)
	attest := binary.BigEndian.AppendUint32(nil, tpmGenerated)
	attest = binary.BigEndian.AppendUint16(attest, stAttestQuote)
	attest = append(attest, sized(qualifiedName(p.ekName, name))...)
	attest = append(attest, sized(digest)...)
	attest = append(attest, make([]byte, 8+4+4+1+8)...) // clock info and firmware version
	attest = binary.BigEndian.AppendUint32(attest, 1)
	attest = binary.BigEndian.AppendUint16(attest, algSHA256)
	attest = append(attest, 3, 0x80, 0, 0)
	attest = append(attest, sized(make([]byte, 32))...)
	hashed := sha256.Sum256(attest)
	signature, _ := ecdsa.SignASN1(rand.Reader, p.ak, hashed[:])
	return &peerSignature{AKPublic: hex.EncodeToString(p.akPublic), Quote: hex.EncodeToString(attest), Sig: hex.EncodeToString(signature)}
}

func (p *fakePeer) send(request []byte) ([]byte, error) {
	var message map[string]any
	if err := json.Unmarshal(request, &message); err != nil {
		return nil, err
	}
	p.requests = append(p.requests, message)
	version, _ := message["v"].(float64) // a peer answers in the version it was asked in (1 or 2)
	if p.onlyV1 && version != 1 {
		return json.Marshal(map[string]any{"v": 1, "error": "INVALID_REQUEST"})
	}
	if p.deny != "" {
		return json.Marshal(map[string]any{"v": version, "error": p.deny})
	}
	if message["op"] == "unlock" && p.refuse != "" {
		return json.Marshal(map[string]any{"v": version, "error": p.refuse})
	}
	if message["op"] == "hello" {
		reply := helloReply{V: int(version), PeerID: p.id, Epoch: p.epoch, Nonce: hex.EncodeToString(p.nonce)}
		if p.hello != nil {
			p.hello(&reply)
		}
		return json.Marshal(map[string]any{"v": reply.V, "peer_id": reply.PeerID, "epoch": reply.Epoch, "nonce": reply.Nonce})
	}
	given := message["evidence"].(map[string]any)
	spki, _ := hex.DecodeString(given["ephemeral_public"].(string))
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, err
	}
	sessionID, _ := hex.DecodeString(message["session_id"].(string))
	nonce, _ := hex.DecodeString(given["nonce"].(string))
	digest := sha256.Sum256(transcript(message["node_id"].(string), p.epoch, sessionID, spki, nonce))
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, parsed.(*rsa.PublicKey), p.contribution, append([]byte(contributionLabel), digest[:]...))
	if err != nil {
		return nil, err
	}
	r := &response{Schema: responseSchema, PeerID: p.id, NodeID: message["node_id"].(string), Epoch: p.epoch, ManifestDigest: strings.Repeat("d1", 32),
		SessionID: message["session_id"].(string), TranscriptSHA256: hex.EncodeToString(digest[:]), PathEpoch: uint64(message["path_epoch"].(float64)),
		Ciphertext: hex.EncodeToString(ciphertext)}
	if p.edit != nil {
		p.edit(r)
	}
	sign := p.sign
	if p.signWith != nil {
		sign = p.signWith
	}
	reply := &unlockReply{Response: r, Signature: sign(r.signedDigest())}
	if p.forge != nil {
		p.forge(reply)
	}
	return json.Marshal(map[string]any{"response": reply.Response, "signature": reply.Signature})
}

func noQuote(qualifying []byte) ([]byte, []byte, map[string]string, error) {
	return []byte("attest"), []byte("signature"), map[string]string{"7": strings.Repeat("77", 32)}, nil
}

func testSession(t *testing.T) *session {
	t.Helper()
	boot, err := newSession("lisbon")
	if err != nil {
		t.Fatal(err)
	}
	return boot
}

func wantError(t *testing.T, err error, fragment string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), fragment) {
		t.Fatalf("got error %v, want one containing %q", err, fragment)
	}
}

func TestTheClientAgreesWithThePeerOnThePublishedVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "unlock-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Transcript struct {
			NodeID          string `json:"node_id"`
			Epoch           uint64 `json:"epoch"`
			SessionID       string `json:"session_id"`
			EphemeralPublic string `json:"ephemeral_public"`
			Nonce           string `json:"nonce"`
			Bytes           string `json:"bytes"`
			SHA256          string `json:"sha256"`
		} `json:"transcript"`
		Response struct {
			Response     response `json:"response"`
			Canonical    string   `json:"canonical"`
			SignedDigest string   `json:"signed_digest"`
		} `json:"response"`
		QualifiedName struct {
			EKName        string `json:"ek_name"`
			AKName        string `json:"ak_name"`
			QualifiedName string `json:"qualified_name"`
		} `json:"qualified_name"`
		Credential struct {
			Local        string `json:"local"`
			Contribution string `json:"contribution"`
			Target       string `json:"target"`
			Peer         string `json:"peer"`
			PathEpoch    uint64 `json:"path_epoch"`
			Info         string `json:"info"`
			Passphrase   string `json:"passphrase"`
		} `json:"credential"`
		Refused struct {
			Variants []struct {
				NodeID          string `json:"node_id"`
				Epoch           uint64 `json:"epoch"`
				SessionID       string `json:"session_id"`
				EphemeralPublic string `json:"ephemeral_public"`
				Nonce           string `json:"nonce"`
				SHA256          string `json:"sha256"`
			} `json:"variants"`
		} `json:"transcripts_a_peer_must_refuse"`
		OAEPLabel      string `json:"oaep_label"`
		ResponseDomain string `json:"response_domain"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	unhex := func(s string) []byte {
		out, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	v := vectors.Transcript
	got := transcript(v.NodeID, v.Epoch, unhex(v.SessionID), unhex(v.EphemeralPublic), unhex(v.Nonce))
	digest := sha256.Sum256(got)
	if hex.EncodeToString(got) != v.Bytes || hex.EncodeToString(digest[:]) != v.SHA256 {
		t.Fatal("the transcript differs from the vector")
	}
	if len(vectors.Refused.Variants) != 5 {
		t.Fatal("the vectors hold no transcripts a peer must refuse")
	}
	for _, x := range vectors.Refused.Variants {
		changed := sha256.Sum256(transcript(x.NodeID, x.Epoch, unhex(x.SessionID), unhex(x.EphemeralPublic), unhex(x.Nonce)))
		if hex.EncodeToString(changed[:]) != x.SHA256 || x.SHA256 == v.SHA256 {
			t.Fatal("a changed transcript differs from the vector, or equals the first")
		}
	}
	r := vectors.Response
	if err := r.Response.validate(); err != nil {
		t.Fatal(err)
	}
	if string(r.Response.canonical()) != r.Canonical || hex.EncodeToString(r.Response.signedDigest()) != r.SignedDigest {
		t.Fatalf("the canonical response or its signed digest differs from the vector:\n%s", r.Response.canonical())
	}
	q := vectors.QualifiedName
	if hex.EncodeToString(qualifiedName(unhex(q.EKName), unhex(q.AKName))) != q.QualifiedName {
		t.Fatal("the qualified name differs from the vector")
	}
	c := vectors.Credential
	key, err := credential(unhex(c.Local), unhex(c.Contribution), c.Target, c.Peer, c.PathEpoch)
	if err != nil || string(key) != c.Passphrase || fmt.Sprintf(hkdfInfoFormat, c.Target, c.Peer, c.PathEpoch) != c.Info {
		t.Fatalf("the credential differs from the vector: %s %v", key, err)
	}
	if hex.EncodeToString(append([]byte(contributionLabel), digest[:]...)) != vectors.OAEPLabel || hex.EncodeToString([]byte(responseDomain)) != vectors.ResponseDomain {
		t.Fatal("the OAEP label or the response domain differs from the vector")
	}
}

func TestAPeerGivesItsContributionAndTheFirstValidResponseSpendsTheSession(t *testing.T) {
	peer, boot := newFakePeer(t, "porto"), testSession(t)
	secret, err := boot.ask(peer.pin(), 3, peer.send, noQuote)
	if err != nil || !bytes.Equal(secret, peer.contribution) || !boot.consumed {
		t.Fatalf("got %x, %v, consumed=%v", secret, err, boot.consumed)
	}
	if len(peer.requests) != 2 || len(peer.requests[0]) != 3 || peer.requests[0]["op"] != "hello" || peer.requests[0]["node_id"] != "lisbon" {
		t.Fatalf("the hello is not {v, op, node_id}: %v", peer.requests)
	}
	if peer.requests[1]["path_epoch"] != float64(3) || len(peer.requests[1]) != 6 {
		t.Fatalf("the unlock request is not as specified: %v", peer.requests[1])
	}
	other := newFakePeer(t, "faro")
	_, err = boot.ask(other.pin(), 3, other.send, noQuote)
	wantError(t, err, "this boot session has already accepted a response")
	if len(other.requests) != 0 {
		t.Fatal("a spent session still asked a peer")
	}
}

func TestTheQuoteIsOverTheTranscriptOfThisBootAndTheEpochThePeerStates(t *testing.T) {
	peer, boot := newFakePeer(t, "porto"), testSession(t)
	peer.epoch = 12
	var qualified []byte
	_, err := boot.ask(peer.pin(), 3, peer.send, func(qualifying []byte) ([]byte, []byte, map[string]string, error) {
		qualified = append([]byte(nil), qualifying...)
		return []byte("a"), []byte("s"), nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(transcript("lisbon", 12, boot.id, boot.ephemeralPublic, peer.nonce))
	if !bytes.Equal(qualified, want[:]) {
		t.Fatal("the quote's qualifying data is not the transcript of this session at the peer's epoch")
	}
	if key, err := x509.ParsePKIXPublicKey(boot.ephemeralPublic); err != nil || key.(*rsa.PublicKey).N.BitLen() != keyBits || len(boot.ephemeralPublic) > 512 {
		t.Fatal("the ephemeral key is not an RSA-3072 SubjectPublicKeyInfo of at most 512 bytes")
	}
	failing := testSession(t)
	_, err = failing.ask(peer.pin(), 3, peer.send, func([]byte) ([]byte, []byte, map[string]string, error) {
		return nil, nil, nil, errors.New("the TPM refused the quote (TPM_RC_LOCKOUT)")
	})
	wantError(t, err, "quote: the TPM refused the quote (TPM_RC_LOCKOUT)")
}

func TestAnInvalidResponseIsRefusedAndSpendsNothing(t *testing.T) {
	impostor := newFakePeer(t, "porto")
	cases := []struct {
		reason string
		change func(*fakePeer)
	}{
		{"hello: the peer that answered is not porto", func(p *fakePeer) { p.hello = func(h *helloReply) { h.PeerID = "faro" } }},
		{"hello: the peer's epoch or nonce is malformed", func(p *fakePeer) { p.hello = func(h *helloReply) { h.Nonce = "zz" } }},
		{"hello: the peer's epoch or nonce is malformed", func(p *fakePeer) { p.hello = func(h *helloReply) { h.Epoch = 0 } }},
		{"hello: the peer refused (DENIED)", func(p *fakePeer) { p.deny = "DENIED" }},
		{"hello: the peer refused (?)", func(p *fakePeer) { p.deny = "the reason, which a peer never sends" }},
		{"the response is not from porto", func(p *fakePeer) { p.edit = func(r *response) { r.PeerID = "faro" } }},
		{"the peer answered for path epoch 2, not 3", func(p *fakePeer) { p.edit = func(r *response) { r.PathEpoch = 2 } }},
		{"the response is for another node or another boot session", func(p *fakePeer) { p.edit = func(r *response) { r.NodeID = "faro" } }},
		{"the response is for another node or another boot session", func(p *fakePeer) { p.edit = func(r *response) { r.SessionID = strings.Repeat("00", 32) } }},
		{"the response does not answer the request this boot session sent", func(p *fakePeer) { p.edit = func(r *response) { r.TranscriptSHA256 = strings.Repeat("ab", 32) } }},
		{"the response was decided under epoch 8, not the epoch 7", func(p *fakePeer) { p.edit = func(r *response) { r.Epoch = 8 } }},
		{"the response has another schema", func(p *fakePeer) { p.edit = func(r *response) { r.Schema = "regalia.unlock-response/v2" } }},
		{"the response's digests must be 64 lowercase hex", func(p *fakePeer) { p.edit = func(r *response) { r.ManifestDigest = strings.Repeat("D1", 32) } }},
		{"the response's ciphertext is not one RSA-3072 block", func(p *fakePeer) { p.edit = func(r *response) { r.Ciphertext = "00" } }},
		{"the response is not signed by the AK recorded for porto", func(p *fakePeer) { p.signWith = impostor.sign }},
		{"the response is not signed under the EK recorded for porto", func(p *fakePeer) { p.ekName = append([]byte{0, 0x0b}, make([]byte, 32)...) }},
		{"the peer's quote is not over this response", func(p *fakePeer) {
			p.forge = func(u *unlockReply) { u.Response.ManifestDigest = strings.Repeat("ee", 32) }
		}},
		{"the peer's quote is not over this response", func(p *fakePeer) {
			p.forge = func(u *unlockReply) { u.Response.Ciphertext = strings.Repeat("00", 384) }
		}},
		{"the response's signature does not verify", func(p *fakePeer) {
			p.forge = func(u *unlockReply) { u.Signature.Quote = u.Signature.Quote[:len(u.Signature.Quote)-2] + "ff" }
		}},
		{"the response's signature is malformed", func(p *fakePeer) { p.forge = func(u *unlockReply) { u.Signature.Sig = "ZZ" } }},
		{"the signer is not a restricted ECDSA P-256 attestation key", func(p *fakePeer) {
			p.forge = func(u *unlockReply) {
				u.Signature.AKPublic = strings.Replace(u.Signature.AKPublic, "00050072", "00060072", 1)
			}
		}},
		{"the contribution does not decrypt", func(p *fakePeer) {
			p.edit = func(r *response) {
				other, _ := rsa.GenerateKey(rand.Reader, keyBits)
				ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &other.PublicKey, p.contribution, []byte(contributionLabel))
				r.Ciphertext = hex.EncodeToString(ciphertext)
			}
		}},
	}
	boot := testSession(t)
	for _, c := range cases {
		peer := newFakePeer(t, "porto")
		recorded := peer.pin()
		c.change(peer)
		_, err := boot.ask(recorded, 3, peer.send, noQuote)
		wantError(t, err, c.reason)
		if boot.consumed {
			t.Fatalf("%s: an invalid response spent the session", c.reason)
		}
	}
	// a contribution encrypted to this key under another label (another exchange) does not decrypt either
	peer := newFakePeer(t, "porto")
	peer.edit = func(r *response) {
		ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &boot.key.PublicKey, peer.contribution, append([]byte(contributionLabel), make([]byte, 32)...))
		r.Ciphertext = hex.EncodeToString(ciphertext)
	}
	_, err := boot.ask(peer.pin(), 3, peer.send, noQuote)
	wantError(t, err, "the contribution does not decrypt")
	// and after all of that the same session still takes the real answer
	good := newFakePeer(t, "porto")
	if secret, err := boot.ask(good.pin(), 3, good.send, noQuote); err != nil || !bytes.Equal(secret, good.contribution) {
		t.Fatalf("the session was not usable after the refusals: %v", err)
	}
}

func TestAReplyIsParsedStrictly(t *testing.T) {
	for _, raw := range []string{``, `[]`, `{"v":1,"peer_id":"porto","epoch":7,"nonce":"aa","extra":1}`, `{"v":1} {"v":1}`, `{"epoch":-1}`, `{"epoch":1.5}`,
		`{"v":1,"error":"DENIED"}}`, `{"v":1,"error":"DENIED"}]anything {{{`, `{"v":1}x`,
		`{"v":1,"peer_id":"porto","epoch":7,"nonce":"` + strings.Repeat("a", maxMessage) + `"}`} {
		var hello helloReply
		if decodeReply([]byte(raw), &hello) == nil {
			t.Fatalf("accepted %.40q", raw)
		}
	}
	boot := testSession(t)
	_, err := boot.ask(newFakePeer(t, "porto").pin(), 1, func([]byte) ([]byte, error) { return nil, errors.New("no connection") }, noQuote)
	wantError(t, err, "hello: the transport failed (no connection)")
	_, err = boot.ask(newFakePeer(t, "porto").pin(), 1, func([]byte) ([]byte, error) { return []byte(`{"v":1,"response":null,"signature":null}`), nil }, noQuote)
	wantError(t, err, "hello: the reply is not the expected JSON object")
}

// deadTPM is a TPM that answers nothing.
type deadTPM struct{}

func (deadTPM) Send([]byte) ([]byte, error) { return nil, errors.New("no TPM") }

// wireTPM answers TPM2_ReadPublic and TPM2_Quote with prepared response BYTES, as a TPM does, and
// records the command bytes it was sent: what go-tpm puts on the wire and what it makes of what comes
// back are both checked against bytes written here from the TPM 2.0 Library (Part 3).
type wireTPM struct {
	commands [][]byte
	public   []byte         // TPM2B_PUBLIC of the key at the handle
	quote    []byte         // the whole TPM2_Quote response
	pcrs     map[int][]byte // what TPM2_PCR_Read answers, per PCR
	moving   int            // that many PCR_Reads answer another value first (a PCR extended under the quote)
}

func tpmResponse(tag uint16, code uint32, body []byte) []byte {
	out := binary.BigEndian.AppendUint16(nil, tag)
	out = binary.BigEndian.AppendUint32(out, uint32(10+len(body)))
	out = binary.BigEndian.AppendUint32(out, code)
	return append(out, body...)
}

// quoteResponse is a TPM2_Quote response: the parameter size, TPM2B_ATTEST, TPMT_SIGNATURE, then the
// response's authorization area for the password session (empty nonce, continueSession, empty HMAC).
func quoteResponse(attest []byte, sigAlg, hashAlg uint16, r, s []byte) []byte {
	parameters := sized(attest)
	parameters = binary.BigEndian.AppendUint16(parameters, sigAlg)
	parameters = binary.BigEndian.AppendUint16(parameters, hashAlg)
	parameters = append(append(parameters, sized(r)...), sized(s)...)
	body := binary.BigEndian.AppendUint32(nil, uint32(len(parameters)))
	return tpmResponse(0x8002, 0, append(append(body, parameters...), 0, 0, 0x01, 0, 0))
}

func (w *wireTPM) Send(command []byte) ([]byte, error) {
	w.commands = append(w.commands, append([]byte(nil), command...))
	switch binary.BigEndian.Uint32(command[6:10]) {
	case 0x00000173: // TPM2_ReadPublic: outPublic, name, qualifiedName
		name := append([]byte{0x00, 0x0b}, make([]byte, 32)...)
		return tpmResponse(0x8001, 0, append(append(append([]byte(nil), w.public...), sized(name)...), sized(name)...)), nil
	case 0x00000158: // TPM2_Quote
		return w.quote, nil
	case 0x0000017e: // TPM2_PCR_Read: one selection of SHA-256 in; the counter, the selection and its digests out
		selection := command[10:20]
		var digests []byte
		count := 0
		for byteIndex, bits := range selection[7:10] {
			for bit := 0; bit < 8; bit++ {
				if bits&(1<<bit) == 0 {
					continue
				}
				value, ok := w.pcrs[byteIndex*8+bit]
				if !ok {
					return tpmResponse(0x8001, 0x1c4, nil), nil // TPM_RC_VALUE
				}
				if w.moving > 0 {
					value = bytes.Repeat([]byte{0xee}, 32)
				}
				digests = append(digests, sized(value)...)
				count++
			}
		}
		if w.moving > 0 {
			w.moving--
		}
		body := binary.BigEndian.AppendUint32(nil, 1)
		body = append(body, selection...)
		body = binary.BigEndian.AppendUint32(body, uint32(count))
		return tpmResponse(0x8001, 0, append(body, digests...)), nil
	}
	return tpmResponse(0x8001, 0x143, nil), nil // TPM_RC_COMMAND_CODE
}

func TestTheQuoteIsAskedForThroughGoTPM(t *testing.T) {
	qualifying := bytes.Repeat([]byte{0x5c}, 32)
	name := tpm2.TPM2BName{Buffer: append([]byte{0x00, 0x0b}, make([]byte, 32)...)}
	command, err := quoteCommand(name, qualifying, []int{7, 11})
	if err != nil {
		t.Fatal(err)
	}
	// the persistent attestation key with its empty password, the key's own scheme, and one SHA-256 selection
	handle, ok := command.SignHandle.(tpm2.AuthHandle)
	if !ok || handle.Handle != 0x81010002 || !bytes.Equal(handle.Name.Buffer, name.Buffer) {
		t.Fatalf("the quote is not by the attestation key at 0x81010002: %+v", command.SignHandle)
	}
	if !bytes.Equal(command.QualifyingData.Buffer, qualifying) || command.InScheme.Scheme != tpm2.TPMAlgNull {
		t.Fatal("the qualifying data or the scheme is not as asked")
	}
	selections := command.PCRSelect.PCRSelections
	if len(selections) != 1 || selections[0].Hash != tpm2.TPMAlgSHA256 || hex.EncodeToString(selections[0].PCRSelect) != "800800" {
		t.Fatalf("the PCR selection is not sha256:7,11: %+v", selections)
	}
	_, err = quoteCommand(name, qualifying[:31], []int{7})
	wantError(t, err, "a quote needs 32 bytes")
	_, err = quoteCommand(name, qualifying, nil)
	wantError(t, err, "a quote needs 32 bytes")
	_, err = quoteCommand(name, qualifying, []int{24})
	wantError(t, err, "PCRs must be 0-23")

	// what comes back: the TPMS_ATTEST exactly as the TPM made it, and the signature in DER
	attestation := append(binary.BigEndian.AppendUint32(nil, tpmGenerated), 0x80, 0x18)
	attestation = append(attestation, sized(make([]byte, 34))...)
	attestation = append(attestation, sized(qualifying)...)
	attestation = append(attestation, make([]byte, 8+4+4+1+8)...)
	attestation = binary.BigEndian.AppendUint32(attestation, 1)
	attestation = append(attestation, 0x00, 0x0b, 3, 0x80, 0x08, 0)
	attestation = append(attestation, sized(make([]byte, 32))...)
	signed := func(alg tpm2.TPMAlgID, hash tpm2.TPMAlgID, r, s []byte) *tpm2.QuoteResponse {
		return &tpm2.QuoteResponse{Quoted: tpm2.BytesAs2B[tpm2.TPMSAttest](attestation),
			Signature: tpm2.TPMTSignature{SigAlg: alg, Signature: tpm2.NewTPMUSignature(alg, &tpm2.TPMSSignatureECC{
				Hash: hash, SignatureR: tpm2.TPM2BECCParameter{Buffer: r}, SignatureS: tpm2.TPM2BECCParameter{Buffer: s}})}}
	}
	attest, signature, err := quoted(signed(tpm2.TPMAlgECDSA, tpm2.TPMAlgSHA256, []byte{0x01, 0x02}, []byte{0x80, 0x03}))
	if err != nil || !bytes.Equal(attest, attestation) || hex.EncodeToString(signature) != "3009"+"02020102"+"0203008003" {
		t.Fatalf("attest %x, signature %x, %v", attest, signature, err)
	}
	if qualifiedSigner, extraData, err := parseAttest(attest); err != nil || len(qualifiedSigner) != 34 || !bytes.Equal(extraData, qualifying) {
		t.Fatalf("go-tpm does not read the quote as the peer's verifier does: %v", err)
	}
	_, _, err = quoted(signed(tpm2.TPMAlgECDSA, tpm2.TPMAlgSHA1, []byte{1}, []byte{2}))
	wantError(t, err, "the quote is not signed with ECDSA and SHA-256")
	_, _, err = quoted(signed(tpm2.TPMAlgECDSA, tpm2.TPMAlgSHA256, nil, []byte{2}))
	wantError(t, err, "the TPM's quote is malformed")
	_, _, err = quoted(&tpm2.QuoteResponse{Signature: tpm2.TPMTSignature{SigAlg: tpm2.TPMAlgRSASSA}})
	wantError(t, err, "the quote is not signed with ECDSA")

	_, _, err = tpmQuoteOnce(deadTPM{}, qualifying, []int{7})
	wantError(t, err, "the TPM has no usable attestation key")

	// On the wire. The Quote command is, byte for byte, the one the TPM specifies: sessions tag, size,
	// TPM_CC_Quote, the handle, a 9-byte password authorization, 32 bytes of qualifying data,
	// TPM_ALG_NULL, one selection of sha256 with PCRs 7 and 11. A go-tpm that sent anything else fails here.
	wantCommand := "8002" + "00000049" + "00000158" + "81010002" + "00000009" + "40000009" + "0000" + "00" + "0000" +
		"0020" + strings.Repeat("5c", 32) + "0010" + "00000001" + "000b" + "03" + "800800"
	peer := newFakePeer(t, "porto") // its public area stands for this TPM's attestation key
	device := &wireTPM{public: peer.akPublic, quote: quoteResponse(attestation, algECDSA, algSHA256, []byte{0x01, 0x02}, []byte{0x80, 0x03})}
	attest, signature, err = tpmQuoteOnce(device, qualifying, []int{7, 11})
	if err != nil || len(device.commands) != 2 || hex.EncodeToString(device.commands[1]) != wantCommand {
		t.Fatalf("%v; the commands sent: %x", err, device.commands)
	}
	if hex.EncodeToString(device.commands[0]) != "8001"+"0000000e"+"00000173"+"81010002" {
		t.Fatalf("the first command is not TPM2_ReadPublic of the attestation key: %x", device.commands[0])
	}
	// and the attestation comes back as the bytes the TPM sent, not a re-encoding of them
	if !bytes.Equal(attest, attestation) || hex.EncodeToString(signature) != "3009"+"02020102"+"0203008003" {
		t.Fatalf("attest %x, signature %x", attest, signature)
	}
	for reason, raw := range map[string][]byte{
		"the TPM refused the quote":                      tpmResponse(0x8001, 0x921, nil), // TPM_RC_LOCKOUT
		"the TPM refused the quote ":                     quoteResponse(attestation, algECDSA, algSHA256, []byte{1}, []byte{2})[:30],
		"the quote is not signed with ECDSA":             quoteResponse(attestation, 0x0014, algSHA256, []byte{1}, nil), // RSASSA
		"the quote is not signed with ECDSA and SHA-256": quoteResponse(attestation, algECDSA, 0x0004, []byte{1}, []byte{2}),
	} {
		_, _, err := tpmQuoteOnce(&wireTPM{public: peer.akPublic, quote: raw}, qualifying, []int{7})
		wantError(t, err, strings.TrimSpace(reason))
	}
	if _, err := openTPM(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a TPM device that does not exist was opened")
	}
	if _, err := openTPM("unix:" + filepath.Join(t.TempDir(), "absent.sock")); err == nil {
		t.Fatal("a TPM socket that does not exist was opened")
	}
}

// THE INITRD-PHASE PCR 11 IS SAID ON THE CONSOLE before anything is quoted (#75 tier Q, regalia-kms-d9): one plain line,
// the value as the TPM holds it, and a line that says so when it cannot be read (nothing else depends on it).
func TestTheInitrdPCR11IsSaidAsTheTPMHoldsIt(t *testing.T) {
	eleven := bytes.Repeat([]byte{0x11}, 32)
	device := &wireTPM{pcrs: map[int][]byte{11: eleven}}
	if got, want := initrdPCR11Line(device), "regalia-unlock: initrd PCR 11 (sha256) = "+hex.EncodeToString(eleven); got != want {
		t.Fatalf("said %q, want %q", got, want)
	}
	if got := initrdPCR11Line(&wireTPM{pcrs: map[int][]byte{}}); !strings.HasPrefix(got, "regalia-unlock: initrd PCR 11 (sha256) could not be read: ") {
		t.Fatalf("an unreadable PCR 11 said %q", got)
	}
}

// Wire v2: the quoted PCRs are read beside the quote, and sent only if they hash to the quote's own digest.
// A PCR that moves between the two is met by quoting again; one that keeps moving is an error, never values
// that do not match.
func TestThePCRValuesBesideTheQuoteAreTheQuotedOnes(t *testing.T) {
	qualifying := bytes.Repeat([]byte{0x5c}, 32)
	seven, eleven := bytes.Repeat([]byte{0x07}, 32), bytes.Repeat([]byte{0x11}, 32)
	digest := sha256.Sum256(append(append([]byte(nil), seven...), eleven...))
	attestation := append(binary.BigEndian.AppendUint32(nil, tpmGenerated), 0x80, 0x18)
	attestation = append(attestation, sized(make([]byte, 34))...)
	attestation = append(attestation, sized(qualifying)...)
	attestation = append(attestation, make([]byte, 8+4+4+1+8)...)
	attestation = binary.BigEndian.AppendUint32(attestation, 1)
	attestation = append(attestation, 0x00, 0x0b, 3, 0x80, 0x08, 0)
	attestation = append(attestation, sized(digest[:])...)
	peer := newFakePeer(t, "porto")
	device := &wireTPM{public: peer.akPublic, quote: quoteResponse(attestation, algECDSA, algSHA256, []byte{1}, []byte{2}),
		pcrs: map[int][]byte{7: seven, 11: eleven}}
	_, _, values, err := tpmQuote(device, qualifying, []int{7, 11})
	if err != nil || len(values) != 2 || values["7"] != hex.EncodeToString(seven) || values["11"] != hex.EncodeToString(eleven) {
		t.Fatalf("values %v, %v", values, err)
	}
	// one PCR_Read over the selection, after the quote: the values are read at one instant
	reads := 0
	for _, command := range device.commands {
		if binary.BigEndian.Uint32(command[6:10]) == 0x17e {
			reads++
		}
	}
	if reads != 1 {
		t.Fatalf("%d PCR_Reads for one selection", reads)
	}
	// a PCR that moved once: quoted again, and the values that match are sent
	device = &wireTPM{public: peer.akPublic, quote: device.quote, pcrs: device.pcrs, moving: 1}
	if _, _, values, err = tpmQuote(device, qualifying, []int{7, 11}); err != nil || values["7"] != hex.EncodeToString(seven) {
		t.Fatalf("after one move: %v, %v", values, err)
	}
	// one that keeps moving: the quote still goes, without values (never values that do not match)
	device = &wireTPM{public: peer.akPublic, quote: device.quote, pcrs: device.pcrs, moving: 100}
	attest, _, values, err := tpmQuote(device, qualifying, []int{7, 11})
	if err != nil || values != nil || len(attest) == 0 {
		t.Fatalf("a quote whose PCRs keep moving: %v, %v", values, err)
	}
	// a PCR the TPM will not read
	device = &wireTPM{public: peer.akPublic, quote: device.quote, pcrs: map[int][]byte{7: seven}}
	_, _, _, err = tpmQuote(device, qualifying, []int{7, 11})
	wantError(t, err, "the TPM refused to read the PCRs")
	if pcrDigest(map[string]string{"11": hex.EncodeToString(eleven), "7": hex.EncodeToString(seven)}) == nil ||
		!bytes.Equal(pcrDigest(map[string]string{"11": hex.EncodeToString(eleven), "7": hex.EncodeToString(seven)}), digest[:]) {
		t.Fatal("the digest is not over the values in index order")
	}
}

// A peer's structures that are not exactly what attest.py accepts are refused, whatever go-tpm can parse.
func TestOnlyARestrictedP256AttestationKeyIsAccepted(t *testing.T) {
	peer := newFakePeer(t, "porto")
	if name, key, err := akIdentity(peer.akPublic); err != nil || len(name) != 34 || key == nil {
		t.Fatal(err)
	}
	area := peer.akPublic[2:]
	patched := func(offset int, value ...byte) []byte {
		out := append([]byte(nil), area...)
		copy(out[offset:], value)
		return sized(out)
	}
	for reason, public := range map[string][]byte{
		"a decrypting key (attributes)":      patched(4, 0x00, 0x06, 0x00, 0x72),
		"not restricted":                     patched(4, 0x00, 0x04, 0x00, 0x72),
		"not fixedTPM":                       patched(4, 0x00, 0x05, 0x00, 0x70),
		"another name algorithm":             patched(2, 0x00, 0x04),
		"another curve":                      patched(16, 0x00, 0x04),
		"trailing bytes after the structure": append(append([]byte(nil), peer.akPublic...), 0x00),
		"a truncated structure":              peer.akPublic[:len(peer.akPublic)-3],
		"nothing":                            nil,
	} {
		if _, _, err := akIdentity(public); err == nil {
			t.Fatalf("accepted an attestation key that is %s", reason)
		}
	}
	offCurve := patched(len(area)-32, bytes.Repeat([]byte{0xff}, 32)...)
	_, _, err := akIdentity(offCurve)
	wantError(t, err, "not on P-256")
	// The signed structure: a quote, generated by a TPM, whole, with one SHA-256 selection. A restricted
	// key signs caller-supplied data that does NOT begin with TPM_GENERATED, so a structure with another
	// magic is exactly what a holder of the key could have built by hand.
	quote, _ := hex.DecodeString(peer.sign(make([]byte, 32)).Quote)
	if _, _, err := parseAttest(quote); err != nil {
		t.Fatal(err)
	}
	mutated := func(change func([]byte) []byte) []byte { return change(append([]byte(nil), quote...)) }
	twoBanks := mutated(func(q []byte) []byte {
		tail := len(q) - (4 + 2 + 1 + 3 + 2 + 32) // count, hash, sizeofSelect, select, digest
		out := append([]byte(nil), q[:tail]...)
		out = append(out, 0, 0, 0, 2, 0x00, 0x0b, 3, 0x80, 0, 0, 0x00, 0x04, 3, 0x80, 0, 0)
		return append(out, q[len(q)-34:]...)
	})
	for reason, attest := range map[string][]byte{
		"another magic (zero)":      mutated(func(q []byte) []byte { copy(q, []byte{0, 0, 0, 0}); return q }),
		"another magic":             mutated(func(q []byte) []byte { copy(q, []byte{0xde, 0xad, 0xbe, 0xef}); return q }),
		"not a quote (certify)":     mutated(func(q []byte) []byte { q[5] = 0x17; return q }),
		"bytes after the structure": append(append([]byte(nil), quote...), 0x00),
		"cut inside the PCR digest": quote[:len(quote)-33],
		"cut before the PCR digest": quote[:len(quote)-34],
		"cut inside the selection":  quote[:len(quote)-38],
		"the SHA-1 bank":            mutated(func(q []byte) []byte { q[len(q)-39] = 0x04; return q }),
		"two PCR selections":        twoBanks,
		"not a structure at all":    []byte("not an attestation"),
		"nothing":                   nil,
	} {
		if _, _, err := parseAttest(attest); err == nil {
			t.Fatalf("accepted a signed structure with %s", reason)
		}
	}
}

func validConfig(peers ...*fakePeer) *bootConfig {
	config := &bootConfig{Schema: bootSchema, NodeID: "lisbon", Device: "/dev/disk/by-partlabel/root", PCRs: []int{7, 11}}
	for _, peer := range peers {
		config.Peers = append(config.Peers, peer.pin())
	}
	return config
}

func TestTheBootConfigurationIsRefusedUnlessExact(t *testing.T) {
	porto := newFakePeer(t, "porto")
	if err := validConfig(porto).validate(); err != nil {
		t.Fatal(err)
	}
	for reason, change := range map[string]func(*bootConfig){
		"schema must be":                         func(c *bootConfig) { c.Schema = "v0" },
		"node_id is not a node ID":               func(c *bootConfig) { c.NodeID = "Lisbon" },
		"device must be a plain path":            func(c *bootConfig) { c.Device = "/dev/sda3; reboot" },
		"pcrs must be an ascending list":         func(c *bootConfig) { c.PCRs = []int{11, 7} },
		"pcrs must be an ascending list of PCR":  func(c *bootConfig) { c.PCRs = []int{7, 7} },
		"pcrs must be an ascending list of PCR ": func(c *bootConfig) { c.PCRs = []int{24} },
		"peers must list 1 to 8 peers":           func(c *bootConfig) { c.Peers = nil },
		"peer porto is listed twice":             func(c *bootConfig) { c.Peers = append(c.Peers, c.Peers[0]) },
		"is listed twice, or is the node itself": func(c *bootConfig) { c.NodeID = "porto" },
		"a peer's endpoint must be host:port":    func(c *bootConfig) { c.Peers[0].Endpoint = "porto.boot" },
		"a peer's endpoint must be host:port,":   func(c *bootConfig) { c.Peers[0].Endpoint = "fd00::2:7000" }, // IPv6 without brackets: nothing can dial it
		"an IPv6 address in brackets":            func(c *bootConfig) { c.Peers[0].Endpoint = "192.0.2.1:70000" },
		"the port 1-65535":                       func(c *bootConfig) { c.Peers[0].Endpoint = "192.0.2.1:0" },
		"must be SHA-256 TPM Names":              func(c *bootConfig) { c.Peers[0].AKName = "000b" + strings.Repeat("ZZ", 32) },
	} {
		config := validConfig(porto)
		change(config)
		wantError(t, config.validate(), strings.TrimSpace(reason))
	}
	for _, endpoint := range []string{"[2001:db8::3]:7443", "porto.boot:7443", "192.0.2.1:65535"} {
		config := validConfig(porto)
		config.Peers[0].Endpoint = endpoint
		if err := config.validate(); err != nil {
			t.Fatalf("%s: %v", endpoint, err)
		}
	}
	path := filepath.Join(t.TempDir(), "unlock.json")
	raw, _ := json.Marshal(validConfig(porto))
	_ = os.WriteFile(path, raw, 0o600)
	if loaded, err := loadBootConfig(path); err != nil || loaded.Peers[0].NodeID != "porto" {
		t.Fatal(err)
	}
	_ = os.WriteFile(path, append(append([]byte{}, raw...), '}'), 0o600)
	_, err := loadBootConfig(path)
	wantError(t, err, "the boot configuration has trailing data")
	_ = os.WriteFile(path, []byte(strings.Replace(string(raw), `"device"`, `"extra":1,"device"`, 1)), 0o600)
	_, err = loadBootConfig(path)
	wantError(t, err, "not the expected JSON object")
	_, err = loadBootConfig(filepath.Join(t.TempDir(), "absent"))
	wantError(t, err, "cannot read the boot configuration")
}

func sealedLocal() string {
	id, _ := hex.DecodeString("0c7cc07b117645919c4b0bea08bc20fe")
	return base64.StdEncoding.EncodeToString(append(id, []byte("an encrypted credential")...))
}

func token(peer, slot string, epoch uint64) map[string]any {
	return map[string]any{"type": tokenType, "keyslots": []string{slot}, "version": 1, "target": "lisbon", "peer": peer, "path_epoch": epoch, "local": sealedLocal()}
}

// luksCopy is one copy of a LUKS2 header as cryptsetup writes it: the 4096-byte binary header with its
// SHA-256 checksum, then the JSON area.
func luksCopy(magic string, offset, sequence uint64, metadata []byte) []byte {
	const size = luksMinHeader
	out := make([]byte, size)
	copy(out, magic)
	binary.BigEndian.PutUint16(out[6:], 2)
	binary.BigEndian.PutUint64(out[8:], size)
	binary.BigEndian.PutUint64(out[16:], sequence)
	copy(out[72:], "sha256")
	binary.BigEndian.PutUint64(out[256:], offset)
	copy(out[luksBinaryHeader:], metadata)
	sum := sha256.Sum256(out)
	copy(out[448:], sum[:])
	return out
}

func luksImage(tokens map[string]any) []byte {
	metadata, _ := json.Marshal(map[string]any{"keyslots": map[string]any{}, "tokens": tokens})
	return append(luksCopy("LUKS\xba\xbe", 0, 5, metadata), luksCopy("SKUL\xba\xbe", luksMinHeader, 5, metadata)...)
}

func tokensFor(peers ...*fakePeer) map[string]any {
	tokens := map[string]any{"0": map[string]any{"type": "systemd-recovery", "keyslots": []string{"0"}}}
	for i, peer := range peers {
		tokens[fmt.Sprint(i+1)] = token(peer.id, fmt.Sprint(i+1), 3)
	}
	return tokens
}

func pathsOf(t *testing.T, tokens map[string]any) (map[string][]pathToken, []string) {
	t.Helper()
	paths, skipped, err := pathTokens(bytes.NewReader(luksImage(tokens)), "lisbon")
	if err != nil {
		t.Fatal(err)
	}
	return paths, skipped
}

func dialer(peers ...*fakePeer) func(string, time.Time) transport {
	byEndpoint := map[string]*fakePeer{}
	for i, peer := range peers {
		byEndpoint[fmt.Sprintf("192.0.2.%d:7443", i+1)] = peer
	}
	return func(endpoint string, _ time.Time) transport {
		if peer := byEndpoint[endpoint]; peer != nil {
			return peer.send
		}
		return func([]byte) ([]byte, error) { return nil, errors.New("no connection") }
	}
}

func configFor(peers ...*fakePeer) *bootConfig {
	config := validConfig(peers...)
	for i := range config.Peers {
		config.Peers[i].Endpoint = fmt.Sprintf("192.0.2.%d:7443", i+1)
	}
	return config
}

func TestTheLUKS2HeaderIsReadFromTheDiskAndItsNewerValidCopyIsUsed(t *testing.T) {
	old, _ := json.Marshal(map[string]any{"tokens": map[string]any{"1": token("porto", "1", 3)}})
	updated, _ := json.Marshal(map[string]any{"tokens": map[string]any{"1": token("porto", "1", 4)}})
	primary, secondary := luksCopy("LUKS\xba\xbe", 0, 5, old), luksCopy("SKUL\xba\xbe", luksMinHeader, 5, old)
	epoch := func(image []byte) uint64 {
		t.Helper()
		paths, _, err := pathTokens(bytes.NewReader(image), "lisbon")
		if err != nil {
			t.Fatal(err)
		}
		return paths["porto"][0].PathEpoch
	}
	if epoch(append(append([]byte{}, primary...), secondary...)) != 3 {
		t.Fatal("the header was not read")
	}
	// a write that reached only the second copy (higher sequence number): that one is current
	if epoch(append(append([]byte{}, primary...), luksCopy("SKUL\xba\xbe", luksMinHeader, 6, updated)...)) != 4 {
		t.Fatal("the newer copy was not chosen")
	}
	// a damaged first copy: the second is found and used
	damaged := append(append([]byte{}, primary...), luksCopy("SKUL\xba\xbe", luksMinHeader, 6, updated)...)
	damaged[luksBinaryHeader+10] ^= 1
	if epoch(damaged) != 4 {
		t.Fatal("the second copy was not used when the first is damaged")
	}
	for reason, image := range map[string][]byte{
		"no valid LUKS2 header":    make([]byte, 2*luksMinHeader),
		"no valid LUKS2 header ":   append(append([]byte{}, damaged[:luksMinHeader]...), damaged[:luksMinHeader]...), // both copies damaged
		"no valid LUKS2 header  ":  primary[:100],
		"no valid LUKS2 header   ": luksCopy("LUKS\xba\xbe", 4096, 5, old), // it says it is somewhere else
	} {
		_, _, err := pathTokens(bytes.NewReader(image), "lisbon")
		wantError(t, err, strings.TrimSpace(reason))
	}
	notJSON := luksCopy("LUKS\xba\xbe", 0, 5, []byte("{"))
	_, _, err := pathTokens(bytes.NewReader(notJSON), "lisbon")
	wantError(t, err, "the LUKS2 metadata is not readable JSON")
}

func TestTheTransportIsOneBoundedRequestPerConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	replies := [][]byte{[]byte(`{"v":1,"error":"DENIED"}`), bytes.Repeat([]byte("x"), maxMessage+10)}
	got := make(chan []byte, len(replies))
	go func() {
		for _, reply := range replies {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			request, _ := io.ReadAll(connection) // ends when the client closes its half
			got <- request
			_, _ = connection.Write(reply)
			connection.Close()
		}
	}()
	send := tcpTransport(listener.Addr().String(), time.Time{})
	reply, err := send([]byte(`{"v":1,"op":"hello","node_id":"lisbon"}`))
	if err != nil || string(reply) != `{"v":1,"error":"DENIED"}` || string(<-got) != `{"v":1,"op":"hello","node_id":"lisbon"}` {
		t.Fatalf("%q %v", reply, err)
	}
	reply, err = send([]byte("x"))
	var hello helloReply
	if err != nil || len(reply) != maxMessage+1 || decodeReply(reply, &hello) == nil {
		t.Fatalf("an oversized reply was not cut and refused: %d bytes, %v", len(reply), err)
	}
	listener.Close()
	if _, err := send([]byte("x")); err == nil || err.Error() != "no connection" {
		t.Fatalf("got %v", err)
	}
}

func newUnlocker(t *testing.T, directory string, log io.Writer, peers ...*fakePeer) *unlocker {
	t.Helper()
	paths, _ := pathsOf(t, tokensFor(peers...))
	return &unlocker{config: configFor(peers...), o: options{sessionDir: directory, askDir: askpass.Dir, requestID: askpass.RootID, volume: "/dev/mapper/root"}, paths: paths,
		local: bytes.Repeat([]byte{0x11}, 32), boot: testSession(t), dial: dialer(peers...), quote: noQuote,
		sleep: func(time.Duration) {}, out: io.Discard, diagnostics: log}
}

func recordOf(t *testing.T, directory string) (id, public string) {
	t.Helper()
	read := func(name string) string {
		content, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return ""
		}
		if info, _ := os.Stat(filepath.Join(directory, name)); info.Mode().Perm() != 0o644 {
			t.Fatalf("%s has mode %o", name, info.Mode().Perm())
		}
		return string(content)
	}
	return read("boot-session"), read("boot-session.pub")
}

// locked makes a peer and a log usable from the test while the serving loop runs in its own goroutine.
type locked struct {
	sync.Mutex
	log bytes.Buffer
}

func (l *locked) Write(p []byte) (int, error) {
	l.Lock()
	defer l.Unlock()
	return l.log.Write(p)
}

func (l *locked) said() string {
	l.Lock()
	defer l.Unlock()
	return l.log.String()
}

// through wraps a dialer: every request to a peer is made under the lock, after `before` (if any).
func (l *locked) through(dial func(string, time.Time) transport, before func()) func(string, time.Time) transport {
	return func(endpoint string, until time.Time) transport {
		send := dial(endpoint, until)
		return func(request []byte) ([]byte, error) {
			if before != nil {
				before()
			}
			l.Lock()
			defer l.Unlock()
			return send(request)
		}
	}
}

func unlockSessions(peer *fakePeer) (sessions map[string]bool, unlocks int) {
	sessions = map[string]bool{}
	for _, request := range peer.requests {
		if request["op"] == "unlock" {
			sessions[request["session_id"].(string)] = true
			unlocks++
		}
	}
	return sessions, unlocks
}

func errHelp() error { return flag.ErrHelp }

func TestThePCRValuesVectorIsWhatTheClientSends(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "pcr-values-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Quote     string            `json:"quote"`
		PCRDigest string            `json:"pcr_digest"`
		Values    map[string]string `json:"pcr_values"`
		Refused   map[string]struct {
			Values map[string]string `json:"pcr_values"`
			Reason string            `json:"reason"`
		} `json:"refused"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	quote, _ := hex.DecodeString(vector.Quote)
	quoted, err := quotedPCRDigest(quote)
	if err != nil || hex.EncodeToString(quoted) != vector.PCRDigest {
		t.Fatalf("the vector's quote: %x, %v", quoted, err)
	}
	if !bytes.Equal(pcrDigest(vector.Values), quoted) {
		t.Fatal("the values read beside the quote do not hash to it")
	}
	if !bytes.Equal(pcrDigest(map[string]string{"12": vector.Values["12"], "11": vector.Values["11"], "7": vector.Values["7"]}), quoted) {
		t.Fatal("the digest depends on the order the values were given in")
	}
	tampered := vector.Refused["tampered"]
	if tampered.Reason != "the reported PCR values do not match the quote" || bytes.Equal(pcrDigest(tampered.Values), quoted) {
		t.Fatalf("the tampered case: %q", tampered.Reason)
	}
}
