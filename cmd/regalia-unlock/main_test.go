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
	"testing"
	"time"
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
	area = binary.BigEndian.AppendUint32(area, akAttributes)
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
	if p.deny != "" {
		return json.Marshal(map[string]any{"v": 1, "error": p.deny})
	}
	if message["op"] == "hello" {
		reply := helloReply{V: 1, PeerID: p.id, Epoch: p.epoch, Nonce: hex.EncodeToString(p.nonce)}
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

func noQuote(qualifying []byte) ([]byte, []byte, error) {
	return []byte("attest"), []byte("signature"), nil
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
	_, err := boot.ask(peer.pin(), 3, peer.send, func(qualifying []byte) ([]byte, []byte, error) {
		qualified = append([]byte(nil), qualifying...)
		return []byte("a"), []byte("s"), nil
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
	_, err = failing.ask(peer.pin(), 3, peer.send, func([]byte) ([]byte, []byte, error) {
		return nil, nil, errors.New("the TPM refused the quote (response code 0x921)")
	})
	wantError(t, err, "quote: the TPM refused the quote (response code 0x921)")
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

// fakeTPM answers one command with a prepared response and records what it was sent.
type fakeTPM struct {
	command  []byte
	response []byte
	chunk    int
}

func (f *fakeTPM) Write(p []byte) (int, error) {
	f.command = append([]byte(nil), p...)
	return len(p), nil
}
func (f *fakeTPM) Read(p []byte) (int, error) {
	n := len(f.response)
	if f.chunk > 0 && n > f.chunk {
		n = f.chunk
	}
	if n == 0 {
		return 0, io.EOF
	}
	n = copy(p, f.response[:n])
	f.response = f.response[n:]
	return n, nil
}

func quoteResponse(code uint32, attest, r, s []byte) []byte {
	parameters := append(sized(attest), 0x00, 0x18, 0x00, 0x0b)
	parameters = append(append(parameters, sized(r)...), sized(s)...)
	body := binary.BigEndian.AppendUint32(nil, code)
	tag := uint16(stSessions)
	if code != 0 {
		tag, parameters = 0x8001, nil
	} else {
		body = binary.BigEndian.AppendUint32(body, uint32(len(parameters)))
		parameters = append(parameters, 0, 0, 0, 0, 0) // the response's authorization area
	}
	body = append(body, parameters...)
	out := binary.BigEndian.AppendUint16(nil, tag)
	out = binary.BigEndian.AppendUint32(out, uint32(6+len(body)))
	return append(out, body...)
}

func TestTheQuoteCommandIsTheOneTheTPMSpecifies(t *testing.T) {
	qualifying := bytes.Repeat([]byte{0x5c}, 32)
	// TPM2_Quote(0x81010002, password session, 32 bytes, TPM_ALG_NULL, sha256:7,11), field by field from
	// Part 3 of the TPM 2.0 Library. That a TPM accepts it is shown on swtpm by e2e/peer-unlock-swtpm.sh.
	want := "8002" + "00000049" + "00000158" + "81010002" + "00000009" + "40000009" + "0000" + "00" + "0000" +
		"0020" + strings.Repeat("5c", 32) + "0010" + "00000001" + "000b" + "03" + "800800"
	device := &fakeTPM{response: quoteResponse(0, []byte("the attest structure"), []byte{0x01, 0x02}, []byte{0x80, 0x03}), chunk: 7}
	attest, signature, err := tpmQuote(device, qualifying, []int{7, 11})
	if err != nil || hex.EncodeToString(device.command) != want {
		t.Fatalf("command %x, error %v", device.command, err)
	}
	if string(attest) != "the attest structure" || hex.EncodeToString(signature) != "3009"+"02020102"+"0203008003" {
		t.Fatalf("attest %q, signature %x", attest, signature)
	}
	for _, c := range []struct {
		reason   string
		response []byte
	}{
		{"the TPM refused the quote (response code 0x921)", quoteResponse(0x921, nil, nil, nil)},
		{"the TPM's response is truncated", []byte{0x80, 0x02, 0, 0}},
		{"the TPM's response is truncated", quoteResponse(0, []byte("a"), []byte{1}, []byte{2})[:20]},
		{"the TPM's response is too long", append([]byte{0x80, 0x02, 0, 0, 0xff, 0xff}, make([]byte, 8)...)},
		{"the TPM's quote is malformed", quoteResponse(0, nil, []byte{1}, []byte{2})},
	} {
		_, _, err := tpmQuote(&fakeTPM{response: c.response}, qualifying, []int{7})
		wantError(t, err, c.reason)
	}
	_, _, err = tpmQuote(&fakeTPM{}, qualifying[:31], []int{7})
	wantError(t, err, "a quote needs 32 bytes")
	_, _, err = tpmQuote(&fakeTPM{}, qualifying, []int{24})
	wantError(t, err, "PCRs must be 0-23")
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
		"must be SHA-256 TPM Names":              func(c *bootConfig) { c.Peers[0].AKName = "000b" + strings.Repeat("ZZ", 32) },
	} {
		config := validConfig(porto)
		change(config)
		wantError(t, config.validate(), strings.TrimSpace(reason))
	}
	path := filepath.Join(t.TempDir(), "unlock.json")
	raw, _ := json.Marshal(validConfig(porto))
	_ = os.WriteFile(path, raw, 0o600)
	if loaded, err := loadBootConfig(path); err != nil || loaded.Peers[0].NodeID != "porto" {
		t.Fatal(err)
	}
	_ = os.WriteFile(path, []byte(strings.Replace(string(raw), `"device"`, `"extra":1,"device"`, 1)), 0o600)
	_, err := loadBootConfig(path)
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

func dialer(peers ...*fakePeer) func(string) transport {
	byEndpoint := map[string]*fakePeer{}
	for i, peer := range peers {
		byEndpoint[fmt.Sprintf("192.0.2.%d:7443", i+1)] = peer
	}
	return func(endpoint string) transport {
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

func TestEitherPeerGivesTheKeyAndWithoutOneTheDiskStaysLocked(t *testing.T) {
	porto, faro := newFakePeer(t, "porto"), newFakePeer(t, "faro")
	faro.contribution = bytes.Repeat([]byte{0x43}, 32)
	config, local := configFor(porto, faro), bytes.Repeat([]byte{0x11}, 32)
	paths, _ := pathsOf(t, tokensFor(porto, faro))
	var log bytes.Buffer
	slept := 0
	sleep := func(time.Duration) { slept++ }
	want := func(peer *fakePeer) string {
		key, _ := credential(local, peer.contribution, "lisbon", peer.id, 3)
		return string(key)
	}
	key, peer, slot, err := deriveKey(config, options{rounds: 3}, paths, local, testSession(t), dialer(porto, faro), noQuote, sleep, &log)
	if err != nil || peer != "porto" || slot != "1" || string(key) != want(porto) {
		t.Fatalf("%s %s %v", peer, slot, err)
	}
	// the first peer refuses: the second gives the key of its own keyslot
	porto.deny = "DENIED"
	key, peer, slot, err = deriveKey(config, options{rounds: 3}, paths, local, testSession(t), dialer(porto, faro), noQuote, sleep, &log)
	if err != nil || peer != "faro" || slot != "2" || string(key) != want(faro) || !strings.Contains(log.String(), "round 1, porto (path epoch 3): hello: the peer refused (DENIED)") {
		t.Fatalf("%s %s %v\n%s", peer, slot, err, log.String())
	}
	// no peer: bounded rounds, then locked; the session is not spent by any of it, and nothing secret is logged
	log.Reset()
	slept = 0
	boot := testSession(t)
	_, _, _, err = deriveKey(config, options{rounds: 3}, paths, local, boot, dialer(), noQuote, sleep, &log)
	wantError(t, err, "the disk stays locked: no peer helped in 3 rounds")
	if slept != 2 || strings.Count(log.String(), "the transport failed (no connection)") != 6 || boot.consumed {
		t.Fatalf("slept %d times, consumed=%v, log:\n%s", slept, boot.consumed, log.String())
	}
	if strings.Contains(log.String(), hex.EncodeToString(local)) || strings.Contains(log.String(), want(porto)) {
		t.Fatal("a secret reached the diagnostics")
	}
}

func TestTheNewestPathIsAskedFirstAndUnusableTokensAreReported(t *testing.T) {
	porto := newFakePeer(t, "porto")
	tokens := tokensFor(porto)
	tokens["5"] = token("porto", "5", 9) // a rotation: the new keyslot beside the old
	tokens["6"] = token("porto", "6", 4)
	tokens["6"].(map[string]any)["target"] = "faro"
	tokens["7"] = token("porto", "7", 4)
	tokens["7"].(map[string]any)["local"] = base64.StdEncoding.EncodeToString(make([]byte, 40)) // not sealed to the TPM alone
	tokens["8"] = token("porto", "8", 4)
	tokens["8"].(map[string]any)["note"] = "an unknown field"
	tokens["9"] = token("lisbon", "9", 4)
	tokens["10"] = token("porto", "1", 4)
	tokens["10"].(map[string]any)["keyslots"] = []string{"1", "2"}
	paths, skipped := pathsOf(t, tokens)
	local := bytes.Repeat([]byte{0x11}, 32)
	var log bytes.Buffer
	key, peer, slot, err := deriveKey(configFor(porto), options{rounds: 1}, paths, local, testSession(t), dialer(porto), noQuote, func(time.Duration) {}, &log)
	want, _ := credential(local, porto.contribution, "lisbon", "porto", 9)
	if err != nil || peer != "porto" || slot != "5" || porto.requests[1]["path_epoch"] != float64(9) || !bytes.Equal(key, want) {
		t.Fatalf("%s %s %v", peer, slot, err)
	}
	reported := strings.Join(skipped, "\n")
	for _, reason := range []string{"token 6: it is for node faro", "token 7: its local contribution is not a systemd credential sealed to the TPM alone",
		"token 8: it has unknown or malformed fields", "token 9: its target or peer is not a node ID", "token 10: it does not name exactly one keyslot"} {
		if !strings.Contains(reported, reason) {
			t.Fatalf("missing %q in:\n%s", reason, reported)
		}
	}
	// a disk with no path from any configured peer is not retried
	none, _ := pathsOf(t, map[string]any{})
	_, _, _, err = deriveKey(configFor(porto), options{rounds: 9}, none, local, testSession(t), dialer(porto), noQuote, func(time.Duration) { t.Fatal("it waited") }, &log)
	wantError(t, err, "it has no path from any peer of the boot configuration")
}

func TestTheKeyHandoffAndTheLocalHalf(t *testing.T) {
	// the key goes to the one connection on the socket; the local half comes from systemd's credentials
	directory, err := os.MkdirTemp("", "ru") // a short path: a UNIX socket address holds 108 bytes
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	address := &net.UnixAddr{Name: filepath.Join(directory, "key.sock"), Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	asker, err := net.DialUnix("unix", nil, address) // systemd-cryptsetup, waiting for its key
	if err != nil {
		t.Fatal(err)
	}
	defer asker.Close()
	if err := giveKey(listener, []byte("the derived credential"), time.Second); err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(asker); string(got) != "the derived credential" {
		t.Fatalf("the asker read %q", got)
	}
	wantError(t, giveKey(listener, []byte("k"), 50*time.Millisecond), "nobody asked for the key on the socket")
	// a run that fails answers the waiting connection with nothing, so it is not left waiting
	waiting, err := net.DialUnix("unix", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	defer waiting.Close()
	giveNothing(listener)
	_ = waiting.SetDeadline(time.Now().Add(2 * time.Second))
	if got, err := io.ReadAll(waiting); err != nil || len(got) != 0 {
		t.Fatalf("the waiting connection read %q, %v", got, err)
	}
	// not socket-activated: refused before anything else is done
	t.Setenv("LISTEN_FDS", "")
	_, err = activatedListener()
	wantError(t, err, "no socket was passed")
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_PID", "1") // passed to another process
	_, err = activatedListener()
	wantError(t, err, "no socket was passed")

	_, err = localContribution("")
	wantError(t, err, "no credentials directory")
	_, err = localContribution(directory)
	wantError(t, err, "is missing or is not 32 bytes")
	_ = os.WriteFile(filepath.Join(directory, localName), []byte("short"), 0o600)
	_, err = localContribution(directory)
	wantError(t, err, "is missing or is not 32 bytes")
	_ = os.WriteFile(filepath.Join(directory, localName), bytes.Repeat([]byte{7}, 32), 0o600)
	if local, err := localContribution(directory); err != nil || len(local) != 32 {
		t.Fatal(err)
	}
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
	send := tcpTransport(listener.Addr().String())
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

func TestTheCommandLine(t *testing.T) {
	var out, diagnostics bytes.Buffer
	wantError(t, run([]string{"-config", filepath.Join(t.TempDir(), "absent")}, &out, &diagnostics), "cannot read the boot configuration")
	wantError(t, run([]string{"-rounds", "0"}, &out, &diagnostics), "usage:")
	wantError(t, run([]string{"extra"}, &out, &diagnostics), "usage:")
	if err := run([]string{"-h"}, &out, &diagnostics); !errors.Is(err, errHelp()) || !strings.Contains(out.String(), "-config") {
		t.Fatalf("%v\n%s", err, out.String())
	}
	path := filepath.Join(t.TempDir(), "unlock.json")
	raw, _ := json.Marshal(validConfig(newFakePeer(t, "porto")))
	_ = os.WriteFile(path, raw, 0o600)
	t.Setenv("LISTEN_FDS", "")
	wantError(t, run([]string{"-config", path}, &out, &diagnostics), "no socket was passed")
}

func errHelp() error { return flag.ErrHelp }
