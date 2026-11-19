package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The owner as the one peer of a single-node host (regalia-kms-dx7.5; deploy/baremetal/ownerunlock.py): the same
// exchange, the response signed by an owner key that the single-node boot configuration holds.

func ownerKeyPair(t *testing.T, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat(string([]byte{seed}), 32)))
	return key.Public().(ed25519.PublicKey), key
}

// singleConfig is a single-node boot configuration: one peer, the owner, and these owner keys.
func singleConfig(keys ...ed25519.PublicKey) *bootConfig {
	config := &bootConfig{Schema: bootSingleSchema, Topology: singleNode, NodeID: "alder", Device: "/dev/disk/by-partlabel/root", PCRs: []int{7, 11},
		Peers: []pin{{NodeID: ownerPeer, Endpoint: "192.0.2.9:7443"}}}
	for _, k := range keys {
		config.OwnerKeys = append(config.OwnerKeys, ownerKey{Alg: "ed25519", Key: hex.EncodeToString(k)})
	}
	return config
}

// singleJSON is what unlock.boot_config writes for a single-node host.
func singleJSON(keys ...ed25519.PublicKey) string {
	var owners []string
	for _, k := range keys {
		owners = append(owners, `{"alg":"ed25519","key":"`+hex.EncodeToString(k)+`"}`)
	}
	return `{"device":"/dev/disk/by-partlabel/root","node_id":"alder","owner_keys":[` + strings.Join(owners, ",") +
		`],"pcrs":[7,11],"peers":[{"endpoint":"192.0.2.9:7443","node_id":"owner"}],"schema":"regalia.unlock-boot/v2","topology":"single-node"}`
}

// ownerSend is the owner's machine (OwnerPeer), from a fake peer named "owner": its reply's signature is replaced by
// an owner key's over the response; `change` edits the reply after that.
func ownerSend(t *testing.T, p *fakePeer, key ed25519.PrivateKey, change func(map[string]any)) transport {
	return func(request []byte) ([]byte, error) {
		raw, err := p.send(request)
		if err != nil {
			return nil, err
		}
		var reply map[string]any
		if err := json.Unmarshal(raw, &reply); err != nil {
			t.Fatal(err)
		}
		if body, has := reply["response"]; has {
			encoded, _ := json.Marshal(body)
			var r response
			if err := json.Unmarshal(encoded, &r); err != nil {
				t.Fatal(err)
			}
			sig := ed25519.Sign(key, append([]byte(ownerResponseDomain), r.canonical()...))
			reply["signature"] = map[string]any{"alg": "ed25519", "key": hex.EncodeToString(key.Public().(ed25519.PublicKey)), "sig": hex.EncodeToString(sig)}
			if change != nil {
				change(reply)
			}
		}
		return json.Marshal(reply)
	}
}

func loadText(t *testing.T, text string) (*bootConfig, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "unlock.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return loadBootConfig(path)
}

func TestTheOwnerIsThePeerOnlyUnderASingleNodeBootConfiguration(t *testing.T) {
	public, private := ownerKeyPair(t, 1)
	config, err := loadText(t, singleJSON(public))
	if err != nil {
		t.Fatal(err)
	}
	owner := config.Peers[0]
	if owner.NodeID != ownerPeer || len(owner.owner) != 1 {
		t.Fatalf("the owner pin was not given the owner keys: %+v", owner)
	}
	peer := newFakePeer(t, ownerPeer)
	boot := testSession(t)
	got, err := boot.ask(owner, 1, ownerSend(t, peer, private, nil), noQuote)
	if err != nil || string(got) != string(peer.contribution) || !boot.consumed {
		t.Fatalf("the owner's valid response was not taken: %v", err)
	}

	// a multi-node (v1) configuration never lists the owner, and keeps 1 to 8 node peers
	birch := newFakePeer(t, "birch")
	v1 := validConfig(birch)
	v1.Peers = append(v1.Peers, pin{NodeID: ownerPeer, Endpoint: "192.0.2.9:7443", EKName: birch.pin().EKName, AKName: birch.pin().AKName})
	wantError(t, v1.validate(), "the owner is a peer only in a single-node boot configuration")
	v1 = validConfig()
	wantError(t, v1.validate(), "peers must list 1 to 8 peers")
	nine := validConfig()
	for _, id := range []string{"b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9"} {
		nine.Peers = append(nine.Peers, newFakePeer(t, id).pin())
	}
	wantError(t, nine.validate(), "peers must list 1 to 8 peers")
	// a node pin of a v1 configuration has no owner keys: its response is judged as a TPM's, never as an owner's
	if loaded, err := loadText(t, mustJSON(t, validConfig(birch))); err != nil || loaded.Peers[0].owner != nil {
		t.Fatalf("a v1 pin got owner keys: %v", err)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestTheSingleNodeBootConfigurationIsRefusedUnlessExact(t *testing.T) {
	one, _ := ownerKeyPair(t, 1)
	two, _ := ownerKeyPair(t, 2)
	if err := singleConfig(one, two).validate(); err != nil {
		t.Fatal(err)
	}
	for reason, change := range map[string]func(*bootConfig){
		"is for the single-node topology":          func(c *bootConfig) { c.Topology = "multi-node" },
		"exactly one peer, the owner":              func(c *bootConfig) { c.Peers[0].NodeID = "birch" },
		"exactly one peer, the owner ":             func(c *bootConfig) { c.Peers = append(c.Peers, c.Peers[0]) },
		"exactly one peer, the owner  ":            func(c *bootConfig) { c.Peers = nil },
		"the owner peer has no TPM Names":          func(c *bootConfig) { c.Peers[0].EKName = "000b" + strings.Repeat("11", 32) },
		"a peer's endpoint must be host:port":      func(c *bootConfig) { c.Peers[0].Endpoint = "owner.boot" },
		"owner_keys must list 1 to 8 keys":         func(c *bootConfig) { c.OwnerKeys = nil },
		"owner_keys[1] is listed twice":            func(c *bootConfig) { c.OwnerKeys[1] = c.OwnerKeys[0] },
		"owner_keys[0] must be an ed25519 key":     func(c *bootConfig) { c.OwnerKeys[0].Alg = "ecdsa-p256" },
		"owner_keys[0].key must be 64 lowercase":   func(c *bootConfig) { c.OwnerKeys[0].Key = strings.ToUpper(c.OwnerKeys[0].Key) },
		"owner_keys[0].key must be 64 lowercase ":  func(c *bootConfig) { c.OwnerKeys[0].Key = c.OwnerKeys[0].Key[:62] },
		"node_id is not a node ID":                 func(c *bootConfig) { c.NodeID = ownerPeer },
		"pcrs must be an ascending list":           func(c *bootConfig) { c.PCRs = []int{11, 7} },
		"device must be a plain path":              func(c *bootConfig) { c.Device = "/dev/sda3; reboot" },
		"schema must be regalia.unlock-boot/v1 or": func(c *bootConfig) { c.Schema = "regalia.unlock-boot/v3" },
	} {
		config := singleConfig(one, two)
		change(config)
		wantError(t, config.validate(), strings.TrimSpace(reason))
	}
	nine := singleConfig()
	for i := byte(1); i <= 9; i++ {
		k, _ := ownerKeyPair(t, i)
		nine.OwnerKeys = append(nine.OwnerKeys, ownerKey{Alg: "ed25519", Key: hex.EncodeToString(k)})
	}
	wantError(t, nine.validate(), "owner_keys must list 1 to 8 keys")
	// a v1 configuration with the single-node fields is not read as either kind
	withOwners := validConfig(newFakePeer(t, "birch"))
	withOwners.OwnerKeys = singleConfig(one).OwnerKeys
	wantError(t, withOwners.validate(), "only a regalia.unlock-boot/v2 boot configuration has a topology and owner_keys")
	// the member names are exact for the schema: an owner pin with TPM Names, a v1 file with owner_keys, an unknown member
	good := singleJSON(one)
	for _, text := range []string{
		strings.Replace(good, `"node_id":"owner"}`, `"node_id":"owner","ek_name":"","ak_name":""}`, 1),
		strings.Replace(good, `"topology":"single-node"`, `"topology":"single-node","extra":1`, 1),
		strings.Replace(good, `,"topology":"single-node"`, "", 1),
		strings.Replace(mustJSON(t, validConfig(newFakePeer(t, "birch"))), `"schema":"regalia.unlock-boot/v1"`,
			`"schema":"regalia.unlock-boot/v1","owner_keys":[]`, 1),
	} {
		if _, err := loadText(t, text); err == nil {
			t.Fatalf("accepted %s", text)
		}
	}
	if _, err := loadText(t, good); err != nil {
		t.Fatal(err)
	}
}

func TestAnOwnerResponseIsRefusedUnlessSignedByAnOwnerKeyOverIt(t *testing.T) {
	public, private := ownerKeyPair(t, 1)
	_, stranger := ownerKeyPair(t, 3)
	config := singleConfig(public)
	if err := config.validate(); err != nil {
		t.Fatal(err)
	}
	owner := config.Peers[0]
	peer := newFakePeer(t, ownerPeer)
	for reason, send := range map[string]transport{
		"not signed by one of the owner_keys": ownerSend(t, peer, stranger, nil),
		"does not verify over this response": ownerSend(t, peer, private, func(r map[string]any) {
			r["response"].(map[string]any)["manifest_digest"] = strings.Repeat("ee", 32)
		}),
		"not signed with ed25519":            ownerSend(t, peer, private, func(r map[string]any) { r["signature"].(map[string]any)["alg"] = "ecdsa-p256" }),
		"the owner's signature is malformed": ownerSend(t, peer, private, func(r map[string]any) { r["signature"].(map[string]any)["sig"] = "ZZ" }),
		// a TPM's signature in the owner's place: the owner pin is never judged as a node's
		"the owner's signature is malformed ":  peer.send,
		"the owner's signature is malformed  ": ownerSend(t, peer, private, func(r map[string]any) { r["signature"].(map[string]any)["extra"] = "1" }),
	} {
		boot := testSession(t)
		_, err := boot.ask(owner, 1, send, noQuote)
		wantError(t, err, strings.TrimSpace(reason))
		if boot.consumed {
			t.Fatalf("%s: a refused response spent the session", reason)
		}
	}
	// and an owner key's signature is no TPM signature: a node pin refuses it
	birch := newFakePeer(t, "birch")
	boot := testSession(t)
	_, err := boot.ask(birch.pin(), 1, ownerSend(t, birch, private, nil), noQuote)
	wantError(t, err, "the response's signature is malformed")
}

func TestTheOwnerSignatureAgreesWithThePythonOnThePublishedVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "unlock-owner-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Seed      string   `json:"seed"`
		Public    string   `json:"public"`
		Domain    string   `json:"domain"`
		Response  response `json:"response"`
		Canonical string   `json:"canonical"`
		Signature string   `json:"signature"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(vector.Seed)
	key := ed25519.NewKeyFromSeed(seed)
	if hex.EncodeToString(key.Public().(ed25519.PublicKey)) != vector.Public || ownerResponseDomain != vector.Domain {
		t.Fatal("the vector's key or domain is not this client's")
	}
	if string(vector.Response.canonical()) != vector.Canonical {
		t.Fatalf("canonical bytes differ:\n%s\n%s", vector.Response.canonical(), vector.Canonical)
	}
	if got := hex.EncodeToString(ed25519.Sign(key, append([]byte(ownerResponseDomain), vector.Response.canonical()...))); got != vector.Signature {
		t.Fatalf("the signature is not the Python's: %s", got)
	}
	signature, _ := json.Marshal(ownerSignature{Alg: "ed25519", Key: vector.Public, Sig: vector.Signature})
	if err := verifyOwnerSignature(signature, []ed25519.PublicKey{key.Public().(ed25519.PublicKey)}, vector.Response.canonical()); err != nil {
		t.Fatal(err)
	}
}
