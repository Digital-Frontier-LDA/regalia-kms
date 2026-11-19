package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	bootSchema = "regalia.unlock-boot/v1"
	// bootSingleSchema is unlock.BOOT_SINGLE_SCHEMA (regalia-kms-dx7.5): a single-node host's configuration, whose one
	// peer is the owner, checked by the manifest's owner_keys instead of a TPM's EK and AK Names.
	bootSingleSchema = "regalia.unlock-boot/v2"
	singleNode       = "single-node" // membership.SINGLE_NODE
	ownerPeer        = "owner"       // membership.OWNER: the owner's name as a peer, never a node ID
	maxOwnerKeys     = 8
)

var (
	bootKeys       = []string{"schema", "node_id", "device", "pcrs", "peers"}
	bootSingleKeys = []string{"schema", "topology", "node_id", "device", "pcrs", "peers", "owner_keys"}
	pinKeys        = []string{"node_id", "endpoint", "ek_name", "ak_name"}
	ownerPinKeys   = []string{"node_id", "endpoint"}
)

var (
	plainPathPattern = regexp.MustCompile(`^[A-Za-z0-9/_.:=-]{1,255}$`)
	// a host name or IPv4 address, or an IPv6 address in brackets; then a port
	endpointPattern = regexp.MustCompile(`^(\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9.-]{1,253}):([0-9]{1,5})$`)
)

func validEndpoint(endpoint string) bool {
	parts := endpointPattern.FindStringSubmatch(endpoint)
	if parts == nil {
		return false
	}
	port, _ := strconv.Atoi(parts[2])
	return port >= 1 && port <= 65535
}

// pin is what the node holds about one peer before root: where to reach it, and the Names of its EK
// and AK from the last manifest the node saw.
type pin struct {
	NodeID   string `json:"node_id"`
	Endpoint string `json:"endpoint"`
	EKName   string `json:"ek_name"`
	AKName   string `json:"ak_name"`
	// owner holds the owner_keys of a single-node configuration, set by validate on its one pin (the owner's) and on
	// no other: a response from this peer is then checked by an owner key, never by a TPM signature.
	owner []ed25519.PublicKey
}

// ownerKey is one of the owner_keys a single-node configuration holds (the manifest's Ed25519 owner keys).
type ownerKey struct {
	Alg string `json:"alg"`
	Key string `json:"key"`
}

// bootConfig is unlock.boot_config: written beside the kernel after every manifest the node accepts.
// It is public data. A stale or forged entry costs that one path: a peer can only give its own half
// of the credential, and the wrong half opens no keyslot.
type bootConfig struct {
	Schema string `json:"schema"`
	NodeID string `json:"node_id"`
	Device string `json:"device"`
	PCRs   []int  `json:"pcrs"`
	Peers  []pin  `json:"peers"`
	// single-node only (bootSingleSchema)
	Topology  string     `json:"topology,omitempty"`
	OwnerKeys []ownerKey `json:"owner_keys,omitempty"`
}

// exactKeys refuses an object whose member names are not exactly `keys`, each once and spelled exactly (Go's decoder
// matches names without regard to case and keeps the last of two equal ones; the reference client does neither): a v1
// configuration with owner_keys, an owner pin with an EK Name, `"ALG"` for `"alg"`, or a member given twice, is refused
// rather than read as something else. It returns the members.
func exactKeys(raw json.RawMessage, keys []string) (map[string]json.RawMessage, error) {
	mismatch := errors.New("fields mismatch")
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if open, err := decoder.Token(); err != nil || open != json.Delim('{') {
		return nil, mismatch
	}
	want, members := map[string]bool{}, map[string]json.RawMessage{}
	for _, k := range keys {
		want[k] = true
	}
	for decoder.More() {
		name, err := decoder.Token()
		key, isString := name.(string)
		if err != nil || !isString || !want[key] {
			return nil, mismatch
		}
		if _, twice := members[key]; twice {
			return nil, mismatch
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, mismatch
		}
		members[key] = value
	}
	if len(members) != len(keys) {
		return nil, mismatch
	}
	return members, nil
}

// integers refuses a PCR list whose elements are not all JSON integers: Go would decode a null as PCR 0.
func integers(raw json.RawMessage) error {
	var elements []json.RawMessage
	if err := json.Unmarshal(raw, &elements); err != nil {
		return errors.New("not a list")
	}
	for _, e := range elements {
		text := string(bytes.TrimSpace(e))
		if text == "" || strings.ContainsAny(text, ".eE") || (text[0] != '-' && (text[0] < '0' || text[0] > '9')) {
			return errors.New("not an integer")
		}
	}
	return nil
}

// shapeOf checks the member names of the configuration and of each peer for its schema, before the strict decoding.
func shapeOf(raw []byte) error {
	var head struct {
		Schema string            `json:"schema"`
		Peers  []json.RawMessage `json:"peers"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return errors.New("the boot configuration is not the expected JSON object")
	}
	keys, peer := bootKeys, pinKeys
	if head.Schema == bootSingleSchema {
		keys, peer = bootSingleKeys, ownerPinKeys
	}
	refused := errors.New("the boot configuration is not the expected JSON object")
	members, err := exactKeys(raw, keys)
	if err != nil {
		return refused
	}
	if integers(members["pcrs"]) != nil {
		return errors.New("pcrs must be an ascending list of PCR indices 0-23")
	}
	for _, p := range head.Peers {
		if _, err := exactKeys(p, peer); err != nil {
			return refused
		}
	}
	if head.Schema == bootSingleSchema {
		var owners []json.RawMessage
		if json.Unmarshal(members["owner_keys"], &owners) != nil {
			return refused
		}
		for _, o := range owners {
			if _, err := exactKeys(o, []string{"alg", "key"}); err != nil {
				return refused
			}
		}
	}
	return nil
}

func loadBootConfig(path string) (*bootConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read the boot configuration %s", path)
	}
	if len(raw) > maxMessage {
		return nil, errors.New("the boot configuration is too long")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config bootConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, errors.New("the boot configuration is not the expected JSON object")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("the boot configuration has trailing data")
	}
	// one JSON object with known members and nothing after it: now its members must be exactly its schema's
	if err := shapeOf(raw); err != nil {
		return nil, err
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &config, nil
}

func (c *bootConfig) validate() error {
	switch {
	case c.Schema == bootSingleSchema:
		return c.validateSingle()
	case c.Schema != bootSchema:
		return errors.New("the boot configuration's schema must be " + bootSchema + " or " + bootSingleSchema)
	case c.Topology != "" || c.OwnerKeys != nil:
		return errors.New("only a " + bootSingleSchema + " boot configuration has a topology and owner_keys")
	case !nodeIDPattern.MatchString(c.NodeID):
		return errors.New("node_id is not a node ID")
	case !plainPathPattern.MatchString(c.Device):
		return errors.New("device must be a plain path")
	case len(c.PCRs) == 0 || !sort.IntsAreSorted(c.PCRs):
		return errors.New("pcrs must be an ascending list of PCR indices 0-23")
	case len(c.Peers) < 1 || len(c.Peers) > 8:
		return errors.New("peers must list 1 to 8 peers")
	}
	for i, pcr := range c.PCRs {
		if pcr < 0 || pcr > 23 || i > 0 && pcr == c.PCRs[i-1] {
			return errors.New("pcrs must be an ascending list of PCR indices 0-23")
		}
	}
	seen := map[string]bool{c.NodeID: true}
	for _, peer := range c.Peers {
		switch {
		case !nodeIDPattern.MatchString(peer.NodeID):
			return errors.New("a peer's node_id is not a node ID")
		case peer.NodeID == ownerPeer:
			return errors.New("the owner is a peer only in a single-node boot configuration (" + bootSingleSchema + ")")
		case peer.owner != nil:
			return errors.New("a peer of a multi-node boot configuration has no owner keys")
		case seen[peer.NodeID]:
			return fmt.Errorf("peer %s is listed twice, or is the node itself", peer.NodeID)
		case !validEndpoint(peer.Endpoint):
			return errors.New("a peer's endpoint must be host:port, an IPv6 address in brackets, the port 1-65535")
		case !namePattern.MatchString(peer.EKName) || !namePattern.MatchString(peer.AKName):
			return errors.New("a peer's ek_name and ak_name must be SHA-256 TPM Names")
		}
		seen[peer.NodeID] = true
	}
	return nil
}

// validateSingle is the single-node half of validate (unlock.validate_boot_config): exactly one peer, the owner, at a
// valid endpoint and with no TPM Names, and one to eight distinct Ed25519 owner keys, which it is given.
func (c *bootConfig) validateSingle() error {
	switch {
	case c.Topology != singleNode:
		return errors.New("a " + bootSingleSchema + " boot configuration is for the " + singleNode + " topology")
	case !nodeIDPattern.MatchString(c.NodeID) || c.NodeID == ownerPeer:
		return errors.New("node_id is not a node ID")
	case !plainPathPattern.MatchString(c.Device):
		return errors.New("device must be a plain path")
	case len(c.PCRs) == 0 || !sort.IntsAreSorted(c.PCRs):
		return errors.New("pcrs must be an ascending list of PCR indices 0-23")
	case len(c.Peers) != 1 || c.Peers[0].NodeID != ownerPeer:
		return errors.New("a single-node boot configuration lists exactly one peer, the owner")
	case !validEndpoint(c.Peers[0].Endpoint):
		return errors.New("a peer's endpoint must be host:port, an IPv6 address in brackets, the port 1-65535")
	case c.Peers[0].EKName != "" || c.Peers[0].AKName != "":
		return errors.New("the owner peer has no TPM Names")
	case len(c.OwnerKeys) < 1 || len(c.OwnerKeys) > maxOwnerKeys:
		return fmt.Errorf("owner_keys must list 1 to %d keys", maxOwnerKeys)
	}
	for i, pcr := range c.PCRs {
		if pcr < 0 || pcr > 23 || i > 0 && pcr == c.PCRs[i-1] {
			return errors.New("pcrs must be an ascending list of PCR indices 0-23")
		}
	}
	keys, seen := make([]ed25519.PublicKey, 0, len(c.OwnerKeys)), map[string]bool{}
	for i, k := range c.OwnerKeys {
		raw, err := lowerHex(k.Key)
		switch {
		case k.Alg != "ed25519":
			return fmt.Errorf("owner_keys[%d] must be an ed25519 key", i)
		case err != nil || len(raw) != ed25519.PublicKeySize:
			return fmt.Errorf("owner_keys[%d].key must be 64 lowercase hex", i)
		case seen[k.Key]:
			return fmt.Errorf("owner_keys[%d] is listed twice", i)
		}
		seen[k.Key] = true
		keys = append(keys, ed25519.PublicKey(raw))
	}
	c.Peers[0].owner = keys
	return nil
}
