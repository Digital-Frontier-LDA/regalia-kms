package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
)

const bootSchema = "regalia.unlock-boot/v1"

var (
	plainPathPattern = regexp.MustCompile(`^[A-Za-z0-9/_.:=-]{1,255}$`)
	endpointPattern  = regexp.MustCompile(`^[A-Za-z0-9.:\[\]-]{1,255}:[0-9]{1,5}$`)
)

// pin is what the node holds about one peer before root: where to reach it, and the Names of its EK
// and AK from the last manifest the node saw.
type pin struct {
	NodeID   string `json:"node_id"`
	Endpoint string `json:"endpoint"`
	EKName   string `json:"ek_name"`
	AKName   string `json:"ak_name"`
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
	if err := decoder.Decode(&config); err != nil || decoder.More() {
		return nil, errors.New("the boot configuration is not the expected JSON object")
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &config, nil
}

func (c *bootConfig) validate() error {
	switch {
	case c.Schema != bootSchema:
		return errors.New("the boot configuration's schema must be " + bootSchema)
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
		case seen[peer.NodeID]:
			return fmt.Errorf("peer %s is listed twice, or is the node itself", peer.NodeID)
		case !endpointPattern.MatchString(peer.Endpoint):
			return errors.New("a peer's endpoint must be host:port")
		case !namePattern.MatchString(peer.EKName) || !namePattern.MatchString(peer.AKName):
			return errors.New("a peer's ek_name and ak_name must be SHA-256 TPM Names")
		}
		seen[peer.NodeID] = true
	}
	return nil
}
