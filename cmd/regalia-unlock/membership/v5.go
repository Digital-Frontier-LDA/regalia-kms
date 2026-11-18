package membership

import (
	"encoding/json"
	"math/big"
)

// Schema v5 (regalia-kms-dx7.1, docs/design/single-node.md 4.1), as membership.py has it ("Schema v5" in its
// docstring): v4's fields and topology, the cluster's DESIGNED size, chosen at genesis and never inferred from how many
// nodes are live. {"profile": "multi-node", "nodes": 3} or {"profile": "single-node", "nodes": 1,
// "single_node_limits_sha256": <64 hex>}. The signer floors are floor(nodes/2)+1 of the designed nodes (2 for v4, a
// three-node cluster); single-node has exactly one live node and one shape of rules; no signer changes the topology.

const (
	SchemaV5        = "regalia.membership/v5"
	singleNode      = "single-node"
	multiNode       = "multi-node"
	v4DesignedNodes = 3 // a v4 manifest predates topology: a three-node cluster
)

var (
	json1, json3        = json.Number("1"), json.Number("3")
	v5ManifestKeys      = append(append([]string(nil), v4ManifestKeys...), "topology")
	supportedMultiNodes = []int64{3} // 5 and 7 are their own epic (regalia-kms-dx7.12)
)

// quorumSchema is membership.QUORUM_SCHEMAS: the nodes and the owner sign. What v4 reads, v5 reads alike.
func quorumSchema(schema any) bool { return schema == SchemaV4 || schema == SchemaV5 }

// designedNodes is membership.designed_nodes: a v5 manifest's topology.nodes, three for v4. Call it on a manifest
// whose topology has been validated.
func designedNodes(manifest map[string]any) *big.Int {
	if manifest["schema"] != SchemaV5 {
		return big.NewInt(v4DesignedNodes)
	}
	n, _ := integer(manifest["topology"].(map[string]any)["nodes"])
	return n
}

// nodeFloor is membership.node_floor: a majority of the designed nodes.
func nodeFloor(manifest map[string]any) *big.Int {
	n := designedNodes(manifest)
	return new(big.Int).Add(new(big.Int).Rsh(n, 1), big.NewInt(1))
}

// topology is membership._topology: the field, and the nodes that are not RETIRED or REVOKED_STOLEN against it.
func topology(manifest map[string]any, byID map[string]map[string]any) ([]string, error) {
	object, ok := manifest["topology"].(map[string]any)
	if !ok {
		return nil, refuse("topology must be an object")
	}
	profile, _ := object["profile"].(string)
	if _, isString := object["profile"].(string); !isString || (profile != singleNode && profile != multiNode) {
		return nil, refuse("topology.profile must be %s or %s", singleNode, multiNode)
	}
	keys := []string{"profile", "nodes"}
	if profile == singleNode {
		keys = append(keys, "single_node_limits_sha256")
	}
	if _, err := exact(object, keys, "topology"); err != nil {
		return nil, err
	}
	n, isInt := integer(object["nodes"])
	if !isInt {
		return nil, refuse("topology.nodes must be an integer")
	}
	var live []string
	for id, node := range byID {
		if !terminal[node["state"].(string)] {
			live = append(live, id)
		}
	}
	if profile == singleNode {
		if n.Cmp(big.NewInt(1)) != 0 {
			return nil, refuse("a single-node topology has nodes 1, not %d", n)
		}
		if err := hexField(object["single_node_limits_sha256"], 64, "topology.single_node_limits_sha256"); err != nil {
			return nil, err
		}
		// none once the owner has revoked it (REVOKED_STOLEN): the KMS is stopped until the root enrols a replacement
		if len(live) > 1 {
			return nil, refuse("a single-node topology lists at most one node that is not RETIRED or REVOKED_STOLEN (%d)", len(live))
		}
		return live, nil
	}
	if n.Cmp(big.NewInt(3)) < 0 || n.Bit(0) == 0 {
		return nil, refuse("a multi-node topology has an odd number of nodes from 3, not %d (an even size has no majority that "+
			"survives a loss)", n)
	}
	supported := false
	for _, s := range supportedMultiNodes {
		supported = supported || n.Cmp(big.NewInt(s)) == 0
	}
	if !supported {
		return nil, refuse("a multi-node topology of %d nodes is not supported yet (3 only; 5 and 7 are regalia-kms-dx7.12)", n)
	}
	if big.NewInt(int64(len(live))).Cmp(n) > 0 {
		return nil, refuse("a %d-node topology lists at most %d nodes that are not RETIRED or REVOKED_STOLEN (%d)", n, n, len(live))
	}
	return live, nil
}

// singleNodeRules is membership._single_node_rules: the node alone signs its heartbeats and its activation, the owner
// alone revokes. The node is the live one; with none (the owner revoked it), the one node of the manifest the heartbeat
// rule names.
func singleNodeRules(manifest map[string]any, live []string, byID map[string]map[string]any) error {
	id := ""
	if len(live) == 1 {
		id = live[0]
	} else if named, _ := manifest["heartbeat_signers"].(map[string]any)["parties"].([]any); len(named) == 1 {
		if name, isString := named[0].(string); isString {
			if _, node := byID[name]; node {
				id = name
			}
		}
	}
	shown := id
	if id == "" {
		shown = "the node"
	}
	alone := map[string]any{"threshold": json1, "parties": []any{id}}
	for _, name := range singleRules {
		if id == "" || !equal(manifest[name], alone) {
			return refuse("under %s %s is {threshold 1, parties [%s]}", singleNode, name, shown)
		}
	}
	owner := []any{map[string]any{"threshold": json1, "parties": []any{ownerParty}}}
	if !equal(manifest["revocation_signers"], owner) {
		return refuse("under %s revocation_signers is [{threshold 1, parties [%s]}]", singleNode, ownerParty)
	}
	return nil
}

// topologyRules is membership._topology_rules: set at genesis and never changed, by any signer, the root included; a
// v1-v4 chain is a three-node cluster, and its root-signed move to v5 says so.
func topologyRules(current, candidate map[string]any) error {
	if current["schema"] == SchemaV5 {
		if !equal(candidate["topology"], current["topology"]) {
			return refuse("topology is set at genesis and never changes, for any signer: another size or profile is a new genesis")
		}
		return nil
	}
	three := map[string]any{"profile": multiNode, "nodes": json3}
	if !equal(candidate["topology"], three) {
		return refuse("a %s chain is a three-node cluster: its move to %s names the topology {%s, %d nodes} (one node is a new genesis)",
			current["schema"], SchemaV5, multiNode, v4DesignedNodes)
	}
	return nil
}
