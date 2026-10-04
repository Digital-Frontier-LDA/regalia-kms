package openbaopoc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type baoHANode struct {
	dir, config string
	api         baoAPI
	process     *baoProcess
}

func (n *baoHANode) waitMember(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-n.process.done:
			t.Fatal("HA node exited before becoming an unsealed member")
		default:
		}
		status, body, err := n.api.call(http.MethodGet, "/v1/sys/health", nil)
		var health struct {
			Initialized bool `json:"initialized"`
			Sealed      bool `json:"sealed"`
		}
		if err == nil && json.Unmarshal(body, &health) == nil && health.Initialized && !health.Sealed && (status == 200 || status == 429) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("HA node did not become an unsealed active/standby member")
}

func waitHALeader(t *testing.T, nodes []*baoHANode) int {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		leader, count := -1, 0
		for i, n := range nodes {
			if n.process.stopped {
				continue
			}
			status, body, err := n.api.call(http.MethodGet, "/v1/sys/leader", nil)
			var state struct {
				HAEnabled bool `json:"ha_enabled"`
				IsSelf    bool `json:"is_self"`
			}
			if err == nil && status == 200 && json.Unmarshal(body, &state) == nil && state.HAEnabled && state.IsSelf {
				leader, count = i, count+1
			}
		}
		if count == 1 {
			status, _, err := nodes[leader].api.call(http.MethodGet, "/v1/sys/health", nil)
			if err == nil && status == 200 {
				return leader
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("HA cluster did not expose exactly one active leader")
	return -1
}

func waitHAPeers(t *testing.T, leader baoAPI, nodes []*baoHANode) {
	t.Helper()
	var result struct {
		Data struct {
			Config struct {
				Servers []struct {
					ID     string `json:"node_id"`
					Voter  bool   `json:"voter"`
					Leader bool   `json:"leader"`
				} `json:"servers"`
			} `json:"config"`
		} `json:"data"`
	}
	// Autopilot initially admits joining nodes as non-voters. Do not kill the
	// leader until the actual configuration has promoted all three voters.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		body := leader.must(t, http.MethodGet, "/v1/sys/storage/raft/configuration", nil)
		if json.Unmarshal(body, &result) != nil {
			t.Fatal("malformed Raft membership response")
		}
		expected := make(map[string]bool, len(nodes))
		for _, n := range nodes {
			expected[filepath.Base(n.dir)] = true
		}
		leaders, voters := 0, 0
		for _, server := range result.Data.Config.Servers {
			if !expected[server.ID] {
				t.Fatal("unexpected or duplicate Raft member")
			}
			delete(expected, server.ID)
			if server.Leader {
				leaders++
			}
			if server.Voter {
				voters++
			}
		}
		if len(expected) == 0 && leaders == 1 && voters == len(nodes) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("Raft did not establish exactly three voters and one leader")
}

func crashBao(t *testing.T, p *baoProcess) {
	t.Helper()
	if err := p.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.done:
	case <-time.After(10 * time.Second):
		t.Fatal("killed HA node did not exit")
	}
	p.stopped = true
	_ = p.log.Close()
}

func crashHAPlugin(t *testing.T, n *baoHANode) {
	t.Helper()
	executable := filepath.Join(n.dir, "openbao-plugin-kms-regalia-poc")
	children := pluginChildren(t, n.process, executable)
	if len(children) == 0 {
		t.Fatal("no live plugin on the active HA node")
	}
	old := make(map[int]bool, len(children))
	for _, pid := range children {
		old[pid] = true
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		for _, pid := range pluginChildren(t, n.process, executable) {
			if !old[pid] {
				n.waitMember(t)
				n.api.assertValue(t)
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("HA node did not respawn its killed plugin")
}

func assertHAValue(t *testing.T, api baoAPI, name string) {
	t.Helper()
	var result struct {
		Data struct {
			Data struct {
				Value string `json:"value"`
			} `json:"data"`
		} `json:"data"`
	}
	// A successful commit does not mean every follower has applied the new
	// entry. Poll only a missing read, never the write or an authorization error.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		status, body, err := api.call(http.MethodGet, "/v1/poc/data/"+name, nil)
		if err != nil || (status != 200 && status != 404) {
			t.Fatalf("HA value read failed (status %d); response omitted", status)
		}
		if status == 200 {
			if json.Unmarshal(body, &result) != nil || result.Data.Data.Value != syntheticValue {
				t.Fatal("HA value read returned an invalid response or different value")
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("HA write did not become readable within the replication deadline")
}

func writeHAValue(t *testing.T, api baoAPI, name string) {
	t.Helper()
	// Write once, with CAS=0, to a new path at every stage. Polling/retrying a
	// mutation could hide ambiguity or an unavailable Raft write quorum.
	api.must(t, http.MethodPost, "/v1/poc/data/"+name, map[string]any{"data": map[string]string{"value": syntheticValue}, "options": map[string]int{"cas": 0}})
	assertHAValue(t, api, name)
}

func TestOpenBao271NativeThreeNodeHA(t *testing.T) {
	binary, dir, plugin, sum := baoTestEnvironmentFor(t, "openbao-plugin-kms-regalia")
	f := newKMSFixtureMode(t, true)
	digest := hex.EncodeToString(sum[:])
	var nodes []*baoHANode
	for i := range 3 {
		nodeDir := filepath.Join(dir, fmt.Sprintf("node-%d", i))
		if err := os.Mkdir(nodeDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(nodeDir, "openbao-plugin-kms-regalia-poc"), plugin, 0o700); err != nil {
			t.Fatal(err)
		}
		address := freeAddress(t)
		n := &baoHANode{dir: nodeDir, config: baoConfig(t, nodeDir, address, freeAddress(t), digest, nativeFixtureConfig(f.pki.config))}
		// A redirect must not disguise a failed node as another node's success.
		n.api = baoAPI{base: "http://" + address, client: &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
		n.process = startBao(t, binary, n.config, n.dir)
		n.api.wait(t, false, true, n.process)
		nodes = append(nodes, n)
	}
	share := nodes[0].api.initialize(t)
	nodes[0].api.seedSyntheticKV(t)
	for _, n := range nodes[1:] {
		n.api.must(t, http.MethodPost, "/v1/sys/storage/raft/join", map[string]any{"leader_api_addr": nodes[0].api.base})
		n.api.token = nodes[0].api.token
		n.waitMember(t)
		n.api.assertValue(t)
	}
	leader := waitHALeader(t, nodes)
	waitHAPeers(t, nodes[leader].api, nodes)
	started := time.Now()
	crashBao(t, nodes[leader].process)
	newLeader := waitHALeader(t, nodes)
	if newLeader == leader {
		t.Fatal("failed node remained the active leader")
	}
	nodes[newLeader].api.assertValue(t)
	writeHAValue(t, nodes[newLeader].api, "after-failover")
	t.Logf("three-voter cluster elected a replacement leader after SIGKILL in %s", time.Since(started).Round(time.Millisecond))
	nodes[leader].process = startBao(t, binary, nodes[leader].config, nodes[leader].dir)
	nodes[leader].waitMember(t)
	leader = waitHALeader(t, nodes)
	waitHAPeers(t, nodes[leader].api, nodes)
	crashHAPlugin(t, nodes[leader])
	if waitHALeader(t, nodes) != leader {
		t.Fatal("plugin crash unexpectedly changed the active OpenBao node")
	}

	f.server.Close()
	seals, releases := f.audit.successful("seal-envelope"), f.audit.successful("release-secret")
	writeHAValue(t, nodes[(leader+1)%len(nodes)].api, "kms-offline")
	for _, n := range nodes {
		n.waitMember(t)
		n.api.assertValue(t)
		assertHAValue(t, n.api, "after-failover")
		assertHAValue(t, n.api, "kms-offline")
	}
	started = time.Now()
	crashBao(t, nodes[leader].process)
	newLeader = waitHALeader(t, nodes)
	nodes[newLeader].api.assertValue(t)
	writeHAValue(t, nodes[newLeader].api, "after-offline-election")
	t.Logf("already-unsealed quorum elected and committed a new write with KMS offline in %s", time.Since(started).Round(time.Millisecond))
	for _, n := range nodes {
		if !n.process.stopped {
			assertHAValue(t, n.api, "after-offline-election")
		}
	}
	// A new process has no in-memory barrier key. Existing quorum members can
	// serve KV, but the stopped node must not recover through a local fallback.
	nodes[leader].process = startBao(t, binary, nodes[leader].config, nodes[leader].dir)
	nodes[leader].api.assertBlocked(t, nodes[leader].process)
	if f.audit.successful("seal-envelope") != seals || f.audit.successful("release-secret") != releases {
		t.Fatal("KMS success was recorded while its listener was unavailable")
	}
	f.start()
	nodes[leader].process = startBao(t, binary, nodes[leader].config, nodes[leader].dir)
	nodes[leader].waitMember(t)
	waitHAPeers(t, nodes[waitHALeader(t, nodes)].api, nodes)
	for _, n := range nodes {
		n.api.assertValue(t)
		for _, name := range []string{"after-failover", "kms-offline", "after-offline-election"} {
			assertHAValue(t, n.api, name)
		}
	}
	for _, n := range nodes {
		n.process.stop(t)
	}
	for _, n := range nodes {
		assertBaoArtifactsClean(t, n.dir, filepath.Join(n.dir, "openbao-plugin-kms-regalia-poc"), nodes[0].api.token, share)
	}
	t.Log("three-node software HA passed: leader/plugin crashes, standby forwarding, committed KV writes and leader replacement during KMS outage, refused offline restart, and recovered member. No hardware, partition, upgrade or production qualification is implied.")
}
