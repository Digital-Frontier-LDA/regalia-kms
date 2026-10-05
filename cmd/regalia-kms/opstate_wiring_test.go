package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/opstate"
)

// An unconfigured daemon watches nothing and publishes nothing.
func TestNoOperationalStateIsWatchedUnlessConfigured(t *testing.T) {
	cache, key, stop, err := watchOperationalState(context.Background(), config.Config{})
	if err != nil || cache != nil || key != nil {
		t.Fatalf("unconfigured: %v %v %v", cache, key, err)
	}
	stop()
}

// THE DAEMON WATCHES THE STATE AND SAYS WHAT IT APPLIED (D32, #432). Against a real etcd on a unix socket, as on
// a host: the session key's public half is published, and applied.json follows the store's revision.
func TestTheDaemonWatchesTheOperationalStateAndPublishesWhatItApplied(t *testing.T) {
	binary := os.Getenv("ETCD_BIN")
	if binary == "" {
		if os.Getenv("REGALIA_EXPECT_ETCD") == "1" {
			t.Fatal("REGALIA_EXPECT_ETCD=1 but ETCD_BIN is not set")
		}
		t.Skip("ETCD_BIN is not set")
	}
	dir := t.TempDir()
	etcd := exec.Command(binary, "--name", "a", "--data-dir", filepath.Join(dir, "data"),
		"--listen-client-urls", "unix://client.sock:0", "--advertise-client-urls", "unix://client.sock:0",
		"--listen-peer-urls", "unix://peer.sock:0", "--initial-advertise-peer-urls", "unix://peer.sock:0",
		"--initial-cluster", "a=unix://peer.sock:0", "--log-level", "error")
	etcd.Dir, etcd.Stderr = dir, os.Stderr
	if err := etcd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = etcd.Process.Kill(); _ = etcd.Wait() })
	stateDir, keyDir := filepath.Join(dir, "state"), filepath.Join(dir, "kms")
	for _, d := range []string{stateDir, keyDir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	settings := config.Config{OperationalStateEndpoint: filepath.Join(dir, "client.sock:0"), OperationalStateDir: stateDir, SessionKeyDir: keyDir}
	cache, key, stop, err := watchOperationalState(context.Background(), settings)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	raw, err := os.ReadFile(filepath.Join(keyDir, opstate.SessionKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	var published map[string]any
	if json.Unmarshal(raw, &published) != nil || published["session_key"] != key.Hex() {
		t.Fatalf("session key file %s", raw)
	}
	client, err := clientv3.New(clientv3.Config{Endpoints: []string{"unix://" + settings.OperationalStateEndpoint}, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var put *clientv3.PutResponse
	deadline := time.Now().Add(30 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		put, err = client.Put(ctx, opstate.Prefix+"keys/a/state", "enabled")
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("etcd did not answer: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for {
		var applied struct {
			Revision  int64  `json:"revision"`
			ClusterID string `json:"cluster_id"`
		}
		raw, err := os.ReadFile(filepath.Join(stateDir, opstate.AppliedFile))
		if err == nil && json.Unmarshal(raw, &applied) == nil && applied.Revision >= put.Header.Revision && len(applied.ClusterID) == 16 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("applied.json never reached revision %d: %s (%s)", put.Header.Revision, raw, cache.Reason())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
