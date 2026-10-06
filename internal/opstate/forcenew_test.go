package opstate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// startMember runs one etcd member on unix sockets in dir (its data under dir/data), with extra flags; the
// returned stop kills it and waits.
func startMember(t *testing.T, dir string, extra ...string) (*clientv3.Client, func()) {
	t.Helper()
	binary := os.Getenv("ETCD_BIN")
	if binary == "" {
		if os.Getenv("REGALIA_EXPECT_ETCD") == "1" {
			t.Fatal("REGALIA_EXPECT_ETCD=1 but ETCD_BIN is not set")
		}
		t.Skip("ETCD_BIN is not set")
	}
	args := append([]string{"--name", "a", "--data-dir", filepath.Join(dir, "data"),
		"--listen-client-urls", "unix://client.sock:0", "--advertise-client-urls", "unix://client.sock:0",
		"--listen-peer-urls", "unix://peer.sock:0", "--initial-advertise-peer-urls", "unix://peer.sock:0",
		"--initial-cluster", "a=unix://peer.sock:0", "--log-level", "error"}, extra...)
	if _, err := os.Lstat(filepath.Join(dir, "etcd")); err != nil {
		etcdInDir(t, binary, dir) // a constant ./etcd, the checked ETCD_BIN linked here (as etcd_test.go)
	}
	process := exec.Command("./etcd", args...)
	process.Dir, process.Stderr = dir, os.Stderr
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	client, err := clientv3.New(clientv3.Config{Endpoints: []string{"unix://" + filepath.Join(dir, "client.sock:0")}, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := client.Get(ctx, "/")
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("etcd did not answer: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return client, func() { client.Close(); _ = process.Process.Kill(); _ = process.Wait() }
}

// MEASURED, NOT ASSUMED (#432, scope full): a member restarted from its own data with --force-new-cluster keeps
// the cluster ID, and the revision it had once its writes have had time to persist. (Killed abruptly right after
// an acknowledged write, it came back WITHOUT that write: force-new-cluster drops WAL entries past the persisted
// commit index. So survivor.py stops etcd gracefully, records applied.json's revision first, and refuses "full"
// if the new cluster starts below it; that case is on #432, not pinned here, since its timing is not
// deterministic.)
func TestForceNewClusterKeepsTheClusterIDAndTheRevision(t *testing.T) {
	dir := t.TempDir()
	client, stop := startMember(t, dir)
	put, err := client.Put(context.Background(), Prefix+"keys/k/state", "x")
	if err != nil {
		t.Fatal(err)
	}
	before, revision := put.Header.ClusterId, put.Header.Revision
	time.Sleep(2 * time.Second) // the write persists (etcd's backend commits every 100 ms; the hard state follows)
	stop()
	client, stop = startMember(t, dir, "--force-new-cluster")
	defer stop()
	got, err := client.Get(context.Background(), Prefix+"keys/k/state")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cluster %016x before, %016x after; revision %d before, %d after", before, got.Header.ClusterId, revision, got.Header.Revision)
	if got.Header.ClusterId != before {
		t.Fatalf("--force-new-cluster changed the cluster ID (%016x to %016x): the survivor's daemon must be restarted at entry", before, got.Header.ClusterId)
	}
	if got.Header.Revision < revision || len(got.Kvs) != 1 {
		t.Fatalf("--force-new-cluster lost the member's own data: revision %d, then %d", revision, got.Header.Revision)
	}
}
