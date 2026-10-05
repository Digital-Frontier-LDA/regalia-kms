package opstate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// A real etcd (v3.6.15, the release #484 builds into the image): the cache over EtcdSource lists,
// watches, is confirmed by progress notifications on a quiet store, and lists again after a compaction.
// ETCD_BIN names the binary; CI installs the pinned release and sets it. Without it the test says so and skips.
func realEtcd(t *testing.T) *clientv3.Client {
	t.Helper()
	binary := os.Getenv("ETCD_BIN")
	if binary == "" {
		// CI installs the checksum-pinned upstream release and sets both: there a missing etcd fails
		if os.Getenv("REGALIA_EXPECT_ETCD") == "1" {
			t.Fatal("REGALIA_EXPECT_ETCD=1 but ETCD_BIN is not set: the real-etcd test would be skipped")
		}
		t.Skip("ETCD_BIN is not set: the real-etcd test needs an etcd binary (CI installs v3.6.15)")
	}
	dir := t.TempDir()
	// etcd takes a unix URL's host as the socket's file name, relative to its working directory
	client, peer := "unix://client.sock:0", "unix://peer.sock:0"
	process := exec.Command(binary, "--name", "a", "--data-dir", filepath.Join(dir, "data"),
		"--listen-client-urls", client, "--advertise-client-urls", client,
		"--listen-peer-urls", peer, "--initial-advertise-peer-urls", peer, "--initial-cluster", "a="+peer,
		"--log-level", "error")
	process.Dir, process.Stdout, process.Stderr = dir, os.Stderr, os.Stderr
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Process.Kill(); _ = process.Wait() })
	c, err := clientv3.New(clientv3.Config{Endpoints: []string{"unix://" + filepath.Join(dir, "client.sock:0")}, DialTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	deadline := time.Now().Add(20 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := c.Get(ctx, "/")
		cancel()
		if err == nil {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("etcd did not answer: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestTheCacheOverARealEtcd(t *testing.T) {
	client := realEtcd(t)
	ctx := context.Background()
	if _, err := client.Put(ctx, "/regalia/v1/keys/a/state", "enabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Put(ctx, "/elsewhere", "not ours"); err != nil {
		t.Fatal(err)
	}
	source, err := NewEtcdSource(client)
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{now: time.Hour}
	cache, err := New(Options{Source: source, Prefix: "/regalia/v1/", Boottime: clk.read, ProgressEvery: 50 * time.Millisecond, Retry: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	run, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { cache.Run(run); close(done) }()
	defer func() { stop(); <-done }()
	wait := func(what string, ok func(int64, time.Duration, bool) bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for !ok(cache.Applied()) {
			if time.Now().After(deadline) {
				rev, at, live := cache.Applied()
				t.Fatalf("%s: revision %d, confirmed %s, live %v (%s)", what, rev, at, live, cache.Reason())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	wait("the first list", func(_ int64, _ time.Duration, live bool) bool { return live })
	if v, ok, _ := cache.Value("/regalia/v1/keys/a/state"); !ok || string(v) != "enabled" {
		t.Fatalf("listed %q %v", v, ok)
	}
	if _, ok, _ := cache.Value("/elsewhere"); ok {
		t.Fatal("a key outside the prefix was read")
	}
	put, err := client.Put(ctx, "/regalia/v1/keys/a/state", "disabled")
	if err != nil {
		t.Fatal(err)
	}
	wait("the change", func(rev int64, _ time.Duration, _ bool) bool { return rev >= put.Header.Revision })
	if v, _, _ := cache.Value("/regalia/v1/keys/a/state"); string(v) != "disabled" {
		t.Fatalf("watched %q", v)
	}
	// a write outside the prefix moves the store's revision; only a progress notification brings the cache
	// to it, and the cache asks for one on its own
	other, err := client.Put(ctx, "/elsewhere", "again")
	if err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Minute)
	wait("a progress notification", func(rev int64, at time.Duration, _ bool) bool {
		return rev >= other.Header.Revision && at == time.Hour+time.Minute
	})
	// a compaction past the cache's watch: it lists again and is live at the store's revision
	for i := 0; i < 5; i++ {
		if _, err := client.Put(ctx, fmt.Sprintf("/regalia/v1/hwm/k/%d", i), "1"); err != nil {
			t.Fatal(err)
		}
	}
	last, err := client.Put(ctx, "/regalia/v1/keys/b/state", "enabled")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Compact(ctx, last.Header.Revision); err != nil {
		t.Fatal(err)
	}
	wait("after the compaction", func(rev int64, _ time.Duration, live bool) bool { return live && rev >= last.Header.Revision })
	if v, ok, _ := cache.Value("/regalia/v1/keys/b/state"); !ok || string(v) != "enabled" {
		t.Fatalf("after the compaction %q %v", v, ok)
	}
}
