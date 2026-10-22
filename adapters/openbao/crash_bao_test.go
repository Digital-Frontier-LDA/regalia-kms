package openbaopoc

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Restrict discovery to direct children of this disposable OpenBao process and
// the exact fixture executable. Never signal a process by name globally.
func pluginChildren(t *testing.T, p *baoProcess, executable string) []int {
	t.Helper()
	taskFiles, err := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", p.cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	var data []byte
	for _, name := range taskFiles {
		value, readErr := os.ReadFile(name)
		if readErr == nil {
			data = append(data, value...)
			data = append(data, ' ')
		}
	}
	var children []int
	for _, value := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(value)
		if err != nil {
			t.Fatal(err)
		}
		path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))

		cmdline, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		args := strings.Split(string(cmdline), "\x00")
		emulated := path == "/run/rosetta/rosetta" && len(args) > 1 && (args[0] == executable || args[1] == executable)
		if err == nil && (path == executable || emulated) {
			children = append(children, pid)
		}
	}
	return children
}

func TestOpenBao271NativePluginCrashAndAmbiguousResponse(t *testing.T) {
	binary, dir, _, digest := baoTestEnvironmentFor(t, "openbao-plugin-kms-regalia")
	f := newKMSFixtureMode(t, true)
	// Hold one already-audited successful seal response. The token operation
	// happened, but killing the plugin prevents OpenBao from receiving it.
	f.server.Close()
	original := f.handler
	var armed atomic.Bool
	held := make(chan string, 1)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/operations/seal-envelope" || !armed.CompareAndSwap(true, false) {
			original.ServeHTTP(w, r)
			return
		}
		recorder := httptest.NewRecorder()
		original.ServeHTTP(recorder, r)
		defer clear(recorder.Body.Bytes())
		if recorder.Code != 200 {
			t.Error("gated KMS request failed before crash")
		}
		held <- r.Header.Get("Idempotency-Key")
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	f.start()
	address := freeAddress(t)
	config := baoConfig(t, dir, address, freeAddress(t), hex.EncodeToString(digest[:]), nativeFixtureConfig(f.pki.config))
	b := baoAPI{base: "http://" + address, client: &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}}
	p := startBao(t, binary, config, dir)
	b.wait(t, false, true, p)
	share := b.initialize(t)
	b.seedSyntheticKV(t)
	executable := filepath.Join(dir, "openbao-plugin-kms-regalia-poc")
	beforeSeal, beforeRelease := f.audit.successful("seal-envelope"), f.audit.successful("release-secret")
	armed.Store(true)
	select {
	case nonce := <-held:
		if nonce == "" {
			t.Fatal("crash request omitted nonce")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("periodic seal request was not intercepted")
	}
	children := pluginChildren(t, p, executable)
	if len(children) == 0 {
		t.Fatal("no live fixture plugin to crash")
	}
	old := map[int]bool{}
	for _, pid := range children {
		old[pid] = true
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(20 * time.Second)
	respawned := false
	for time.Now().Before(deadline) {
		for _, pid := range pluginChildren(t, p, executable) {
			if !old[pid] {
				respawned = true
			}
		}
		if respawned && f.audit.successful("seal-envelope") >= beforeSeal+2 && f.audit.successful("release-secret") > beforeRelease {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !respawned || f.audit.successful("seal-envelope") < beforeSeal+2 || f.audit.successful("release-secret") <= beforeRelease {
		t.Fatal("OpenBao did not respawn/recover the interrupted plugin")
	}
	if f.audit.outcomes("seal-envelope", "policy-REPLAY:replay") != 0 {
		t.Fatal("respawn replayed a consumed nonce")
	}
	b.wait(t, true, false, p)
	b.assertValue(t)
	p.stop(t)
	p = startBao(t, binary, config, dir)
	b.wait(t, true, false, p)
	b.assertValue(t)
	p.stop(t)
	assertBaoArtifactsClean(t, dir, executable, b.token, share)
	t.Log("Real OpenBao respawned after SIGKILL during an already-audited seal; subsequent operations used new nonces, KV stayed available and restart unsealed. An interrupted operation can still have executed: audit reconciliation is required.")
}
