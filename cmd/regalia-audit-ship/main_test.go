package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
)

// fakeSink is a collector that holds `head` lines, or is unreachable.
type fakeSink struct {
	head        uint64
	hash        string
	unreachable bool
	alarms      []string
	sends       int
}

func (sink *fakeSink) Send(context.Context, audit.Event) error { sink.sends++; return nil }
func (sink *fakeSink) CommittedHead(context.Context, string) (uint64, string, error) {
	if sink.unreachable {
		return 0, "", audit.ErrSinkUnavailable
	}
	return sink.head, sink.hash, nil
}
func (sink *fakeSink) ReportAlarm(_ context.Context, _ uint64, _ string, reason string) error {
	sink.alarms = append(sink.alarms, reason)
	return nil
}

func TestATamperedTrailStopsTheLoopAndSaysSoInTheMetrics(t *testing.T) {
	dir := t.TempDir()
	o := options{trail: "sync", path: filepath.Join(dir, "missing.jsonl"), site: "sitea", metrics: filepath.Join(dir, "sync.prom"), interval: time.Hour}
	sink := &fakeSink{head: 4, hash: "sha256:" + strings.Repeat("ab", 32)}
	done := make(chan error, 1)
	go func() { done <- loop(context.Background(), sink, o, &bytes.Buffer{}) }()
	select {
	case err := <-done:
		if !errors.Is(err, audit.ErrTrailTampered) {
			t.Fatalf("the loop ended with %v, want ErrTrailTampered (exit %d)", err, exitTampered)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the loop kept going on a trail the collector holds 4 lines of and the host none")
	}
	if len(sink.alarms) != 1 || sink.sends != 0 {
		t.Fatalf("%d alarms, %d sends", len(sink.alarms), sink.sends)
	}
	metrics, err := os.ReadFile(o.metrics)
	if err != nil || !strings.Contains(string(metrics), `regalia_audit_trail_tampered{trail="sync"} 1`) {
		t.Fatalf("metrics: %s %v", metrics, err)
	}
}

func TestAnUnreachableCollectorIsRetriedNotStopped(t *testing.T) {
	dir := t.TempDir()
	o := options{trail: "sync", path: filepath.Join(dir, "missing.jsonl"), site: "sitea", metrics: filepath.Join(dir, "sync.prom"), interval: time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	var out bytes.Buffer
	if err := loop(ctx, &fakeSink{unreachable: true}, o, &out); err != nil {
		t.Fatalf("the loop stopped on an unreachable collector: %v", err)
	}
	if strings.Count(out.String(), "retrying") < 2 {
		t.Fatalf("not retried: %s", out.String())
	}
	metrics, _ := os.ReadFile(o.metrics)
	if !strings.Contains(string(metrics), `regalia_audit_trail_tampered{trail="sync"} 0`) || strings.Contains(string(metrics), "last_success") {
		t.Fatalf("metrics: %s", metrics)
	}
}

func TestTheTrailIsNeverReadThroughALink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "audit.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrail(link); err == nil {
		t.Fatal("the trail was read through a symlink")
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readTrail(filepath.Join(dir, "d")); err == nil {
		t.Fatal("a directory was read as a trail")
	}
}

func TestTheStreamMustBeASiteTheCollectorAccepts(t *testing.T) {
	err := run([]string{"-trail", "sync", "-path", "p", "-collector", "https://c", "-site", "a/b", "-tls-cert", "c", "-tls-key", "k", "-server-ca", "ca"}, os.Stderr)
	if err == nil || !strings.Contains(err.Error(), "not a site the collector accepts") {
		t.Fatalf("%v", err)
	}
}

// TestARotatedAndPrunedTrailShipsTheSameEvents runs the real trails.py: it writes a trail that rotates,
// and prunes it with the head file this shipper writes. At each stage the events read from the files
// are the events of the whole trail, hash for hash (#278).
func TestARotatedAndPrunedTrailShipsTheSameEvents(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		if expect := os.Getenv("REGALIA_EXPECT_PYTHON"); expect != "" && expect != "0" {
			t.Fatal("REGALIA_EXPECT_PYTHON is set, but python3 is not on PATH")
		}
		t.Skip("python3 is not installed")
	}
	_, here, _, _ := runtime.Caller(0)
	baremetal := filepath.Join(filepath.Dir(here), "..", "..", "deploy", "baremetal")
	dir := t.TempDir()
	path := filepath.Join(dir, "sync-audit.jsonl")
	trails := func(script string, args ...string) string {
		t.Helper()
		argv := append([]string{"-Es", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import trails\n" + script, baremetal}, args...)
		output, err := exec.Command(python, argv...).CombinedOutput()
		if err != nil {
			t.Fatalf("trails.py: %v: %s", err, output)
		}
		return strings.TrimSpace(string(output))
	}
	trails("trails.ROTATE_BYTES = 500\nfor i in range(30): trails.append(sys.argv[2], {'event': 'sync-pull', 'outcome': 'ALLOW', 'i': i}, now=lambda: 1790000000 + i)", path)

	read, err := readSegments(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(read.archives) < 3 {
		t.Fatalf("%d archives: the trail did not rotate", len(read.archives))
	}
	whole, err := audit.TrailEvents("sync", read.data)
	if err != nil || len(whole) != 30 {
		t.Fatalf("the archives and the current file are not one chain of 30: %d, %v", len(whole), err)
	}
	committed := read.archives[0].lines + read.archives[1].lines // the collector holds the first two archives
	head := filepath.Join(dir, "sync.head.json")
	if err := writeHead(head, "sync", read, committed); err != nil {
		t.Fatal(err)
	}
	if removed := trails("print(trails.prune(sys.argv[2], sys.argv[3]))", path, head); removed != "2" {
		t.Fatalf("prune removed %s archives, not the 2 the collector holds", removed)
	}
	trails("print(trails.verify_trail(sys.argv[2])['chained'])", path)

	after, err := readSegments(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.start.Sequence != committed || len(after.archives) != len(read.archives)-2 {
		t.Fatalf("after the prune: from line %d with %d archives", after.start.Sequence, len(after.archives))
	}
	rest, err := audit.TrailEventsFrom("sync", after.start, after.data)
	if err != nil {
		t.Fatal(err)
	}
	if uint64(len(rest)) != 30-committed {
		t.Fatalf("%d events after the marker, want %d", len(rest), 30-committed)
	}
	for i, event := range rest {
		if want := whole[committed+uint64(i)]; event.Hash != want.Hash || event.Sequence != want.Sequence {
			t.Fatalf("line %d rebuilt from the marker is not the line rebuilt from the start", want.Sequence)
		}
	}
}

func TestAPruneAheadOfTheCollectorIsTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sync-audit.jsonl")
	marker := `{"seq":10,"sequence":10,"event_hash":"sha256:` + strings.Repeat("ab", 32) + `","line_sha256":"` + strings.Repeat("cd", 32) + `","timestamp":1790000000}`
	if err := os.WriteFile(path+".pruned", []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	o := options{trail: "sync", path: path, site: "sitea", interval: time.Hour}
	sink := &fakeSink{head: 4, hash: "sha256:" + strings.Repeat("ef", 32)}
	if err := loop(context.Background(), sink, o, &bytes.Buffer{}); !errors.Is(err, audit.ErrTrailTampered) || len(sink.alarms) != 1 || !strings.Contains(sink.alarms[0], "removed before they shipped") {
		t.Fatalf("a marker past the collector's head: %v, alarms %q", err, sink.alarms)
	}
}
