package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
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
