package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
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
	sent        []string
}

func (sink *fakeSink) Send(_ context.Context, event audit.Event) error {
	sink.sends++
	sink.sent = append(sink.sent, event.Hash)
	return nil
}
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

	// The whole trail, as one chain: the archives in order, then the current file.
	names, _ := filepath.Glob(path + ".*")
	sort.Strings(names)
	var whole []byte
	archives := 0
	for _, name := range append(names, path) {
		if name != path && !archiveSuffix.MatchString(strings.TrimPrefix(name, path)) {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		whole = append(whole, data...)
		if name != path {
			archives++
		}
	}
	events, err := audit.TrailEvents("sync", whole)
	if err != nil || len(events) != 30 || archives < 3 {
		t.Fatalf("the trail is not one chain of 30 over 3 or more archives: %d events, %d archives, %v", len(events), archives, err)
	}
	first2, _ := os.ReadFile(names[0])
	second, _ := os.ReadFile(names[1])
	committed := uint64(bytes.Count(first2, []byte("\n")) + bytes.Count(second, []byte("\n"))) // the collector holds two archives

	// A collector that holds the first two archives and signs receipts as the real one does. A pass whose
	// sends all fail writes no head file; the next one commits everything and receipts every archive.
	head := filepath.Join(dir, "sync.head.json")
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	identity := strings.Repeat("cd", 32)
	sink := &receiptSink{fakeSink: fakeSink{head: committed, hash: events[committed-1].Hash}, key: private, identity: identity,
		stream: "sitea.sync", events: events, refuseSends: true}
	o := options{trail: "sync", path: path, site: "sitea", head: head, interval: time.Hour, once: true}
	if err := loop(context.Background(), sink, o, &bytes.Buffer{}); err == nil {
		t.Fatal("a pass whose sends all fail reported success")
	}
	if _, err := os.Stat(head); err == nil {
		t.Fatal("a failed pass wrote a head file")
	}
	sink.refuseSends = false
	if err := loop(context.Background(), sink, o, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if want := events[committed:]; len(sink.sent) != len(want) || sink.sent[0] != want[0].Hash || sink.sent[len(want)-1] != want[len(want)-1].Hash {
		t.Fatalf("the pass sent %d events, not the %d after the collector's head", len(sink.sent), len(want))
	}
	// The real trails.py checks each receipt (Go's ReceiptPreimage, signed here) and removes every archive.
	pinned := hex.EncodeToString(public)
	if removed := trails("print(trails.prune(sys.argv[2], sys.argv[3], 'sync', 'sitea', sys.argv[4], [sys.argv[5]]))", path, head, identity, pinned); removed != strconv.Itoa(archives) {
		t.Fatalf("prune removed %s archives, not the %d the collector receipted", removed, archives)
	}
	marker, err := os.ReadFile(path + ".pruned")
	if err != nil {
		t.Fatal(err)
	}
	var start audit.TrailStart
	if err := json.Unmarshal(marker, &start); err != nil {
		t.Fatal(err)
	}
	committed = start.Sequence
	if start.EventHash != events[committed-1].Hash {
		t.Fatal("the marker's event hash is not the collector's (receipted) event at that line")
	}
	trails("print(trails.verify_trail(sys.argv[2])['chained'])", path)

	// From the marker: the same events, hash for hash, as from the first line.
	again := &fakeSink{head: committed, hash: events[committed-1].Hash}
	if err := loop(context.Background(), again, options{trail: "sync", path: path, site: "sitea", interval: time.Hour, once: true}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if len(again.sent) != len(events)-int(committed) {
		t.Fatalf("from the marker %d events were sent, want %d", len(again.sent), len(events)-int(committed))
	}
	for i, hash := range again.sent {
		if hash != events[int(committed)+i].Hash {
			t.Fatalf("line %d rebuilt from the marker is not the line rebuilt from the start", int(committed)+i+1)
		}
	}
}

// TestATrailOfAnySizeShipsInBoundedMemory: the shipper walks a trail line by line (#288, regalia-kms-51:
// a trail larger than a fixed bound must never strand). 4 MiB of chained lines from a generator, not
// a file, pass through the walker; the heap does not grow with them (holding them would take ~24 MiB).
func TestATrailOfAnySizeShipsInBoundedMemory(t *testing.T) {
	generator := &chainedLines{left: 4 << 20}
	walker, err := audit.NewTrailWalker("sync", audit.TrailStart{})
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, peak runtime.MemStats
	runtime.ReadMemStats(&before)
	count := 0
	err = walker.Feed(generator, false, func(audit.Event) error {
		count++
		if count%5000 == 0 {
			var now runtime.MemStats
			runtime.ReadMemStats(&now)
			if now.HeapInuse > peak.HeapInuse {
				peak = now
			}
		}
		return nil
	})
	if err != nil || count < 25000 {
		t.Fatalf("%d lines walked: %v", count, err)
	}
	if grown := int64(peak.HeapInuse) - int64(before.HeapInuse); grown > 4<<20 {
		t.Fatalf("the heap grew by %d MiB walking 4 MiB: the trail is being held", grown>>20)
	}
}

// chainedLines yields lines as trails.append writes them, chained, until left bytes have been read.
type chainedLines struct {
	left    int
	seq     int
	prev    string
	pending []byte
}

func (g *chainedLines) Read(p []byte) (int, error) {
	if len(g.pending) == 0 {
		if g.left <= 0 {
			return 0, io.EOF
		}
		g.seq++
		line := fmt.Sprintf(`{"at":%d,"event":"sync-pull","outcome":"ALLOW","peer":"node-b","prev":%q,"seq":%d}`+"\n", 1790000000+g.seq, g.prev, g.seq)
		sum := sha256.Sum256([]byte(line))
		g.prev, g.pending = hex.EncodeToString(sum[:]), []byte(line)
		g.left -= len(line)
	}
	n := copy(p, g.pending)
	g.pending = g.pending[n:]
	return n, nil
}

// receiptSink is a collector that also signs receipts, as internal/audit/collector.go does.
type receiptSink struct {
	fakeSink
	key         ed25519.PrivateKey
	identity    string
	stream      string
	events      []audit.Event
	refuseSends bool
}

func (sink *receiptSink) Send(ctx context.Context, event audit.Event) error {
	if sink.refuseSends {
		return audit.ErrSinkUnavailable
	}
	return sink.fakeSink.Send(ctx, event)
}

func (sink *receiptSink) Receipt(_ context.Context, sequence uint64) (audit.Receipt, error) {
	event := sink.events[sequence-1]
	var detail struct {
		LineSHA256 string `json:"line_sha256"`
	}
	if err := json.Unmarshal(event.Detail, &detail); err != nil {
		return audit.Receipt{}, err
	}
	chain := audit.LineChainStart
	for _, earlier := range sink.events[:sequence] {
		var d struct {
			LineSHA256 string `json:"line_sha256"`
		}
		_ = json.Unmarshal(earlier.Detail, &d)
		chain = audit.LineChain(chain, d.LineSHA256)
	}
	signature := ed25519.Sign(sink.key, audit.ReceiptPreimage(sink.identity, sink.stream, sequence, event.Hash, detail.LineSHA256, chain))
	return audit.Receipt{Sequence: sequence, EventHash: event.Hash, LineSHA256: detail.LineSHA256, LineChain: chain, Signature: hex.EncodeToString(signature)}, nil
}

func TestAPruneAheadOfTheCollectorIsTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sync-audit.jsonl")
	marker := `{"seq":10,"sequence":10,"event_hash":"sha256:` + strings.Repeat("ab", 32) + `","line_sha256":"` + strings.Repeat("cd", 32) + `","timestamp":1790000000,"line_chain":"` + strings.Repeat("ef", 32) + `"}`
	if err := os.WriteFile(path+".pruned", []byte(marker), 0o644); err != nil {
		t.Fatal(err)
	}
	o := options{trail: "sync", path: path, site: "sitea", interval: time.Hour}
	sink := &fakeSink{head: 4, hash: "sha256:" + strings.Repeat("ef", 32)}
	if err := loop(context.Background(), sink, o, &bytes.Buffer{}); !errors.Is(err, audit.ErrTrailTampered) || len(sink.alarms) != 1 || !strings.Contains(sink.alarms[0], "removed before they shipped") {
		t.Fatalf("a marker past the collector's head: %v, alarms %q", err, sink.alarms)
	}
}

func TestAMarkerThatIsNotOneRaisesTheAlarm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sync-audit.jsonl")
	if err := os.WriteFile(path+".pruned", []byte(`{"seq":10,"sequence":10,"event_hash":"not a hash","line_sha256":"","timestamp":1,"line_chain":""}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{head: 10, hash: "sha256:" + strings.Repeat("ef", 32)}
	err := loop(context.Background(), sink, options{trail: "sync", path: path, site: "sitea", interval: time.Hour}, &bytes.Buffer{})
	if !errors.Is(err, audit.ErrTrailTampered) || len(sink.alarms) != 1 || sink.sends != 0 {
		t.Fatalf("a forged marker: %v, %d alarms, %d sends", err, len(sink.alarms), sink.sends)
	}
}
