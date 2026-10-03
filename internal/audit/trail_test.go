package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// trailLines writes n chained lines the way trails.append does (canonical: sorted keys, no
// spaces, ASCII), after `before`, which may hold legacy or torn lines.
func trailLines(before []byte, n int, event string) []byte {
	out := append([]byte(nil), before...)
	previous := lastTrailLine(out)
	seq := 1
	for _, line := range bytes.SplitAfter(out, []byte("\n")) {
		var fields map[string]json.RawMessage
		if json.Unmarshal(bytes.TrimSuffix(line, []byte("\n")), &fields) == nil && fields["seq"] != nil {
			seq++
		}
	}
	for i := 0; i < n; i++ {
		prev := ""
		if previous != nil {
			sum := sha256.Sum256(previous)
			prev = hex.EncodeToString(sum[:])
		}
		line := []byte(fmt.Sprintf(`{"at":%d,"event":%q,"i":%d,"outcome":"ALLOW","prev":%q,"seq":%d}`+"\n", 1790000000+seq, event, i, prev, seq))
		out = append(out, line...)
		previous, seq = line, seq+1
	}
	return out
}

func lastTrailLine(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	cut := bytes.LastIndexByte(data[:len(data)-1], '\n')
	return data[cut+1:]
}

func TestTrailEventsReadWhatTrailsPyWrites(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	_, here, _, _ := runtime.Caller(0)
	baremetal := filepath.Join(filepath.Dir(here), "..", "..", "deploy", "baremetal")
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	script := `import sys; sys.path.insert(0, sys.argv[1]); import trails
for i in range(3): trails.append(sys.argv[2], {"event": "sync-pull", "outcome": "DENY" if i == 1 else "ALLOW", "note": "<&>é"})
open(sys.argv[2], "ab").write(b'{"event":"cut')
trails.append(sys.argv[2], {"event": "after-a-crash"})`
	if output, err := exec.Command(python, "-Es", "-c", script, baremetal, path).CombinedOutput(); err != nil {
		t.Fatalf("trails.py: %v: %s", err, output)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	events, err := TrailEvents("sync", data)
	if err != nil {
		t.Fatalf("a trail trails.py wrote does not map: %v", err)
	}
	if len(events) != 5 {
		t.Fatalf("5 lines (one torn by a crash) give %d events", len(events))
	}
	if events[1].Decision != "deny" || events[0].Decision != "allow" || events[0].Operation != "sync-pull" || events[4].Operation != "after-a-crash" {
		t.Fatalf("the header fields are not the line's: %+v", events[:2])
	}
	var torn trailDetail
	if err := json.Unmarshal(events[3].Detail, &torn); err != nil || torn.Kind != "torn" || events[3].Operation != "trail-torn-line" {
		t.Fatalf("the torn line is not shipped as torn: %s", events[3].Detail)
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	for i, event := range events {
		var detail trailDetail
		if err := json.Unmarshal(event.Detail, &detail); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(lines[i])
		if detail.LineSHA256 != hex.EncodeToString(sum[:]) || detail.Format != TrailFormat || detail.Trail != "sync" {
			t.Fatalf("event %d does not name line %d's exact bytes: %+v", i+1, i+1, detail)
		}
	}
}

func TestTrailEventsAreDeterministicAndPassTheCollectorsRules(t *testing.T) {
	data := trailLines([]byte(`{"at":1789999999,"event":"before the chain"}`+"\n"+`[1,2]`+"\n"), 4, "enrol")
	first, err := TrailEvents("enrol", data)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // a clock read anywhere in the mapping would show
	second, _ := TrailEvents("enrol", data)
	var journal bytes.Buffer
	for i := range first {
		if first[i].Hash != second[i].Hash {
			t.Fatalf("event %d is not a pure function of the file", i+1)
		}
		event := first[i]
		if err := validateDraft(Draft{Timestamp: event.Timestamp, RequestID: event.RequestID, Principal: event.Principal,
			Decision: event.Decision, Operation: event.Operation, Outcome: event.Outcome,
			RegistryDigest: event.RegistryDigest, PolicyDigest: event.PolicyDigest, RBACDigest: event.RBACDigest}); err != nil {
			t.Fatalf("event %d fails validateDraft: %v", i+1, err)
		}
		if err := validateDetail(event.Detail); err != nil {
			t.Fatalf("event %d fails validateDetail: %v", i+1, err)
		}
		encoded, _ := json.Marshal(event)
		journal.Write(append(encoded, '\n'))
	}
	if _, err := verifyEvents(&journal); err != nil {
		t.Fatalf("the events do not verify as a collector stream: %v", err)
	}
	if first[1].Timestamp != first[0].Timestamp {
		t.Fatal("a line without at must take the time of the line before it")
	}
	if !first[0].Timestamp.Equal(time.Unix(1789999999, 0)) {
		t.Fatalf("at is not the event's time: %v", first[0].Timestamp)
	}
}

func TestTrailEventsRefuseABrokenChain(t *testing.T) {
	good := trailLines(nil, 4, "e")
	lines := bytes.SplitAfter(good, []byte("\n"))[:4]
	edited := bytes.Replace(lines[1], []byte(`"i":1`), []byte(`"i":9`), 1)
	for label, data := range map[string][]byte{
		"edited":    bytes.Join([][]byte{lines[0], edited, lines[2], lines[3]}, nil),
		"deleted":   bytes.Join([][]byte{lines[0], lines[2], lines[3]}, nil),
		"reordered": bytes.Join([][]byte{lines[0], lines[2], lines[1], lines[3]}, nil),
		"unchained": append(append([]byte(nil), good...), []byte(`{"event":"after"}`+"\n")...),
	} {
		if _, err := TrailEvents("e", data); !errors.Is(err, ErrTrailTampered) {
			t.Errorf("%s: %v, want ErrTrailTampered", label, err)
		}
	}
}

func TestTrailEventsNeverShipALineWithoutItsNewline(t *testing.T) {
	data := append(trailLines(nil, 2, "e"), []byte(`{"at":1,"event":"being wri`)...)
	events, err := TrailEvents("e", data)
	if err != nil || len(events) != 2 {
		t.Fatalf("%d events, %v: the line being written must wait for its newline", len(events), err)
	}
}

func TestTrailContentIsWithheldNotShippedWhenItCarriesAKeyOrIsTooLong(t *testing.T) {
	data := trailLines(nil, 1, "the PRIVATE KEY of the node")
	data = trailLines(data, 1, strings.Repeat("x", maxTrailContent))
	events, err := TrailEvents("e", data)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"secret key marker", "longer than an event"} {
		var detail trailDetail
		_ = json.Unmarshal(events[i].Detail, &detail)
		if !strings.Contains(detail.Withheld, want) || detail.Content != nil || validateDetail(events[i].Detail) != nil {
			t.Fatalf("line %d: %s", i+1, events[i].Detail)
		}
		if strings.Contains(events[i].Operation, "PRIVATE") || len(events[i].Operation) > 512 {
			t.Fatalf("line %d's operation carries what the detail withholds", i+1)
		}
	}
}

func TestEventDetailIsHashedOnlyWhenPresent(t *testing.T) {
	event := collectorChainedEvents(1, "p")[0]
	encoded, _ := json.Marshal(event)
	if bytes.Contains(encoded, []byte(`"detail"`)) {
		t.Fatal("an event without detail must marshal, and hash, as it did before the field existed")
	}
	for _, bad := range []string{`[1]`, `"s"`, `{"k":"the PRIVATE KEY of the node"}`, `{"k":"` + strings.Repeat("x", maxDetail) + `"}`} {
		if validateDetail(json.RawMessage(bad)) == nil {
			t.Errorf("validateDetail accepted %.40s", bad)
		}
	}
	_, clientCertificate, _, _ := collectorTestTLS(t)
	collector, err := OpenCollector(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	event.Detail = json.RawMessage(`["not","an","object"]`)
	event.Hash = eventHash(event)
	if code := postCollectorEvent(t, collector.Handler(), clientCertificate, "s", event).Code; code != 400 {
		t.Fatalf("the collector answered %d to an event whose detail is not an object", code)
	}
}

// countingSink counts sends on its way to the real collector.
type countingSink struct {
	*HTTPSink
	sends int
}

func (sink *countingSink) Send(ctx context.Context, event Event) error {
	sink.sends++
	return sink.HTTPSink.Send(ctx, event)
}

func TestShipTrailAgainstARealCollector(t *testing.T) {
	authority, clientCertificate, clientKey, serverTLS := collectorTestTLS(t)
	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	server := httptest.NewUnstartedServer(collector.Handler())
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()
	client, err := NewMTLSHTTPClient(tls.Certificate{Certificate: [][]byte{clientCertificate.Raw}, PrivateKey: clientKey}, authority, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	httpSink, err := NewHTTPSink(server.URL, client, 5*time.Second, "sitea.sync")
	if err != nil {
		t.Fatal(err)
	}
	sink := &countingSink{HTTPSink: httpSink}
	ctx := context.Background()
	ship := func(data []byte) (uint64, uint64, error) { return ShipTrail(ctx, sink, "sitea.sync", "sync", data) }

	three := trailLines(nil, 3, "sync-pull")
	if committed, total, err := ship(three); err != nil || committed != 3 || total != 3 {
		t.Fatalf("first pass: %d/%d, %v", committed, total, err)
	}
	five := trailLines(three, 2, "sync-pull")
	if committed, _, err := ship(five); err != nil || committed != 5 {
		t.Fatalf("second pass: %d, %v", committed, err)
	}
	sink.sends = 0
	if committed, _, err := ship(five); err != nil || committed != 5 || sink.sends != 0 {
		t.Fatalf("an unchanged file re-sent %d events (%d, %v)", sink.sends, committed, err)
	}

	rewritten := trailLines(nil, 5, "something else")
	for label, data := range map[string][]byte{"cut short": three, "rewritten": rewritten, "removed": nil} {
		before := len(collectorAlarmReasons(t, stateDir))
		for pass := 0; pass < 2; pass++ { // a second start repeats the refusal: no quiet resume
			sink.sends = 0
			_, _, err := ship(data)
			if !errors.Is(err, ErrTrailTampered) || !strings.Contains(err.Error(), "alarm raised") || sink.sends != 0 {
				t.Fatalf("%s, pass %d: %v after %d sends", label, pass, err, sink.sends)
			}
		}
		reasons := collectorAlarmReasons(t, stateDir)
		if len(reasons) != before+2 || !strings.Contains(reasons[len(reasons)-1], "reported by the client") {
			t.Fatalf("%s: the collector's alarms are %q", label, reasons[before:])
		}
	}
	if head, _ := getCollectorPosition(t, collector.Handler(), clientCertificate, "sitea.sync"); head != 5 {
		t.Fatalf("a refused pass moved the committed head to %d", head)
	}
	seven := trailLines(five, 2, "sync-pull")
	if committed, _, err := ship(seven); err != nil || committed != 7 {
		t.Fatalf("the file again holds what was committed, and more: %d, %v", committed, err)
	}
	// The collector re-verifies every stream at start: events with a detail must survive that.
	if err := collector.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatalf("the collector does not reload a stream of trail events: %v", err)
	}
	defer reopened.Close()
	events, _ := TrailEvents("sync", seven)
	if head, hash := getCollectorPosition(t, reopened.Handler(), clientCertificate, "sitea.sync"); head != 7 || hash != events[6].Hash {
		t.Fatalf("the reloaded head is %d %s, not the shipper's event 7", head, hash)
	}
}

func TestReportAlarmIsRefusedOutOfBounds(t *testing.T) {
	_, clientCertificate, _, _ := collectorTestTLS(t)
	collector, err := OpenCollector(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	for _, body := range []string{`{"reason":""}`, `{"reason":"a\nb"}`, `{"reason":"r","hash":"md5:x"}`, `{"reason":"r","extra":1}`, `{"reason":"r"}{}`} {
		request := httptest.NewRequest("POST", "/v1/alarms", strings.NewReader(body))
		request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{clientCertificate}}
		recorder := httptest.NewRecorder()
		collector.Handler().ServeHTTP(recorder, request)
		if recorder.Code != 400 {
			t.Errorf("%s: %d", body, recorder.Code)
		}
	}
	request := httptest.NewRequest("POST", "/v1/alarms", strings.NewReader(`{"reason":"r"}`))
	recorder := httptest.NewRecorder()
	collector.Handler().ServeHTTP(recorder, request)
	if recorder.Code != 401 {
		t.Fatalf("an unauthenticated alarm: %d", recorder.Code)
	}
}
