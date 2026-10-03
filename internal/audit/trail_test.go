package audit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
		if expect := os.Getenv("REGALIA_EXPECT_PYTHON"); expect != "" && expect != "0" {
			t.Fatal("REGALIA_EXPECT_PYTHON is set, but python3 is not on PATH: the trails.py interop test must run here")
		}
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
		if !strings.Contains(detail.Withheld, want) || detail.Line != "" || detail.LineBase64 != "" || validateDetail(events[i].Detail) != nil {
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

// TestTheTrailMappingIsPinned holds tests/vectors/trail-events-v2.json: fixed trail bytes, as
// trails.py wrote them, to the fixed event hashes they map to (#283, regalia-kms-3e). The
// determinism test proves two builds agree; this proves today's build agrees with every shipped
// stream. A refactor here, or a Go release that compacts or escapes a RawMessage differently,
// fails this test instead of stopping every shipper in production with a tamper alarm.
func TestTheTrailMappingIsPinned(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(here), "..", "..", "tests", "vectors", "trail-events-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Format      string   `json:"format"`
		Trail       string   `json:"trail"`
		Lines       []string `json:"lines"`
		LineSHA256  []string `json:"line_sha256"`
		EventHashes []string `json:"event_hashes"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Format != TrailFormat {
		t.Fatalf("the vector pins %s, the mapping is %s", vector.Format, TrailFormat)
	}
	events, err := TrailEvents(vector.Trail, []byte(strings.Join(vector.Lines, "\n")+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(events))
	for i, event := range events {
		got[i] = event.Hash
		var detail trailDetail
		if err := json.Unmarshal(event.Detail, &detail); err != nil || detail.LineSHA256 != vector.LineSHA256[i] {
			t.Errorf("event %d names line hash %s, the vector %s", i+1, detail.LineSHA256, vector.LineSHA256[i])
		}
	}
	if len(vector.EventHashes) != len(got) {
		t.Fatalf("the vector pins %d event hashes for %d lines; this build maps them to %q", len(vector.EventHashes), len(vector.Lines), got)
	}
	for i := range got {
		if got[i] != vector.EventHashes[i] {
			t.Errorf("line %d maps to %s, pinned %s: the mapping changed, and every shipped stream would read as rewritten", i+1, got[i], vector.EventHashes[i])
		}
	}
}

func TestReportedAlarmsAreCappedPerIdentity(t *testing.T) {
	limit, window, now := reportedAlarmLimit, reportedAlarmWindow, collectorNow
	defer func() { reportedAlarmLimit, reportedAlarmWindow, collectorNow = limit, window, now }()
	clock := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	reportedAlarmLimit, reportedAlarmWindow, collectorNow = 3, time.Hour, func() time.Time { return clock }
	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	first := collectorTestCertificate(t, "first")
	second := collectorTestCertificate(t, "second")
	report := func(certificate *x509.Certificate) int {
		request := httptest.NewRequest("POST", "/v1/alarms", strings.NewReader(`{"reason":"cut short"}`))
		request.Header.Set("X-Regalia-Site", "sitea.sync")
		request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
		recorder := httptest.NewRecorder()
		collector.Handler().ServeHTTP(recorder, request)
		return recorder.Code
	}
	var codes []int
	for i := 0; i < 5; i++ {
		codes = append(codes, report(first))
	}
	if fmt.Sprint(codes) != "[204 204 204 429 429]" {
		t.Fatalf("five reports in a window answered %v", codes)
	}
	reasons := collectorAlarmReasons(t, stateDir)
	floods := 0
	for _, reason := range reasons {
		if strings.Contains(reason, "alarm flood") {
			floods++
		}
	}
	if len(reasons) != 4 || floods != 1 {
		t.Fatalf("the alarm log holds %d lines, %d of them a flood: %q", len(reasons), floods, reasons)
	}
	if code := report(second); code != 204 {
		t.Fatalf("another identity was refused: %d", code)
	}
	clock = clock.Add(time.Hour)
	if code := report(first); code != 204 {
		t.Fatalf("a new window refused: %d", code)
	}
}

func TestTheCollectorSignsReceiptsForTheCallersOwnStreamOnly(t *testing.T) {
	_, first, _, _ := collectorTestTLS(t)
	second := collectorTestCertificate(t, "second")
	collector, err := OpenCollector(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	ask := func(certificate *x509.Certificate, site string, sequence string) *httptest.ResponseRecorder {
		request := httptest.NewRequest("GET", "/v1/receipt?sequence="+sequence, nil)
		request.Header.Set("X-Regalia-Site", site)
		request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
		recorder := httptest.NewRecorder()
		collector.Handler().ServeHTTP(recorder, request)
		return recorder
	}
	events, err := TrailEvents("sync", trailLines(nil, 3, "sync-pull"))
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if code := postCollectorEvent(t, collector.Handler(), first, "sitea.sync", event).Code; code != 204 {
			t.Fatalf("event %d: %d", event.Sequence, code)
		}
	}
	if code := ask(first, "sitea.sync", "2").Code; code != 404 {
		t.Fatalf("a collector without a receipt key answered %d", code)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	collector.SetReceiptKey(private)
	answer := ask(first, "sitea.sync", "2")
	var receipt Receipt
	if answer.Code != 200 || json.Unmarshal(answer.Body.Bytes(), &receipt) != nil {
		t.Fatalf("receipt: %d %s", answer.Code, answer.Body.String())
	}
	var detail trailDetail
	_ = json.Unmarshal(events[1].Detail, &detail)
	signature, _ := hex.DecodeString(receipt.Signature)
	if receipt.EventHash != events[1].Hash || receipt.LineSHA256 != detail.LineSHA256 ||
		!ed25519.Verify(public, ReceiptPreimage(fingerprintOf(first), "sitea.sync", 2, events[1].Hash, detail.LineSHA256), signature) {
		t.Fatalf("the receipt does not sign what the collector holds at 2: %+v", receipt)
	}
	for label, recorder := range map[string]*httptest.ResponseRecorder{
		"past the head":           ask(first, "sitea.sync", "4"),
		"position 0":              ask(first, "sitea.sync", "0"),
		"another site":            ask(first, "sitea.admission", "2"),
		"another client's stream": ask(second, "sitea.sync", "2"),
	} {
		if recorder.Code == 200 {
			t.Errorf("%s: a receipt was signed", label)
		}
	}
	// After a restart the line hashes are rebuilt from the stream file.
	stateDir := t.TempDir()
	reloaded, _ := OpenCollector(stateDir)
	for _, event := range events {
		postCollectorEvent(t, reloaded.Handler(), first, "sitea.sync", event)
	}
	reloaded.Close()
	reopened, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.SetReceiptKey(private)
	collector = reopened
	if answer := ask(first, "sitea.sync", "3"); !strings.Contains(answer.Body.String(), `"line_sha256":"`+mustLineHash(t, events[2])) {
		t.Fatalf("after a reload: %s", answer.Body.String())
	}
}

func mustLineHash(t *testing.T, event Event) string {
	t.Helper()
	var detail trailDetail
	if err := json.Unmarshal(event.Detail, &detail); err != nil {
		t.Fatal(err)
	}
	return detail.LineSHA256
}

// TestATrailEventWhoseContentIsNotItsLineIsRefused: regalia-kms-24 on #288. A receipt binds a line
// hash, so the collector holds each event's content to it: a shipper cannot ship the right hash with
// other content, only withhold it.
func TestATrailEventWhoseContentIsNotItsLineIsRefused(t *testing.T) {
	_, certificate, _, _ := collectorTestTLS(t)
	collector, err := OpenCollector(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	events, _ := TrailEvents("sync", trailLines(nil, 1, "sync-pull"))
	honest := events[0]
	var detail map[string]any
	_ = json.Unmarshal(honest.Detail, &detail)
	for label, change := range map[string]func(map[string]any){
		"other content":             func(d map[string]any) { d["line"] = `{"event":"forged"}` },
		"other length":              func(d map[string]any) { d["line_bytes"] = 3 },
		"content and base64":        func(d map[string]any) { d["line_base64"] = "eA==" },
		"withheld but carried":      func(d map[string]any) { d["withheld"] = "reasons" },
		"an older format":           func(d map[string]any) { d["format"] = "regalia.trail/v1" },
		"no line hash":              func(d map[string]any) { delete(d, "line_sha256") },
		"base64 of another content": func(d map[string]any) { delete(d, "line"); d["line_base64"] = "eyJ4IjoxfQ==" },
	} {
		forged := map[string]any{}
		for k, v := range detail {
			forged[k] = v
		}
		change(forged)
		event := honest
		event.Detail, _ = json.Marshal(forged)
		event.Hash = eventHash(event)
		if code := postCollectorEvent(t, collector.Handler(), certificate, "sitea.sync", event).Code; code != 400 {
			t.Errorf("%s: the collector answered %d", label, code)
		}
	}
	if code := postCollectorEvent(t, collector.Handler(), certificate, "sitea.sync", honest).Code; code != 204 {
		t.Fatalf("the honest event: %d", code)
	}
}
