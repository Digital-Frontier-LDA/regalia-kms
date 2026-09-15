package audit

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// collectorChainedEvents builds n events exactly the way the recorder does — sequence from
// 1, previous_hash linking, hash computed by eventHash over the canonical marshal — so a
// POST of their marshalled form is byte-equivalent to what HTTPSink.Send puts on the wire.
func collectorChainedEvents(n int, principal string) []Event {
	events := make([]Event, 0, n)
	previous := genesisHash
	for i := 0; i < n; i++ {
		event := Event{
			Sequence:            uint64(i + 1),
			Timestamp:           time.Date(2026, 9, 12, 10, 0, i, 0, time.UTC),
			RequestID:           "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
			Principal:           principal,
			Decision:            "allow",
			ObjectID:            "o",
			Purpose:             "pu",
			Operation:           "op",
			DeviceID:            "d",
			Outcome:             "ok",
			LatencyMilliseconds: 1,
			RegistryDigest:      "aa" + strings.Repeat("bb", 31),
			PolicyDigest:        "cc" + strings.Repeat("dd", 31),
			RBACDigest:          "ee" + strings.Repeat("ff", 31),
			PreviousHash:        previous,
		}
		event.Hash = eventHash(event)
		previous = event.Hash
		events = append(events, event)
	}
	return events
}

func postCollectorEvent(t *testing.T, handler http.Handler, certificate *x509.Certificate, site string, event Event) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	if site != "" {
		request.Header.Set("X-Regalia-Site", site)
	}
	if certificate != nil {
		request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func getCollectorPosition(t *testing.T, handler http.Handler, certificate *x509.Certificate, site string) (uint64, string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/v1/stream-position", nil)
	request.Header.Set("Accept", "application/json")
	if site != "" {
		request.Header.Set("X-Regalia-Site", site)
	}
	if certificate != nil {
		request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("stream position answered %d: %s", recorder.Code, recorder.Body.String())
	}
	var position struct {
		Sequence uint64 `json:"sequence"`
		Hash     string `json:"hash"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &position); err != nil {
		t.Fatalf("stream position body does not parse: %v", err)
	}
	return position.Sequence, position.Hash
}

// collectorAlarmReasons reads the durable alarm log.
func collectorAlarmReasons(t *testing.T, stateDir string) []string {
	t.Helper()
	file, err := os.Open(filepath.Join(stateDir, alarmsFileName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	defer file.Close()
	var reasons []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var alarm collectorAlarm
		if err := json.Unmarshal(scanner.Bytes(), &alarm); err != nil {
			t.Fatalf("alarm log holds a line that does not parse: %v", err)
		}
		reasons = append(reasons, alarm.Reason)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return reasons
}

func collectorStreamLines(t *testing.T, stateDir, identity, site string) int {
	t.Helper()
	file, err := os.Open(filepath.Join(stateDir, streamsDirName, identity, streamFilePrefix+site+streamFileSuffix))
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	defer file.Close()
	lines := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

func containsSubstring(values []string, wanted string) bool {
	for _, value := range values {
		if strings.Contains(value, wanted) {
			return true
		}
	}
	return false
}

// fingerprintOf mirrors peerIdentity's derivation; tests key streams by the same value the
// collector computes, so a change in the derivation shows up as a red test, not a silent
// re-keying of every stream.
func fingerprintOf(certificate *x509.Certificate) string {
	digest := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(digest[:])
}

func collectorTestCertificate(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestCollectorCommitsBeforeAcknowledging(t *testing.T) {
	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	handler := collector.Handler()
	certificate := collectorTestCertificate(t, "sitea-daemon")
	identity := fingerprintOf(certificate)
	events := collectorChainedEvents(2, "legit")

	// The ack carries the event's exact chained hash and the position moves with it.
	first := postCollectorEvent(t, handler, certificate, "sitea", events[0])
	if first.Code != http.StatusNoContent || first.Header().Get("X-Regalia-Audit-Hash") != events[0].Hash {
		t.Fatalf("first event was not acknowledged with its hash: status=%d ack=%q", first.Code, first.Header().Get("X-Regalia-Audit-Hash"))
	}
	sequence, hash := getCollectorPosition(t, handler, certificate, "sitea")
	if sequence != 1 || hash != events[0].Hash {
		t.Fatalf("after the ack the committed position is (%d, %s), want (1, %s)", sequence, hash, events[0].Hash)
	}

	// THE ORDERING CONTRACT, made observable from outside: if the durable write fails, no
	// acknowledgement may issue. The stream's file handle is closed under the collector —
	// the append then fails — and a client that nevertheless received 204 would hold an
	// acknowledgement for an event that was never committed, which is precisely the
	// ack-without-commit the protocol says is impossible.
	collector.mu.Lock()
	if err := collector.streams[streamKey(identity, "sitea")].file.Close(); err != nil {
		collector.mu.Unlock()
		t.Fatal(err)
	}
	collector.mu.Unlock()
	failed := postCollectorEvent(t, handler, certificate, "sitea", events[1])
	if failed.Code == http.StatusNoContent {
		t.Fatal("an event whose durable commit FAILED was acknowledged 204 — the ack must come only after the commit")
	}
	sequence, hash = getCollectorPosition(t, handler, certificate, "sitea")
	if sequence != 1 || hash != events[0].Hash {
		t.Fatalf("a failed commit moved the position to (%d, %s)", sequence, hash)
	}

	// And the reverse direction: a real restart (every in-memory value dropped, state
	// re-read and re-verified from disk) still holds exactly what was acknowledged. The
	// Close error is ignored: the deliberately-broken file handle from the ordering probe
	// reports its own error on the way out, which is not what this arm asserts.
	_ = collector.Close()
	reopened, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatalf("the collector state does not survive a restart: %v", err)
	}
	defer reopened.Close()
	if sequence, hash := getCollectorPosition(t, reopened.Handler(), certificate, "sitea"); sequence != 1 || hash != events[0].Hash {
		t.Fatalf("after restart the committed position is (%d, %s), want the acknowledged (1, %s)", sequence, hash, events[0].Hash)
	}
}

func TestCollectorRejectsARewrittenJournal(t *testing.T) {
	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	handler := collector.Handler()
	certificate := collectorTestCertificate(t, "sitea-daemon")
	identity := fingerprintOf(certificate)
	original := collectorChainedEvents(2, "legit")
	for _, event := range original {
		if response := postCollectorEvent(t, handler, certificate, "sitea", event); response.Code != http.StatusNoContent {
			t.Fatalf("fixture event %d was refused: %s", event.Sequence, response.Body.String())
		}
	}

	// The rewrite: a correctly-chained event 2 whose CONTENT differs from the committed
	// copy — the row-2 attack, arriving as a replay of a committed sequence.
	rewrite := collectorChainedEvents(2, "attacker")
	rewrite[1].PreviousHash = original[0].Hash // chains honestly onto the committed event 1
	rewrite[1].Hash = eventHash(rewrite[1])
	response := postCollectorEvent(t, handler, certificate, "sitea", rewrite[1])
	if response.Code != http.StatusConflict {
		t.Fatalf("a replay of sequence 2 with different content was answered %d, want 409: %s", response.Code, response.Body.String())
	}
	if sequence, _ := getCollectorPosition(t, handler, certificate, "sitea"); sequence != 2 {
		t.Fatalf("the rewrite moved the committed head to %d", sequence)
	}
	if lines := collectorStreamLines(t, stateDir, identity, "sitea"); lines != 2 {
		t.Fatalf("the rewrite appended to the committed stream: %d lines", lines)
	}
	reasons := collectorAlarmReasons(t, stateDir)
	if len(reasons) == 0 || !strings.Contains(reasons[len(reasons)-1], "differs from the committed copy") {
		t.Fatalf("the rewrite was rejected without a durable alarm: %v", reasons)
	}
}

func TestCollectorIdempotentlyReacksTheCommittedCopy(t *testing.T) {
	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	handler := collector.Handler()
	certificate := collectorTestCertificate(t, "sitea-daemon")
	identity := fingerprintOf(certificate)
	events := collectorChainedEvents(2, "legit")
	if response := postCollectorEvent(t, handler, certificate, "sitea", events[0]); response.Code != http.StatusNoContent {
		t.Fatalf("fixture event was refused: %s", response.Body.String())
	}

	// The shipper retries the SAME head event whenever an ack is lost, and a restart replays
	// from the lagging .shipped mark (shipper.go: "the collector dedupes it on the unchanged
	// Idempotency-Key"). Re-delivery of the exact committed event must therefore re-ack —
	// refusing it would wedge the daemon on an event it already shipped.
	again := postCollectorEvent(t, handler, certificate, "sitea", events[0])
	if again.Code != http.StatusNoContent || again.Header().Get("X-Regalia-Audit-Hash") != events[0].Hash {
		t.Fatalf("an exact re-delivery of committed event 1 was answered %d — the shipper's documented retry path would wedge", again.Code)
	}
	if lines := collectorStreamLines(t, stateDir, identity, "sitea"); lines != 1 {
		t.Fatalf("the idempotent re-ack appended %d lines, want the single committed one", lines)
	}
	if reasons := collectorAlarmReasons(t, stateDir); len(reasons) != 0 {
		t.Fatalf("the idempotent re-ack raised alarms: %v", reasons)
	}

	// A replay from deeper history (a lagging .shipped mark on restart) re-acks too, and the
	// next fresh event still chains.
	if response := postCollectorEvent(t, handler, certificate, "sitea", events[1]); response.Code != http.StatusNoContent {
		t.Fatalf("the next fresh event was refused after a re-ack: %s", response.Body.String())
	}
}

func TestCollectorRejectsOutOfOrderAndUnchainedEvents(t *testing.T) {
	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	handler := collector.Handler()
	certificate := collectorTestCertificate(t, "sitea-daemon")
	identity := fingerprintOf(certificate)

	// A gap: event 3 against an empty stream — chained honestly from genesis, still refused.
	gap := collectorChainedEvents(3, "legit")
	if response := postCollectorEvent(t, handler, certificate, "sitea", gap[2]); response.Code != http.StatusConflict {
		t.Fatalf("out-of-order event 3 on an empty stream was answered %d, want 409: %s", response.Code, response.Body.String())
	}
	// Sequence zero is never a link in this chain.
	zero := gap[0]
	zero.Sequence = 0
	zero.Hash = eventHash(zero)
	if response := postCollectorEvent(t, handler, certificate, "sitea", zero); response.Code != http.StatusConflict {
		t.Fatalf("event 0 was answered %d, want 409", response.Code)
	}
	if lines := collectorStreamLines(t, stateDir, identity, "sitea"); lines != 0 {
		t.Fatalf("refused events were stored anyway: %d lines", lines)
	}
	reasons := collectorAlarmReasons(t, stateDir)
	if len(reasons) < 2 {
		t.Fatalf("out-of-order refusals raised %d alarms, want one per refusal: %v", len(reasons), reasons)
	}

	// An event that does not chain onto the committed copy: previous_hash names a hash the
	// stream never committed.
	if response := postCollectorEvent(t, handler, certificate, "sitea", gap[0]); response.Code != http.StatusNoContent {
		t.Fatalf("fixture event was refused: %s", response.Body.String())
	}
	unchained := gap[1]
	unchained.PreviousHash = "sha256:" + strings.Repeat("11", 32)
	unchained.Hash = eventHash(unchained)
	if response := postCollectorEvent(t, handler, certificate, "sitea", unchained); response.Code != http.StatusConflict {
		t.Fatalf("an event chaining onto a hash the stream never committed was answered %d, want 409", response.Code)
	}
	if !containsSubstring(collectorAlarmReasons(t, stateDir), "does not chain onto the committed copy") {
		t.Fatal("the unchained event was rejected without the chain alarm")
	}
	if sequence, _ := getCollectorPosition(t, handler, certificate, "sitea"); sequence != 1 {
		t.Fatalf("refused events moved the head to %d", sequence)
	}
}

func TestCollectorRejectsAForgedHashBeforeStoring(t *testing.T) {
	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	handler := collector.Handler()
	certificate := collectorTestCertificate(t, "sitea-daemon")
	identity := fingerprintOf(certificate)

	forged := collectorChainedEvents(1, "legit")[0]
	forged.Principal = "attacker" // content changed, claimed hash left as the original's
	response := postCollectorEvent(t, handler, certificate, "sitea", forged)
	if response.Code != http.StatusConflict {
		t.Fatalf("an event whose hash does not bind its content was answered %d, want 409: %s", response.Code, response.Body.String())
	}
	if lines := collectorStreamLines(t, stateDir, identity, "sitea"); lines != 0 {
		t.Fatalf("the forged event was stored: %d lines", lines)
	}
	if !containsSubstring(collectorAlarmReasons(t, stateDir), "does not bind its content") {
		t.Fatal("the forged event was rejected without its alarm")
	}
	if sequence, hash := getCollectorPosition(t, handler, certificate, "sitea"); sequence != 0 || hash != "" {
		t.Fatalf("a refused event left the stream at (%d, %s)", sequence, hash)
	}
}

func TestCollectorRefusesMalformedBodies(t *testing.T) {
	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	handler := collector.Handler()
	certificate := collectorTestCertificate(t, "sitea-daemon")
	identity := fingerprintOf(certificate)

	fixture := collectorChainedEvents(1, "legit")[0]
	valid, _ := json.Marshal(fixture)
	post := func(body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(body))
		request.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	// Two documents in one body: the second answer travels alongside the checked one.
	if response := post(string(valid) + string(valid)); response.Code != http.StatusBadRequest {
		t.Fatalf("a two-document body was answered %d, want 400", response.Code)
	}
	// An unknown field is not part of the audit contract.
	if response := post(strings.Replace(string(valid), `"operation":"op"`, `"operation":"op","extra":1`, 1)); response.Code != http.StatusBadRequest {
		t.Fatalf("an unknown-field body was answered %d, want 400", response.Code)
	}
	// The contract's size bound, one byte past it.
	if response := post(string(valid) + strings.Repeat(" ", maxCollectorEventBody)); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("an oversized body was answered %d, want 413", response.Code)
	}
	// A hash that is not the sha256:… shape at all — the shape check runs before any chain
	// arithmetic, and its refusal is a 400, distinct from the 409 the chain checks answer.
	misshapen := strings.Replace(string(valid), fixture.Hash, "not-a-hash", 1)
	if response := post(misshapen); response.Code != http.StatusBadRequest {
		t.Fatalf("a misshapen hash was answered %d, want 400", response.Code)
	}
	// Key-material markers in an event field: the collector re-runs the journal's own
	// write-time refusal (validateDraft). The event's hash is RECOMPUTED over the leaky
	// content so the marker check — not the hash-bind check — is the one under test.
	leakyEvent := fixture
	leakyEvent.Principal = "-----BEGIN PRIVATE KEY----- canary"
	leakyEvent.Hash = eventHash(leakyEvent)
	if response := postCollectorEvent(t, handler, certificate, "sitea", leakyEvent); response.Code != http.StatusBadRequest {
		t.Fatalf("an event carrying a key-material marker was answered %d, want 400", response.Code)
	}
	if !containsSubstring(collectorAlarmReasons(t, stateDir), "unsafe audit metadata") {
		t.Fatal("the key-material event was refused without the field-validation alarm")
	}
	if lines := collectorStreamLines(t, stateDir, identity, "sitea"); lines != 0 {
		t.Fatalf("malformed bodies were stored: %d lines", lines)
	}
}

// The sink's site becomes an HTTP header value, so header-hostile sites are refused at
// construction rather than smuggled onto the wire.
func TestHTTPSinkRefusesHeaderHostileSites(t *testing.T) {
	client := &http.Client{}
	for _, site := range []string{"two\r\nlines", strings.Repeat("s", 65)} {
		if _, err := NewHTTPSink("https://collector.test", client, time.Second, site); err == nil {
			t.Fatalf("site %q was accepted by the sink constructor", site)
		}
	}
	if _, err := NewHTTPSink("https://collector.test", client, time.Second, "sitea"); err != nil {
		t.Fatalf("an ordinary site was refused: %v", err)
	}
}

func TestCollectorRefusesUnauthenticatedRequests(t *testing.T) {
	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	handler := collector.Handler()

	body, _ := json.Marshal(collectorChainedEvents(1, "legit")[0])
	request := httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader(string(body))) // no TLS state at all
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("an event with no client certificate was answered %d, want 401", recorder.Code)
	}

	position := httptest.NewRequest(http.MethodGet, "/v1/stream-position", nil)
	positionRecorder := httptest.NewRecorder()
	handler.ServeHTTP(positionRecorder, position)
	if positionRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("a position request with no client certificate was answered %d, want 401", positionRecorder.Code)
	}
	if reasons := collectorAlarmReasons(t, stateDir); len(reasons) != 2 {
		t.Fatalf("unauthenticated requests raised %d alarms, want one per endpoint", len(reasons))
	}
	// An identity-less request must not have created a stream directory either.
	if entries, _ := os.ReadDir(filepath.Join(stateDir, streamsDirName)); len(entries) != 0 {
		t.Fatalf("an unauthenticated request created state: %d entries", len(entries))
	}
}

func TestCollectorValidatesTheSiteHeaderBeforeItTouchesTheFileSystem(t *testing.T) {
	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	handler := collector.Handler()
	certificate := collectorTestCertificate(t, "sitea-daemon")

	event := collectorChainedEvents(1, "legit")[0]
	for _, site := range []string{"../escape", "with/slash", strings.Repeat("s", 65), "space in it"} {
		if response := postCollectorEvent(t, handler, certificate, site, event); response.Code != http.StatusBadRequest {
			t.Fatalf("site %q was answered %d, want 400", site, response.Code)
		}
	}
	entries, err := os.ReadDir(filepath.Join(stateDir, streamsDirName))
	if err != nil || len(entries) != 0 {
		t.Fatalf("an invalid site header created filesystem state: %d entries (%v)", len(entries), err)
	}
	if !containsSubstring(collectorAlarmReasons(t, stateDir), "invalid site header") {
		t.Fatal("an invalid site header was refused without its alarm")
	}
}

func TestCollectorKeysStreamsByIdentityAndSite(t *testing.T) {
	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	handler := collector.Handler()

	sitea := collectorTestCertificate(t, "sitea-daemon")
	siteb := collectorTestCertificate(t, "siteb-daemon")

	siteaEvents := collectorChainedEvents(2, "legit")
	for _, event := range siteaEvents {
		if response := postCollectorEvent(t, handler, sitea, "sitea", event); response.Code != http.StatusNoContent {
			t.Fatalf("sitea event %d refused: %s", event.Sequence, response.Body.String())
		}
	}
	otherEvents := collectorChainedEvents(1, "legit")
	if response := postCollectorEvent(t, handler, siteb, "sitea", otherEvents[0]); response.Code != http.StatusNoContent {
		t.Fatalf("second identity's event refused: %s", response.Body.String())
	}
	if response := postCollectorEvent(t, handler, sitea, "siteb", otherEvents[0]); response.Code != http.StatusNoContent {
		t.Fatalf("second site's event refused: %s", response.Body.String())
	}

	// Each stream holds its own head; neither the certificate nor the site alone is the key.
	if sequence, _ := getCollectorPosition(t, handler, sitea, "sitea"); sequence != 2 {
		t.Fatalf("sitea/sitea head is %d, want 2", sequence)
	}
	if sequence, _ := getCollectorPosition(t, handler, siteb, "sitea"); sequence != 1 {
		t.Fatalf("siteb/sitea head is %d, want 1", sequence)
	}
	if sequence, _ := getCollectorPosition(t, handler, sitea, "siteb"); sequence != 1 {
		t.Fatalf("sitea/siteb head is %d, want 1", sequence)
	}
	// And on disk the three streams are three files.
	streamFiles, err := filepath.Glob(filepath.Join(stateDir, streamsDirName, "*", streamFilePrefix+"*"+streamFileSuffix))
	if err != nil || len(streamFiles) != 3 {
		t.Fatalf("expected 3 stream files, found %d (%v)", len(streamFiles), streamFiles)
	}
}

func TestCollectorRefusesToLoadStateItCannotVerify(t *testing.T) {
	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	certificate := collectorTestCertificate(t, "sitea-daemon")
	identity := fingerprintOf(certificate)
	for _, event := range collectorChainedEvents(2, "legit") {
		if response := postCollectorEvent(t, collector.Handler(), certificate, "sitea", event); response.Code != http.StatusNoContent {
			t.Fatalf("fixture event %d refused: %s", event.Sequence, response.Body.String())
		}
	}
	if err := collector.Close(); err != nil {
		t.Fatal(err)
	}

	// THE CONTENT-REWRITE TEST (the hash-chain lesson, applied to the collector's own
	// store): rewrite one field of the last committed event and leave every recorded hash
	// byte-identical. A loader that does not re-verify the chain adopts the rewrite.
	path := filepath.Join(stateDir, streamsDirName, identity, streamFilePrefix+"sitea"+streamFileSuffix)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := strings.Replace(string(contents), `"legit"`, `"attacker"`, 1)
	if rewritten == string(contents) {
		t.Fatal("the rewrite fixture did not change the file")
	}
	if err := os.WriteFile(path, []byte(rewritten), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCollector(stateDir); err == nil {
		t.Fatal("a collector whose stored chain does not verify loaded anyway — the off-host memory must refuse its own tampering")
	} else if !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("the refusal does not name the defect: %v", err)
	}

	// State no collector wrote is refused at load, not adopted as a stream.
	unclean := t.TempDir()
	if err := os.MkdirAll(filepath.Join(unclean, streamsDirName, "not-a-fingerprint"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCollector(unclean); err == nil {
		t.Fatal("a state directory holding a directory no collector wrote loaded anyway")
	}
}

// swapHandler lets the E2E replace the collector behind a live server (the restart arm)
// without tearing the listener down, which would invalidate every sink URL handed out.
type swapHandler struct {
	mu    sync.Mutex
	inner http.Handler
}

func (handler *swapHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	handler.mu.Lock()
	inner := handler.inner
	handler.mu.Unlock()
	inner.ServeHTTP(writer, request)
}

func (handler *swapHandler) set(inner http.Handler) {
	handler.mu.Lock()
	handler.inner = inner
	handler.mu.Unlock()
}

// The E2E reconciliation matrix: the REAL collector behind the REAL mTLS wire, driven by the
// REAL HTTPSink and the REAL ReconcileContinuity. reconcile_test.go proves each rule with a
// scripted sink; this proves the rules survive contact with the actual protocol halves.
//
// ORDERING IS LOAD-BEARING: the continuity arm ships three events and every later arm
// reconciles against that committed head. None of the later journals ship — the arms where
// the local journal is rewritten, shortened, or forged must NOT teach the collector their
// content, so they are recorded with a nil sink and only reconciled.
func TestReconciliationAgainstARealCollector(t *testing.T) {
	authority, clientCertificate, clientKey, serverTLS := collectorTestTLS(t)
	collectorClient := func() tls.Certificate {
		return tls.Certificate{Certificate: [][]byte{clientCertificate.Raw}, PrivateKey: clientKey}
	}

	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	routing := &swapHandler{inner: collector.Handler()}
	server := httptest.NewUnstartedServer(routing)
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()

	makeSink := func() *HTTPSink {
		client, err := NewMTLSHTTPClient(collectorClient(), authority, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		sink, err := NewHTTPSink(server.URL, client, 5*time.Second, "sitea")
		if err != nil {
			t.Fatal(err)
		}
		return sink
	}
	recordEvents := func(path string, count int, principal string, sink Sink) []Event {
		t.Helper()
		recorder, err := Open(path, sink)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < count; i++ {
			draft := Draft{
				Timestamp: time.Date(2026, 9, 12, 11, 0, i, 0, time.UTC),
				RequestID: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
				Principal: principal, Decision: "allow", ObjectID: "o", Purpose: "pu",
				Operation: "op", DeviceID: "d", Outcome: "ok",
				RegistryDigest: "aa" + strings.Repeat("bb", 31),
				PolicyDigest:   "cc" + strings.Repeat("dd", 31),
				RBACDigest:     "ee" + strings.Repeat("ff", 31),
			}
			if err := recorder.Record(context.Background(), draft, sink != nil); err != nil {
				t.Fatalf("record %d: %v", i, err)
			}
		}
		if err := recorder.Close(); err != nil {
			t.Fatal(err)
		}
		events, err := Verify(path)
		if err != nil {
			t.Fatalf("fixture journal does not verify: %v", err)
		}
		return events
	}
	refusal := func(t *testing.T, journalPath string, messagePart string) {
		t.Helper()
		if err := ReconcileContinuity(context.Background(), journalPath, makeSink(), "sitea"); err == nil {
			t.Fatalf("reconciliation passed where %q was required", messagePart)
		} else if !strings.Contains(err.Error(), messagePart) {
			t.Fatalf("the refusal does not name %q: %v", messagePart, err)
		}
	}
	// A private collector for the arms that need an EMPTY off-host memory.
	freshSink := func(t *testing.T) *HTTPSink {
		fresh, err := OpenCollector(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		freshServer := httptest.NewUnstartedServer(fresh.Handler())
		freshServer.TLS = serverTLS
		freshServer.StartTLS()
		t.Cleanup(freshServer.Close)
		client, err := NewMTLSHTTPClient(collectorClient(), authority, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		sink, err := NewHTTPSink(freshServer.URL, client, 5*time.Second, "sitea")
		if err != nil {
			t.Fatal(err)
		}
		return sink
	}
	// AN ATTACKER REWRITES THE MARKS TO MATCH THE REWRITE — the whole premise of row 2/row
	// 4 in the #220 table. Every arm below that replaces a journal must replace its
	// sidecars coherently too: a stale sidecar is caught by VerifyIntegrity locally and
	// never reaches the off-host rule under test.
	installForgedJournal := func(t *testing.T, path, source string, events []Event, shippedThrough int) {
		t.Helper()
		if err := os.Rename(source, path); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(source+highWaterSuffix, path+highWaterSuffix); err != nil {
			t.Fatal(err)
		}
		// The forged .shipped claims the collector acknowledged the rewritten history.
		if err := writeShippedMark(path, highWaterMark{Sequence: uint64(shippedThrough), Hash: events[shippedThrough-1].Hash}); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("fresh stream: empty journal, collector holds nothing", func(t *testing.T) {
		path, _ := reconcileJournal(t, 0)
		if err := ReconcileContinuity(context.Background(), path, freshSink(t), "sitea"); err != nil {
			t.Fatalf("a fresh stream was refused: %v", err)
		}
	})

	t.Run("continuity after the real wire, including a stale shipped mark", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		events := recordEvents(path, 3, "legit", makeSink())
		// A stale mark only ever LAGS, and its hash must still match the event it names —
		// the zeros-hash test helper would be caught locally, which is not this arm.
		if err := writeShippedMark(path, highWaterMark{Sequence: 1, Hash: events[0].Hash}); err != nil {
			t.Fatal(err)
		}
		if err := ReconcileContinuity(context.Background(), path, makeSink(), "sitea"); err != nil {
			t.Fatalf("continuity was refused: %v", err)
		}
		// The collector's head is what the daemon shipped, not what the stale mark says.
		sequence, _, err := makeSink().CommittedHead(context.Background(), "sitea")
		if err != nil || sequence != 3 {
			t.Fatalf("committed head after shipping 3 events is (%d, %v), want 3", sequence, err)
		}
	})

	t.Run("heads survive a collector restart over the wire", func(t *testing.T) {
		if err := collector.Close(); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenCollector(stateDir)
		if err != nil {
			t.Fatalf("collector state does not survive restart: %v", err)
		}
		collector = reopened
		routing.set(reopened.Handler())
		sequence, hash, err := makeSink().CommittedHead(context.Background(), "sitea")
		if err != nil || sequence != 3 || !strings.HasPrefix(hash, "sha256:") {
			t.Fatalf("after restart the head is (%d, %s, %v), want the pre-restart (3, sha256:…)", sequence, hash, err)
		}
	})

	t.Run("collector forgot: empty memory against a shipped journal", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		recordEvents(path, 2, "legit", nil)
		if err := ReconcileContinuity(context.Background(), path, freshSink(t), "sitea"); err == nil {
			t.Fatal("a collector that forgot what this host shipped was accepted as a fresh stream")
		} else if !strings.Contains(err.Error(), "forgot what this host already shipped") {
			t.Fatalf("the refusal does not name collector-forgot: %v", err)
		}
	})

	t.Run("journal rewrite: valid chain, different content (row 2)", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		recordEvents(path, 3, "legit", makeSink())
		// The rewrite: an honest recorder, marks rewritten to match, content that differs
		// from event 1 on. It is never shipped — reconciliation alone must refuse it.
		rewrittenPath := filepath.Join(t.TempDir(), "rewritten.jsonl")
		rewritten := recordEvents(rewrittenPath, 4, "rewritten", nil)
		installForgedJournal(t, path, rewrittenPath, rewritten, 3)
		refusal(t, path, "does not match what this site already shipped")
	})

	t.Run("missing history: the host holds less than it shipped", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		recordEvents(path, 3, "legit", makeSink())
		shorterPath := filepath.Join(t.TempDir(), "shorter.jsonl")
		shorter := recordEvents(shorterPath, 2, "legit", nil)
		installForgedJournal(t, path, shorterPath, shorter, 2)
		refusal(t, path, "host holds less history")
	})

	t.Run("shipped mark ahead of the collector", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		recordEvents(path, 3, "legit", makeSink()) // the shipper wrote an honest mark at 3
		// A mark ahead of the COLLECTOR but consistent with the LOCAL journal: the
		// collector was restored from a backup taken before event 3 — its memory ends at
		// 2, the journal and its marks are honest, and the disagreement is the incident.
		// (A forged mark past the journal itself is refused by VerifyIntegrity before
		// this rule, which is a different detector doing its job.)
		streamFile := filepath.Join(stateDir, streamsDirName, fingerprintOf(clientCertificate), streamFilePrefix+"sitea"+streamFileSuffix)
		if err := truncateFileToLines(t, streamFile, 2); err != nil {
			t.Fatal(err)
		}
		if err := collector.Close(); err != nil {
			t.Fatal(err)
		}
		restored, err := OpenCollector(stateDir)
		if err != nil {
			t.Fatalf("the truncated collector state does not load: %v", err)
		}
		collector = restored
		routing.set(restored.Handler())
		refusal(t, path, "ahead of the collector")
	})
}

// truncateFileToLines rewrites a file keeping its first n lines — the shape of a collector
// restored from a backup that predates the tail.
func truncateFileToLines(t *testing.T, path string, n int) error {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimSuffix(string(contents), "\n"), "\n")
	if len(lines) <= n {
		return fmt.Errorf("test fixture: %s holds %d lines, cannot truncate to %d", path, len(lines), n)
	}
	return os.WriteFile(path, []byte(strings.Join(lines[:n], "\n")+"\n"), 0o600)
}

// collectorTestTLS builds a one-test CA with a server TLS configuration (certificate for
// 127.0.0.1, client certificates REQUIRED and chain-verified) and a client certificate.
func collectorTestTLS(t *testing.T) (authority *x509.CertPool, clientCertificate *x509.Certificate, clientKey ed25519.PrivateKey, serverTLS *tls.Config) {
	t.Helper()
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "collector-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	authority = x509.NewCertPool()
	authority.AddCert(caCertificate)

	issue := func(commonName string, extKeyUsage x509.ExtKeyUsage, serverNames bool) (*x509.Certificate, ed25519.PrivateKey) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: commonName},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{extKeyUsage},
		}
		if serverNames {
			template.DNSNames = []string{"localhost"}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, public, caPrivate)
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return certificate, private
	}
	serverCertificate, serverKey := issue("collector-test-server", x509.ExtKeyUsageServerAuth, true)
	clientCertificate, clientKey = issue("sitea-daemon", x509.ExtKeyUsageClientAuth, false)
	serverTLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverCertificate.Raw}, PrivateKey: serverKey}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    authority,
	}
	return authority, clientCertificate, clientKey, serverTLS
}
