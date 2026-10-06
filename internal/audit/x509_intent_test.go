package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestX509IntentIsCompleteAndHashBound(t *testing.T) {
	base := draft("018f0000-0000-7000-8000-000000000001", "allow")
	base.X509ProfileID = "synthetic-profile-v1"
	base.PayloadDigest = "sha256:" + strings.Repeat("d", 64)
	base.ArtifactKind = "certificate"
	base.KeyFingerprint = "sha256:" + strings.Repeat("e", 64)
	for name, edit := range map[string]func(*Draft){
		"missing-profile": func(d *Draft) { d.X509ProfileID = "" },
		"missing-payload": func(d *Draft) { d.PayloadDigest = "" },
		"missing-kind":    func(d *Draft) { d.ArtifactKind = "" },
		"missing-key":     func(d *Draft) { d.KeyFingerprint = "" },
		"opaque-kind":     func(d *Draft) { d.ArtifactKind = "digest" },
		"unsafe-profile":  func(d *Draft) { d.X509ProfileID = "synthetic\nprofile" },
		"bad-digest":      func(d *Draft) { d.PayloadDigest = "sha256:unverified" },
		"bad-key":         func(d *Draft) { d.KeyFingerprint = "sha256:unverified" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			edit(&changed)
			if validateDraft(changed) == nil {
				t.Fatal("incomplete or unsafe signing intent accepted")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	if err := recorder.Record(context.Background(), base, false); err != nil {
		t.Fatal(err)
	}
	events, err := VerifyIntegrity(path)
	if err != nil || len(events) != 1 {
		t.Fatal("X.509 event did not verify", err)
	}
	event := events[0]
	if event.X509ProfileID != base.X509ProfileID || event.PayloadDigest != base.PayloadDigest || event.ArtifactKind != base.ArtifactKind || event.KeyFingerprint != base.KeyFingerprint {
		t.Fatal("signing intent was dropped from the durable event")
	}
	for _, edit := range []func(*Event){
		func(e *Event) { e.X509ProfileID = "synthetic-profile-v2" },
		func(e *Event) { e.PayloadDigest = "sha256:" + strings.Repeat("f", 64) },
		func(e *Event) { e.ArtifactKind = "crl" },
		func(e *Event) { e.KeyFingerprint = "sha256:" + strings.Repeat("f", 64) },
	} {
		changed := event
		edit(&changed)
		if eventHash(changed) == event.Hash {
			t.Fatal("signing intent is not bound into the event hash")
		}
	}
}

func TestX509OptionalFieldsPreserveHistoricalEventBytes(t *testing.T) {
	event := Event{
		Sequence: 1, Timestamp: time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC),
		RequestID: "synthetic-request", Principal: "synthetic-principal", Decision: "allow",
		Operation: "sign", Outcome: "success", RegistryDigest: "synthetic-registry",
		PolicyDigest: "synthetic-policy", RBACDigest: "synthetic-rbac",
		PreviousHash: "historical-previous", Hash: "historical-hash",
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	const historical = `{"sequence":1,"timestamp":"2026-09-12T10:00:00Z","request_id":"synthetic-request","principal":"synthetic-principal","decision":"allow","operation":"sign","outcome":"success","latency_ms":0,"registry_digest":"synthetic-registry","policy_digest":"synthetic-policy","rbac_digest":"synthetic-rbac","previous_hash":"historical-previous","hash":"historical-hash"}`
	if string(encoded) != historical {
		t.Fatal("optional signing intent changed historical event bytes")
	}
}

func TestX509CollectorValidatesAndPersistsIntent(t *testing.T) {
	stateDir := t.TempDir()
	collector, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer collector.Close()
	certificate := collectorTestCertificate(t, "synthetic-x509-daemon")
	event := collectorChainedEvents(1, "synthetic-principal")[0]
	event.Operation = "sign"
	event.X509ProfileID = "synthetic-profile-v1"
	event.PayloadDigest = "sha256:" + strings.Repeat("d", 64)
	event.ArtifactKind = "certificate"
	event.KeyFingerprint = "sha256:" + strings.Repeat("e", 64)
	event.Hash = eventHash(event)
	invalid := event
	invalid.KeyFingerprint = ""
	invalid.Hash = eventHash(invalid)
	if response := postCollectorEvent(t, collector.Handler(), certificate, "synthetic", invalid); response.Code != http.StatusBadRequest {
		t.Fatalf("collector accepted partial intent with valid event hash: %d", response.Code)
	}
	response := postCollectorEvent(t, collector.Handler(), certificate, "synthetic", event)
	if response.Code != http.StatusNoContent || response.Header().Get("X-Regalia-Audit-Hash") != event.Hash {
		t.Fatalf("complete signing intent was not durably acknowledged: %d", response.Code)
	}
	if err := collector.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenCollector(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if sequence, hash := getCollectorPosition(t, reopened.Handler(), certificate, "synthetic"); sequence != 1 || hash != event.Hash {
		t.Fatal("collector lost the acknowledged signing-intent event on restart")
	}
}

func TestX509IntentFieldShapes(t *testing.T) {
	base := draft("018f0000-0000-7000-8000-000000000001", "allow")
	base.X509ProfileID = strings.Repeat("a", 64)
	base.PayloadDigest = "sha256:" + strings.Repeat("d", 64)
	base.ArtifactKind = "crl"
	base.KeyFingerprint = "sha256:" + strings.Repeat("e", 64)
	if err := validateDraft(base); err != nil {
		t.Fatal("valid field boundaries were refused", err)
	}
	for name, edit := range map[string]func(*Draft){
		"65-byte-profile":      func(d *Draft) { d.X509ProfileID += "a" },
		"profile-space":        func(d *Draft) { d.X509ProfileID = "synthetic profile" },
		"profile-leading-dash": func(d *Draft) { d.X509ProfileID = "-synthetic" },
		"short-digest":         func(d *Draft) { d.PayloadDigest = d.PayloadDigest[:len(d.PayloadDigest)-1] },
		"long-digest":          func(d *Draft) { d.PayloadDigest += "d" },
		"upper-key":            func(d *Draft) { d.KeyFingerprint = strings.ToUpper(d.KeyFingerprint) },
		"wrong-operation":      func(d *Draft) { d.Operation = "decrypt" },
	} {
		t.Run(name, func(t *testing.T) {
			item := base
			edit(&item)
			if err := validateDraft(item); err == nil || err.Error() != "invalid X.509 signing intent" {
				t.Fatal("invalid shape was not refused as signing intent", err)
			}
		})
	}
}
