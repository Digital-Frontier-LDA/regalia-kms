package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/admission"
	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/server"
)

// THE DAEMON MUST ACTUALLY ASK. internal/admission could be complete and tested and still have no
// caller: the daemon would then serve with no runtime lease and every admission test would be green,
// which is how internal/fencing once sat unwired. This fails if admitRunner stops gating the runner.
//
// The file here is owned by whoever runs the test, so the gate that admits is built with that owner;
// the wiring under test (admitRunner) is exercised on the refusing side, which needs no file at all,
// and on a file that root does not own.
func TestAdmitRunnerRefusesWorkUntilTheNodeIsAdmitted(t *testing.T) {
	directory := t.TempDir()
	settings := config.Config{
		RuntimeAdmission: config.RuntimeAdmissionRequired, NodeID: "site-a",
		RuntimeAdmissionPath: filepath.Join(directory, "admission.json"), BootSessionPath: filepath.Join(directory, "boot-session"),
	}
	var seen []admission.Status
	base := &passthroughRunner{}
	runner, gate, err := admitRunner(settings, base, func(status admission.Status) { seen = append(seen, status) })
	if err != nil {
		t.Fatalf("the daemon refused to start before the lease service had written its file: %v", err)
	}
	if gate == nil {
		t.Fatal("runtime admission is required but contributed no gate: the node would report itself ready with no lease")
	}
	// No file yet: not admitted, which is an answer and not an error.
	if gate.Ready(context.Background()) {
		t.Fatal("a node with no admission file reported ready")
	}
	if err := runner.Run(context.Background(), func(context.Context) error { return nil }); !errors.Is(err, admission.ErrNotAdmitted) {
		t.Fatalf("a node with no admission file ran an operation (err=%v)", err)
	}
	if base.ran {
		t.Fatal("the ungated runner was reached on a node that is not admitted")
	}
	if len(seen) != 1 || seen[0].Admitted || !strings.Contains(seen[0].Reason, "the admission file") {
		t.Fatalf("transitions = %+v, want one refusal naming the admission file", seen)
	}
	// A file that says "admitted" but that root did not write is still a refusal (unless the test IS root).
	now, err := admission.Boottime()
	if err != nil {
		t.Fatal(err)
	}
	boot, err := admission.KernelBootID()
	if err != nil {
		t.Fatal(err)
	}
	session := strings.Repeat("5e", 32)
	document, _ := json.Marshal(map[string]any{
		"schema": admission.Schema, "node_id": "site-a", "session_id": session, "boot_id": boot, "epoch": 3,
		"manifest_digest": strings.Repeat("d1", 32), "lease_issued_at": "2026-10-02T09:00:00Z",
		"requested_boottime_ms": now - 1000, "serve_until_boottime_ms": now + 60_000, "reason": "",
	})
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string][]byte{"admission.json": document, "boot-session": []byte(session + "\n")} {
		if err := os.WriteFile(filepath.Join(directory, name), contents, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(directory, name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getuid() != 0 {
		if gate.Ready(context.Background()) {
			t.Fatal("an admission file root did not write admitted the node")
		}
		return
	}
	// As root (CI's privileged job): the same wiring admits, and the runner reaches the executor.
	if !gate.Ready(context.Background()) {
		t.Fatalf("a current admission file written by root did not admit the node: %+v", gate.Check(context.Background()))
	}
	if err := runner.Run(context.Background(), func(context.Context) error { return nil }); err != nil || !base.ran {
		t.Fatalf("an admitted node was refused: err=%v ran=%v", err, base.ran)
	}
}

// A lab host, and a host with no token, keep working and gain no readiness dependency they have no
// lease service to satisfy.
func TestWithoutRequiredAdmissionTheRunnerIsUnchanged(t *testing.T) {
	for _, settings := range []config.Config{{}, {RuntimeAdmission: config.RuntimeAdmissionDisabledForLab}} {
		base := &passthroughRunner{}
		runner, gate, err := admitRunner(settings, base, nil)
		if err != nil || gate != nil {
			t.Fatalf("admitRunner(%q) = gate %v, err %v", settings.RuntimeAdmission, gate, err)
		}
		if err := runner.Run(context.Background(), func(context.Context) error { return nil }); err != nil || !base.ran {
			t.Fatalf("an ungated host stopped running operations: err=%v ran=%v", err, base.ran)
		}
	}
}

// Required and unusable is a startup refusal: a node that silently never becomes ready looks the
// same as one that is correctly waiting for its lease.
func TestRequiredAdmissionWithAnUnusableSettingRefusesAtStartup(t *testing.T) {
	for name, settings := range map[string]config.Config{
		"a relative path": {RuntimeAdmission: config.RuntimeAdmissionRequired, NodeID: "site-a", RuntimeAdmissionPath: "admission.json", BootSessionPath: "/run/regalia/boot-session"},
		"no node ID":      {RuntimeAdmission: config.RuntimeAdmissionRequired, RuntimeAdmissionPath: "/run/regalia/admission.json", BootSessionPath: "/run/regalia/boot-session"},
	} {
		if _, _, err := admitRunner(settings, &passthroughRunner{}, nil); err == nil || !strings.Contains(err.Error(), "runtime admission") {
			t.Fatalf("%s: admitRunner = %v, want a startup refusal", name, err)
		}
	}
}

// READINESS MUST DEPEND ON IT. The probe was added to Dependencies; this is what stops it being
// populated in main and read nowhere, which is exactly what happened to the fencing probe once.
func TestReadinessIsFalseWhileTheNodeIsNotAdmitted(t *testing.T) {
	ready := readyProbe(true)
	dependencies := server.Dependencies{Policy: ready, Registry: ready, Audit: ready, Token: ready}
	if !readinessOf(server.NewRequired(dependencies)) {
		t.Fatal("the fixture is not ready without admission")
	}
	dependencies.Admission = readyProbe(false)
	if readinessOf(server.NewRequired(dependencies)) {
		t.Fatal("a node that is not admitted reported ready: a load balancer would keep sending it work")
	}
	dependencies.Admission = ready
	if !readinessOf(server.NewRequired(dependencies)) {
		t.Fatal("an admitted node reported not ready")
	}
}

// THE EXEMPTION MUST NOT BE A HOLE. config.Validate lets a configuration leave runtime_admission out
// when it has no token, so that a host which serves nothing need not state how it serves. That is
// only safe if "no token" means "no key operation at all". Three things hold it:
//
//   - every configuration that gives the daemon a backend is refused without the setting;
//   - every configuration accepted without the setting gives the daemon no backend;
//   - a daemon with no backend answers every key operation with its ordinary refusal.
func TestNoTokenMeansNoKeyOperation(t *testing.T) {
	routing := func(cfg *config.Config) {
		cfg.RegistryPath, cfg.Site = "/etc/regalia/registry.json", "sitea"
		cfg.PolicyPath, cfg.PolicyStatePath = "/etc/regalia/policy.json", "/var/lib/regalia/policy-state.jsonl"
		cfg.RBACPolicyPath = "/etc/regalia/rbac.json"
	}
	withBackend := map[string]func(*config.Config){
		"a PKCS#11 token": func(cfg *config.Config) {
			routing(cfg)
			cfg.PKCS11ModulePath = "/usr/lib/opensc-pkcs11.so"
			cfg.PINPaths = map[string]string{"hsm-sitea": "/run/credentials/regalia-kms.service/hsm-sitea.pin"}
			cfg.SecureChannelEvidence, cfg.AuditJournalPath = "/etc/regalia/secure-channel.json", "/var/lib/regalia/audit.jsonl"
		},
		"a YubiKey": func(cfg *config.Config) {
			routing(cfg)
			cfg.YubiKeyDevices = map[string]string{"yubi-a": "25923905"}
			cfg.PINPaths = map[string]string{"yubi-a": "/run/credentials/regalia-kms.service/yubi-a.pin"}
			cfg.AuditJournalPath = "/var/lib/regalia/audit.jsonl"
		},
	}
	for name, build := range withBackend {
		cfg := config.Default()
		build(&cfg)
		if !tokenConfigured(cfg) {
			t.Fatalf("%s: the fixture gives the daemon no backend", name)
		}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "must state runtime_admission") {
			t.Fatalf("%s with runtime_admission left out: Validate = %v, want the refusal", name, err)
		}
		cfg.RuntimeAdmission = config.RuntimeAdmissionDisabledForLab
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s: the fixture is not otherwise valid: %v", name, err)
		}
	}
	// Accepted without the setting: no backend, whatever else is configured.
	withoutBackend := map[string]func(*config.Config){
		"nothing at all": func(*config.Config) {},
		"routing, policy and authorization, no token": routing,
		"fencing and a registry": func(cfg *config.Config) {
			cfg.RegistryPath, cfg.Site = "/etc/regalia/registry.json", "sitea"
			cfg.FencingLeasePath, cfg.FencingStatePath, cfg.FencingPublicKeyPath = "/run/regalia/lease.json", "/var/lib/regalia/epochs.jsonl", "/etc/regalia/fencing.pub"
		},
	}
	for name, build := range withoutBackend {
		cfg := config.Default()
		build(&cfg)
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s: Validate = %v", name, err)
		}
		if tokenConfigured(cfg) {
			t.Fatalf("%s: accepted with runtime_admission left out, and the daemon would still build a backend", name)
		}
	}
	// And such a daemon serves no key operation: there is no coordinator to hand one to.
	handler := api.NewHandler(nil)
	identity, _ := url.Parse("spiffe://regalia/workload/e2e")
	expires := time.Now().Add(time.Minute).UTC().Format("2006-01-02T15:04:05Z")
	accepted := `{"object_id":"production-signing","context":{"environment":"production","purpose":"release-signing","expires_at":"` + expires +
		`","nonce":"018f0000000070008000000000000001"},"content_type":"application/vnd.regalia.digest","payload_base64":"` +
		base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}`
	for _, operation := range []string{"sign", "wrap", "unwrap", "certificate-sign", "key-agreement", "release-secret", "seal-envelope"} {
		request := httptest.NewRequest(http.MethodPost, "/v1/operations/"+operation, strings.NewReader(accepted))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Request-ID", "018f0000-0000-7000-8000-000000000001")
		request.Header.Set("Idempotency-Key", "018f0000000070008000000000000001")
		request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{
			SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity},
		}}}}
		recorder := httptest.NewRecorder()
		// behind the authenticator, as in the daemon: the request arrives as an identified workload
		auth.NewAuthenticator("spiffe://regalia/", nil, time.Now, time.Minute).Middleware(handler).ServeHTTP(recorder, request)
		if recorder.Code < 400 || strings.Contains(recorder.Body.String(), "result_base64") {
			t.Fatalf("%s on a daemon with no backend: HTTP %d %s", operation, recorder.Code, recorder.Body.String())
		}
		if operation == "sign" && (recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "DEPENDENCY_UNAVAILABLE")) {
			t.Fatalf("an otherwise accepted sign request on a daemon with no backend: HTTP %d %s, want 503 DEPENDENCY_UNAVAILABLE", recorder.Code, recorder.Body.String())
		}
	}
}

// readinessOf asks the health handler the question a load balancer asks.
func readinessOf(handler http.Handler) bool {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/health/ready", nil))
	return recorder.Code == http.StatusOK
}

type readyProbe bool

func (probe readyProbe) Ready(context.Context) bool { return bool(probe) }
