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
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/admission"
	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/reauth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/yubikey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
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

// THE PROVIDER MUST ACTUALLY BE TOLD. RequireReauthorization can be complete and tested in its own
// package and never called: a returned token would then resume on the old lease, as before #72's
// hook, with every provider test green.
func TestRequiredAdmissionMakesTheTokenProviderWaitForAFreshLease(t *testing.T) {
	directory := t.TempDir()
	gate, err := admission.Open(admission.Options{Path: filepath.Join(directory, "admission.json"), NodeID: "site-a",
		SessionPath: filepath.Join(directory, "boot-session")})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := nitrokey.New(unopenableDriver{}, noPIN{})
	if err != nil {
		t.Fatal(err)
	}
	if err := requireReauthorization(managing(t, "nitrokey-pkcs11", provider), gate, admission.ProcessStart); err != nil {
		t.Fatal(err)
	}
	// A token the provider fails to open is now remembered as gone: the mark only exists once
	// reauthorization has been required.
	binding := registry.Binding{Backend: "nitrokey-pkcs11", DeviceID: "hsm-sitea", DeviceSerial: "serial-1",
		DevAuthFingerprint: "sha256:" + strings.Repeat("a", 64), ObjectID: "01"}
	provider.Healthy(context.Background(), binding)
	if waiting := provider.AwaitingReauthorization(); len(waiting) != 1 || waiting["hsm-sitea"] != -1 {
		t.Fatalf("after requireReauthorization, a token that cannot be opened is not tracked: %v", waiting)
	}
	// Not required, or no PKCS#11 provider: nothing changes and nothing fails.
	untouched, _ := nitrokey.New(unopenableDriver{}, noPIN{})
	if err := requireReauthorization(managing(t, "nitrokey-pkcs11", untouched), nil, admission.ProcessStart); err != nil {
		t.Fatal(err)
	}
	untouched.Healthy(context.Background(), binding)
	if len(untouched.AwaitingReauthorization()) != 0 {
		t.Fatal("a provider on a host with no required admission tracks absences")
	}
}

// managing is a manager holding the given providers: name, provider, name, provider, ...
func managing(t *testing.T, pairs ...any) *backend.Manager {
	t.Helper()
	providers := map[string]backend.Provider{}
	for i := 0; i < len(pairs); i += 2 {
		providers[pairs[i].(string)] = pairs[i+1].(backend.Provider)
	}
	manager, err := backend.New(providers)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

// ungatedProvider can execute key operations and has no reauthorization hook.
type ungatedProvider struct{}

func (ungatedProvider) Execute(context.Context, registry.Route, string, string, string, []byte, []byte) ([]byte, string, error) {
	return nil, "", errors.New("unused")
}
func (ungatedProvider) Healthy(context.Context, registry.Binding) bool { return true }
func (ungatedProvider) Ready(context.Context) bool                     { return true }

// sliceProvider is a provider passed by value whose type cannot be a map key.
type sliceProvider struct {
	ungatedProvider
	devices []string
}

func (sliceProvider) RequireReauthorization(reauth.Gate, func() (int64, error), int64) error {
	return nil
}

// countingProvider records how often it is told.
type countingProvider struct {
	ungatedProvider
	told  int
	since int64
	fail  error
}

func (provider *countingProvider) RequireReauthorization(_ reauth.Gate, _ func() (int64, error), sinceMs int64) error {
	provider.told++
	provider.since = sinceMs
	return provider.fail
}

// THE RULE IS FOR EVERY KEY THE DAEMON SERVES (regalia-kms#72 PoC 12.4). The providers are walked, not
// named, so a provider added later cannot skip the rule by not being mentioned: it stops the daemon.
func TestEveryProviderThatServesKeysIsGatedOrTheDaemonDoesNotStart(t *testing.T) {
	directory := t.TempDir()
	gate, err := admission.Open(admission.Options{Path: filepath.Join(directory, "admission.json"), NodeID: "site-a",
		SessionPath: filepath.Join(directory, "boot-session")})
	if err != nil {
		t.Fatal(err)
	}
	start := func() (int64, error) { return 4321, nil }
	first, second := &countingProvider{}, &countingProvider{}
	if err := requireReauthorization(managing(t, "nitrokey-pkcs11", first, "some-new-token", second), gate, start); err != nil {
		t.Fatal(err)
	}
	if first.told != 1 || second.told != 1 || first.since != 4321 || second.since != 4321 {
		t.Fatalf("told %d and %d times, since %d and %d", first.told, second.told, first.since, second.since)
	}
	// one provider under two backend names (the PKCS#11 provider and the OpenPGP applet) is told once
	shared := &countingProvider{}
	if err := requireReauthorization(managing(t, "nitrokey-pkcs11", shared, nitrokey.OpenPGPAppletBackend, shared), gate, start); err != nil {
		t.Fatal(err)
	}
	if shared.told != 1 {
		t.Fatalf("a provider serving two backends was told %d times: the second would forget what it had seen", shared.told)
	}
	// a provider with no hook, under a name nobody wrote down, stops the daemon and is named
	err = requireReauthorization(managing(t, "nitrokey-pkcs11", &countingProvider{}, "some-new-token", ungatedProvider{}), gate, start)
	if err == nil || !strings.Contains(err.Error(), "some-new-token") {
		t.Fatalf("an ungated provider did not stop the daemon: %v", err)
	}
	// a provider whose hook fails stops the daemon too, with its backend named
	failing := &countingProvider{fail: errors.New("no clock")}
	err = requireReauthorization(managing(t, "nitrokey-pkcs11", failing), gate, start)
	if err == nil || !strings.Contains(err.Error(), "nitrokey-pkcs11") || !strings.Contains(err.Error(), "no clock") {
		t.Fatalf("a failing hook: %v", err)
	}
	// a provider that a map cannot hold as a key is refused, not left to panic when "told once" is asked
	err = requireReauthorization(managing(t, "nitrokey-pkcs11", &countingProvider{}, "some-new-token", sliceProvider{}), gate, start)
	if err == nil || !strings.Contains(err.Error(), "must be a pointer") {
		t.Fatalf("a provider that is not comparable: %v", err)
	}
	// with no admission required nobody is told, gated or not
	quiet := &countingProvider{}
	if err := requireReauthorization(managing(t, "nitrokey-pkcs11", quiet, "some-new-token", ungatedProvider{}), nil, start); err != nil || quiet.told != 0 {
		t.Fatalf("without admission: %v, told %d", err, quiet.told)
	}
	if err := requireReauthorization(nil, gate, start); err != nil {
		t.Fatal(err)
	}
}

// THE EXEMPTIONS ARE WRITTEN DOWN AND MUST SHRINK. A backend named in awaitingReauthorization starts
// with a warning. The moment its provider gains the hook, the name must go: this test then fails.
func TestTheNamedExemptionsAreExactlyTheProvidersThatLackTheHook(t *testing.T) {
	directory := t.TempDir()
	gate, err := admission.Open(admission.Options{Path: filepath.Join(directory, "admission.json"), NodeID: "site-a",
		SessionPath: filepath.Join(directory, "boot-session")})
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(awaitingReauthorization))
	for name := range awaitingReauthorization {
		names = append(names, name)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"yubikey-piv"}) {
		t.Fatalf("exemptions = %v: a new one needs a decision recorded on regalia-kms#72, not only a line here", names)
	}
	// an exempted backend with no hook starts
	if err := requireReauthorization(managing(t, "nitrokey-pkcs11", &countingProvider{}, "yubikey-piv", ungatedProvider{}), gate, admission.ProcessStart); err != nil {
		t.Fatalf("the exempted backend stopped the daemon: %v", err)
	}
	// the providers this build really assembles: each is gated, or exempt and NOT gated
	for name, provider := range assembledProviders(t) {
		_, gated := provider.(reauth.Provider)
		_, exempt := awaitingReauthorization[name]
		switch {
		case gated && exempt:
			t.Errorf("%s now has the reauthorization hook: delete it from awaitingReauthorization, and the interim notes in main.go and deploy/baremetal/README.md", name)
		case !gated && !exempt:
			t.Errorf("%s serves keys with no reauthorization hook and no recorded exemption", name)
		}
	}
}

// assembledProviders is one provider of each concrete type buildHardware registers, under the backend
// names it registers them with. A backend added to buildHardware belongs here too: this is the list the
// exemptions are checked against.
func assembledProviders(t *testing.T) map[string]backend.Provider {
	t.Helper()
	pkcs11, err := nitrokey.New(unopenableDriver{}, noPIN{})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]backend.Provider{
		"nitrokey-pkcs11":             pkcs11,
		nitrokey.OpenPGPAppletBackend: pkcs11,
		"yubikey-piv":                 &yubikey.Provider{},
	}
}

// buildHardware's own text is read: every `providers[...] =` it contains must be a backend that
// assembledProviders lists, so a provider registered there cannot be left out of the check above.
func TestEveryBackendBuildHardwareRegistersIsInTheConformanceList(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	listed := assembledProviders(t)
	names := map[string]string{`"nitrokey-pkcs11"`: "nitrokey-pkcs11", `nitrokey.OpenPGPAppletBackend`: nitrokey.OpenPGPAppletBackend,
		`"yubikey-piv"`: "yubikey-piv"}
	registered := regexp.MustCompile(`providers\[([^\]]+)\]\s*=`).FindAllStringSubmatch(string(source), -1)
	if len(registered) < 3 {
		t.Fatalf("found %d provider registrations in main.go: the pattern no longer matches how they are written", len(registered))
	}
	for _, match := range registered {
		name, known := names[match[1]]
		if _, present := listed[name]; !known || !present {
			t.Errorf("main.go registers a provider under %s, which assembledProviders does not list: add it there, with or without the hook", match[1])
		}
	}
}

// THE DAEMON AND THE LEASE SERVICE MUST MEAN THE SAME MOMENT. The baseline handed to the provider is
// this process's start as the kernel dates it, which is what the lease service reads for the daemon's
// PID; a process that cannot read it falls back to "now" (later: never weaker) and still starts.
func TestTheReauthorizationBaselineIsTheProcessStart(t *testing.T) {
	directory := t.TempDir()
	gate, err := admission.Open(admission.Options{Path: filepath.Join(directory, "admission.json"), NodeID: "site-a",
		SessionPath: filepath.Join(directory, "boot-session")})
	if err != nil {
		t.Fatal(err)
	}
	binding := registry.Binding{Backend: "nitrokey-pkcs11", DeviceID: "hsm-sitea", DeviceSerial: "serial-1",
		DevAuthFingerprint: "sha256:" + strings.Repeat("a", 64), ObjectID: "01"}
	baseline := func(processStart func() (int64, error)) int64 {
		t.Helper()
		provider, _ := nitrokey.New(presentDriver{}, noPIN{})
		if err := requireReauthorization(managing(t, "nitrokey-pkcs11", provider), gate, processStart); err != nil {
			t.Fatal(err)
		}
		provider.Healthy(context.Background(), binding) // the first look records what the token waits for
		waiting := provider.AwaitingReauthorization()
		if len(waiting) != 1 {
			t.Fatalf("waiting = %v", waiting)
		}
		return waiting["hsm-sitea"]
	}
	started, err := admission.ProcessStart()
	if err != nil {
		t.Fatal(err)
	}
	if got := baseline(admission.ProcessStart); got != started {
		t.Fatalf("the baseline is %d, the process started at %d", got, started)
	}
	if got := baseline(func() (int64, error) { return 1234, nil }); got != 1234 {
		t.Fatalf("the baseline is %d, not what the process-start reading returned", got)
	}
	before, _ := admission.Boottime()
	got := baseline(func() (int64, error) { return 0, errors.New("stat refused") })
	after, _ := admission.Boottime()
	if got < before || got > after {
		t.Fatalf("with no process start, the baseline is %d, not now (%d..%d)", got, before, after)
	}
	// The start time is the tick AFTER the true start, so a process in its first 10 ms reads one just
	// ahead of the clock: "now" is the baseline then, and the daemon starts.
	before, _ = admission.Boottime()
	got = baseline(func() (int64, error) { ahead, _ := admission.Boottime(); return ahead + 9, nil })
	after, _ = admission.Boottime()
	if got < before || got > after {
		t.Fatalf("with a start time one tick ahead, the baseline is %d, not now (%d..%d)", got, before, after)
	}
	// a start time in the future is refused rather than waited for
	provider, _ := nitrokey.New(presentDriver{}, noPIN{})
	if err := requireReauthorization(managing(t, "nitrokey-pkcs11", provider), gate, func() (int64, error) { return after + 3_600_000, nil }); err == nil {
		t.Fatal("a process start in the future was accepted")
	}
}

// presentDriver opens a token that proves to be the bound one.
type presentDriver struct{}

func (presentDriver) Open(context.Context, registry.Binding) (nitrokey.Session, error) {
	return presentSession{}, nil
}
func (presentDriver) Ready(context.Context) bool { return true }

type unopenableDriver struct{}

func (unopenableDriver) Open(context.Context, registry.Binding) (nitrokey.Session, error) {
	return nil, errors.New("token not present")
}
func (unopenableDriver) Ready(context.Context) bool { return true }

type noPIN struct{}

func (noPIN) PIN(context.Context, string) ([]byte, error) { return nil, errors.New("no PIN") }

// readinessOf asks the health handler the question a load balancer asks.
func readinessOf(handler http.Handler) bool {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/health/ready", nil))
	return recorder.Code == http.StatusOK
}

type readyProbe bool

func (probe readyProbe) Ready(context.Context) bool { return bool(probe) }

// presentSession answers only what the provider asks before it reaches the reauthorization check;
// anything further would be a call on the nil embedded Session, and a panic.
type presentSession struct{ nitrokey.Session }

func (presentSession) Identity(context.Context) (string, string, error) {
	return "serial-1", "sha256:" + strings.Repeat("a", 64), nil
}
func (presentSession) EstablishSecureChannel(context.Context) error { return nil }
func (presentSession) Close() error                                 { return nil }
