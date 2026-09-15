package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/certs"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/controlplane"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/executor"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/fencing"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/operations"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/pin"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/secrets"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/server"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/telemetry"
)

var version = "development"

func main() {
	if err := run(); err != nil {
		// A failure that already wrote its operator line must not get a second, differently-shaped
		// one: doc/RUNBOOK-KMS-OPERATOR.md and doc/RUNBOOK-DISASTER-RECOVERY.md quote those lines
		// verbatim in fenced blocks and tell the reader to "read the last line, not the exit code
		// alone". A slog line appended after it would become the last line and make that wrong.
		if !errors.Is(err, errAlreadyReported) {
			slog.Error("KMS stopped", "error", err)
		}
		os.Exit(1)
	}
}

// errAlreadyReported marks a failure run() has already written to stderr in the operator-facing form
// the runbooks quote. It exists so those paths can RETURN instead of calling os.Exit(1).
//
// WHY RETURNING MATTERS (#384). os.Exit(1) inside run() kills the TEST BINARY mid-test. `go test`
// then reports the package as failed and names nothing — measured on main.go:100 and main.go:147,
// a mutation there produced "package FAIL, 0 named failures". That is distinct from a panic, which
// at least prints a stack naming the test and the line: os.Exit leaves nothing, so a harness
// reading "exit code non-zero" as a kill records a detection that does not exist. Fourteen operands
// of the #237 sweep sit behind these paths.
var errAlreadyReported = errors.New("already reported to stderr")

// reported writes the operator line exactly as before and returns the failure instead of exiting.
// The label carries the runbook-visible text, so the string an operator greps for stays on the line
// that prints it rather than moving into main().
func reported(label string, err error) error {
	fmt.Fprintln(os.Stderr, label+":", err)
	return fmt.Errorf("%w: %s: %w", errAlreadyReported, label, err)
}

func run() error {
	configPath := flag.String("config", "", "path to strict JSON configuration")
	listen := flag.String("listen", "", "override loopback listen address")
	showVersion := flag.Bool("version", false, "print version and exit")
	verifyAudit := flag.String("verify-audit", "", "verify an audit journal's integrity and exit")
	verifyPolicyState := flag.String("verify-policy-state", "", "verify a policy state journal's integrity and exit")
	checkConfig := flag.Bool("check-config", false, "run every startup check that does not need the token, then exit")
	exportControlPlane := flag.String("export-control-plane", "", "export the durable control-plane state as a sealed envelope and exit (#49)")
	exportRecipientPEM := flag.String("export-recipient-pem", "", "custody authority P-256 public key (PEM) the export is sealed to")
	exportVersionFile := flag.String("export-version-file", "/etc/regalia-kms/deployment-version", "provenance file carried in the export; a missing file travels as an explicit absent marker, and an empty one is refused")
	inspectExport := flag.String("inspect-export", "", "open and fully verify a sealed control-plane export and exit")
	expectSite := flag.String("expect-site", "", "bind an inspected export to the site it is being restored as; a file naming any other site is refused")
	authorityKeyPEM := flag.String("authority-key-pem", "", "custody authority P-256 private key (PEM) that opens an export")
	scanTree := flag.String("scan-tree", "", "scan a restored directory tree for secret shapes and exit")
	flag.Parse()

	// AN AUDIT TRAIL NOBODY CAN CHECK IS TAMPER-EVIDENT ONLY IN PRINCIPLE.
	//
	// audit.VerifyIntegrity existed with no caller outside its own package tests, and internal/
	// packages cannot be imported from outside the module — so the KMS wrote a hash-chained,
	// truncation-detecting journal that an operator had no way to verify. The evidence was
	// unreachable by the people the evidence is for.
	//
	// This runs read-only and takes no configuration, so it works on a journal copied off the host
	// onto a machine that has nothing else from this deployment.
	if *verifyAudit != "" {
		if err := verifyAuditJournal(*verifyAudit, os.Stdout); err != nil {
			return reported("audit verification FAILED", err)
		}
		return nil
	}
	// The policy state journal records spent quota and consumed nonces, so shortening it restores
	// both. It had no verification path at all, and OpenFileState takes an exclusive lock for the
	// process lifetime — so checking it meant stopping the daemon. This takes no lock.
	if *verifyPolicyState != "" {
		if err := verifyPolicyStateJournal(*verifyPolicyState, os.Stdout); err != nil {
			return reported("policy state verification FAILED", err)
		}
		return nil
	}

	// THE RESTORE SIDE OF #49. These run on the ceremony host, against an export file or a
	// rebuilt guest's tree, with nothing else from the deployment — the same reachability
	// rule as the journal verifiers above: a recovery control nobody can run at the point of
	// use is a control that does not exist.
	if *inspectExport != "" {
		if *authorityKeyPEM == "" {
			return errors.New("-inspect-export requires -authority-key-pem")
		}
		if err := inspectControlPlaneExport(*inspectExport, *authorityKeyPEM, *expectSite); err != nil {
			return reported("export inspection FAILED", err)
		}
		return nil
	}
	if *scanTree != "" {
		findings, err := controlplane.ScanTree(*scanTree)
		if err != nil {
			return reported("tree scan FAILED", err)
		}
		if len(findings) > 0 {
			for _, finding := range findings {
				fmt.Fprintln(os.Stderr, "secret-shaped content:", finding)
			}
			// The per-finding lines above ARE the operator output, so this adds no stderr of its
			// own; it carries the count so a caller can assert the scan refused and with how many.
			return fmt.Errorf("%w: %d secret-shaped finding(s) in %s", errAlreadyReported, len(findings), *scanTree)
		}
		fmt.Println("tree clean — and the same pass caught its own planted canary, so the clean verdict is armed")
		return nil
	}

	if *showVersion {
		fmt.Println(version)
		return nil
	}
	if *checkConfig && *configPath == "" {
		return errors.New("-check-config requires -config")
	}
	settings := config.Default()
	var err error
	if *configPath != "" {
		settings, err = config.Load(*configPath)
		if err != nil {
			return err
		}
	}
	if *listen != "" {
		settings.ListenAddress = *listen
	}
	// THE EXPORT SIDE OF #49: the durable, reconstructable control plane leaves the guest as
	// a sealed envelope for the custody procedure — never as a machine image. Runs as the kms
	// user against the live journals; every chain is verified before anything is sealed.
	if *exportControlPlane != "" {
		if *exportRecipientPEM == "" {
			return errors.New("-export-control-plane requires -export-recipient-pem")
		}
		if err := exportControlPlaneState(settings, *exportControlPlane, *exportRecipientPEM, *exportVersionFile); err != nil {
			return reported("control-plane export FAILED", err)
		}
		return nil
	}
	if err := settings.Validate(); err != nil {
		return err
	}
	mutualTLS := settings.TLSCertificatePath != ""
	if err := requireLoopbackUnlessMutualTLS(settings.ListenAddress, mutualTLS); err != nil {
		return err
	}

	// PREFLIGHT IS THE SAME CODE THE DAEMON RUNS, not a second validator beside it. Two validators
	// for one document is the defect this repository spent a day removing; a preflight that
	// re-implemented these checks would be the next instance, and the worst one, because it is the
	// check people trust before deploying.
	keyRegistryFromPreflight, rbacFromPreflight, engineFromPreflight, approverKeys, report, preflightErr := preflight(settings)
	if *checkConfig {
		writePreflight(report, os.Stdout)
		if preflightErr != nil {
			return reported("preflight FAILED", preflightErr)
		}
		fmt.Fprintln(os.Stdout, "preflight passed: the checks above hold; the UNCHECKED items were not attempted")
		return nil
	}
	if preflightErr != nil {
		return preflightErr
	}
	keyRegistry := keyRegistryFromPreflight
	// THE SAME POINTER IS NIL-CHECKED HERE AND DEREFERENCED UNCONDITIONALLY BY fenceRunner, which
	// takes keyRegistry.Digest(). A bare `regalia-kms` — no flags at all — reaches that call with
	// nil and the process dies with a SIGSEGV stack trace and exit 2, which is the worst
	// possible answer to the simplest possible invocation: the operator learns nothing, and a crash
	// on startup reads as a broken build rather than a missing argument.
	//
	// Refusing here rather than guarding Digest() with a nil receiver, because a Digest() that
	// returns "" for a nil registry would let the daemon proceed to serve with no custody manifest
	// — a plausible value standing in for a missing one, which is worse than the panic. Nothing is
	// lost by refusing: any nil reaching the fenceRunner call below already panicked, so no
	// working configuration is affected. The wording mirrors `-check-config requires -config`
	// above, because it is the same class of mistake and the operator should recognise it as one.
	//
	// Naming fenceRunner rather than a line number is deliberate: review caught an earlier draft
	// of this comment citing the call site by line, in the same session its author had been
	// correcting other people's stale line references. A name is greppable and survives an edit
	// above it; a number silently starts pointing at something else. The number is described
	// rather than reproduced here, for the same reason .gitleaksignore describes its offenders:
	// a note that quotes the bad form is still findable by anything hunting for it.
	if keyRegistry == nil {
		return errors.New("no custody manifest is configured: the daemon cannot serve without one — pass -config, or set registry_path and site in the configuration file")
	}
	slog.Info("KMS registry loaded", "digest", keyRegistry.Digest(), "site", settings.Site)
	// Reuse what preflight already loaded and cross-checked. Loading it a second time would give
	// the daemon a different object than the one the checks were run against, which is a small
	// version of exactly the divergence those checks exist to catch.
	rbacPolicy := rbacFromPreflight
	if rbacPolicy != nil {
		slog.Info("KMS RBAC policy loaded", "digest", rbacPolicy.Digest())
	}
	_ = engineFromPreflight
	var policyEngine *policy.Engine
	var policyState *policy.FileState
	// The purpose-policy digest has to outlive this block: it identifies the ruleset every audit
	// event was decided under, and it used to be logged here and then dropped while the coordinator
	// was handed the REGISTRY digest under the name PolicyDigest.
	var purposePolicyDigest string
	if settings.PolicyPath != "" {
		// The engine IS rebuilt rather than reused: preflight compiles it against a discarding
		// state because it must not take the journal's exclusive lock, and the daemon needs the
		// real FileState. Same policies, same digest — only the state differs, which is the one
		// thing preflight deliberately cannot hold.
		policies, digest, loadErr := policy.LoadFile(settings.PolicyPath)
		if loadErr != nil {
			return loadErr
		}
		policyState, err = policy.OpenFileState(settings.PolicyStatePath)
		if err != nil {
			return err
		}
		defer policyState.Close()
		policyEngine, err = policy.New(policies, policyState, time.Now)
		if err != nil {
			return err
		}
		purposePolicyDigest = digest
		slog.Info("KMS purpose policy loaded", "digest", digest)
	}
	listener, err := net.Listen("tcp", settings.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	if mutualTLS {
		tlsConfig, tlsErr := mutualTLSConfig(settings)
		if tlsErr != nil {
			return tlsErr
		}
		listener = tls.NewListener(listener, tlsConfig)
		slog.Info("KMS mutual TLS enabled", "client_roots", settings.TLSClientCAPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// HARDWARE, WHEN IT IS CONFIGURED. Without it the daemon serves health and refuses every
	// authenticated operation with DEPENDENCY_UNAVAILABLE, which is the right posture for an
	// unconfigured host — not an error, and not a permissive fallback.
	// READINESS PROBES. NewRequired treats a nil probe as not-ready, so leaving these nil made
	// /v1/health/ready return 503 unconditionally — even on a fully configured host, where the
	// service was in fact able to serve. A readiness endpoint that is always false is not
	// fail-closed, it is uninformative: nothing can distinguish "not configured" from "broken".
	var auditProbe server.ReadinessProbe
	var tokenProbe server.ReadinessProbe
	var fencingProbe server.ReadinessProbe
	// The observability seams: the concrete components, hoisted so the metrics
	// handler can read them after the block narrows them to probe interfaces.
	var recorder *audit.Recorder
	var tokenObserver *nitrokey.Provider
	// ACTIVE/PASSIVE FENCING. internal/fencing existed with no caller at all: the package was
	// tested, the daemon never opened a lease, and ADR-0001 §8 — never two simultaneous signers —
	// was enforced by nothing at runtime. Two hosts pointed at the same key would both have signed.
	//
	// The lease is checked twice per operation, and that is deliberate. Once before admission, so a
	// passive site refuses work; once inside the operation, so a site that LOSES the lease mid-flight
	// stops rather than finishing the signature it had already started.
	fencedRunner, standby, fencingErr := fenceRunner(settings, keyRegistry.Digest(),
		executor.New(settings.MaxConcurrentOperations, settings.OperationTimeout))
	if fencingErr != nil {
		return fencingErr
	}
	if standby != nil {
		fencingProbe = standby
		// THE SPEND JOURNAL LEARNS THE LEASE EPOCH HERE (#428). Every policy reservation
		// is stamped with the epoch this site holds NOW — read per reservation, because
		// failover changes the epoch under a running daemon — so a stale leader's
		// reservations are refused by the journal's monotonic-epoch rule even in the
		// window before its own lease check notices the promotion. The quota is one
		// global budget on one journal; the epoch rule is what stops a replaced site
		// from still spending out of it. An unheld or unreadable lease stamps 0, which
		// the journal refuses outright once any fenced reservation exists: fail closed.
		if policyEngine != nil {
			policyEngine.SetEpochSource(epochSourceFor(standby))
		}
		slog.Info("KMS fencing enabled", "site", settings.Site, "lease", settings.FencingLeasePath)
	}

	var coordinator *operations.Coordinator
	var coordErr error
	if settings.PKCS11ModulePath != "" || len(settings.YubiKeyDevices) > 0 {
		hardware, manager, observer, closer, buildErr := buildHardware(settings, keyRegistry)
		if buildErr != nil {
			return buildErr
		}
		defer closer()
		if bindErr := bindBackendToRegistry(keyRegistry, manager); bindErr != nil {
			return bindErr
		}
		// requireDeclaredPoliciesAreEnforced and requireGrantsReferenceRealObjects already ran in
		// preflight, against the same documents. Repeating them here would be a second call site
		// that could drift from the one an operator runs before deploying.
		tokenProbe = manager
		tokenObserver = observer

		var auditErr error
		// COLLECTOR RECONCILIATION before the recorder opens: the off-host copy's committed
		// position is the only value a host-level attacker cannot rewrite, so the journal is
		// refused the moment it disagrees with what this site already shipped (#220 rows 2/4).
		auditSink, sinkErr := auditSinkFor(settings)
		if sinkErr != nil {
			return sinkErr
		}
		// The signal-aware startup context, not Background: reconciliation is a network
		// call, and a startup cancellation or deadline must reach it the same way it
		// reaches every other startup operation.
		if auditErr := audit.ReconcileContinuity(ctx, settings.AuditJournalPath, auditSink, settings.Site); auditErr != nil {
			return auditErr
		}
		recorder, auditErr = openAudit(settings, auditSink)
		if auditErr != nil {
			return auditErr
		}
		defer recorder.Close()
		auditProbe = recorder
		// The daemon re-verifies its own journal on an interval: -verify-audit
		// answers when an operator asks, and between asks nothing else is watching.
		recorder.StartVerifier(ctx, audit.DefaultVerifyInterval)

		coordinator, coordErr = operations.New(rbacPolicy, keyRegistry, policyEngine, recorder,
			fencedRunner, hardware, purposePolicyDigest, approverKeys, time.Now)
		if coordErr != nil {
			return coordErr
		}
		slog.Info("KMS hardware backend ready", "module", settings.PKCS11ModulePath)
	}

	healthHandler := server.NewRequired(server.Dependencies{
		Policy:   server.RequireAll(rbacPolicy, policyEngine),
		Registry: keyRegistry,
		Audit:    auditProbe,
		Token:    tokenProbe,
		Fencing:  fencingProbe,
	})
	// THE METRICS SURFACE. The collector counts what only the request path can see
	// (router decisions, per-route outcomes, authentication rejections); the sources
	// pull what the components already know (audit backlog, lease state, quarantine,
	// PIN budget, quota rejections, readiness history). A source stays nil when its
	// component is not configured, so "not configured" never reads as healthy-zero.
	collector := telemetry.NewCollector(api.OperationPaths())
	sources := telemetry.Sources{Now: time.Now, Readiness: healthHandler.ReadinessStats}
	if recorder != nil {
		sources.AuditShipping = func() (bool, int, time.Time, uint64) {
			state := recorder.ShippingState()
			return state.Configured, state.Backlog, state.OldestUnshipped, state.ShippedSequence
		}
		sources.AuditVerify = func() (string, time.Time) {
			state := recorder.VerifyState()
			return string(state.Outcome), state.At
		}
	}
	if standby != nil {
		// Snapshot's ok means a gate has ever been acquired, which is exactly the condition
		// under which there is an evaluation to report -- so it is what the metrics surface
		// calls "evaluated". The translation is named here rather than left implicit: if the
		// two ever come apart, this is the line that has to change, and a metric that says
		// the lease was evaluated when it was not would report a passive site as lease-lost.
		sources.Fencing = func() (evaluated, held bool, epoch uint64, checkedAt time.Time) {
			held, epoch, checked, acquiredAGate := standby.Snapshot()
			return acquiredAGate, held, epoch, checked
		}
	}
	if tokenObserver != nil {
		sources.Quarantined = tokenObserver.Quarantined
		sources.PINRetries = func() map[string]telemetry.PINReading {
			readings := make(map[string]telemetry.PINReading)
			for device, reading := range tokenObserver.PINRetriesReadings() {
				readings[device] = telemetry.PINReading{Retries: reading.Retries, At: reading.At}
			}
			return readings
		}
	}
	if policyEngine != nil {
		sources.QuotaRejections = policyEngine.QuotaRejections
	}
	if coordinator != nil {
		// Nil when the coordinator is not configured, per the rule above: a zero drop count
		// from a daemon that has no coordinator would read as "the audit sink is healthy".
		sources.AuditDroppedRecords = coordinator.DroppedAuditRecords
	}
	handler := server.Routes(healthHandler, collector.InstrumentOperations(api.NewHandler(coordinator)),
		telemetry.NewHandler(collector, sources, settings.MetricsReaderPrincipals), collector)
	// REVOCATION LIST. The list caches the parsed file behind a stat+ModTime guard, so an
	// entry the operator appends at runtime takes effect on the next request — within one
	// stat cycle, no daemon restart, no signal. An empty RevokedSerialsPath returns a no-op
	// list whose Check returns (false, nil) without touching the filesystem; the
	// authenticator still calls Check, the check just does no I/O.
	revocation, err := auth.NewRevocationList(settings.RevokedSerialsPath)
	if err != nil {
		return err
	}
	authenticator := auth.NewAuthenticator("spiffe://regalia/", revocation, time.Now, auth.DefaultClockSkew)
	authenticator.OnUnauthorized(collector.RecordUnauthenticated)
	handler = authenticator.Middleware(handler)
	slog.Info("KMS skeleton listening", "address", listener.Addr().String(), "ready", false)
	return server.Serve(ctx, listener, handler, server.Options{
		ShutdownTimeout:  settings.ShutdownTimeout,
		OperationTimeout: settings.OperationTimeout,
	})
}

// requireLoopbackUnlessMutualTLS permits a routable listener only when the transport
// authenticates the caller. Loopback without TLS remains available for development.
//
// This previously refused every non-loopback address unconditionally, because the listener was
// plain TCP: auth.Authenticator reads the verified chain from request.TLS, which is nil over
// plaintext, so every authenticated route failed closed and binding anywhere routable would have
// exposed only the unauthenticated health endpoints. The TLS material now decides instead.
func requireLoopbackUnlessMutualTLS(address string, mutualTLS bool) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		if !mutualTLS {
			return fmt.Errorf("refusing non-loopback listener without mutual TLS")
		}
	}
	return nil
}

// mutualTLSConfig loads the server identity and the client trust roots. Every failure here is
// fatal: a daemon that starts without the trust roots it was configured with would accept callers
// it cannot authenticate.
func mutualTLSConfig(settings config.Config) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(settings.TLSCertificatePath, settings.TLSPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load server TLS keypair: %w", err)
	}
	pemBytes, err := os.ReadFile(settings.TLSClientCAPath)
	if err != nil {
		return nil, fmt.Errorf("read client trust roots: %w", err)
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("client trust roots contain no usable certificate: %s", settings.TLSClientCAPath)
	}
	return auth.ServerTLSConfig(certificate, clientRoots)
}

// buildHardware assembles the token stack from configuration. Every step is fatal on failure: a
// daemon that starts with a partially built backend would answer some requests and fail others in
// ways the operator did not choose.
// buildHardware returns the concrete provider alongside the manager: the manager serves the
// operations path, and the provider carries the quarantine and PIN-budget state the metrics
// surface reads. Narrowing to the backend.Provider interface here would hide both.
func buildHardware(settings config.Config, keyRegistry *registry.Registry) (*certs.Issuer, *backend.Manager, *nitrokey.Provider, func(), error) {
	pins, err := pin.NewLockedFileSource(settings.PINPaths)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	providers := make(map[string]backend.Provider)
	var observer *nitrokey.Provider
	var closers []func()
	if settings.PKCS11ModulePath != "" {
		channel, channelErr := nitrokey.LoadSecureChannelEvidence(settings.SecureChannelEvidence, time.Now)
		if channelErr != nil {
			return nil, nil, nil, nil, channelErr
		}
		driver, driverErr := nitrokey.NewPKCS11DriverWithProbes(settings.PKCS11ModulePath, channel)
		if driverErr != nil {
			return nil, nil, nil, nil, driverErr
		}
		provider, providerErr := nitrokey.New(driver, pins)
		if providerErr != nil {
			_ = driver.Close()
			return nil, nil, nil, nil, providerErr
		}
		providers["nitrokey-pkcs11"] = provider
		observer = provider
		closers = append(closers, func() { _ = driver.Close() })
	}
	if len(settings.YubiKeyDevices) > 0 {
		provider, providerErr := newYubiKeyBackend(settings.YubiKeyDevices, pins)
		if providerErr != nil {
			for _, close := range closers {
				close()
			}
			return nil, nil, nil, nil, providerErr
		}
		providers["yubikey-piv"] = provider
	}
	closer := func() {
		for _, close := range closers {
			close()
		}
	}
	manager, err := backend.New(providers)
	if err != nil {
		closer()
		return nil, nil, nil, nil, err
	}
	// release-secret is always available once hardware is: the registry already advertises it as a
	// capability, and a capability the matrix promises but nothing serves is worse than none.
	releaser, err := secrets.NewReleaser(manager)
	if err != nil {
		closer()
		return nil, nil, nil, nil, err
	}
	if settings.IssuerCertificatePath == "" {
		// No issuer configured: certificate-sign simply has no route, and the manager answers the
		// rest. Wrapping is skipped rather than defaulted to a permissive profile.
		issuer, wrapErr := certs.NewPassthrough(releaser)
		if wrapErr != nil {
			closer()
			return nil, nil, nil, nil, wrapErr
		}
		return issuer, manager, observer, closer, nil
	}
	caCertificate, err := loadIssuerCertificate(settings.IssuerCertificatePath)
	if err != nil {
		closer()
		return nil, nil, nil, nil, err
	}
	issuer, err := certs.NewIssuer(releaser, caCertificate, certs.Profile{
		AllowedDNSSuffixes: settings.IssuerDNSSuffixes,
		Validity:           settings.IssuerValidity,
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, time.Now)
	if err != nil {
		closer()
		return nil, nil, nil, nil, err
	}
	return issuer, manager, observer, closer, nil
}

func loadIssuerCertificate(path string) (*x509.Certificate, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read issuer certificate: %w", err)
	}
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("issuer certificate is not a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// auditSinkFor builds the configured sink once: startup reconciliation asks it for the
// collector's committed position BEFORE the recorder opens, and the recorder then ships to
// the same authenticated client. A journal-only host (no sink) gets nil, and reconciliation
// has nothing to reconcile against — stated, not hidden.
func auditSinkFor(settings config.Config) (audit.Sink, error) {
	if settings.AuditSinkURL == "" {
		return nil, nil
	}
	{
		// THE AUDIT SINK IS AUTHENTICATED, PINNED AND PROXY-FREE.
		//
		// This used http.DefaultClient, which contradicts AUDIT.md: no client identity, system
		// trust roots, and whatever HTTP_PROXY the environment happens to carry. The audit trail is
		// the record of every key use, so shipping it to a host proved only by the ambient CA set,
		// through a proxy nobody declared, is the wrong place to be relaxed. The mTLS material is
		// the same the listener uses: a sink that cannot be authenticated is not configured.
		if settings.TLSCertificatePath == "" {
			return nil, errors.New("audit_sink_url requires mutual TLS material: the audit trail must not ship over an unauthenticated client")
		}
		certificate, err := tls.LoadX509KeyPair(settings.TLSCertificatePath, settings.TLSPrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load audit client keypair: %w", err)
		}
		pemBytes, err := os.ReadFile(settings.TLSClientCAPath)
		if err != nil {
			return nil, fmt.Errorf("read audit trust roots: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("audit trust roots contain no usable certificate")
		}
		serverName, err := sinkServerName(settings.AuditSinkURL)
		if err != nil {
			return nil, err
		}
		client, err := audit.NewMTLSHTTPClient(certificate, roots, serverName)
		if err != nil {
			return nil, err
		}
		httpSink, err := audit.NewHTTPSink(settings.AuditSinkURL, client, 10*time.Second, settings.Site)
		if err != nil {
			return nil, err
		}
		return httpSink, nil
	}
}

// openAudit opens the recorder on the already-built sink. Reconciliation has already run
// against this sink before this call — the order is the guarantee.
func openAudit(settings config.Config, sink audit.Sink) (*audit.Recorder, error) {
	return audit.Open(settings.AuditJournalPath, sink)
}

func sinkServerName(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("audit_sink_url is not a usable URL: %q", rawURL)
	}
	if parsed.Scheme != "https" {
		return "", errors.New("audit_sink_url must be https")
	}
	return parsed.Hostname(), nil
}

// epochSourceFor names the fencing epoch stamped into every policy reservation: the epoch
// this site holds NOW, read per reservation, and 0 — which the journal refuses outright once
// any fenced reservation exists — when the lease is unheld or cannot be read. Both
// not-holding states therefore fail closed at the reservation rather than after it.
func epochSourceFor(standby *fencing.Standby) func() uint64 {
	return func() uint64 {
		held, epoch, _, ok := standby.Snapshot()
		if !ok || !held {
			return 0
		}
		return epoch
	}
}

// loadFencingKey reads the ed25519 public key a site lease must be signed by.
//
// The key is the whole basis for trusting a lease, so an unreadable or wrong-sized file is a
// startup error rather than a site that quietly never becomes ready — the two look identical from
// outside, and only one of them is a configuration mistake someone can fix.
func loadFencingKey(path string) (ed25519.PublicKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fencing public key: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(contents)))
	if err != nil {
		return nil, errors.New("fencing public key must be base64-encoded")
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("fencing public key must be %d bytes, got %d", ed25519.PublicKeySize, len(decoded))
	}
	return ed25519.PublicKey(decoded), nil
}

// fenceRunner wraps the operation runner in the site lease when fencing is configured.
//
// It is a named function rather than inline setup because it IS the control: internal/fencing was
// fully implemented and fully tested and had no non-test importer at all, so the lease was never
// taken and ADR-0001 §8 held only on paper. A wiring step that nothing can call is a wiring step
// nothing notices the absence of, so this one is callable, and
// TestFenceRunnerRefusesWorkUntilTheSiteHoldsTheLease exercises it.
//
// The concrete Standby is returned rather than the probe interface: the readiness probe and the
// metrics snapshot are the same object, and narrowing it here would hide the lease's state from
// the metrics surface.
//
// Returns the runner unchanged and a nil standby when fencing is not configured — an unfenced
// single-site deployment stays supported, and readiness does not gain a dependency it has no way
// to satisfy.
func fenceRunner(settings config.Config, registryDigest string, base operations.Runner) (operations.Runner, *fencing.Standby, error) {
	if settings.FencingLeasePath == "" {
		return base, nil, nil
	}
	publicKey, err := loadFencingKey(settings.FencingPublicKeyPath)
	if err != nil {
		return nil, nil, err
	}
	standby, err := fencing.NewStandby(settings.FencingLeasePath, settings.FencingStatePath,
		settings.Site, registryDigest, publicKey, time.Now)
	if err != nil {
		return nil, nil, err
	}
	return fencing.NewRunner(standby, base), standby, nil
}

// bindBackendToRegistry refuses a key registry that routes to a backend the daemon cannot serve.
//
// The registry accepts bindings to yubikey-piv and yubikey-openpgp — it has capability entries for
// both and will route to them — while buildHardware only ever constructs a nitrokey-pkcs11
// provider. Nothing connected the two, so an operator could bind a key to a YubiKey, watch the
// custody manifest validate and the daemon start clean, and then have every operation on that key
// fail at signing time as DEPENDENCY_UNAVAILABLE. Fail-closed, but discovered one request at a
// time, at the moment someone needed the key.
//
// A backend the routing table names and the daemon cannot reach is a configuration error, and a
// configuration error belongs at startup where somebody is watching.
func bindBackendToRegistry(keyRegistry *registry.Registry, manager *backend.Manager) error {
	// ATTACH THE HEALTH PROBE. The registry is loaded before the manager exists, so it starts with
	// none — and Route denies every object while that is true. The daemon therefore served nothing
	// and was never ready, with no error anywhere: an unattached probe is indistinguishable from
	// hardware that is down. Attaching and checking servability are one step because doing either
	// without the other leaves the same silence.
	keyRegistry.SetBackendHealth(manager)
	if !keyRegistry.HasBackendHealth() {
		return errors.New("key registry has no backend health probe: every operation would fail as DEPENDENCY_UNAVAILABLE and readiness would never be true")
	}
	var missing []string
	for _, name := range keyRegistry.RequiredBackends() {
		if !manager.Serves(name) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("key registry routes to backends this daemon cannot serve: %s — every operation on those objects would fail at signing time",
			strings.Join(missing, ", "))
	}
	return nil
}

// requireDeclaredPoliciesAreEnforced refuses a manifest whose stated policy is not the one applied.
//
// Every object in a custody manifest carries a policy_id, and the loader refuses an object without
// one, so an operator reasonably reads it as the binding between object and policy. It is not. The
// policy engine looks a policy up by (object_id, operation) and never consults that field — so
// whatever policy happens to name the object governs it, whatever the manifest says, and nothing
// reports the difference.
//
// The two ways that goes wrong are both silent. A manifest naming a policy that does not exist
// leaves the object denied at every request with "unknown-object", which reads as a routing problem
// rather than a missing policy. A manifest naming one policy while a differently-named policy
// governs the same object means the enforced rules are not the reviewed ones — and the review
// happened against the manifest.
//
// Neither is a runtime condition worth discovering per request, so both are startup errors.
func requireDeclaredPoliciesAreEnforced(keyRegistry *registry.Registry, engine *policy.Engine) error {
	var problems []string
	for _, declared := range keyRegistry.DeclaredPolicies() {
		for _, operation := range declared.Operations {
			governing, exists := engine.GoverningPolicyID(declared.ObjectID, operation)
			switch {
			case !exists:
				problems = append(problems, fmt.Sprintf("%s/%s declares policy %q but no policy governs it: every request would be denied as unknown-object",
					declared.ObjectID, operation, declared.PolicyID))
			case governing != declared.PolicyID:
				problems = append(problems, fmt.Sprintf("%s/%s declares policy %q but %q is what actually governs it: the enforced rules are not the reviewed ones",
					declared.ObjectID, operation, declared.PolicyID, governing))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("custody manifest and policy document disagree:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

// requireGrantsReferenceRealObjects refuses an RBAC document that grants access to something the
// key registry does not have.
//
// auth.LoadPolicy never sees the registry, so a grant naming an object that does not exist — a
// typo, a key that was retired, a manifest that was split — is accepted in silence. The daemon
// starts clean and the operator believes that principal is authorized. It is not: every request
// denies at RBAC. That is fail-closed, and it is still wrong, because the failure is invisible
// until someone needs the access and the configuration says they already have it.
//
// The same applies to an operation the object does not declare: a grant for an operation outside
// the object's manifest entry can never be exercised.
//
// An object with NO grant is not an error. That is an object nobody is authorized for yet, which
// is a legitimate state and the correct default for a key that has just been commissioned.
func requireGrantsReferenceRealObjects(keyRegistry *registry.Registry, rbacPolicy *auth.Policy) error {
	known := map[string]map[string]struct{}{}
	for _, declared := range keyRegistry.DeclaredPolicies() {
		operations := make(map[string]struct{}, len(declared.Operations))
		for _, operation := range declared.Operations {
			operations[operation] = struct{}{}
		}
		known[declared.ObjectID] = operations
	}

	var problems []string
	for _, granted := range rbacPolicy.GrantedObjects() {
		operations, exists := known[granted.ObjectID]
		if !exists {
			problems = append(problems, fmt.Sprintf("%s is granted %s on %q, which the key registry does not contain",
				granted.Principal, granted.Operation, granted.ObjectID))
			continue
		}
		if _, allowed := operations[granted.Operation]; !allowed {
			problems = append(problems, fmt.Sprintf("%s is granted %s on %q, which the manifest does not list among that object's operations",
				granted.Principal, granted.Operation, granted.ObjectID))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("RBAC policy grants access that can never be exercised:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

// exportControlPlaneState seals the site's durable control plane to the custody authority's
// public key (#49). The envelope is written 0600: it is the one artifact this host produces
// that is MEANT to leave, and it is unreadable on this host by construction.
func exportControlPlaneState(settings config.Config, outputPath, recipientPath, versionFile string) error {
	recipientPEM, err := os.ReadFile(recipientPath)
	if err != nil {
		return fmt.Errorf("read recipient key: %w", err)
	}
	recipient, err := controlplane.ParseRecipient(recipientPEM)
	if err != nil {
		return err
	}
	sources := controlplane.Sources{
		AuditJournal: settings.AuditJournalPath,
		PolicyState:  settings.PolicyStatePath,
		FencingState: settings.FencingStatePath,
		SiteVersion:  versionFile,
	}
	export, err := controlplane.Build(sources, settings.Site, time.Now())
	if err != nil {
		return err
	}
	payload, err := json.Marshal(export)
	if err != nil {
		return err
	}
	envelope, err := controlplane.Seal(payload, recipient.PublicKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outputPath, envelope, 0o600); err != nil {
		return fmt.Errorf("write export: %w", err)
	}
	for _, line := range controlplane.SummaryLines(export) {
		fmt.Println(line)
	}
	fmt.Printf("sealed to custody authority key sha256:%s\n", recipient.Digest)
	fmt.Printf("envelope: %s (%d bytes, mode 0600)\n", outputPath, len(envelope))
	fmt.Println("The authority signs this FILE after carry-out; the guest holds no signing key.")
	return nil
}

// inspectControlPlaneExport is the offline verdict over a carried-out export: decrypt with the
// authority key, re-verify every digest and journal chain, and secret-scan with the canary in
// the same pass. Run it from the trusted ceremony checkout before any restore.
func inspectControlPlaneExport(envelopePath, authorityKeyPath, expectedSite string) error {
	keyPEM, err := os.ReadFile(authorityKeyPath)
	if err != nil {
		return fmt.Errorf("read authority key: %w", err)
	}
	key, err := controlplane.ParseAuthorityKey(keyPEM)
	if err != nil {
		return err
	}
	encoded, err := os.ReadFile(envelopePath)
	if err != nil {
		return fmt.Errorf("read export: %w", err)
	}
	export, err := controlplane.InspectForSite(encoded, key, expectedSite)
	if err != nil {
		return err
	}
	for _, line := range controlplane.SummaryLines(export) {
		fmt.Println(line)
	}
	fmt.Println("export verified: envelope opened, digests and journal chains intact, no secret-shaped content")
	if expectedSite != "" {
		fmt.Printf("recovery point bound to site %s\n", expectedSite)
	}
	return nil
}

// verifyAuditJournal reports what an operator needs to act: how much of the trail is intact, and
// the head it ends at, so two copies of the same journal can be compared without reading them.
func verifyAuditJournal(path string, out io.Writer) error {
	// A MISSING JOURNAL IS A VERIFICATION FAILURE, even though it is fine for Open.
	//
	// VerifyIntegrity tolerates os.ErrNotExist because the daemon creates the journal on first
	// start. Verification is the opposite situation: the operator is asking about a trail that is
	// supposed to exist, so "no such file" answered "intact and empty" — a green result for a
	// deleted journal, or for a typo in the path. That is the fail-open version of the control this
	// command exists to provide, and the first thing running it revealed.
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("cannot verify %s: %w", path, err)
	}
	events, err := audit.VerifyIntegrity(path)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		fmt.Fprintf(out, "audit journal %s is intact and empty\n", path)
		return nil
	}
	head := events[len(events)-1]
	fmt.Fprintf(out, "audit journal %s is intact: %d events, head sequence %d, head hash %s\n",
		path, len(events), head.Sequence, head.Hash)
	fmt.Fprintf(out, "first event %s, last event %s\n",
		events[0].Timestamp.UTC().Format(time.RFC3339), head.Timestamp.UTC().Format(time.RFC3339))
	return nil
}

func verifyPolicyStateJournal(path string, out io.Writer) error {
	summary, err := policy.VerifyState(path)
	if err != nil {
		return err
	}
	if summary.Reservations == 0 {
		fmt.Fprintf(out, "policy state journal %s is intact and empty\n", path)
		return nil
	}
	fmt.Fprintf(out, "policy state journal %s is intact: %d reservations, head sequence %d, head hash %s\n",
		path, summary.Reservations, summary.HeadSequence, summary.HeadHash)
	return nil
}
