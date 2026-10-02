package openbaopoc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	wrapping "github.com/openbao/go-kms-wrapping/v2"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/executor"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/keywrap"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/operations"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

func wrappingConfig(c map[string]string) wrapping.Option { return wrapping.WithConfigMap(c) }

// This provider is compiled only into tests; it makes no hardware qualification claim.
type softwareRSA struct{ key *rsa.PrivateKey }

func (s softwareRSA) Execute(ctx context.Context, route registry.Route, operation, format, contentType string, data, aad []byte) ([]byte, string, error) {
	if ctx.Err() != nil || format != "regalia-envelope-v2" || route.Algorithm != "rsa2048" {
		return nil, "", backend.ErrUnavailable
	}
	switch operation {
	case "wrap":
		if len(data) != 32 {
			return nil, "", backend.ErrUnavailable
		}
		public, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
		if err != nil {
			return nil, "", err
		}
		wrapped, err := keywrap.RSAOAEP(public, data, aad, route.Algorithm)
		return wrapped, "application/vnd.regalia.wrapped-data-key", err
	case "unwrap":
		frame, err := rsa.DecryptOAEP(keywrap.OAEPHash.New(), rand.Reader, s.key, data, nil)
		defer clear(frame)
		if err != nil {
			return nil, "", err
		}
		key, err := keywrap.OpenFrame(frame, aad)
		return key, "application/octet-stream", err
	}
	return nil, "", backend.ErrUnavailable
}
func (softwareRSA) Healthy(context.Context, registry.Binding) bool { return true }
func (softwareRSA) Ready(context.Context) bool                     { return true }

type fixtureAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (s *fixtureAudit) Send(_ context.Context, event audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}
func (*fixtureAudit) Ready(context.Context) bool { return true }
func (s *fixtureAudit) successful(operation string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.events {
		if e.Operation == operation && e.Outcome == "success" {
			n++
		}
	}
	return n
}

func (s *fixtureAudit) deniedUnwraps() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.events {
		if e.Operation == "unwrap" && e.Outcome == "rbac-denied" {
			n++
		}
	}
	return n
}

type kmsFixture struct {
	server  *httptest.Server
	handler http.Handler
	pki     fixturePKI
	audit   *fixtureAudit
	address string
	t       *testing.T
}

func newKMSFixture(t *testing.T) *kmsFixture {
	t.Helper()
	pki := newFixturePKI(t)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	hardware, err := backend.New(map[string]backend.Provider{"nitrokey-pkcs11": softwareRSA{key}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := `{"schema_version":1,"manifest_id":"synthetic-poc","generated_at":"2026-10-02T00:00:00Z","objects":[{"id":"poc-seal-key","name":"Synthetic seal fixture","kind":"symmetric-key","classification":"restricted","environment":"development","owner":"fixture","purpose":"openbao-seal","custody":"direct-hardware","algorithm":"rsa2048","operations":["wrap","unwrap"],"policy_id":"poc-policy","bindings":[{"site":"poc-site","backend":"nitrokey-pkcs11","device_id":"software-fixture","device_serial":"synthetic","devaut_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","object_id":"02","public_fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"active"}],"recovery":{},"rotation":{},"migration":{},"verification":{"status":"verified"}}]}`
	router, err := registry.Load(strings.NewReader(manifest), "poc-site", hardware)
	if err != nil {
		t.Fatal(err)
	}
	rbac, err := auth.LoadPolicy(strings.NewReader(`{"schema_version":1,"principals":[{"uri":"spiffe://regalia/workload/openbao-poc","grants":[{"objects":["poc-seal-key"],"operations":["wrap","unwrap"],"environments":["development"]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	state, err := policy.OpenFileState(filepath.Join(t.TempDir(), "policy.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	base := policy.Policy{ObjectID: "poc-seal-key", Purpose: "openbao-seal", Environment: "development", Algorithm: "rsa2048", ContentTypes: []string{operations.DataKeyContentType}, MaxPayloadBytes: 4096, MaxFuture: 2 * time.Minute}
	wrap, unwrap := base, base
	wrap.ID, wrap.Operation = "poc-wrap", "wrap"
	unwrap.ID, unwrap.Operation = "poc-unwrap", "unwrap"
	semantic, err := policy.New([]policy.Policy{wrap, unwrap}, state, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	sink := &fixtureAudit{}
	recorder, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"), sink)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recorder.Close() })
	coordinator, err := operations.New(rbac, router, semantic, recorder, executor.New(1, 5*time.Second), hardware, "sha256:synthetic-poc", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	handler := auth.NewAuthenticator("spiffe://regalia/", nil, time.Now, time.Minute).Middleware(api.NewHandler(coordinator))
	f := &kmsFixture{handler: handler, pki: pki, audit: sink, t: t}
	f.start()
	pki.config["kms_url"] = f.server.URL
	pki.strangerConfig["kms_url"] = f.server.URL
	t.Cleanup(func() { f.server.Close() })
	return f
}

func (f *kmsFixture) start() {
	f.t.Helper()
	server := httptest.NewUnstartedServer(f.handler)
	if f.address != "" {
		_ = server.Listener.Close()
		listener, err := net.Listen("tcp", f.address)
		if err != nil {
			f.t.Fatal(err)
		}
		server.Listener = listener
	}
	tls, err := auth.ServerTLSConfig(f.pki.server, f.pki.roots)
	if err != nil {
		f.t.Fatal(err)
	}
	server.TLS = tls
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	f.server = server
	f.address = server.Listener.Addr().String()
}

func TestRealKMSStackRejectsWrongIdentityPurposeAndAAD(t *testing.T) {
	f := newKMSFixture(t)
	ctx := context.Background()
	w := New()
	if _, err := w.SetConfig(ctx, wrappingConfig(f.pki.config)); err != nil {
		t.Fatal(err)
	}
	blob, err := w.Encrypt(ctx, []byte("synthetic-poc-payload"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := w.Decrypt(ctx, blob)
	if err != nil || !bytes.Equal(out, []byte("synthetic-poc-payload")) {
		t.Fatal("real stack roundtrip failed", err)
	}
	for _, mode := range []string{"identity", "purpose", "object", "aad"} {
		t.Run(mode, func(t *testing.T) {
			c := cloneConfig(f.pki.config)
			if mode == "identity" {
				c = cloneConfig(f.pki.strangerConfig)
			}
			if mode == "purpose" {
				c["kms_purpose"] = "wrong-purpose"
			}
			if mode == "object" {
				c["object_id"] = "unknown-object"
			}
			target := New()
			if _, err := target.SetConfig(ctx, wrappingConfig(c)); err != nil {
				t.Fatal(err)
			}
			before := f.audit.successful("unwrap")
			var opts []wrapping.Option
			if mode == "aad" {
				opts = []wrapping.Option{wrapping.WithAad([]byte("wrong"))}
			}
			if mode == "object" {
				beforeWrap := f.audit.successful("wrap")
				if result, err := target.Encrypt(ctx, []byte("synthetic")); err == nil || result != nil {
					t.Fatal("unknown object wrapped a key")
				}
				if f.audit.successful("wrap") != beforeWrap {
					t.Fatal("unknown object executed successfully")
				}
				return
			}
			if plain, err := target.Decrypt(ctx, blob, opts...); err == nil || len(plain) != 0 {
				t.Fatal("unauthorized unwrap succeeded")
			}
			if f.audit.successful("unwrap") != before {
				t.Fatal("unauthorized unwrap executed successfully")
			}
		})
	}
}
