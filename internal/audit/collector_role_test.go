package audit

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roleFixture struct {
	root   string
	reader *collectorFileReader
	wire   []byte
	opts   CollectorEndpointOptions
	now    time.Time
	der    []byte
}

func newRoleFixture(t *testing.T, role CollectorRole, origin string) roleFixture {
	t.Helper()
	root, reader := collectorScratchRoot(t)
	wire := []byte(strings.Replace(collectorFixture, "https://collector.invalid/", origin, 1))
	d, err := DecodeCollectorDescriptor(wire)
	collectorMust(t, err)
	opts, err := d.EndpointOptions(role)
	collectorMust(t, err)
	pemFiles, now, der := collectorEndpointFixture(t)
	writeCollectorFixtureFile(t, root, collectorSelectorPath, wire, 0o644)
	for _, pair := range [][2]string{
		{opts.CertificatePath, pemFiles.CertificatePath}, {opts.PrivateKeyPath, pemFiles.PrivateKeyPath},
		{opts.CAPath, pemFiles.CAPath}, {opts.ReceiptKeysPath, pemFiles.ReceiptKeysPath},
	} {
		raw, err := os.ReadFile(pair[1])
		collectorMust(t, err)
		mode := os.FileMode(0o644)
		if pair[0] == opts.PrivateKeyPath {
			mode = 0o640
		}
		writeCollectorFixtureFile(t, root, pair[0], raw, mode)
	}
	return roleFixture{root, reader, wire, opts, now, der}
}

func (f roleFixture) raw(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.root, name))
	collectorMust(t, err)
	return data
}

func (f roleFixture) load(role CollectorRole, trail string) (*LoadedCollectorRole, error) {
	clear(f.reader.seen)
	return loadCollectorRole(f.reader, role, trail, f.now)
}

func (f roleFixture) valid(t *testing.T, role CollectorRole, trail string) *LoadedCollectorRole {
	t.Helper()
	loaded, err := f.load(role, trail)
	if err != nil || loaded == nil {
		t.Fatalf("valid role did not build the sink: %v", err)
	}
	return loaded
}

func TestCollectorRoleBindsRealSinkAndOnlyReadsItsRole(t *testing.T) {
	for _, tc := range []struct {
		role                         CollectorRole
		trail, stream, unselectedKey string
	}{
		{CollectorRoleDaemon, "", "Site.a", fixtureShipperRoot + "/ship.key"},
		{CollectorRoleNodeShipper, "sync", "Site.a.sync", fixtureDaemonRoot + "/daemon.key"},
	} {
		t.Run(string(tc.role), func(t *testing.T) {
			f := newRoleFixture(t, tc.role, "https://collector.invalid:8443/")
			unselected := writeCollectorFixtureFile(t, f.root, tc.unselectedKey, []byte("unselected fixture marker"), 0o600)
			loaded := f.valid(t, tc.role, tc.trail)
			if len(f.reader.seen) != 5 {
				t.Fatalf("role read another object or missed a selected file: %d opened identities", len(f.reader.seen))
			}
			collectorMust(t, os.Remove(unselected))
			f.valid(t, tc.role, tc.trail)

			b := loaded.Binding()
			wantID := sha256.Sum256(f.der)
			if b.Role != tc.role || b.NodeID != "node-1" || b.Site != "Site.a" ||
				b.Generation != descriptorGeneration || b.Stream != tc.stream ||
				b.DescriptorSHA256 != sha256.Sum256(f.wire) || b.CASHA256 != sha256.Sum256(f.raw(t, f.opts.CAPath)) ||
				b.ReceiptKeysSHA256 != sha256.Sum256(f.raw(t, f.opts.ReceiptKeysPath)) ||
				b.ClientIdentity != hex.EncodeToString(wantID[:]) ||
				!b.NotBefore.Equal(f.now.Add(-time.Hour)) || !b.NotAfter.Equal(f.now.Add(time.Hour)) {
				t.Fatal("sink binding is missing verified role, stream, generation or same-input identity data")
			}
			sink := loaded.Sink()
			if sink == nil || sink.client == nil || sink.baseURL != "https://collector.invalid:8443" ||
				sink.site != tc.stream || sink.client.Timeout != 10*time.Second || sink.client.CheckRedirect == nil {
				t.Fatal("returned role did not retain the actual constructed HTTPS sink for its stream")
			}
			transport, ok := sink.client.Transport.(*http.Transport)
			if !ok || transport.Proxy != nil || transport.TLSClientConfig == nil {
				t.Fatal("returned sink does not use the real pinned proxy-free transport")
			}
			cfg := transport.TLSClientConfig
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(f.raw(t, f.opts.CAPath)) || !cfg.RootCAs.Equal(roots) ||
				cfg.ServerName != "collector.invalid" || cfg.MinVersion != tls.VersionTLS13 ||
				len(cfg.Certificates) != 1 || !bytes.Equal(cfg.Certificates[0].Certificate[0], f.der) ||
				cfg.Certificates[0].PrivateKey == nil {
				t.Fatal("transport did not retain the selected trusted TLS material and pinned configuration")
			}
		})
	}
}

func TestCollectorRoleRefusesWrongStreamSelection(t *testing.T) {
	f := newRoleFixture(t, CollectorRoleDaemon, "https://collector.invalid")
	f.valid(t, CollectorRoleDaemon, "")
	for _, tc := range []struct {
		name  string
		role  CollectorRole
		trail string
		want  error
	}{
		{"daemon-trail", CollectorRoleDaemon, "sync", ErrCollectorDescriptorStream},
		{"shipper-no-trail", CollectorRoleNodeShipper, "", ErrCollectorDescriptorStream},
		{"shipper-unsafe-trail", CollectorRoleNodeShipper, "bad/name", ErrCollectorDescriptorStream},
		{"unknown-role", CollectorRole("unknown"), "", ErrCollectorDescriptorRole},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loaded, err := f.load(tc.role, tc.trail)
			if loaded != nil || err != tc.want || len(f.reader.seen) != 0 {
				t.Fatalf("bad role or trail reached the files or wrong refusal: %v", err)
			}
		})
	}
}

func TestCollectorRoleChecksFullShipperStream(t *testing.T) {
	f := newRoleFixture(t, CollectorRoleNodeShipper, "https://collector.invalid")
	wire := strings.Replace(string(f.wire), "Site.a", strings.Repeat("s", 60), 1)
	writeCollectorFixtureFile(t, f.root, collectorSelectorPath, []byte(wire), 0o644)
	f.valid(t, CollectorRoleNodeShipper, "one")
	if loaded, err := f.load(CollectorRoleNodeShipper, "sync"); loaded != nil || err != ErrCollectorDescriptorStream {
		t.Fatalf("shipper accepted a full stream longer than the collector permits: %v", err)
	}
}

func TestCollectorRoleRejectsUntrustedMaterialWithFixedErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *roleFixture)
		want   error
	}{
		{"missing-selected-key", func(t *testing.T, f *roleFixture) {
			collectorMust(t, os.Remove(filepath.Join(f.root, f.opts.PrivateKeyPath)))
		}, ErrCollectorRoleFile},
		{"keypair-mismatch", func(t *testing.T, f *roleFixture) {
			other, _, _ := collectorEndpointFixture(t)
			b, err := os.ReadFile(other.PrivateKeyPath)
			collectorMust(t, err)
			writeCollectorFixtureFile(t, f.root, f.opts.PrivateKeyPath, b, 0o640)
		}, ErrCollectorRoleMaterial},
		{"expired-leaf", func(t *testing.T, f *roleFixture) { f.now = f.now.Add(2 * time.Hour) }, ErrCollectorRoleMaterial},
		{"future-leaf", func(t *testing.T, f *roleFixture) { f.now = f.now.Add(-2 * time.Hour) }, ErrCollectorRoleMaterial},
		{"ca", func(t *testing.T, f *roleFixture) {
			writeCollectorFixtureFile(t, f.root, f.opts.CAPath, []byte("private-input-marker"), 0o644)
		}, ErrCollectorRoleMaterial},
		{"receipt-format", func(t *testing.T, f *roleFixture) {
			writeCollectorFixtureFile(t, f.root, f.opts.ReceiptKeysPath, []byte("private-input-marker"), 0o644)
		}, ErrCollectorRoleMaterial},
		{"receipt-empty", func(t *testing.T, f *roleFixture) {
			writeCollectorFixtureFile(t, f.root, f.opts.ReceiptKeysPath, []byte("# no keys\n"), 0o644)
		}, ErrCollectorRoleMaterial},
		{"first-pem-block", func(t *testing.T, f *roleFixture) {
			prefix := pem.EncodeToMemory(&pem.Block{Type: "NOTE", Bytes: []byte("private-input-marker")})
			content := append(prefix, f.raw(t, f.opts.CertificatePath)...)
			// TLS itself skips the prefix, so this protects C1's distinct identity rule.
			if _, err := tls.X509KeyPair(content, f.raw(t, f.opts.PrivateKeyPath)); err != nil {
				t.Fatal("first-block fixture does not reach the identity guard")
			}
			writeCollectorFixtureFile(t, f.root, f.opts.CertificatePath, content, 0o644)
		}, ErrCollectorRoleMaterial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRoleFixture(t, CollectorRoleDaemon, "https://collector.invalid")
			f.valid(t, CollectorRoleDaemon, "")
			tc.change(t, &f)
			got, err := f.load(CollectorRoleDaemon, "")
			if got != nil || err != tc.want {
				t.Fatalf("role accepted invalid material or did not give the fixed refusal: %T", err)
			}
		})
	}
}

func TestCollectorRoleBoundsEveryCanonicalFile(t *testing.T) {
	for _, name := range []string{"selector", "certificate", "private-key", "ca", "receipt"} {
		t.Run(name, func(t *testing.T) {
			f := newRoleFixture(t, CollectorRoleDaemon, "https://collector.invalid")
			path, bound := collectorSelectorPath, 16<<10
			switch name {
			case "certificate":
				path, bound = f.opts.CertificatePath, 128<<10
			case "private-key":
				path, bound = f.opts.PrivateKeyPath, 64<<10
			case "ca":
				path, bound = f.opts.CAPath, 256<<10
			case "receipt":
				path, bound = f.opts.ReceiptKeysPath, 64<<10
			}
			raw := f.raw(t, path)
			exact := append(raw, bytes.Repeat([]byte("\n"), bound-len(raw))...)
			writeCollectorFixtureFile(t, f.root, path, exact, 0o640)
			f.valid(t, CollectorRoleDaemon, "")
			writeCollectorFixtureFile(t, f.root, path, append(exact, '\n'), 0o640)
			got, err := f.load(CollectorRoleDaemon, "")
			if got != nil || err != ErrCollectorRoleFile {
				t.Fatalf("role did not enforce canonical %s file bound: %v", name, err)
			}
		})
	}
}

func TestCollectorRoleRequiresActualTransportConstruction(t *testing.T) {
	f := newRoleFixture(t, CollectorRoleDaemon, "https://[::1]:9443")
	got, err := f.load(CollectorRoleDaemon, "")
	if got != nil || err != ErrCollectorRoleSink {
		t.Fatalf("role accepted a syntactic origin the existing mTLS transport refuses: %v", err)
	}
}

func TestCollectorRoleIsOfflineWithRawTCPWitness(t *testing.T) {
	server, connections, requests := collectorEndpointTestServer(t)
	f := newRoleFixture(t, CollectorRoleDaemon, server.URL)
	f.valid(t, CollectorRoleDaemon, "")
	server.Close()
	if connections.accepted.Load() != 0 || requests.Load() != 0 {
		t.Fatal("offline role loader contacted the collector")
	}

	server, connections, requests = collectorEndpointTestServer(t)
	f = newRoleFixture(t, CollectorRoleNodeShipper, server.URL)
	loaded := f.valid(t, CollectorRoleNodeShipper, "sync")
	reply, err := loaded.Sink().client.Get(server.URL)
	if reply != nil {
		reply.Body.Close()
	}
	server.Close()
	var untrusted x509.UnknownAuthorityError
	if !errors.As(err, &untrusted) || connections.accepted.Load() != 1 || requests.Load() != 0 {
		t.Fatalf("positive control did not observe TCP without HTTP on rejected TLS trust: %v", err)
	}
}
