package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
)

// externalCollector is this repository's regalia-audit-collector behind mutual TLS, standing in for the external
// service (#351), with the files a host is configured with written to a directory: client.crt, client.key,
// collector-ca.pem, collector-receipt.pub; plus an expired certificate and a key that is not the certificate's.
type externalCollector struct {
	url, dir string
}

func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newExternalCollector(t *testing.T) externalCollector {
	t.Helper()
	dir := t.TempDir()
	caPublic, caPrivate, _ := ed25519.GenerateKey(rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "external-collector-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPublic, caPrivate)
	ca, _ := x509.ParseCertificate(caDER)
	writePEM(t, filepath.Join(dir, "collector-ca.pem"), "CERTIFICATE", caDER)
	issue := func(name string, usage x509.ExtKeyUsage, server bool, notAfter time.Time) ([]byte, ed25519.PrivateKey) {
		public, private, _ := ed25519.GenerateKey(rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		if server {
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, public, caPrivate)
		if err != nil {
			t.Fatal(err)
		}
		return der, private
	}
	writeKey := func(path string, key ed25519.PrivateKey) {
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		writePEM(t, path, "PRIVATE KEY", der)
	}
	serverDER, serverKey := issue("collector", x509.ExtKeyUsageServerAuth, true, time.Now().Add(time.Hour))
	clientDER, clientKey := issue("sitea-node", x509.ExtKeyUsageClientAuth, false, time.Now().Add(time.Hour))
	writePEM(t, filepath.Join(dir, "client.crt"), "CERTIFICATE", clientDER)
	writeKey(filepath.Join(dir, "client.key"), clientKey)
	expiredDER, expiredKey := issue("sitea-node", x509.ExtKeyUsageClientAuth, false, time.Now().Add(-time.Hour))
	writePEM(t, filepath.Join(dir, "expired.crt"), "CERTIFICATE", expiredDER)
	writeKey(filepath.Join(dir, "expired.key"), expiredKey)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	writeKey(filepath.Join(dir, "other.key"), other)

	collector, err := audit.OpenCollector(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { collector.Close() })
	receiptPublic, receiptPrivate, _ := ed25519.GenerateKey(rand.Reader)
	collector.SetReceiptKey(receiptPrivate)
	if err := os.WriteFile(filepath.Join(dir, "collector-receipt.pub"), []byte("# the collector's receipt key\n"+hex.EncodeToString(receiptPublic)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server := httptest.NewUnstartedServer(collector.Handler())
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
		Certificates: []tls.Certificate{{Certificate: [][]byte{serverDER}, PrivateKey: serverKey}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return externalCollector{url: server.URL, dir: dir}
}

// args is the endpoint's flags as a host's configuration gives them, with `change` ({flag: value}) applied.
func (c externalCollector) args(change map[string]string) []string {
	values := map[string]string{"-collector": c.url, "-site": "sitea", "-tls-cert": filepath.Join(c.dir, "client.crt"),
		"-tls-key": filepath.Join(c.dir, "client.key"), "-server-ca": filepath.Join(c.dir, "collector-ca.pem"),
		"-receipt-keys": filepath.Join(c.dir, "collector-receipt.pub")}
	for k, v := range change {
		values[k] = v
	}
	var out []string
	for _, k := range []string{"-collector", "-site", "-tls-cert", "-tls-key", "-server-ca", "-receipt-keys"} {
		out = append(out, k, values[k])
	}
	return out
}

func runCommand(arguments ...string) (string, error) {
	var out bytes.Buffer
	err := run(arguments, &out)
	return out.String(), err
}

func TestCheckValidatesTheWholeEndpointBeforeAnythingRuns(t *testing.T) {
	c := newExternalCollector(t)
	out, err := runCommand(append([]string{"check"}, c.args(nil)...)...)
	if err != nil || !strings.Contains(out, "1 receipt key(s)") {
		t.Fatalf("a good configuration: %v\n%s", err, out)
	}
	bad := filepath.Join(c.dir, "bad.pub")
	os.WriteFile(bad, []byte("not-a-key\n"), 0o644)
	empty := filepath.Join(c.dir, "empty.pub")
	os.WriteFile(empty, []byte("# nothing pinned\n"), 0o644)
	noCA := filepath.Join(c.dir, "no-ca.pem")
	os.WriteFile(noCA, []byte("nothing\n"), 0o644)
	for _, tc := range []struct {
		change map[string]string
		reason string
	}{
		{map[string]string{"-collector": "http://collector.invalid:8443"}, "audit collector must be an https origin"},
		{map[string]string{"-collector": c.url + "/v1"}, "must be an origin with no path"},
		{map[string]string{"-collector": "https://user@collector.invalid"}, "audit collector must be an https origin"},
		{map[string]string{"-site": "site a"}, "not a site the collector accepts"},
		{map[string]string{"-tls-cert": filepath.Join(c.dir, "expired.crt"), "-tls-key": filepath.Join(c.dir, "expired.key")}, "not now"},
		{map[string]string{"-tls-key": filepath.Join(c.dir, "other.key")}, "client certificate and key"},
		{map[string]string{"-server-ca": noCA}, "holds no usable certificate"},
		{map[string]string{"-receipt-keys": bad}, "is not an Ed25519 public key in hex"},
		{map[string]string{"-receipt-keys": empty}, "pins no receipt key"},
		{map[string]string{"-receipt-keys": ""}, "are required"},
	} {
		if _, err := runCommand(append([]string{"check"}, c.args(tc.change)...)...); err == nil || !strings.Contains(err.Error(), tc.reason) {
			t.Errorf("%v: %v, not %q", tc.change, err, tc.reason)
		}
	}
}

func TestCheckProbeReachesTheCollectorReadOnlyAndNamesWhatFailed(t *testing.T) {
	c := newExternalCollector(t)
	out, err := runCommand(append([]string{"check", "-probe", "-trail", "sync"}, c.args(nil)...)...)
	if err != nil || !strings.Contains(out, "collector: ready") || !strings.Contains(out, "sitea.sync: committed 0") {
		t.Fatalf("%v\n%s", err, out)
	}
	_, err = runCommand(append([]string{"check", "-probe"}, c.args(map[string]string{"-collector": "https://127.0.0.1:1"})...)...)
	if err == nil || !strings.Contains(err.Error(), "does not answer HEAD /v1/health/ready over mutual TLS") {
		t.Fatalf("an unreachable collector: %v", err)
	}
}

func TestConformanceAgainstOurCollectorAndAgainstTheWrongReceiptKey(t *testing.T) {
	c := newExternalCollector(t)
	out, err := runCommand(append([]string{"conformance"}, c.args(nil)...)...)
	if err != nil || !strings.Contains(out, "meets the audit collector contract: 13 rules") || strings.Contains(out, "FAIL") {
		t.Fatalf("%v\n%s", err, out)
	}
	_, otherPublic, _ := ed25519.GenerateKey(rand.Reader)
	wrong := filepath.Join(c.dir, "wrong.pub")
	os.WriteFile(wrong, []byte(hex.EncodeToString(otherPublic.Public().(ed25519.PublicKey))+"\n"), 0o644)
	out, err = runCommand(append([]string{"conformance"}, c.args(map[string]string{"-receipt-keys": wrong})...)...)
	if err == nil || !strings.Contains(err.Error(), "does NOT meet") || !strings.Contains(out, "FAIL GET /v1/receipt") {
		t.Fatalf("%v\n%s", err, out)
	}
}
