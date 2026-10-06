package openbaopoc

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/dns/dnsmessage"
)

// An authoritative loopback resolver serves only synthetic DNS-01 TXT records.
// The drill needs no system DNS changes, privileged port or external CA account.
type pocChallengeDNS struct {
	conn    *net.UDPConn
	mu      sync.Mutex
	txt     map[string]string
	queries int
}

func newPOCChallengeDNS(t *testing.T) *pocChallengeDNS {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	d := &pocChallengeDNS{conn: conn, txt: map[string]string{}}
	done := make(chan struct{})
	t.Cleanup(func() { _ = conn.Close(); <-done })
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buf[:n]) != nil || query.Response || len(query.Questions) != 1 {
				continue
			}
			q := query.Questions[0]
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true, RecursionDesired: query.RecursionDesired, RecursionAvailable: true}, Questions: query.Questions}
			d.mu.Lock()
			value, ok := d.txt[strings.ToLower(q.Name.String())]
			if ok && q.Type == dnsmessage.TypeTXT && q.Class == dnsmessage.ClassINET {
				d.queries++
				response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}, Body: &dnsmessage.TXTResource{TXT: []string{value}}}}
			} else {
				response.RCode = dnsmessage.RCodeNameError
			}
			d.mu.Unlock()
			encoded, err := response.Pack()
			if err == nil {
				_, _ = conn.WriteToUDP(encoded, addr)
			}
		}
	}()
	return d
}

func (d *pocChallengeDNS) set(name, value string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.txt["_acme-challenge."+name+"."] = value
}

func pocACMEOrder(t *testing.T, client *acme.Client, dns *pocChallengeDNS) tls.Certificate {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs("web.svc.poc.invalid"))
	if err != nil {
		t.Fatal("synthetic ACME order failed", err)
	}
	for _, authURL := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, authURL)
		if err != nil {
			t.Fatal("synthetic ACME authorization failed", err)
		}
		if auth.Status == acme.StatusValid {
			continue
		}
		var challenge *acme.Challenge
		for _, candidate := range auth.Challenges {
			if candidate.Type == "dns-01" {
				challenge = candidate
				break
			}
		}
		if challenge == nil {
			t.Fatal("DNS-01 challenge unavailable")
		}
		value, err := client.DNS01ChallengeRecord(challenge.Token)
		if err != nil {
			t.Fatal("DNS-01 record failed")
		}
		dns.set(auth.Identifier.Value, value)
		if _, err = client.Accept(ctx, challenge); err != nil {
			t.Fatal("synthetic challenge acceptance failed", err)
		}
		if _, err = client.WaitAuthorization(ctx, authURL); err != nil {
			t.Fatal("synthetic DNS-01 verification failed", err)
		}
	}
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		t.Fatal("synthetic ACME order not ready", err)
	}
	leafKey := testSigner(t, "p256")
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "web.svc.poc.invalid"}, DNSNames: []string{"web.svc.poc.invalid"}}, leafKey)
	if err != nil {
		t.Fatal("synthetic CSR failed")
	}
	certs, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil || len(certs) == 0 {
		t.Fatal("synthetic ACME finalization failed", err)
	}
	leaf, err := x509.ParseCertificate(certs[0])
	if err != nil {
		t.Fatal("invalid ACME leaf")
	}
	want, _ := x509.MarshalPKIXPublicKey(leafKey.Public())
	if string(leaf.RawSubjectPublicKeyInfo) != string(want) {
		t.Fatal("ACME certificate does not match fresh client key")
	}
	return tls.Certificate{Certificate: certs, PrivateKey: leafKey, Leaf: leaf}
}

func pocACME(t *testing.T, b baoAPI, root, issuer *x509.Certificate, f *signingFixture, backend *pocDaemonCA) {
	t.Helper()
	dns := newPOCChallengeDNS(t)
	b.must(t, http.MethodPost, "/v1/sys/mounts/pki/tune", map[string]any{"allowed_response_headers": []string{"Replay-Nonce", "Link", "Location"}})
	b.must(t, http.MethodPost, "/v1/pki/config/cluster", map[string]string{"path": b.base + "/v1/pki"})
	b.must(t, http.MethodPost, "/v1/pki/config/acme", map[string]any{"enabled": true, "allowed_roles": []string{"poc"}, "default_directory_policy": "role:poc", "dns_resolver": dns.conn.LocalAddr().String(), "eab_policy": "always-required"})
	// No Bao root token is attached to ACME requests. The test account proves
	// control through DNS-01. All transport targets must remain on this listener.
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	localClient := &http.Client{Timeout: 30 * time.Second, Transport: pocLocalTransport{base: b.base, transport: transport}}
	client := &acme.Client{Key: testSigner(t, "p256"), DirectoryURL: b.base + "/v1/pki/roles/poc/acme/directory", HTTPClient: localClient}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err == nil {
		t.Fatal("ACME accepted account without EAB")
	} else {
		var problem *acme.Error
		if !errors.As(err, &problem) || !strings.HasSuffix(problem.ProblemType, ":externalAccountRequired") {
			t.Fatal("ACME account refusal did not enforce EAB", err)
		}
	}
	response := pocData(t, b.must(t, http.MethodPost, "/v1/pki/roles/poc/acme/new-eab", map[string]any{}))
	secret, err := base64.RawURLEncoding.DecodeString(pocString(t, response, "key"))
	if err != nil {
		t.Fatal("invalid synthetic EAB secret")
	}
	defer clear(secret)
	binding := &acme.ExternalAccountBinding{KID: pocString(t, response, "id"), Key: secret}
	if _, err := client.Register(ctx, &acme.Account{ExternalAccountBinding: binding}, acme.AcceptTOS); err != nil {
		t.Fatal("synthetic ACME registration failed", err)
	}
	pocUnprovenACME(t, client, backend)
	first := pocACMEOrder(t, client, dns)
	second := pocACMEOrder(t, client, dns)
	leaf1 := pocLeaf(t, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: first.Certificate[0]})), root, issuer, f, backend)
	leaf2 := pocLeaf(t, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: second.Certificate[0]})), root, issuer, f, backend)
	if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) == 0 || string(leaf1.RawSubjectPublicKeyInfo) == string(leaf2.RawSubjectPublicKeyInfo) {
		t.Fatal("ACME renewal did not issue a fresh serial and client key")
	}
	pocHTTPSRotation(t, root, first, second)
	dns.mu.Lock()
	queries := dns.queries
	dns.mu.Unlock()
	if queries == 0 {
		t.Fatal("ACME did not perform DNS-01 verification")
	}
}

func pocUnprovenACME(t *testing.T, client *acme.Client, backend *pocDaemonCA) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	before := len(backend.snapshot())
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs("unproven.svc.poc.invalid"))
	if err != nil || len(order.AuthzURLs) != 1 {
		t.Fatal("unproven ACME order failed", err)
	}
	auth, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatal("unproven ACME authorization failed", err)
	}
	var challenge *acme.Challenge
	for _, candidate := range auth.Challenges {
		if candidate.Type == "dns-01" {
			challenge = candidate
			break
		}
	}
	if challenge == nil {
		t.Fatal("unproven DNS-01 challenge unavailable")
	}
	// Do not publish its TXT token. A valid EAB alone cannot authorize issuance.
	if _, err = client.Accept(ctx, challenge); err != nil {
		t.Fatal("unproven challenge acceptance failed", err)
	}
	// OpenBao retries failed challenges before terminally invalidating them.
	// Observe a real verification error, then prove the pending order cannot sign.
	for {
		checked, err := client.GetChallenge(ctx, challenge.URI)
		if err != nil {
			t.Fatal("unproven challenge polling failed", err)
		}
		if checked.Status == acme.StatusValid {
			t.Fatal("unproven DNS challenge became valid")
		}
		if checked.Error != nil {
			var problem *acme.Error
			if !errors.As(checked.Error, &problem) || !strings.HasSuffix(problem.ProblemType, ":incorrectResponse") {
				t.Fatal("unexpected DNS verification error", checked.Error)
			}
			break
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatal("no DNS verification failure before deadline")
		case <-timer.C:
		}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "unproven.svc.poc.invalid"}, DNSNames: []string{"unproven.svc.poc.invalid"}}, testSigner(t, "p256"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	var refused *acme.Error
	if !errors.As(err, &refused) || !strings.HasSuffix(refused.ProblemType, ":orderNotReady") || len(backend.snapshot()) != before {
		t.Fatal("unproven DNS ownership was not refused before KMS signing", err)
	}
}

type pocLocalTransport struct {
	base      string
	transport *http.Transport
}

func (p pocLocalTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme+"://"+r.URL.Host != p.base {
		return nil, fmt.Errorf("ACME target outside synthetic listener")
	}
	return p.transport.RoundTrip(r)
}

// Present each ACME-issued chain to an actual TLS client using the pinned root.
// Leaf private keys stay with this synthetic application, outside the KMS.
func pocHTTPSRotation(t *testing.T, root *x509.Certificate, first, second tls.Certificate) {
	t.Helper()
	var active atomic.Pointer[tls.Certificate]
	active.Store(&first)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return active.Load(), nil }}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	address := server.Listener.Addr().String()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
		if target != "web.svc.poc.invalid:443" {
			return nil, fmt.Errorf("HTTPS target outside synthetic application")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, cert := range []*tls.Certificate{&first, &second} {
		active.Store(cert)
		response, err := client.Get("https://web.svc.poc.invalid/")
		if err != nil {
			t.Fatal("ACME application TLS verification failed", err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || response.TLS.PeerCertificates[0].SerialNumber.Cmp(cert.Leaf.SerialNumber) != 0 {
			t.Fatal("HTTPS did not serve expected ACME certificate")
		}
	}
}
