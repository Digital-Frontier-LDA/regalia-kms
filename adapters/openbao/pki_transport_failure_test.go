package openbaopoc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

// A signature can execute without ever reaching the caller. These tests use the
// real mTLS API, policy state and coordinator audit recorder; only the software
// token and the response-loss injector are synthetic. The durable reservation
// must remain spent, and this logical signing request must never be retried.
func TestPKIPoCLostSignatureResponseIsNotRetried(t *testing.T) {
	for _, mode := range []string{"transport-error", "truncated-response"} {
		t.Run(mode, func(t *testing.T) {
			ca := testSigner(t, "p256").(*ecdsa.PrivateKey)
			issuer := pocIssuer(t, ca)
			provider := &pocDaemonCA{key: ca, issuer: issuer, leafCap: 1, crlCap: 1}
			f := newSigningFixtureWith(t, "p256", "sha256", ca, provider, true)
			key := configuredPKIPoC(t, f, f.pki.caConfig).(*pkiPOCKey)
			input := pocFailureLeafTBS(t, issuer, ca)
			original := key.client.http.Transport
			var requests atomic.Int64
			key.client.http.Transport = responseTransport(func(r *http.Request) (*http.Response, error) {
				requests.Add(1)
				response, err := original.RoundTrip(r)
				if err != nil {
					return nil, err
				}
				if response.StatusCode != http.StatusOK {
					response.Body.Close()
					return nil, errors.New("synthetic response-loss setup failed")
				}
				if mode == "truncated-response" {
					response.Body = pocTruncatedSignatureBody{response.Body}
					return response, nil
				}
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				return nil, errors.New("synthetic lost signature response")
			})
			result, err := key.Sign(context.Background(), &kms.SignOptions{Data: input, SignerOpts: crypto.SHA256})
			var failure *APIError
			if len(result) != 0 || !errors.As(err, &failure) || failure.Code != "TRANSPORT_UNAVAILABLE" || failure.Retryable || requests.Load() != 1 {
				t.Fatal("an ambiguous response returned bytes or retried", requests.Load(), err)
			}
			pocAssertFailureAccounting(t, f, provider, input, "success")
			key.client.http.Transport = original
			if result, err = key.Sign(context.Background(), &kms.SignOptions{Data: input, SignerOpts: crypto.SHA256}); err == nil || len(result) != 0 {
				t.Fatal("a lost result reclaimed the consumed issuance reservation")
			}
			if f.audit.successful("sign") != 1 {
				t.Fatal("a lost result permitted another signature")
			}
		})
	}
}

type pocTruncatedSignatureBody struct{ io.ReadCloser }

func (pocTruncatedSignatureBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// Go's HTTP transport considers Idempotency-Key POSTs replayable when GetBody
// is populated. Closing a reused HTTP/1 connection after the real coordinator
// signs must not silently send the same request a second time beneath the
// adapter's retry loop. A replay guard preventing a second signature is a
// separate guarantee; this test counts requests at the actual server boundary.
func TestPKIPoCClosedConnectionAfterSigningIsNotReplayed(t *testing.T) {
	ca := testSigner(t, "p256").(*ecdsa.PrivateKey)
	issuer := pocIssuer(t, ca)
	provider := &pocDaemonCA{key: ca, issuer: issuer, leafCap: 1, crlCap: 1}
	f := newSigningFixtureWith(t, "p256", "sha256", ca, provider, true)
	var requests atomic.Int64
	original := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/operations/sign" || requests.Add(1) != 1 {
			original.ServeHTTP(w, r)
			return
		}
		result := httptest.NewRecorder()
		original.ServeHTTP(result, r)
		defer clear(result.Body.Bytes())
		if result.Code != http.StatusOK {
			t.Error("synthetic connection-close setup did not sign")
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("synthetic connection-close setup requires HTTP/1")
			return
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			t.Error("synthetic connection-close setup cannot hijack HTTP/1 connection")
			return
		}
		connection.Close()
	})
	key := configuredPKIPoC(t, f, f.pki.caConfig).(*pkiPOCKey)
	transport := key.client.http.Transport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	t.Cleanup(transport.CloseIdleConnections)
	key.client.http.Transport = transport
	// Prime a persistent connection so the standard transport's retry branch is
	// eligible. This read-only health request consumes neither nonce nor budget.
	response, err := key.client.http.Get(f.server.URL + "/v1/health/ready")
	if err != nil {
		t.Fatal("cannot prime the synthetic persistent connection", err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	input := pocFailureLeafTBS(t, issuer, ca)
	var reused atomic.Bool
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		if info.Reused {
			reused.Store(true)
		}
	}})
	result, err := key.Sign(ctx, &kms.SignOptions{Data: input, SignerOpts: crypto.SHA256})
	if !reused.Load() {
		t.Fatal("synthetic connection-close test did not exercise a reused connection")
	}
	var failure *APIError
	if len(result) != 0 || !errors.As(err, &failure) || failure.Code != "TRANSPORT_UNAVAILABLE" || failure.Retryable || requests.Load() != 1 {
		t.Fatal("HTTP transport replayed an already executed CA request", requests.Load(), err)
	}
	pocAssertFailureAccounting(t, f, provider, input, "success")
}

type pocExecutedFailureCA struct {
	*pocDaemonCA
	mode  string
	calls atomic.Int64
}

func (p *pocExecutedFailureCA) Execute(ctx context.Context, route registry.Route, op, format, content string, data, aad []byte) ([]byte, string, error) {
	p.calls.Add(1)
	result, outputType, err := p.pocDaemonCA.Execute(ctx, route, op, format, content, data, aad)
	if err != nil {
		return result, outputType, err
	}
	if p.mode == "panic" {
		clear(result)
		panic("synthetic failure after signature execution")
	}
	// Manager must discard and clear the returned output when the provider reports
	// a failure. The server cannot infer whether the token executed from this error.
	return result, outputType, errors.New("synthetic failure after signature execution")
}

func TestPKIPoCExecutedBackendFailureIsNotRetried(t *testing.T) {
	for _, mode := range []string{"error", "panic"} {
		t.Run(mode, func(t *testing.T) {
			ca := testSigner(t, "p256").(*ecdsa.PrivateKey)
			issuer := pocIssuer(t, ca)
			software := &pocDaemonCA{key: ca, issuer: issuer, leafCap: 1, crlCap: 1}
			provider := &pocExecutedFailureCA{pocDaemonCA: software, mode: mode}
			f := newSigningFixtureWith(t, "p256", "sha256", ca, provider, true)
			key := configuredPKIPoC(t, f, f.pki.caConfig)
			input := pocFailureLeafTBS(t, issuer, ca)
			result, err := key.Sign(context.Background(), &kms.SignOptions{Data: input, SignerOpts: crypto.SHA256})
			var failure *APIError
			if len(result) != 0 || !errors.As(err, &failure) || failure.Code != "BACKEND_UNAVAILABLE" || failure.Retryable || provider.calls.Load() != 1 {
				t.Fatal("an executed backend failure returned bytes or repeated the operation", provider.calls.Load(), err)
			}
			pocAssertFailureAccounting(t, f, software, input, "backend-failed")
			if result, err = key.Sign(context.Background(), &kms.SignOptions{Data: input, SignerOpts: crypto.SHA256}); err == nil || len(result) != 0 {
				t.Fatal("backend failure reclaimed the consumed issuance reservation")
			}
			if provider.calls.Load() != 1 || len(software.snapshot()) != 1 {
				t.Fatal("a later request executed after the failed signature consumed its issuance reservation")
			}
			if f.audit.successful("sign") != 0 {
				t.Fatal("an executed backend failure was audited as a successful signature release")
			}
		})
	}
}

func pocFailureLeafTBS(t *testing.T, issuer *x509.Certificate, ca *ecdsa.PrivateKey) []byte {
	t.Helper()
	now := time.Now().UTC()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "web.svc.poc.invalid"}, DNSNames: []string{"web.svc.poc.invalid"}, NotBefore: now.Add(-30 * time.Second), NotAfter: now.Add(5 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	key := testSigner(t, "p256").(*ecdsa.PrivateKey)
	encoded, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &key.PublicKey, ca)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.RawTBSCertificate
}

func pocAssertFailureAccounting(t *testing.T, f *signingFixture, provider *pocDaemonCA, input []byte, terminal string) {
	t.Helper()
	records := provider.snapshot()
	if len(records) != 1 || !records[0].Allowed || records[0].Kind != "digest" || records[0].Digest != sha256.Sum256(input) {
		t.Fatal("lost signature accounting does not identify exactly one accepted payload")
	}
	events := f.audit.snapshotEvents()
	digest := sha256.Sum256(input)
	payloadDigest := "sha256:" + hex.EncodeToString(digest[:])
	if len(events) != 2 || events[0].Outcome != "authorized" || events[1].Outcome != terminal || events[0].RequestID != events[1].RequestID {
		t.Fatal("coordinator audit does not correlate authorization and terminal outcome")
	}
	for _, event := range events {
		if event.X509ProfileID != f.profile.ID || event.PayloadDigest != payloadDigest || event.ArtifactKind != "certificate" || event.KeyFingerprint != f.keyConfig["public_key_sha256"] {
			t.Fatal("ambiguous signature lacks server-derived intent")
		}
	}
	pocDurableIntent(t, f, events[1], "certificate")
}
