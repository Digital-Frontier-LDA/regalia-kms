package config

import (
	"strings"
	"testing"
	"time"
)

func baseConfig() Config {
	cfg := Default()
	cfg.OperationTimeout = 15 * time.Second
	cfg.ShutdownTimeout = 10 * time.Second
	cfg.MaxConcurrentOperations = 4
	return cfg
}

// MUTUAL TLS IS ALL OR NOTHING. A certificate without its key, or either without the client trust
// roots, is a half-configured transport — and the missing half is the half that authenticates the
// caller. Starting on that would look like mTLS while accepting anyone the roots would have refused.
func TestPartialTLSConfigurationIsRefused(t *testing.T) {
	partials := []struct {
		name                    string
		certificate, key, roots string
	}{
		{"certificate only", "/tls/server.crt", "", ""},
		{"key only", "", "/tls/server.key", ""},
		{"roots only", "", "", "/tls/clients.pem"},
		{"certificate and key, no roots", "/tls/server.crt", "/tls/server.key", ""},
		{"certificate and roots, no key", "/tls/server.crt", "", "/tls/clients.pem"},
		{"key and roots, no certificate", "", "/tls/server.key", "/tls/clients.pem"},
	}
	for _, partial := range partials {
		t.Run(partial.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.TLSCertificatePath, cfg.TLSPrivateKeyPath, cfg.TLSClientCAPath = partial.certificate, partial.key, partial.roots
			err := cfg.Validate()
			if err == nil {
				t.Fatal("partial mTLS configuration was accepted")
			}
			if !strings.Contains(err.Error(), "configured together") {
				t.Fatalf("error does not name the cause: %v", err)
			}
		})
	}
}

// A routable listener is reachable by anything that can route to it, so the transport must
// authenticate the caller before the handler sees a request.
func TestNonLoopbackListenerRequiresMutualTLS(t *testing.T) {
	cfg := baseConfig()
	cfg.ListenAddress = "0.0.0.0:8443"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("non-loopback listener accepted without mutual TLS")
	}
	if !strings.Contains(err.Error(), "mutual TLS") {
		t.Fatalf("error does not name the cause: %v", err)
	}

	cfg.TLSCertificatePath = "/tls/server.crt"
	cfg.TLSPrivateKeyPath = "/tls/server.key"
	cfg.TLSClientCAPath = "/tls/clients.pem"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("non-loopback listener with mutual TLS was refused: %v", err)
	}
}

// Loopback stays usable without TLS for development, and complete mTLS is always acceptable.
func TestLoopbackRemainsValidWithAndWithoutTLS(t *testing.T) {
	cfg := baseConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("loopback without TLS refused: %v", err)
	}
	cfg.TLSCertificatePath = "/tls/server.crt"
	cfg.TLSPrivateKeyPath = "/tls/server.key"
	cfg.TLSClientCAPath = "/tls/clients.pem"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("loopback with complete mTLS refused: %v", err)
	}
}

// The document must be able to carry the paths, and must still refuse key material.
func TestTLSPathsParseFromDocumentAndNoKeyMaterialIsRepresentable(t *testing.T) {
	cfg, err := Decode(strings.NewReader(`{
		"listen_address": "0.0.0.0:8443",
		"tls_certificate_path": "/tls/server.crt",
		"tls_private_key_path": "/tls/server.key",
		"tls_client_ca_path": "/tls/clients.pem"
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.TLSCertificatePath != "/tls/server.crt" || cfg.TLSPrivateKeyPath != "/tls/server.key" || cfg.TLSClientCAPath != "/tls/clients.pem" {
		t.Fatalf("paths not parsed: %#v", cfg)
	}
	if _, err := Decode(strings.NewReader(`{"tls_private_key_pem": "-----BEGIN PRIVATE KEY-----"}`)); err == nil {
		t.Fatal("a document carrying inline key material was accepted")
	}
}

// CERTIFICATE ISSUING IS ALL OR NOTHING. A partially configured issuer is one whose missing part is
// the part that constrains it: no namespace certifies anything, no lifetime certifies it forever.
func TestPartialIssuerConfigurationIsRefused(t *testing.T) {
	partials := []struct {
		name     string
		path     string
		suffixes []string
		validity time.Duration
	}{
		{"certificate only", "/pki/ca.crt", nil, 0},
		{"suffixes only", "", []string{"staging.internal"}, 0},
		{"validity only", "", nil, 24 * time.Hour},
		{"certificate and suffixes, no validity", "/pki/ca.crt", []string{"staging.internal"}, 0},
		{"certificate and validity, no suffixes", "/pki/ca.crt", nil, 24 * time.Hour},
		{"suffixes and validity, no certificate", "", []string{"staging.internal"}, 24 * time.Hour},
	}
	for _, partial := range partials {
		t.Run(partial.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.IssuerCertificatePath, cfg.IssuerDNSSuffixes, cfg.IssuerValidity = partial.path, partial.suffixes, partial.validity
			if err := cfg.Validate(); err == nil {
				t.Fatal("a partially configured issuer was accepted")
			}
		})
	}
}

func TestIssuerConstraintsAreBounded(t *testing.T) {
	cfg := baseConfig()
	cfg.IssuerCertificatePath = "/pki/ca.crt"
	cfg.IssuerDNSSuffixes = []string{"staging.internal"}

	cfg.IssuerValidity = time.Minute // below the floor
	if err := cfg.Validate(); err == nil {
		t.Fatal("an implausibly short issuer validity was accepted")
	}
	cfg.IssuerValidity = 3650 * 24 * time.Hour // ten years
	if err := cfg.Validate(); err == nil {
		t.Fatal("a ten-year issuer validity was accepted")
	}
	cfg.IssuerValidity = 90 * 24 * time.Hour
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a reasonable issuer configuration was refused: %v", err)
	}

	// A wildcard or blank suffix would widen the namespace rather than describe it.
	for _, bad := range [][]string{{""}, {"*.staging.internal"}, {"staging internal"}} {
		cfg.IssuerDNSSuffixes = bad
		if err := cfg.Validate(); err == nil {
			t.Fatalf("issuer accepted an unusable suffix %q", bad)
		}
	}
}

func TestIssuerFieldsParseFromDocument(t *testing.T) {
	cfg, err := Decode(strings.NewReader(`{
		"issuer_certificate_path": "/pki/ca.crt",
		"issuer_dns_suffixes": ["staging.internal", "svc.internal"],
		"issuer_validity": "2160h"
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.IssuerCertificatePath != "/pki/ca.crt" || len(cfg.IssuerDNSSuffixes) != 2 || cfg.IssuerValidity != 2160*time.Hour {
		t.Fatalf("issuer fields not parsed: %#v", cfg)
	}
}
