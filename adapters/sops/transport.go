package sopsadapter

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

// ClientTLSConfig constructs the only supported network identity path for the
// sidecar. Private key bytes are never accepted: the certificate key must be a
// crypto.Signer, allowing a PKCS#11-backed implementation.
func ClientTLSConfig(certificate tls.Certificate, roots *x509.CertPool, serverName string) (*tls.Config, error) {
	serverName = strings.TrimSpace(serverName)
	if roots == nil || len(certificate.Certificate) == 0 || serverName == "" ||
		strings.Contains(serverName, "://") || strings.ContainsAny(serverName, "/\\") {
		return nil, errors.New("invalid KMS TLS configuration")
	}
	if _, ok := certificate.PrivateKey.(crypto.Signer); !ok {
		return nil, errors.New("KMS client private key must implement crypto.Signer")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      roots,
		ServerName:   serverName,
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

// NewMTLSHTTPClient builds a direct, bounded client. It deliberately ignores
// ambient proxy variables so KMS traffic cannot be redirected through an
// operator or CI proxy, and it never follows redirects with client credentials.
func NewMTLSHTTPClient(certificate tls.Certificate, roots *x509.CertPool, serverName string, timeout time.Duration) (*http.Client, error) {
	if timeout < time.Second || timeout > time.Minute {
		return nil, errors.New("KMS client timeout must be between 1s and 1m")
	}
	tlsConfig, err := ClientTLSConfig(certificate, roots, serverName)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig:       tlsConfig,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}
