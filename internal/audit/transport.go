package audit

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"strings"
	"time"
)

// NewMTLSHTTPClient builds the only supported production transport for the
// off-host collector. The certificate key may be any hardware-backed
// crypto.Signer; private key bytes are neither required nor accepted here.
func NewMTLSHTTPClient(certificate tls.Certificate, roots *x509.CertPool, serverName string) (*http.Client, error) {
	if roots == nil || strings.TrimSpace(serverName) == "" || strings.ContainsAny(serverName, "/:@") || len(certificate.Certificate) == 0 {
		return nil, errors.New("invalid audit mTLS configuration")
	}
	if _, ok := certificate.PrivateKey.(crypto.Signer); !ok {
		return nil, errors.New("audit client private key must implement crypto.Signer")
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   serverName,
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	transport := &http.Transport{
		Proxy:                 nil,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		DisableCompression:    true,
	}
	return &http.Client{Transport: transport}, nil
}
