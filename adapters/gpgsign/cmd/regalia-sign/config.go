package main

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/gpgsign"
	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/gpgsign/internal/protected"
)

const maxConfigBytes = 16 << 10

// config is everything regalia-sign is told. It names no device, slot or algorithm: the KMS object
// decides those, and the pinned public key is how this side knows it got the key it expected.
type config struct {
	KMSURL          string `json:"kms_url"`
	ServerName      string `json:"server_name"`
	CAPath          string `json:"ca_path"`
	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`
	Timeout         string `json:"timeout"`

	ObjectID    string `json:"object_id"`
	Environment string `json:"environment"`
	Purpose     string `json:"purpose"`

	// PublicKeyPath is the release key's public half (PEM, "PUBLIC KEY"), read off the token when
	// the key was generated. KeyCreated and UserID are the other two inputs to the OpenPGP key's
	// identity; change either and every verifier sees a different key.
	PublicKeyPath string `json:"public_key_path"`
	KeyCreated    string `json:"key_created"`
	UserID        string `json:"user_id"`
}

func loadConfig(path string) (config, error) {
	contents, err := readProtected(path, maxConfigBytes, false)
	if err != nil {
		return config{}, fmt.Errorf("read the configuration: %w", err)
	}
	var result config
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return config{}, errors.New("the configuration is not the expected JSON document")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return config{}, errors.New("the configuration must contain one JSON document")
	}
	if _, _, err := result.validate(); err != nil {
		return config{}, err
	}
	return result, nil
}

func (cfg config) validate() (time.Duration, time.Time, error) {
	for _, value := range []string{cfg.CAPath, cfg.CertificatePath, cfg.PrivateKeyPath, cfg.PublicKeyPath} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return 0, time.Time{}, errors.New("configuration paths must be absolute and clean")
		}
	}
	// The same rule as the SOPS sidecar's kms_url and the daemon's audit sink URL
	// (adapters/sops/cmd/regalia-sops-kms/config.go, audit.ValidateSinkURL): an HTTPS origin, with at
	// most a bare trailing slash. Three modules cannot share the code; change one, change all three.
	parsed, err := url.Parse(cfg.KMSURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return 0, time.Time{}, errors.New("kms_url must be an HTTPS origin")
	}
	if strings.TrimSpace(cfg.ServerName) == "" || strings.ContainsAny(cfg.ServerName, "/:@") {
		return 0, time.Time{}, errors.New("invalid KMS server name")
	}
	timeout, err := time.ParseDuration(cfg.Timeout)
	if err != nil || timeout < time.Second || timeout > time.Minute {
		return 0, time.Time{}, errors.New("timeout must be between 1s and 1m")
	}
	// RFC 3339 in UTC, to the second: the creation time is hashed into the fingerprint, so it is
	// written exactly, never derived.
	created, err := time.Parse("2006-01-02T15:04:05Z", cfg.KeyCreated)
	if err != nil {
		return 0, time.Time{}, errors.New("key_created must be a UTC time such as 2026-10-02T00:00:00Z")
	}
	if cfg.ObjectID == "" || cfg.Purpose == "" || cfg.Environment == "" || strings.TrimSpace(cfg.UserID) == "" {
		return 0, time.Time{}, errors.New("object_id, environment, purpose and user_id are required")
	}
	return timeout, created, nil
}

// key builds the OpenPGP key and the KMS client behind it.
func (cfg config) key(now func() time.Time) (*gpgsign.Key, time.Duration, error) {
	timeout, created, err := cfg.validate()
	if err != nil {
		return nil, 0, err
	}
	public, err := cfg.publicKey()
	if err != nil {
		return nil, 0, err
	}
	certificate, roots, err := cfg.identity()
	if err != nil {
		return nil, 0, err
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, ServerName: cfg.ServerName, RootCAs: roots,
			Certificates: []tls.Certificate{certificate},
		},
		// One request per run. A proxy from the environment would put a third party between this
		// process and the KMS; the KMS is reached directly or not at all.
		Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: true,
	}
	client, err := gpgsign.NewClient(cfg.KMSURL, &http.Client{Transport: transport, Timeout: timeout}, now)
	if err != nil {
		return nil, 0, err
	}
	signer, err := gpgsign.NewSigner(public, client, gpgsign.Target{ObjectID: cfg.ObjectID, Environment: cfg.Environment, Purpose: cfg.Purpose})
	if err != nil {
		return nil, 0, err
	}
	key, err := gpgsign.NewKey(signer, created, cfg.UserID)
	if err != nil {
		return nil, 0, err
	}
	return key, timeout, nil
}

func (cfg config) publicKey() (crypto.PublicKey, error) {
	return protected.PublicKey(cfg.PublicKeyPath, "the release public key", "public_key_path")
}

func (cfg config) identity() (tls.Certificate, *x509.CertPool, error) {
	certificatePEM, err := readProtected(cfg.CertificatePath, 256<<10, false)
	if err != nil {
		return tls.Certificate{}, nil, errors.New("the workload identity is unavailable")
	}
	privatePEM, err := readProtected(cfg.PrivateKeyPath, 256<<10, true)
	if err != nil {
		return tls.Certificate{}, nil, errors.New("the workload identity is unavailable")
	}
	defer zero(privatePEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privatePEM)
	if err != nil {
		return tls.Certificate{}, nil, errors.New("the workload identity is unavailable")
	}
	caPEM, err := readProtected(cfg.CAPath, 256<<10, false)
	if err != nil {
		return tls.Certificate{}, nil, errors.New("the KMS trust roots are unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return tls.Certificate{}, nil, errors.New("the KMS trust roots are unavailable")
	}
	return certificate, roots, nil
}

// readProtected and zero are shared with regalia-approve (internal/protected).
func readProtected(path string, maximum int64, secret bool) ([]byte, error) {
	return protected.Read(path, maximum, secret)
}

func zero(value []byte) { protected.Zero(value) }
