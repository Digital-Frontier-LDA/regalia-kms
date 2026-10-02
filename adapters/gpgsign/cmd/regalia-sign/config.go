package main

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/gpgsign"
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
	contents, err := readProtected(cfg.PublicKeyPath, 16<<10, false)
	if err != nil {
		return nil, errors.New("the release public key is unavailable")
	}
	block, rest := pem.Decode(contents)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("public_key_path must hold exactly one PEM PUBLIC KEY")
	}
	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("public_key_path does not hold a public key")
	}
	return public, nil
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

// readProtected reads a file this process must be able to trust: a regular file, not reached
// through a symbolic link, owned by root or by this user, writable by nobody else, and — when it is
// a secret — readable by nobody else. The rule is the SOPS sidecar's, for the same reason: whoever
// can rewrite the configuration or the pinned key chooses what gets signed with.
func readProtected(path string, maximum int64, secret bool) ([]byte, error) {
	if !filepath.IsAbs(path) || maximum < 1 {
		return nil, errors.New("invalid protected file")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open protected file")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open protected file")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return nil, errors.New("unsafe protected file owner")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || (secret && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("unsafe protected file")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) > maximum {
		zero(contents)
		return nil, errors.New("read protected file")
	}
	return contents, nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
