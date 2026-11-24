package audit

// Offline collector configuration shared by the daemon's future configuredness gate
// and regalia-audit-ship check. Loading validates only this endpoint's files at now;
// it does not probe the collector or attest any other service's configuration.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// CollectorEndpointOptions names the existing files of one service-role endpoint.
// It is not a persistent configuration format or evidence that another role is configured.
type CollectorEndpointOptions struct {
	Collector, Site                                          string
	CertificatePath, PrivateKeyPath, CAPath, ReceiptKeysPath string
}

// CollectorEndpoint holds the same loaded material used by the shipper's check and
// conformance commands. A caller must revalidate when its configuration or validity
// interval changes; this result is neither a receipt nor continuing authorization.
// Supplied files must remain stable while loading: this is not an atomic snapshot
// or a file ownership/permission attestation.
type CollectorEndpoint struct {
	Collector, Site string
	Certificate     tls.Certificate
	Leaf            *x509.Certificate
	Identity        string
	Roots           *x509.CertPool
	ReceiptKeys     []ed25519.PublicKey
}

// endpointReceiptKeyLine is trails.py receipt_keys' rule for one pinned key: an Ed25519 public key, 64 lowercase hex.
var endpointReceiptKeyLine = regexp.MustCompile(`^[0-9a-f]{64}$`)

// readEndpointReceiptKeys reads the pinned receipt keys as trails.py prune does: one a line, '#' comments, at least one.
func readEndpointReceiptKeys(path string) ([]ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("receipt keys: %w", err)
	}
	return parseEndpointReceiptKeys(raw, path)
}

func parseEndpointReceiptKeys(raw []byte, path string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		if !endpointReceiptKeyLine.MatchString(line) {
			return nil, fmt.Errorf("receipt keys: %s: %q is not an Ed25519 public key in hex", path, line)
		}
		key, _ := hex.DecodeString(line)
		keys = append(keys, ed25519.PublicKey(key))
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("receipt keys: %s pins no receipt key", path)
	}
	return keys, nil
}

// LoadCollectorEndpoint validates one endpoint offline, preserving the check CLI's
// validation and error semantics. Network health and acknowledgement are separate.
func LoadCollectorEndpoint(options CollectorEndpointOptions, now time.Time) (CollectorEndpoint, error) {
	collector, site := options.Collector, options.Site
	certPath, keyPath := options.CertificatePath, options.PrivateKeyPath
	caPath, receiptPath := options.CAPath, options.ReceiptKeysPath
	var e CollectorEndpoint
	if collector == "" || site == "" || certPath == "" || keyPath == "" || caPath == "" || receiptPath == "" {
		return e, errors.New("-collector, -site, -tls-cert, -tls-key, -server-ca and -receipt-keys are required")
	}
	if err := ValidateSinkURL(collector); err != nil {
		return e, fmt.Errorf("collector %q: %w (https://host[:port], no path, query, fragment or user)", collector, err)
	}
	if !collectorSitePattern.MatchString(site + ".x") {
		return e, fmt.Errorf("site %q: not a site the collector accepts (%s)", site, collectorSitePattern)
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return e, fmt.Errorf("client certificate and key: %w", err)
	}
	leaf, err := parseEndpointLeaf(certificate, now)
	if err != nil {
		return e, err
	}
	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		return e, fmt.Errorf("collector CA: %w", err)
	}
	roots, err := parseEndpointRoots(pemBytes, caPath)
	if err != nil {
		return e, err
	}
	receiptKeys, err := readEndpointReceiptKeys(receiptPath)
	if err != nil {
		return e, err
	}
	identity, err := CollectorCertificateIdentity(certPath)
	if err != nil {
		return e, err
	}
	return CollectorEndpoint{Collector: collector, Site: site, Certificate: certificate, Leaf: leaf, Identity: identity, Roots: roots,
		ReceiptKeys: receiptKeys}, nil
}

func parseEndpointLeaf(certificate tls.Certificate, now time.Time) (*x509.Certificate, error) {
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("client certificate: %w", err)
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("client certificate: valid %s to %s, not now", leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return leaf, nil
}

func parseEndpointRoots(pemBytes []byte, label string) (*x509.CertPool, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("collector CA: %s holds no usable certificate", label)
	}
	return roots, nil
}

// CollectorCertificateIdentity hashes the DER in the first decoded PEM block,
// which must be a CERTIFICATE. This is the existing collector/shipper identity
// format; it neither validates the certificate nor proves collector acceptance.
func CollectorCertificateIdentity(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("client certificate: %w", err)
	}
	return collectorCertificateIdentity(raw)
}

func collectorCertificateIdentity(raw []byte) (string, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("client certificate: not a PEM certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
