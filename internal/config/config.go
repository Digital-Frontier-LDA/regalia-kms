// Package config loads and validates the daemon's non-secret runtime settings.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

const maxConfigBytes = 32 << 10

// Config contains operational limits only. Credentials, PINs and key material
// are deliberately not representable in this format.
type Config struct {
	ListenAddress  string
	RegistryPath   string
	RBACPolicyPath string
	PolicyPath     string
	// ApproverKeysPath is optional. Left empty, no approver keys load, nothing is ever
	// counted as an approver, and any policy with required_approvals > 0 denies -- which
	// is the posture every deployment already has. Dual control is opt-in by configuring
	// it, never by default, because a key set that appeared implicitly would be a key set
	// nobody reviewed.
	ApproverKeysPath        string
	PolicyStatePath         string
	Site                    string
	OperationTimeout        time.Duration
	ShutdownTimeout         time.Duration
	MaxConcurrentOperations int

	// Mutual TLS. Paths only: no key material is representable here, and the
	// private key is read from a file the service account can open, never
	// from this document.
	TLSCertificatePath string
	TLSPrivateKeyPath  string
	TLSClientCAPath    string

	// Certificate issuing. Paths and constraints only: what a certificate may say is a server
	// decision, so the namespace and lifetime live here rather than in a request.
	IssuerCertificatePath string
	IssuerDNSSuffixes     []string
	IssuerValidity        time.Duration

	// Hardware. Without these the daemon runs with no cryptographic backend and readiness stays
	// false — it serves health and nothing else, which is the correct posture for an unconfigured
	// host rather than an error.
	PKCS11ModulePath      string
	YubiKeyDevices        map[string]string
	SecureChannelEvidence string
	PINPaths              map[string]string
	AuditJournalPath      string
	AuditSinkURL          string

	// Active/passive fencing. A site signs only while it holds an externally granted lease. The
	// fencing triple is paths: the lease document, the epoch journal that stops an old active
	// from coming back, and the ed25519 public key the lease must be signed by. The commissioning
	// record rides this block because it is verified by the same authority key — it is #220's
	// provenance, not fencing itself.
	FencingLeasePath        string
	FencingStatePath        string
	CommissioningRecordPath string
	FencingPublicKeyPath    string

	// Revocation list. One serial per line; the file is cached behind a
	// stat+ModTime guard, so an entry added at runtime is observed on the next
	// Check call without a restart. Empty / unset returns a no-op list whose
	// Check returns (false, nil) without filesystem access — the authenticator
	// still calls Check, the check just does no I/O.
	RevokedSerialsPath string

	// Metrics reader principals: the SPIFFE identities allowed to scrape
	// /v1/metrics. Metrics are authorized per identity rather than merely
	// authenticated, because aggregate per-route rates still reveal the business
	// rhythm of what is being signed. Empty refuses everyone.
	MetricsReaderPrincipals []string
}

type document struct {
	ListenAddress           *string            `json:"listen_address"`
	RegistryPath            *string            `json:"registry_path"`
	RBACPolicyPath          *string            `json:"rbac_policy_path"`
	PolicyPath              *string            `json:"policy_path"`
	ApproverKeysPath        *string            `json:"approver_keys_path"`
	PolicyStatePath         *string            `json:"policy_state_path"`
	Site                    *string            `json:"site"`
	OperationTimeout        *string            `json:"operation_timeout"`
	ShutdownTimeout         *string            `json:"shutdown_timeout"`
	MaxConcurrentOperations *int               `json:"max_concurrent_operations"`
	TLSCertificatePath      *string            `json:"tls_certificate_path"`
	TLSPrivateKeyPath       *string            `json:"tls_private_key_path"`
	TLSClientCAPath         *string            `json:"tls_client_ca_path"`
	IssuerCertificatePath   *string            `json:"issuer_certificate_path"`
	IssuerDNSSuffixes       *[]string          `json:"issuer_dns_suffixes"`
	IssuerValidity          *string            `json:"issuer_validity"`
	PKCS11ModulePath        *string            `json:"pkcs11_module_path"`
	YubiKeyDevices          *map[string]string `json:"yubikey_devices"`
	SecureChannelEvidence   *string            `json:"secure_channel_evidence_path"`
	PINPaths                *map[string]string `json:"pin_paths"`
	AuditJournalPath        *string            `json:"audit_journal_path"`
	AuditSinkURL            *string            `json:"audit_sink_url"`
	FencingLeasePath        *string            `json:"fencing_lease_path"`
	FencingStatePath        *string            `json:"fencing_state_path"`
	CommissioningRecordPath *string            `json:"commissioning_record_path"`
	FencingPublicKeyPath    *string            `json:"fencing_public_key_path"`
	RevokedSerialsPath      *string            `json:"revoked_serials_path"`
	MetricsReaderPrincipals *[]string          `json:"metrics_reader_principals"`
}

func Default() Config {
	return Config{
		ListenAddress:           "127.0.0.1:8443",
		OperationTimeout:        15 * time.Second,
		ShutdownTimeout:         10 * time.Second,
		MaxConcurrentOperations: 4,
	}
}

// Load reads a configuration from a regular file that is not writable by the
// service account's group or by other users.
func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("stat configuration: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Config{}, errors.New("configuration must be a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return Config{}, errors.New("configuration must not be group- or world-writable")
	}
	return Decode(file)
}

// Decode reads one strict JSON document and applies safe defaults to omitted fields.
func Decode(reader io.Reader) (Config, error) {
	contents, err := io.ReadAll(io.LimitReader(reader, maxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("read configuration: %w", err)
	}
	if len(contents) > maxConfigBytes {
		return Config{}, errors.New("configuration exceeds 32 KiB")
	}

	var input document
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return Config{}, fmt.Errorf("decode configuration: %w", err)
	}
	if err := requireEndOfJSON(decoder); err != nil {
		return Config{}, err
	}

	result := Default()
	if input.ListenAddress != nil {
		result.ListenAddress = *input.ListenAddress
	}
	if input.RegistryPath != nil {
		result.RegistryPath = *input.RegistryPath
	}
	if input.RBACPolicyPath != nil {
		result.RBACPolicyPath = *input.RBACPolicyPath
	}
	if input.ApproverKeysPath != nil {
		result.ApproverKeysPath = *input.ApproverKeysPath
	}
	if input.PolicyPath != nil {
		result.PolicyPath = *input.PolicyPath
	}
	if input.PolicyStatePath != nil {
		result.PolicyStatePath = *input.PolicyStatePath
	}
	if input.TLSCertificatePath != nil {
		result.TLSCertificatePath = *input.TLSCertificatePath
	}
	if input.TLSPrivateKeyPath != nil {
		result.TLSPrivateKeyPath = *input.TLSPrivateKeyPath
	}
	if input.TLSClientCAPath != nil {
		result.TLSClientCAPath = *input.TLSClientCAPath
	}
	if input.IssuerCertificatePath != nil {
		result.IssuerCertificatePath = *input.IssuerCertificatePath
	}
	if input.IssuerDNSSuffixes != nil {
		result.IssuerDNSSuffixes = append([]string(nil), (*input.IssuerDNSSuffixes)...)
	}
	if input.PKCS11ModulePath != nil {
		result.PKCS11ModulePath = *input.PKCS11ModulePath
	}
	if input.YubiKeyDevices != nil {
		result.YubiKeyDevices = make(map[string]string, len(*input.YubiKeyDevices))
		for device, serial := range *input.YubiKeyDevices {
			result.YubiKeyDevices[device] = serial
		}
	}
	if input.SecureChannelEvidence != nil {
		result.SecureChannelEvidence = *input.SecureChannelEvidence
	}
	if input.PINPaths != nil {
		result.PINPaths = make(map[string]string, len(*input.PINPaths))
		for device, path := range *input.PINPaths {
			result.PINPaths[device] = path
		}
	}
	if input.AuditJournalPath != nil {
		result.AuditJournalPath = *input.AuditJournalPath
	}
	if input.AuditSinkURL != nil {
		result.AuditSinkURL = *input.AuditSinkURL
	}
	if input.FencingLeasePath != nil {
		result.FencingLeasePath = *input.FencingLeasePath
	}
	if input.FencingStatePath != nil {
		result.FencingStatePath = *input.FencingStatePath
	}
	if input.CommissioningRecordPath != nil {
		// Deliberately NO rule here, unlike the other path families: requiring
		// fencing_public_key_path (which verifies the record) would drag the whole
		// all-or-nothing fencing triple onto any commissioned host — a coupling nobody
		// asked for. The pairing is enforced at runtime in checkProvenance, ordered so a
		// key problem cannot mask the missing-record refusals.
		result.CommissioningRecordPath = *input.CommissioningRecordPath
	}
	if input.FencingPublicKeyPath != nil {
		result.FencingPublicKeyPath = *input.FencingPublicKeyPath
	}
	if input.RevokedSerialsPath != nil {
		result.RevokedSerialsPath = *input.RevokedSerialsPath
	}
	if input.MetricsReaderPrincipals != nil {
		result.MetricsReaderPrincipals = append([]string(nil), (*input.MetricsReaderPrincipals)...)
	}
	if input.IssuerValidity != nil {
		result.IssuerValidity, err = time.ParseDuration(*input.IssuerValidity)
		if err != nil {
			return Config{}, fmt.Errorf("invalid issuer_validity: %w", err)
		}
	}
	if input.Site != nil {
		result.Site = *input.Site
	}
	if input.OperationTimeout != nil {
		result.OperationTimeout, err = time.ParseDuration(*input.OperationTimeout)
		if err != nil {
			return Config{}, fmt.Errorf("invalid operation_timeout: %w", err)
		}
	}
	if input.ShutdownTimeout != nil {
		result.ShutdownTimeout, err = time.ParseDuration(*input.ShutdownTimeout)
		if err != nil {
			return Config{}, fmt.Errorf("invalid shutdown_timeout: %w", err)
		}
	}
	if input.MaxConcurrentOperations != nil {
		result.MaxConcurrentOperations = *input.MaxConcurrentOperations
	}
	if err := result.Validate(); err != nil {
		return Config{}, err
	}
	return result, nil
}

func requireEndOfJSON(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("configuration contains more than one JSON value")
		}
		return fmt.Errorf("decode trailing configuration data: %w", err)
	}
	return nil
}

func (cfg Config) Validate() error {
	host, _, err := net.SplitHostPort(cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("invalid listen_address: %w", err)
	}
	// MUTUAL TLS IS ALL OR NOTHING. A certificate without its key, or either without the client
	// trust roots, is a half-configured transport — and the half that is missing is the half that
	// authenticates the caller. Refuse rather than start something that looks like mTLS.
	tlsFields := 0
	for _, path := range []string{cfg.TLSCertificatePath, cfg.TLSPrivateKeyPath, cfg.TLSClientCAPath} {
		if path != "" {
			tlsFields++
		}
	}
	if tlsFields != 0 && tlsFields != 3 {
		return errors.New("tls_certificate_path, tls_private_key_path and tls_client_ca_path must be configured together")
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			// A non-loopback listener is reachable by anything that can route to it, so the
			// transport must authenticate the caller before the handler ever sees a request.
			// Loopback stays permitted without TLS for development only.
			if tlsFields != 3 {
				return errors.New("listen_address is non-loopback: mutual TLS must be configured")
			}
		}
	}
	if cfg.OperationTimeout < 100*time.Millisecond || cfg.OperationTimeout > 10*time.Minute {
		return errors.New("operation_timeout must be between 100ms and 10m")
	}
	if cfg.ShutdownTimeout < time.Second || cfg.ShutdownTimeout > 2*time.Minute {
		return errors.New("shutdown_timeout must be between 1s and 2m")
	}
	if cfg.MaxConcurrentOperations < 1 || cfg.MaxConcurrentOperations > 64 {
		return errors.New("max_concurrent_operations must be between 1 and 64")
	}
	if (cfg.RegistryPath == "") != (cfg.Site == "") {
		return errors.New("registry_path and site must be configured together")
	}
	// CERTIFICATE ISSUING IS ALL OR NOTHING, for the same reason mutual TLS is: a partially
	// configured issuer is one whose missing part is the part that constrains it. An issuer with
	// no namespace would certify anything; one with no lifetime would certify it forever.
	issuerFields := 0
	if cfg.IssuerCertificatePath != "" {
		issuerFields++
	}
	if len(cfg.IssuerDNSSuffixes) > 0 {
		issuerFields++
	}
	if cfg.IssuerValidity != 0 {
		issuerFields++
	}
	if issuerFields != 0 && issuerFields != 3 {
		return errors.New("issuer_certificate_path, issuer_dns_suffixes and issuer_validity must be configured together")
	}
	if issuerFields == 3 {
		if cfg.IssuerValidity < time.Hour || cfg.IssuerValidity > 825*24*time.Hour {
			// 825 days is the longest lifetime widely accepted for a server certificate.
			return errors.New("issuer_validity must be between 1h and 825 days")
		}
		for _, suffix := range cfg.IssuerDNSSuffixes {
			if strings.TrimSpace(suffix) == "" || strings.ContainsAny(suffix, " *\t") {
				return fmt.Errorf("issuer_dns_suffixes contains an unusable entry %q", suffix)
			}
		}
	}
	// HARDWARE IS ALL OR NOTHING. A module without PIN material cannot log in; PIN material without
	// secure-channel evidence would use the token over an unproven channel; and either without an
	// audit journal would operate the token without a record. Each missing piece removes a control
	// the others assume is present.
	hardwareFields := 0
	if cfg.PKCS11ModulePath != "" {
		hardwareFields++
	}
	if len(cfg.YubiKeyDevices) > 0 {
		hardwareFields++
	}
	if len(cfg.PINPaths) > 0 {
		hardwareFields++
	}
	if cfg.SecureChannelEvidence != "" {
		hardwareFields++
	}
	if cfg.AuditJournalPath != "" {
		hardwareFields++
	}
	if cfg.PKCS11ModulePath != "" {
		if len(cfg.YubiKeyDevices) > 0 || hardwareFields != 4 {
			return errors.New("pkcs11_module_path, pin_paths, secure_channel_evidence_path and audit_journal_path must be configured together")
		}
	} else if len(cfg.YubiKeyDevices) > 0 {
		if cfg.SecureChannelEvidence != "" || hardwareFields != 3 {
			return errors.New("yubikey_devices, pin_paths and audit_journal_path must be configured together")
		}
		for device := range cfg.YubiKeyDevices {
			if _, ok := cfg.PINPaths[device]; !ok {
				return fmt.Errorf("yubikey device %q has no PIN credential mapping", device)
			}
		}
	}
	if hardwareFields > 0 && (cfg.RegistryPath == "" || cfg.PolicyPath == "" || cfg.RBACPolicyPath == "") {
		return errors.New("hardware requires registry_path, policy_path and rbac_policy_path: a token must not be operated without routing, policy and authorization")
	}
	if (cfg.PolicyPath == "") != (cfg.PolicyStatePath == "") {
		return errors.New("policy_path and policy_state_path must be configured together")
	}
	// FENCING IS ALL OR NOTHING, and the missing piece is always the one that makes it safe. A lease
	// without its public key would be trusted unsigned; a lease without its epoch journal would let
	// a revoked active site present an old lease and sign again. Half a fence is a gate.
	fencingFields := 0
	for _, path := range []string{cfg.FencingLeasePath, cfg.FencingStatePath, cfg.FencingPublicKeyPath} {
		if path != "" {
			fencingFields++
		}
	}
	if fencingFields != 0 && fencingFields != 3 {
		return errors.New("fencing_lease_path, fencing_state_path and fencing_public_key_path must be configured together")
	}
	// The lease names the site it grants and is bound to the key registry it was issued against, so
	// fencing without either would have nothing to check the lease's claims against.
	if fencingFields == 3 && (cfg.Site == "" || cfg.RegistryPath == "") {
		return errors.New("fencing requires site and registry_path: a lease is granted to a named site for a known key set")
	}
	// Metrics readers are SPIFFE identities under the trust-domain prefix the
	// authenticator enforces. Anything else can never authenticate — accepting it
	// would be a silent no-op in the configuration.
	seen := map[string]struct{}{}
	for _, principal := range cfg.MetricsReaderPrincipals {
		if len(principal) == 0 || len(principal) > 256 || !strings.HasPrefix(principal, "spiffe://regalia/") || strings.ContainsAny(principal, " \t\n\r") {
			return fmt.Errorf("invalid metrics_reader_principals entry %q: want a spiffe://regalia/ identity", principal)
		}
		if _, duplicate := seen[principal]; duplicate {
			return fmt.Errorf("metrics_reader_principals repeats %q", principal)
		}
		seen[principal] = struct{}{}
	}
	return nil
}
