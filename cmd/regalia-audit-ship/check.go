package main

// `regalia-audit-ship check` and `regalia-audit-ship conformance`: the node's side of an EXTERNAL audit collector
// (#351; deploy/baremetal/AUDIT-COLLECTOR.md).
//
//   check        every file and value the shippers and prune take, validated together, before anything runs:
//                the collector's https origin, the site, the client certificate and key (a pair, valid now), the
//                collector's CA bundle, and the pinned receipt keys. With -probe it also reaches the collector,
//                read-only (HEAD /v1/health/ready and GET /v1/stream-position of each -trail), and says which
//                step failed. The unit runs it without -probe before each start (ExecStartPre), so a host with
//                a broken configuration refuses at once, by name, instead of retrying forever.
//   conformance  a candidate collector checked against the contract (internal/audit/conformance.go), through
//                the shippers' own client, on a stream of its own; exit 0 only when every rule held.

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
)

// receiptKeyLine is trails.py receipt_keys' rule for one pinned key: an Ed25519 public key, 64 lowercase hex.
var receiptKeyLine = regexp.MustCompile(`^[0-9a-f]{64}$`)

// readReceiptKeys reads the pinned receipt keys as trails.py prune does: one a line, '#' comments, at least one.
func readReceiptKeys(path string) ([]ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("receipt keys: %w", err)
	}
	var keys []ed25519.PublicKey
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		if !receiptKeyLine.MatchString(line) {
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

// endpoint is the whole configuration of one host's collector endpoint, validated.
type endpoint struct {
	collector, site string
	certificate     tls.Certificate
	leaf            *x509.Certificate
	identity        string
	roots           *x509.CertPool
	receiptKeys     []ed25519.PublicKey
}

func loadEndpoint(collector, site, certPath, keyPath, caPath, receiptPath string, now time.Time) (endpoint, error) {
	var e endpoint
	if collector == "" || site == "" || certPath == "" || keyPath == "" || caPath == "" || receiptPath == "" {
		return e, errors.New("-collector, -site, -tls-cert, -tls-key, -server-ca and -receipt-keys are required")
	}
	if err := audit.ValidateSinkURL(collector); err != nil {
		return e, fmt.Errorf("collector %q: %w (https://host[:port], no path, query, fragment or user)", collector, err)
	}
	if !streamPattern.MatchString(site + ".x") {
		return e, fmt.Errorf("site %q: not a site the collector accepts (%s)", site, streamPattern)
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return e, fmt.Errorf("client certificate and key: %w", err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return e, fmt.Errorf("client certificate: %w", err)
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return e, fmt.Errorf("client certificate: valid %s to %s, not now", leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		return e, fmt.Errorf("collector CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return e, fmt.Errorf("collector CA: %s holds no usable certificate", caPath)
	}
	receiptKeys, err := readReceiptKeys(receiptPath)
	if err != nil {
		return e, err
	}
	identity, err := certificateIdentity(certPath)
	if err != nil {
		return e, err
	}
	return endpoint{collector: collector, site: site, certificate: certificate, leaf: leaf, identity: identity, roots: roots,
		receiptKeys: receiptKeys}, nil
}

func (e endpoint) sink(stream string) (*audit.HTTPSink, error) {
	parsed, _ := url.Parse(e.collector)
	client, err := audit.NewMTLSHTTPClient(e.certificate, e.roots, parsed.Hostname())
	if err != nil {
		return nil, err
	}
	return audit.NewHTTPSink(e.collector, client, 10*time.Second, stream)
}

// endpointFlags declares the endpoint's flags, the same names the shipper and its unit use.
func endpointFlags(flags *flag.FlagSet) func(time.Time) (endpoint, error) {
	collector := flags.String("collector", "", "the audit collector's https origin")
	site := flags.String("site", "", "this host's site; streams are <site>.<trail>")
	cert := flags.String("tls-cert", "", "PEM client certificate")
	key := flags.String("tls-key", "", "PEM client private key")
	ca := flags.String("server-ca", "", "PEM CA bundle the collector's certificate is verified against")
	receipts := flags.String("receipt-keys", "", "the pinned receipt keys (one Ed25519 public key a line, hex)")
	return func(now time.Time) (endpoint, error) { return loadEndpoint(*collector, *site, *cert, *key, *ca, *receipts, now) }
}

func checkCommand(arguments []string, out io.Writer) error {
	flags := flag.NewFlagSet("regalia-audit-ship check", flag.ContinueOnError)
	flags.SetOutput(out)
	load := endpointFlags(flags)
	probe := flags.Bool("probe", false, "also reach the collector, read-only")
	var trails multiFlag
	flags.Var(&trails, "trail", "a trail whose stream -probe reads the head of (repeatable)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	e, err := load(time.Now())
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "configuration: collector %s, site %s, client certificate %s (identity %s, valid until %s), %d receipt key(s)\n",
		e.collector, e.site, e.leaf.Subject.CommonName, e.identity, e.leaf.NotAfter.UTC().Format(time.RFC3339), len(e.receiptKeys))
	if !*probe {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sink, err := e.sink(e.site)
	if err != nil {
		return err
	}
	if !sink.Ready(ctx) {
		return fmt.Errorf("the collector at %s does not answer HEAD /v1/health/ready over mutual TLS: unreachable, its certificate "+
			"not from the CA given, or this client certificate refused", e.collector)
	}
	fmt.Fprintf(out, "collector: ready\n")
	for _, trail := range trails {
		stream := e.site + "." + trail
		if !streamPattern.MatchString(stream) {
			return fmt.Errorf("the stream %q is not one the collector accepts", stream)
		}
		head, hash, err := sink.WithSite(stream).CommittedHead(ctx, stream)
		if err != nil {
			return fmt.Errorf("%s: the collector does not report its head: %w", stream, err)
		}
		fmt.Fprintf(out, "%s: committed %d %s\n", stream, head, hash)
	}
	return nil
}

func conformanceCommand(arguments []string, out io.Writer) error {
	flags := flag.NewFlagSet("regalia-audit-ship conformance", flag.ContinueOnError)
	flags.SetOutput(out)
	load := endpointFlags(flags)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	e, err := load(time.Now())
	if err != nil {
		return err
	}
	sink, err := e.sink(e.site)
	if err != nil {
		return err
	}
	parsed, _ := url.Parse(e.collector)
	anonymous, err := audit.NewHTTPSink(e.collector, &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: e.roots, ServerName: parsed.Hostname()}}}, 10*time.Second, e.site)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	checks, err := audit.CheckConformance(ctx, audit.ConformanceTarget{Sink: sink, Anonymous: anonymous, Identity: e.identity,
		ReceiptKeys: e.receiptKeys, Site: e.site})
	if err != nil {
		return err
	}
	for _, c := range checks {
		mark := "PASS"
		if !c.Passed {
			mark = "FAIL"
		}
		fmt.Fprintf(out, "  %s %s (%s)\n", mark, c.Rule, c.Detail)
	}
	if !audit.Conforms(checks) {
		return fmt.Errorf("%s does NOT meet the audit collector contract (deploy/baremetal/AUDIT-COLLECTOR.md)", e.collector)
	}
	fmt.Fprintf(out, "%s meets the audit collector contract: %d rules\n", e.collector, len(checks))
	return nil
}

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
