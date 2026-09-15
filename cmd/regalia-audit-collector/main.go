// Command regalia-audit-collector is the off-host half of the audit protocol
// (doc/AUDIT-COLLECTOR-RECONCILIATION.md): the durable memory the daemons reconcile
// against at startup.
//
// It is deliberately a separate binary from the daemon. The whole premise of the
// reconciliation protocol is a committed head the HOST cannot author — a collector that
// shared the daemon's process, credentials, or state directory would be memory the same
// attacker rewrites. Separate binary, separate host, separate trust root.
//
// The three endpoints it serves are the sink's whole world: POST /v1/events (commit then
// ack), GET /v1/stream-position (the head reconciliation asks about), and
// HEAD /v1/health/ready. See internal/audit/collector.go for the protocol rules.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
)

func main() {
	err := run(os.Args[1:], os.Stdout)
	// -h is a request, not a failure (same reasoning as regalia-fence: the usage has
	// already been printed; an error prefix and a non-zero exit read as a broken tool).
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "regalia-audit-collector: "+err.Error())
		os.Exit(1)
	}
}

func run(arguments []string, out *os.File) error {
	flags := flag.NewFlagSet("regalia-audit-collector", flag.ContinueOnError)
	flags.SetOutput(out)
	stateDir := flags.String("state", "", "directory holding the committed streams and the alarm log; this is the collector's durable memory, so put it on storage whose loss is its own incident")
	listen := flags.String("listen", "", "address to serve the audit protocol on (host:port)")
	tlsCert := flags.String("tls-cert", "", "PEM server certificate for the mTLS listener")
	tlsKey := flags.String("tls-key", "", "PEM private key for the mTLS listener")
	clientCA := flags.String("client-ca", "", "PEM CA bundle audit clients are verified against; a connection without a chain-verified client certificate never reaches a handler")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *stateDir == "" || *listen == "" || *tlsCert == "" || *tlsKey == "" || *clientCA == "" {
		return errors.New("-state, -listen, -tls-cert, -tls-key and -client-ca are required")
	}
	collector, err := audit.OpenCollector(*stateDir)
	if err != nil {
		return err
	}
	defer collector.Close()
	server, err := buildServer(*listen, *tlsCert, *tlsKey, *clientCA, collector.Handler())
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", *listen, err)
	}
	fmt.Fprintf(out, "regalia-audit-collector: serving %s, durable state in %s\n", *listen, *stateDir)
	// The key material was loaded and validated by buildServer, so ServeTLS takes no file
	// paths: passing them again would let a second load disagree with the first.
	if err := server.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// buildServer is the mTLS wiring, separate from run so a test can hold the server object
// and prove the listener's client-certificate discipline without serving on a fixed port.
//
// ClientAuth is RequireAndVerifyClientCert, not VerifyClientCertIfGiven: the stream key
// IS the client identity, so a connection that presents no certificate is not a stricter
// mode to fall back from — it is a stream with no key, and the handler-level refusal in
// peerIdentity is the belt to this brace.
func buildServer(listen, certificatePath, keyPath, clientCAPath string, handler http.Handler) (*http.Server, error) {
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}
	pemBytes, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, fmt.Errorf("read client trust roots: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("client trust roots contain no usable certificate")
	}
	return &http.Server{
		Addr:    listen,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    roots,
		},
		// The sink's own timeouts are 10s per request; the server's bounds only need to
		// exceed them and contain slow-loris style hangs.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}, nil
}
