// Command regalia-audit-ship ships one of a node's (or the revocation authority's) audit trails to
// the audit collector (#278): one audit event a trail line, on the stream "<site>.<trail>". The rules
// are internal/audit/trail.go's; this is the loop around them.
//
// It keeps no state of its own: every pass rebuilds the events from the file and checks them against
// the collector's committed head. A file that no longer holds what the collector committed (cut
// short, rewritten, removed) raises an alarm at the collector and the process exits 3, which the unit
// does not restart: the trail stays stopped until an operator acts, and a manual start repeats the
// same check. Any other failure (the collector unreachable) is retried, and the backlog metric shows
// it.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
)

// exitTampered is the status the unit's RestartPreventExitStatus names.
const exitTampered = 3

// streamPattern is the collector's rule for a site header (internal/audit/collector.go).
var streamPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// maxTrail bounds what one pass reads. A trail past it is an incident of its own (rotation, #278).
const maxTrail = 256 << 20

func main() {
	err := run(os.Args[1:], os.Stdout)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "regalia-audit-ship: "+err.Error())
		if errors.Is(err, audit.ErrTrailTampered) {
			os.Exit(exitTampered)
		}
		os.Exit(1)
	}
}

type options struct {
	trail, path, collector, site, metrics string
	interval                              time.Duration
	once                                  bool
}

func run(arguments []string, out io.Writer) error {
	flags := flag.NewFlagSet("regalia-audit-ship", flag.ContinueOnError)
	flags.SetOutput(out)
	var o options
	flags.StringVar(&o.trail, "trail", "", "the trail's name in deploy/baremetal/trails.py's registry (sync, admission, authority, ...)")
	flags.StringVar(&o.path, "path", "", "the trail file")
	flags.StringVar(&o.collector, "collector", "", "the audit collector's https origin")
	flags.StringVar(&o.site, "site", "", "this host's site; the stream is <site>.<trail>")
	tlsCert := flags.String("tls-cert", "", "PEM client certificate")
	tlsKey := flags.String("tls-key", "", "PEM client private key")
	serverCA := flags.String("server-ca", "", "PEM CA bundle the collector's certificate is verified against")
	flags.StringVar(&o.metrics, "metrics", "", "Prometheus textfile to write after every pass (optional)")
	flags.DurationVar(&o.interval, "interval", 30*time.Second, "time between passes")
	flags.BoolVar(&o.once, "once", false, "one pass, then exit")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if o.trail == "" || o.path == "" || o.collector == "" || o.site == "" || *tlsCert == "" || *tlsKey == "" || *serverCA == "" {
		return errors.New("-trail, -path, -collector, -site, -tls-cert, -tls-key and -server-ca are required")
	}
	if !streamPattern.MatchString(o.site + "." + o.trail) {
		return fmt.Errorf("the stream %q is not a site the collector accepts (%s)", o.site+"."+o.trail, streamPattern)
	}
	if o.interval < time.Second {
		return errors.New("-interval must be at least a second")
	}
	sink, err := buildSink(o.collector, o.site+"."+o.trail, *tlsCert, *tlsKey, *serverCA)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return loop(ctx, sink, o, out)
}

func loop(ctx context.Context, sink audit.TrailSink, o options, out io.Writer) error {
	stream := o.site + "." + o.trail
	for {
		data, err := readTrail(o.path)
		var committed, total uint64
		if err == nil {
			committed, total, err = audit.ShipTrail(ctx, sink, stream, o.trail, data)
		}
		tampered := errors.Is(err, audit.ErrTrailTampered)
		if metricsErr := writeMetrics(o.metrics, o.trail, committed, total, tampered, err == nil); metricsErr != nil {
			fmt.Fprintf(out, "regalia-audit-ship: the metrics file could not be written: %v\n", metricsErr)
		}
		if tampered {
			return err
		}
		if err != nil {
			fmt.Fprintf(out, "regalia-audit-ship: %s: %d of %d lines committed, retrying: %v\n", stream, committed, total, err)
		}
		if o.once {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(o.interval):
		}
	}
}

// readTrail reads the trail as trails.append opens it: never through a link, a regular file only. A
// trail not yet written is empty, which ShipTrail refuses if the collector already holds lines of it.
func readTrail(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxTrail+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxTrail {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxTrail)
	}
	return data, nil
}

// writeMetrics replaces the textfile whole (write, fsync, rename), so the exporter never reads half.
func writeMetrics(path, trail string, committed, total uint64, tampered, ok bool) error {
	if path == "" {
		return nil
	}
	flag := 0
	if tampered {
		flag = 1
	}
	body := fmt.Sprintf(`# HELP regalia_audit_trail_lines Complete lines in the trail file.
# TYPE regalia_audit_trail_lines gauge
regalia_audit_trail_lines{trail=%[1]q} %[2]d
# HELP regalia_audit_trail_committed Lines the collector has committed.
# TYPE regalia_audit_trail_committed gauge
regalia_audit_trail_committed{trail=%[1]q} %[3]d
# HELP regalia_audit_trail_backlog Lines not yet committed at the collector.
# TYPE regalia_audit_trail_backlog gauge
regalia_audit_trail_backlog{trail=%[1]q} %[4]d
# HELP regalia_audit_trail_tampered 1 when the file no longer holds what the collector committed: shipping stopped.
# TYPE regalia_audit_trail_tampered gauge
regalia_audit_trail_tampered{trail=%[1]q} %[5]d
`, trail, total, committed, saturatingBacklog(total, committed), flag)
	if ok {
		body += fmt.Sprintf("# HELP regalia_audit_trail_last_success_seconds When a pass last committed everything.\n# TYPE regalia_audit_trail_last_success_seconds gauge\nregalia_audit_trail_last_success_seconds{trail=%q} %d\n", trail, time.Now().Unix())
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.WriteString(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

func saturatingBacklog(total, committed uint64) uint64 {
	if committed >= total {
		return 0
	}
	return total - committed
}

// buildSink is the daemon's audit client (cmd/regalia-kms): mutual TLS, pinned roots, no proxy.
func buildSink(collector, stream, certificatePath, keyPath, caPath string) (*audit.HTTPSink, error) {
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read collector trust roots: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("collector trust roots contain no usable certificate")
	}
	if err := audit.ValidateSinkURL(collector); err != nil {
		return nil, err
	}
	parsed, _ := url.Parse(collector)
	client, err := audit.NewMTLSHTTPClient(certificate, roots, parsed.Hostname())
	if err != nil {
		return nil, err
	}
	return audit.NewHTTPSink(collector, client, 10*time.Second, stream)
}
