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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
	trail, path, collector, site, metrics, head string
	identity                                    string // this host's client certificate: SHA-256 of its DER, hex
	interval                                    time.Duration
	once                                        bool
}

func run(arguments []string, out io.Writer) error {
	if len(arguments) > 0 && arguments[0] == "handover" {
		return handover(arguments[1:], out)
	}
	if len(arguments) > 0 && arguments[0] == "check" {
		return checkCommand(arguments[1:], out)
	}
	if len(arguments) > 0 && arguments[0] == "conformance" {
		return conformanceCommand(arguments[1:], out)
	}
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
	flags.StringVar(&o.head, "head", "", "where to record the committed line and the archives wholly behind it, for trails.py prune (optional)")
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
	var err error
	if o.identity, err = certificateIdentity(*tlsCert); err != nil {
		return err
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
		var committed, total uint64
		var boundaries []boundary
		trail, err := openSegments(o.path)
		if err == nil {
			err = handoverPending(ctx, sink, o)
		}
		if err == nil {
			committed, total, err = audit.ShipTrailLines(ctx, sink, stream, o.trail, trail.start, func(walker *audit.TrailWalker, each func(audit.Event) error) error {
				for _, archive := range trail.archives {
					if err := walker.Feed(archive.file, true, each); err != nil {
						return err
					}
					boundaries = append(boundaries, boundary{archive.name, archive.seq, walker.Last()})
				}
				if trail.current == nil {
					return nil
				}
				return walker.Feed(trail.current, false, each)
			})
			trail.close()
		}
		if err == nil {
			if headErr := writeHead(ctx, sink, o.head, o.identity, o.site+"."+o.trail, o.trail, boundaries, committed); headErr != nil {
				fmt.Fprintf(out, "regalia-audit-ship: the head file could not be written: %v\n", headErr)
			}
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

// openedTrail is a trail as trails.py's segments() lays it out, open: where it continues from (the
// prune marker), its archives in order, then its current file. It holds descriptors, not bytes, so a
// trail of any size ships (#288); and a rotation or a prune while it ships cannot take lines from under
// it (a renamed or unlinked file stays readable through its descriptor).
type openedTrail struct {
	start    audit.TrailStart
	archives []openedArchive
	current  *os.File
}

type openedArchive struct {
	name string
	seq  uint64
	file *os.File
}

func (trail openedTrail) close() {
	for _, archive := range trail.archives {
		archive.file.Close()
	}
	if trail.current != nil {
		trail.current.Close()
	}
}

// boundary is where an archive ends in the stream: what prune records for it.
type boundary struct {
	name string
	seq  uint64
	at   audit.TrailStart
}

var archiveSuffix = regexp.MustCompile(`^\.([0-9]{20})$`)

// openSegments opens the whole trail. A rotation or a prune running meanwhile would hand it a set of
// files with lines missing, which would read as tampering: so it takes the directory's listing and the
// marker before and after, and opens again when they moved. A trail still moving after a few tries is
// an ordinary error, retried at the next pass.
func openSegments(path string) (openedTrail, error) {
	for attempt := 0; attempt < 5; attempt++ {
		before, err := segmentsState(path)
		if err != nil {
			return openedTrail{}, err
		}
		trail, err := openSegmentsOnce(path, before)
		after, stateErr := segmentsState(path)
		if stateErr != nil {
			trail.close()
			return openedTrail{}, stateErr
		}
		if before == after {
			return trail, err
		}
		trail.close()
	}
	return openedTrail{}, fmt.Errorf("%s kept rotating while it was opened", path)
}

// segmentsState names what a rotation or a prune changes: the files beside the trail, by name and
// inode, and the marker's bytes. Appends are not in it: they only add lines after the ones read.
func segmentsState(path string) (string, error) {
	directory, base := filepath.Split(path)
	entries, err := os.ReadDir(filepath.Clean(directory))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var state strings.Builder
	for _, entry := range entries {
		name := entry.Name()
		if name != base && !strings.HasPrefix(name, base+".") {
			continue
		}
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil {
			continue
		}
		identity := ""
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			identity = fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
		}
		fmt.Fprintf(&state, "%s %s -\n", name, identity) // no size: an append to the current file moves nothing
	}
	if marker, err := os.ReadFile(path + ".pruned"); err == nil {
		state.Write(marker)
	}
	return state.String(), nil
}

func openSegmentsOnce(path, state string) (openedTrail, error) {
	var trail openedTrail
	directory, base := filepath.Split(path)
	if marker, err := readRegular(path+".pruned", 4096); err == nil {
		decoder := json.NewDecoder(bytes.NewReader(marker))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&trail.start); err != nil || trail.start == (audit.TrailStart{}) {
			return trail, fmt.Errorf("%w: %s.pruned is not a prune marker", audit.ErrTrailTampered, path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return trail, err
	}
	current, err := openRegular(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return trail, err
	}
	trail.current = current
	var currentInfo os.FileInfo
	if current != nil {
		if currentInfo, err = current.Stat(); err != nil {
			return trail, err
		}
	}
	for _, line := range strings.Split(state, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		match := archiveSuffix.FindStringSubmatch(strings.TrimPrefix(fields[0], base))
		if match == nil {
			continue
		}
		seq, _ := strconv.ParseUint(match[1], 10, 64)
		if trail.start.Sequence > 0 && seq <= trail.start.Seq {
			continue // a prune cut before it removed this: the marker covers it
		}
		file, err := openRegular(filepath.Join(directory, fields[0]))
		if err != nil {
			return trail, err
		}
		if info, err := file.Stat(); err != nil || (currentInfo != nil && os.SameFile(info, currentInfo)) {
			file.Close() // a rotation cut after its link: this is the current file
			if err != nil {
				return trail, err
			}
			continue
		}
		trail.archives = append(trail.archives, openedArchive{name: fields[0], seq: seq, file: file})
	}
	sort.Slice(trail.archives, func(i, j int) bool { return trail.archives[i].seq < trail.archives[j].seq })
	return trail, nil
}

// openRegular opens a file as trails.append does: never through a link, a regular file only.
func openRegular(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return file, nil
}

// readRegular reads a file as trails.append opens it: never through a link, a regular file only.
func readRegular(path string, limit int64) ([]byte, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return data, nil
}

// readTrail reads one file as the trail; a missing one is empty (readSegments for the whole trail).
func readTrail(path string) ([]byte, error) {
	data, err := readRegular(path, maxTrail)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

// receipter is a sink that can fetch the collector's signed receipts (HTTPSink).
type receipter interface {
	Receipt(context.Context, uint64) (audit.Receipt, error)
}

// writeHead records, for trails.py prune, each archive the collector holds wholly: its name, the
// time of its last line, and the collector's SIGNED RECEIPT for that line (#288). prune trusts the
// receipt, verified against the keys it pins, and its own count of positions, never this file's
// word: a compromised shipper cannot make it remove a line the collector does not hold. An archive
// whose receipt cannot be had is left out, and waits.
func writeHead(ctx context.Context, sink audit.TrailSink, path, identity, stream, trail string, boundaries []boundary, committed uint64) error {
	if path == "" {
		return nil
	}
	type entry struct {
		Name      string        `json:"name"`
		Seq       uint64        `json:"seq"`
		Timestamp int64         `json:"timestamp"`
		Receipt   audit.Receipt `json:"receipt"`
	}
	record := struct {
		Identity  string  `json:"identity"` // the certificate these receipts name: prune waits when it is not its own
		Trail     string  `json:"trail"`
		Stream    string  `json:"stream"`
		Committed uint64  `json:"committed"`
		Archives  []entry `json:"archives"`
	}{Identity: identity, Trail: trail, Stream: stream, Committed: committed, Archives: []entry{}}
	receipts, ok := sink.(receipter)
	for _, b := range boundaries {
		if !ok || b.at.Sequence == 0 || b.at.Sequence > committed {
			break
		}
		receipt, err := receipts.Receipt(ctx, b.at.Sequence)
		if err != nil {
			break
		}
		record.Archives = append(record.Archives, entry{b.name, b.seq, b.at.Timestamp, receipt})
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return replaceFile(path, encoded)
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
	return replaceFile(path, []byte(body))
}

// replaceFile writes path whole (write, fsync, rename), 0644, so no reader sees half of it.
func replaceFile(path string, body []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(body); err != nil {
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

// handover is `regalia-audit-ship handover`: before this host's audit client certificate is swapped,
// the old certificate's key signs that its streams continue under the new one, and the new certificate
// presents that to the collector (#291; internal/audit/handover.go). Then swap client.crt and
// client.key, and restart the shippers: their streams, prune markers and receipts carry on.
func handover(arguments []string, out io.Writer) error {
	flags := flag.NewFlagSet("regalia-audit-ship handover", flag.ContinueOnError)
	flags.SetOutput(out)
	collector := flags.String("collector", "", "the audit collector's https origin")
	oldCert := flags.String("old-cert", "", "the certificate being retired (PEM)")
	oldKey := flags.String("old-key", "", "its private key (PEM), which signs the hand-over")
	tlsCert := flags.String("tls-cert", "", "the new client certificate (PEM), which presents it")
	tlsKey := flags.String("tls-key", "", "the new client key (PEM)")
	serverCA := flags.String("server-ca", "", "PEM CA bundle the collector's certificate is verified against")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *collector == "" || *oldCert == "" || *oldKey == "" || *tlsCert == "" || *tlsKey == "" || *serverCA == "" {
		return errors.New("handover needs -collector, -old-cert, -old-key, -tls-cert, -tls-key and -server-ca")
	}
	old, err := tls.LoadX509KeyPair(*oldCert, *oldKey)
	if err != nil {
		return fmt.Errorf("the old certificate and key: %w", err)
	}
	replacement, err := tls.LoadX509KeyPair(*tlsCert, *tlsKey)
	if err != nil {
		return fmt.Errorf("the new certificate and key: %w", err)
	}
	oldSum, newSum := sha256.Sum256(old.Certificate[0]), sha256.Sum256(replacement.Certificate[0])
	preimage := audit.HandoverPreimage(hex.EncodeToString(oldSum[:]), hex.EncodeToString(newSum[:]))
	signer, ok := old.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("the old key cannot sign")
	}
	var signature []byte
	switch signer.Public().(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(preimage)
		signature, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	case ed25519.PublicKey:
		signature, err = signer.Sign(rand.Reader, preimage, crypto.Hash(0))
	default:
		return errors.New("the old key is neither ECDSA nor Ed25519: the collector verifies only those")
	}
	if err != nil {
		return err
	}
	sink, err := buildSink(*collector, "", *tlsCert, *tlsKey, *serverCA)
	if err != nil {
		return err
	}
	if err := sink.Handover(context.Background(), old.Certificate[0], signature); err != nil {
		return err
	}
	fmt.Fprintf(out, "regalia-audit-ship: the collector continues %x's streams under %x; swap client.crt/client.key and restart the shippers\n", oldSum, newSum)
	return nil
}

// errHandoverPending: this host's certificate changed, and the collector holds nothing for the new one.
var errHandoverPending = errors.New("hand-over pending: this trail shipped under another client certificate, " +
	"and the collector knows nothing for this one; run `regalia-audit-ship handover` first (#291)")

// handoverPending refuses to ship as a new certificate before the hand-over (regalia-kms-51 on #296).
// Shipping first would start the new certificate's own stream, and the collector then refuses every
// hand-over to it. The head file says under which certificate this trail last shipped and how far: if
// that is another certificate, with lines shipped, while the collector has nothing for this one, the
// hand-over has not happened. Nothing is sent; the next pass asks again. (Without a head file there is
// nothing to compare: the operator's `regalia-audit-collector handover -discard-new-streams` recovers.)
func handoverPending(ctx context.Context, sink audit.TrailSink, o options) error {
	if o.head == "" || o.identity == "" {
		return nil
	}
	raw, err := readRegular(o.head, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var head struct {
		Identity  string `json:"identity"`
		Committed uint64 `json:"committed"`
	}
	if json.Unmarshal(raw, &head) != nil || head.Identity == "" || head.Identity == o.identity || head.Committed == 0 {
		return nil
	}
	position, _, err := sink.CommittedHead(ctx, o.site+"."+o.trail)
	if err != nil {
		return err
	}
	if position == 0 {
		return errHandoverPending
	}
	return nil
}

// certificateIdentity is how the collector names this host: the SHA-256 of its client certificate's DER.
func certificateIdentity(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("client certificate: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("client certificate: not a PEM certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
