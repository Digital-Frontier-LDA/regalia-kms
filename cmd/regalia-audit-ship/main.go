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
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
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
	interval                                    time.Duration
	once                                        bool
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
		trail, err := readSegments(o.path)
		var committed, total uint64
		if err == nil {
			committed, total, err = audit.ShipTrailFrom(ctx, sink, stream, o.trail, trail.start, trail.data)
		}
		if err == nil {
			if headErr := writeHead(o.head, o.trail, trail, committed); headErr != nil {
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

// segmentsRead is a trail as trails.py's segments() lays it out: where it continues from (the prune
// marker), and its archives then its current file, concatenated.
type segmentsRead struct {
	start    audit.TrailStart
	data     []byte
	archives []archiveRead
}

type archiveRead struct {
	name     string
	seq      uint64
	lines    uint64 // complete lines in it
	lastLine []byte
}

var archiveSuffix = regexp.MustCompile(`^\.([0-9]{20})$`)

// readSegments reads the whole trail. A rotation or a prune running meanwhile would hand it a
// concatenation with lines missing, which would read as tampering: so it takes the directory's
// listing, the marker and the current file's identity before and after, and reads again when they
// moved. A trail still moving after a few tries is an ordinary error, retried at the next pass.
func readSegments(path string) (segmentsRead, error) {
	for attempt := 0; attempt < 5; attempt++ {
		before, err := segmentsState(path)
		if err != nil {
			return segmentsRead{}, err
		}
		read, err := readSegmentsOnce(path, before)
		after, stateErr := segmentsState(path)
		if stateErr != nil {
			return segmentsRead{}, stateErr
		}
		if before == after {
			return read, err
		}
	}
	return segmentsRead{}, fmt.Errorf("%s kept rotating while it was read", path)
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

func readSegmentsOnce(path, state string) (segmentsRead, error) {
	var read segmentsRead
	directory, base := filepath.Split(path)
	if marker, err := readRegular(path+".pruned", 4096); err == nil {
		decoder := json.NewDecoder(bytes.NewReader(marker))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&read.start); err != nil || read.start == (audit.TrailStart{}) {
			return read, fmt.Errorf("%w: %s.pruned is not a prune marker", audit.ErrTrailTampered, path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return read, err
	}
	current, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return read, err
	}
	var archives []archiveRead
	for _, line := range strings.Split(state, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		match := archiveSuffix.FindStringSubmatch(strings.TrimPrefix(fields[0], base))
		if match == nil {
			continue
		}
		info, err := os.Lstat(filepath.Join(directory, fields[0]))
		if err != nil {
			return read, err
		}
		if current != nil && os.SameFile(info, current) {
			continue // a rotation cut after its link: this is the current file
		}
		seq, _ := strconv.ParseUint(match[1], 10, 64)
		if read.start.Sequence > 0 && seq <= read.start.Seq {
			continue // a prune cut before it removed this: the marker covers it
		}
		archives = append(archives, archiveRead{name: fields[0], seq: seq})
	}
	sort.Slice(archives, func(i, j int) bool { return archives[i].seq < archives[j].seq })
	var data bytes.Buffer
	for i := range archives {
		content, err := readRegular(filepath.Join(directory, archives[i].name), maxTrail)
		if err != nil {
			return read, err
		}
		if len(content) > 0 && content[len(content)-1] != '\n' {
			return read, fmt.Errorf("%w: %s does not end with a whole line: not an archive rotation made", audit.ErrTrailTampered, archives[i].name)
		}
		archives[i].lines = uint64(bytes.Count(content, []byte("\n")))
		archives[i].lastLine = content[bytes.LastIndexByte(content[:max(len(content)-1, 0)], '\n')+1:]
		data.Write(content)
		if data.Len() > maxTrail {
			return read, fmt.Errorf("%s and its archives are larger than %d bytes: prune them", path, maxTrail)
		}
	}
	content, err := readRegular(path, maxTrail)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return read, err
	}
	data.Write(content)
	if data.Len() > maxTrail {
		return read, fmt.Errorf("%s and its archives are larger than %d bytes: prune them", path, maxTrail)
	}
	read.data, read.archives = data.Bytes(), archives
	return read, nil
}

// readRegular reads a file as trails.append opens it: never through a link, a regular file only.
func readRegular(path string, limit int64) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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

// writeHead records, for trails.py prune, the line the collector has committed and each archive
// wholly behind it: its last line's hash and the event that line shipped as. prune removes an archive
// only if it is named here and its last line on disk is the one named.
func writeHead(path, trail string, read segmentsRead, committed uint64) error {
	if path == "" {
		return nil
	}
	events, err := audit.TrailEventsFrom(trail, read.start, read.data)
	if err != nil {
		return err
	}
	type entry struct {
		Name       string `json:"name"`
		Seq        uint64 `json:"seq"`
		Sequence   uint64 `json:"sequence"`
		EventHash  string `json:"event_hash"`
		LineSHA256 string `json:"line_sha256"`
		Timestamp  int64  `json:"timestamp"`
	}
	record := struct {
		Trail     string  `json:"trail"`
		Committed uint64  `json:"committed"`
		Archives  []entry `json:"archives"`
	}{Trail: trail, Committed: committed, Archives: []entry{}}
	sequence := read.start.Sequence
	for _, archive := range read.archives {
		sequence += archive.lines
		if archive.lines == 0 || sequence > committed || sequence-read.start.Sequence > uint64(len(events)) {
			break
		}
		event := events[sequence-read.start.Sequence-1]
		sum := sha256.Sum256(archive.lastLine)
		record.Archives = append(record.Archives, entry{archive.name, archive.seq, sequence, event.Hash, hex.EncodeToString(sum[:]), event.Timestamp.Unix()})
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
