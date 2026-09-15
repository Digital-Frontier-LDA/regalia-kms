package controlplane

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The secret-shape scan. Its job is the belt-and-braces half of the export contract: the
// journals are hash-chained, so tampering with them already fails verification — this scan
// exists for the case verification cannot see, a COMPROMISED WRITER that produces a perfectly
// valid chain whose records contain key material anyway. The marker set mirrors the key-material
// markers internal/audit's draft validation applies to every record field at write time
// ("PRIVATE KEY", "AGE-SECRET-KEY"): the export scan refuses exactly what the journal refuses.
//
// WHAT IT CANNOT SEE, STATED. A bare secret value with no marker — a PIN printed as naked
// digits inside an otherwise valid, correctly chained record — is not detectable by shape.
// The journal's own write-time validation is the control for that; this scan is the second
// net, not the only one. The restore drill's tree scan adds filename shapes on top, because a
// restored guest must not carry a credentials file at all, whatever its content looks like.

// markerShapes are the byte strings whose presence in exported or restored state is a refusal.
// Each is stored split so the scanner's own source does not carry the assembled marker as a
// findable literal (the same composition discipline the secret scanner's prose rules use).
var markerShapes = []markerShape{
	{name: "pkcs-private-key-header", parts: []string{"-----BEGIN ", "PRIVATE KEY-----"}},
	{name: "age-secret-key", parts: []string{"AGE-SECRET-KEY-", "1"}},
}

type markerShape struct {
	name  string
	parts []string
}

func (m markerShape) assembled() string {
	return strings.Join(m.parts, "")
}

// ErrScannerUnarmed is returned when the scanner failed to detect its own canary in the same
// pass that produced a verdict. A clean result is only meaningful if the pass that produced it
// demonstrably could see a planted secret: a config error, an empty input list, or a regressed
// detector all produce "found nothing", and finding nothing is what failure looks like here.
// The canary therefore travels WITH every scan, and this error means the clean verdict — or the
// findings list — cannot be trusted. (Lesson paid for twice on 2026-09-06, #212 and #211's
// review: nothing tied "we found zero" to "we could have found one".)
var ErrScannerUnarmed = errors.New("controlplane: the secret scan failed its own positive control and its verdict is void")

// canary returns a freshly generated line that carries every marker shape. It is generated at
// runtime from cryptographic randomness so it is never a repo literal and never a fixed string
// a regressed detector could be tuned to recognize.
func canary() string {
	suffix := make([]byte, 16)
	if _, err := io.ReadFull(entropyReader, suffix); err != nil {
		// Falling back to a fixed canary would make the positive control weaker exactly when
		// the system is degraded; refusing is the fail-closed alternative.
		return ""
	}
	// Assembled from parts for the same reason the markers are: the assembled form must not
	// appear verbatim in this file.
	return strings.Join([]string{"-----BEGIN ", "PRIVATE KEY----- canary ", hex.EncodeToString(suffix), " AGE-SECRET-KEY-", "1", hex.EncodeToString(suffix)}, "")
}

// Finding names a caught shape without reproducing it: evidence carries the shape NAME and the
// location, never the matched bytes — the offender is never reprinted to explain itself.
type Finding struct {
	Path  string `json:"path"`
	Line  int    `json:"line"`
	Shape string `json:"shape"`
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s", f.Path, f.Line, f.Shape)
}

// scanBytes returns every marker hit in data. It is the shared detector for the export payload
// scan and the tree scan; the canary check is applied by the callers that report verdicts.
func scanBytes(path string, data []byte) []Finding {
	return scanBytesWith(markerShapes, path, data)
}

func scanBytesWith(shapes []markerShape, path string, data []byte) []Finding {
	var findings []Finding
	for lineNumber, line := range bytes.Split(data, []byte("\n")) {
		for _, shape := range shapes {
			if bytes.Contains(line, []byte(shape.assembled())) {
				findings = append(findings, Finding{Path: path, Line: lineNumber + 1, Shape: shape.name})
			}
		}
	}
	return findings
}

// armedScan runs scanBytes over every named input, WITH the canary in the same pass. If the
// canary was not caught, the verdict is void and ErrScannerUnarmed is returned regardless of
// what else was or was not found. The shape list is a parameter of armedScanWith so a test (or
// a mutation) can demonstrate the unarmed behaviour directly: a scanner with no shapes cannot
// catch its own canary and therefore cannot return a clean verdict — neutering the detector
// fails CLOSED, not silently.
func armedScan(inputs map[string][]byte) ([]Finding, error) {
	return armedScanWith(markerShapes, inputs)
}

func armedScanWith(shapes []markerShape, inputs map[string][]byte) ([]Finding, error) {
	if !shapesArmedWith(shapes) {
		return nil, ErrScannerUnarmed
	}
	var findings []Finding
	for _, path := range sortedKeys(inputs) {
		findings = append(findings, scanBytesWith(shapes, path, inputs[path])...)
	}
	return findings, nil
}

// shapesArmedWith proves, in THIS invocation and with THIS shape list, that the detector can
// see a planted secret — a freshly generated canary, scanned with the same scanBytesWith call
// the real input is about to go through. Tree scanning uses this once up front and then scans
// files one at a time, so a tree of any size is covered by one arming proof and a bounded peak.
func shapesArmedWith(shapes []markerShape) bool {
	probe := canary()
	if probe == "" {
		return false
	}
	return len(scanBytesWith(shapes, "(scan-canary)", []byte(probe))) > 0
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	// Sorted so findings (and therefore error text) are deterministic.
	sortStrings(keys)
	return keys
}

func sortStrings(values []string) {
	for outer := 1; outer < len(values); outer++ {
		for inner := outer; inner > 0 && values[inner] < values[inner-1]; inner-- {
			values[inner], values[inner-1] = values[inner-1], values[inner]
		}
	}
}

// secretFileNames are basenames a restored guest must not carry at all, regardless of content:
// these are the shapes the deployment uses for credentials (token PIN files, the TLS server
// key, TPM-wrapped credential blobs), and their presence in a rebuilt tree means the custody
// procedure leaked operational authority into state that is about to be restored.
var secretFileNamePatterns = []string{
	"pin.txt",     // hsm-auto-import.sh's PIN file shape
	".pin",        // the daemon's per-token credential file suffix
	"server-key",  // the TLS private key materialised at runtime
	"credentials", // the systemd LoadCredential directory name
}

// maxTreeFileBytes caps what ScanTree will read into memory for one file. A restored guest's
// configuration and state tree is journals and small files; anything past this bound is flagged
// rather than read, so a tree that cannot be honestly content-scanned cannot be certified
// clean either — and the peak memory of a scan is one bounded file, not the sum of the tree.
const maxTreeFileBytes = 256 << 20

// ScanTree inspects a restored directory tree for secret shapes: content markers in every
// regular file, plus credential-shaped names. The scanner is armed once, in this invocation,
// with the same detector that then scans each file one at a time (so findings are kept, not
// file bytes); an oversized file is a finding, not an attempted read.
func ScanTree(root string) ([]Finding, error) {
	if !shapesArmedWith(markerShapes) {
		return nil, ErrScannerUnarmed
	}
	var findings []Finding
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if matchName(entry.Name(), "credentials") {
				findings = append(findings, Finding{Path: path, Line: 0, Shape: "credential-directory"})
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, statErr := entry.Info()
		if statErr != nil {
			return statErr
		}
		if info.Size() > maxTreeFileBytes {
			findings = append(findings, Finding{Path: path, Line: 0, Shape: "oversized-file"})
			return nil
		}
		data, readErr := readBounded(path, maxTreeFileBytes)
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) {
				return nil // raced with removal; nothing left to scan
			}
			return readErr
		}
		findings = append(findings, scanBytesWith(markerShapes, path, data)...)
		for _, pattern := range secretFileNamePatterns {
			if matchName(entry.Name(), pattern) {
				findings = append(findings, Finding{Path: path, Line: 0, Shape: "credential-file-name"})
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("controlplane: walk %s: %w", root, walkErr)
	}
	return findings, nil
}

// matchName reports whether the pattern appears as a SUBSTRING of the file or directory
// name — measured (2026-09-06): bare strings.Contains, so "server-key" matches
// "my-server-keyring" and "credentials" matches "no-credentials-here.md". That is broader
// than equality, suffix, or path-segment matching, and the breadth is the choice: a leak
// scanner's error direction is over-matching (an extra finding costs a review) where
// under-matching costs a secret, and "10-token.pin", "staging/pin.txt" and "credentials.new"
// are the same leak with a mangled name. The cost is real and stated: findings people learn
// to discount are how a scanner dies, so the finding MESSAGE names the file that matched —
// a discountable finding is one whose evidence you cannot see. This docstring previously
// claimed "whole path segment", which the behaviour never was; a reader trusting it would
// have concluded "server-key" cannot match a keyring file. It does.
func matchName(name, pattern string) bool {
	return strings.Contains(name, pattern)
}
