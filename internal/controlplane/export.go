package controlplane

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/fencing"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// ExportFormatVersion is the payload schema version. The inspector refuses anything else.
const ExportFormatVersion = 1

// highWaterSuffix must stay identical to the suffix internal/audit and internal/policy use for
// their truncation sidecars, and shippedSuffix to audit's collector-acknowledged mark. They are
// restated here rather than imported because the export needs to NAME the sidecar paths as
// first-class fields; if those packages ever change a suffix, these constants — and the test
// that pins them against the real ones — must move with it.
const (
	highWaterSuffix = ".high-water"
	shippedSuffix   = ".shipped"
)

// Sources names every guest path the control plane consists of. It is assembled from the
// daemon's own configuration so the export can never drift from what the site actually runs.
// What is deliberately ABSENT is the point: no /run path (PINs, TLS key, lease — runtime
// credentials, excluded by the export contract), no token state (never leaves the HSM), no
// /etc/regalia-kms/public tree (non-secret, reconstructable from the reviewed repository).
type Sources struct {
	AuditJournal string // audit_journal_path
	PolicyState  string // policy_state_path
	FencingState string // fencing_state_path
	SiteVersion  string // deployment-version, carried for provenance
}

// Entry is one exported file. Absent marks a file the daemon has not created yet (a site that
// has never held a lease has no epochs file; that is a valid early state and travels as an
// explicit marker, not as silence).
//
// NotConfigured marks a source this site does not configure at all (a single-site host has no
// fencing journal): no path, no data, no digest. It is a third state, deliberately distinct from
// Absent ("configured, not created yet"). Before it existed, an unconfigured source became an
// entry that was neither present nor absent, the verifier refused it, and a supported single-site
// configuration could not be exported at all (found by the 2026-09-24 bench restore drill). A
// journal and its marks are configured together or not at all.
type Entry struct {
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	Data          []byte `json:"data"`
	Absent        bool   `json:"absent,omitempty"`
	NotConfigured bool   `json:"not_configured,omitempty"`
}

// Export is the sealed payload: the complete control plane of one site at one moment.
//
// THE SCHEMA IS NAMED FIELDS, NOT A LIST WITH A KIND TAG. A list whose entries name their own
// verification kind lets a forged payload claim a journal is a sidecar and skip its chain
// check — caught by the first adversarial test of this format — so the expectation lives in
// the schema itself: whatever arrives in the audit_journal field is verified as an audit
// journal, and no field value changes which check runs.
type Export struct {
	Version        int       `json:"version"`
	Site           string    `json:"site"`
	CreatedAt      time.Time `json:"created_at"`
	AuditJournal   Entry     `json:"audit_journal"`
	AuditHighWater Entry     `json:"audit_high_water"`
	AuditShipped   Entry     `json:"audit_shipped"`
	PolicyState    Entry     `json:"policy_state"`
	PolicyMark     Entry     `json:"policy_mark"`
	FencingEpochs  Entry     `json:"fencing_epochs"`
	SiteVersion    Entry     `json:"site_version"`
}

// validateEntryPath is the shape every entry path must have: guest-absolute, clean, and
// carrying no control characters — the direct sibling of the Site fix, found one review round
// later because the sweep stopped at the field that had been named. Entry paths are
// payload-controlled in a forged export and reach the operator report.
func validateEntryPath(path string) error {
	if path == "" || path[0] != '/' || path != filepath.Clean(path) || len(path) > 512 {
		return fmt.Errorf("path %q is not a clean guest-absolute path", path)
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("path %q carries a control character", path)
		}
	}
	return nil
}

// validateSiteName applies the REGISTRY's identifier shape, from one definition: a Site the
// registry would refuse is not accepted by the export either. The field is
// payload-controlled (anyone can seal an envelope to the authority's public key) and flows
// into the operator report, where a newline-bearing site injects a fabricated entry line
// into the very report used to decide whether to trust the export — the seventh instance of
// the payload-decides family, and the first that writes what the operator is TOLD rather
// than what gets checked. The shape bounds length as well (62 max): a report field with no
// bound is its own denial of legibility.
func validateSiteName(site string) error {
	if !registry.MatchesIdentifier(site) {
		return fmt.Errorf("controlplane: site name %q is not an identifier the registry would accept — an export cannot name a site it could not have been configured as", site)
	}
	return nil
}

// ErrNoSources refuses the "exported nothing" shape. An exporter configured with no
// control-plane paths would otherwise emit a valid envelope containing an empty state and
// exit 0 — a success indistinguishable from a misconfiguration, and exactly the hole a
// stripped or partially-supplied configuration produces (#185's lesson: the defect lives in
// the configuration the code runs under, and a harness that always supplies the fields cannot
// see it).
var ErrNoSources = errors.New("controlplane: no control-plane paths are configured; refusing to export an empty state as if it were a complete one")

// maxPlainFileBytes bounds the non-journal entries (sidecar marks, deployment version).
// These are tiny by construction; a "mark" that has grown is not a mark.
const maxPlainFileBytes = 4096

// maxJournalBytes bounds any single journal before it is exported: unbounded input through the
// backup path is the same hazard it is through the network path.
const maxJournalBytes = 64 << 20

// readBounded refuses a file over the bound BEFORE reading it. ReadFile-then-check
// materialises the oversized file first — on the offline host the inspection runs on, that is
// an OOM in the exact moment a refusal was already decided. The handle is stat-ed (not the
// path), and the read is capped again so a file that grew between stat and read still cannot
// exceed the bound by more than one byte.
func readBounded(path string, bound int64) ([]byte, error) {
	file, err := os.Open(path)
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
	if info.Size() > bound {
		return nil, fmt.Errorf("%s is %d bytes, over the %d-byte bound for its kind", path, info.Size(), bound)
	}
	data, err := io.ReadAll(io.LimitReader(file, bound+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > bound {
		return nil, fmt.Errorf("%s grew past the %d-byte bound while being read", path, bound)
	}
	return data, nil
}

// Build reads every configured source, verifies the journals' integrity chains WITH their
// sidecars beside them, secret-scans the payload with the canary in the same pass, and returns
// the export ready to be sealed. Any failure is a refusal: an export is evidence, and evidence
// that cannot be trusted is worse than no export, because it blocks a rebuild with false
// confidence.
func Build(s Sources, site string, now time.Time) (*Export, error) {
	if s.AuditJournal == "" && s.PolicyState == "" && s.FencingState == "" {
		// Covers both the fully-stripped configuration and the one that names only the
		// version file: provenance without a journal is not a control plane.
		return nil, ErrNoSources
	}
	if err := validateSiteName(site); err != nil {
		return nil, err
	}
	// The optional provenance file gets its canonical path here rather than an empty one, so
	// every field of the export carries a real path and the absence check below can demand
	// exactly that — an entry whose path is empty is a malformed field, never a "not
	// configured" marker the verifier has to guess the meaning of.
	if s.SiteVersion == "" {
		s.SiteVersion = "/etc/regalia-kms/deployment-version"
	}
	read := func(path string, bound int64, label string, emptyIsAbsent bool) (Entry, error) {
		if path == "" {
			return Entry{NotConfigured: true}, nil
		}
		data, err := readBounded(path, bound)
		if errors.Is(err, os.ErrNotExist) {
			return Entry{Path: path, Absent: true}, nil
		}
		if err != nil {
			return Entry{}, fmt.Errorf("controlplane: read %s: %w", label, err)
		}
		// A ZERO-BYTE FILE IS AN ABSENT HISTORY — FOR JOURNALS ONLY. The journals are
		// created eagerly by their first open (audit.Open O_CREATEs), so a running daemon
		// with nothing recorded yet HAS the file, 0 bytes, with no sidecars; exporting that
		// as "present and empty" would refuse a state every fresh site is in. The caller
		// decides whether empty-means-absent applies: for the sidecar marks and the version
		// file it does NOT — a file that exists and is empty is exactly the state their own
		// guards ("not a valid sidecar mark", "deployment version is blank") exist to
		// refuse, and normalising it to absent would silently disarm both (found by
		// building both variants: each row alone passes against the wrong rule).
		if len(data) == 0 && emptyIsAbsent {
			return Entry{Path: path, Absent: true}, nil
		}
		digest := sha256.Sum256(data)
		return Entry{Path: path, SHA256: hex.EncodeToString(digest[:]), Data: data}, nil
	}
	var readErr error
	entry := func(path string, bound int64, label string, emptyIsAbsent bool) (e Entry) {
		if readErr != nil {
			return Entry{}
		}
		e, readErr = read(path, bound, label, emptyIsAbsent)
		return e
	}
	export := &Export{
		Version:        ExportFormatVersion,
		Site:           site,
		CreatedAt:      now.UTC(),
		AuditJournal:   entry(s.AuditJournal, maxJournalBytes, "audit journal", true),
		AuditHighWater: entry(sidecar(s.AuditJournal, highWaterSuffix), maxPlainFileBytes, "audit high-water mark", false),
		AuditShipped:   entry(sidecar(s.AuditJournal, shippedSuffix), maxPlainFileBytes, "audit shipped mark", false),
		PolicyState:    entry(s.PolicyState, maxJournalBytes, "policy state journal", true),
		PolicyMark:     entry(sidecar(s.PolicyState, highWaterSuffix), maxPlainFileBytes, "policy state mark", false),
		FencingEpochs:  entry(s.FencingState, maxJournalBytes, "fencing epoch journal", true),
		SiteVersion:    entry(s.SiteVersion, maxPlainFileBytes, "deployment version", false),
	}
	if readErr != nil {
		return nil, readErr
	}
	if err := verifyExport(export); err != nil {
		return nil, err
	}
	scanned := make(map[string][]byte)
	for _, e := range exportEntries(export) {
		if !e.entry.Absent && len(e.entry.Data) > 0 {
			scanned[e.label] = e.entry.Data
		}
	}
	findings, err := armedScan(scanned)
	if err != nil {
		return nil, err
	}
	if len(findings) > 0 {
		return nil, fmt.Errorf("controlplane: refusing to export: secret-shaped content in control-plane state: %s", findings[0])
	}
	return export, nil
}

// sidecar is a journal's mark path, or "" (not configured) for an unconfigured journal. Appending
// the suffix to "" produced the RELATIVE path ".high-water", read from whatever the working
// directory happened to be.
func sidecar(journal, suffix string) string {
	if journal == "" {
		return ""
	}
	return journal + suffix
}

type namedEntry struct {
	label string
	entry Entry
}

// exportEntries fixes ONE iteration order for the verification loops, the payload scan and the
// summary report — as a SLICE, because a map ranges in random order (measured: 7 distinct
// SummaryLines orderings across 300 calls, defeating the line-by-line comparison of export
// output against inspection output that the report exists for). The same determinism rule as
// sortedKeys in scan.go, applied one file over.
func exportEntries(export *Export) []namedEntry {
	return []namedEntry{
		{"audit journal", export.AuditJournal},
		{"audit high-water mark", export.AuditHighWater},
		{"audit shipped mark", export.AuditShipped},
		{"policy state journal", export.PolicyState},
		{"policy state mark", export.PolicyMark},
		{"fencing epoch journal", export.FencingEpochs},
		{"deployment version", export.SiteVersion},
	}
}

// verifyExport is the shared verdict: it is run at Build time over live state and at Inspect
// time over decrypted bytes, so the two cannot drift. Journals are materialised in one private
// directory with their sidecars adjacent — VerifyIntegrity's truncation check reads the
// sidecar by path convention, so a journal verified alone is verified against a mark that
// silently defaults to genesis, which is exactly the post-attack state the sidecars exist to
// detect.
func verifyExport(export *Export) error {
	// STRUCTURE: every entry is present-with-digest or explicitly absent. A half-formed
	// field is refused rather than guessed at.
	configured := 0
	for _, named := range exportEntries(export) {
		label, e := named.label, named.entry
		if e.NotConfigured {
			// NOT CONFIGURED carries nothing, and the deployment version always has a path.
			if e.Path != "" || e.Absent || len(e.Data) > 0 || e.SHA256 != "" || label == "deployment version" {
				return fmt.Errorf("controlplane: %s is malformed as a not-configured marker — it must carry nothing at all", label)
			}
			continue
		}
		if label == "audit journal" || label == "policy state journal" || label == "fencing epoch journal" {
			configured++
		}
		if e.Absent {
			// ABSENCE IS CHECKED, NOT OBEYED. A marker that arrives with a body contradicts
			// itself: bytes claiming to be absent would ride past the digest, the secret
			// scan and the operator's report in one move (found on #219 review — the third
			// instance of a payload value deciding what the payload skips). An absence
			// marker must carry a real path and nothing else.
			if e.Path == "" || len(e.Data) > 0 || e.SHA256 != "" {
				return fmt.Errorf("controlplane: %s is malformed as an absence marker — it must carry a real path and nothing else, but has no path, or carries data or a digest", label)
			}
			// Absence markers carry a path too, and it reaches the same report: the
			// injection found on #219 review arrived THROUGH an absent entry's path.
			if err := validateEntryPath(e.Path); err != nil {
				return fmt.Errorf("controlplane: %s: %w", label, err)
			}
			continue
		}
		if e.Path == "" || e.SHA256 == "" {
			return fmt.Errorf("controlplane: %s is neither present nor absent — the field is malformed", label)
		}
		if len(e.Data) == 0 {
			return fmt.Errorf("controlplane: %s is present but empty — absence must travel as an explicit marker, not as an empty file", label)
		}
		digest := sha256.Sum256(e.Data)
		if hex.EncodeToString(digest[:]) != e.SHA256 {
			return fmt.Errorf("controlplane: %s does not match its recorded digest", label)
		}
		if err := validateEntryPath(e.Path); err != nil {
			return fmt.Errorf("controlplane: %s: %w", label, err)
		}
	}
	// CONFIGURED TOGETHER: a journal and its marks are one source. A journal present with its mark
	// "not configured" would travel with truncation detection silently off.
	for _, group := range []struct {
		label string
		all   []Entry
	}{
		{"audit journal", []Entry{export.AuditJournal, export.AuditHighWater, export.AuditShipped}},
		{"policy state journal", []Entry{export.PolicyState, export.PolicyMark}},
	} {
		for _, e := range group.all[1:] {
			if e.NotConfigured != group.all[0].NotConfigured {
				return fmt.Errorf("controlplane: the %s and its marks must be configured together", group.label)
			}
		}
	}
	if configured == 0 {
		return ErrNoSources
	}
	// AMPUTATION: a journal may be absent only if nothing remembers history it should have.
	// A sidecar recording a non-zero position beside an absent journal is a deletion, and an
	// export carrying that pair would restore a site whose history was amputated with the
	// stump certified intact.
	if export.AuditJournal.Absent {
		if err := sidecarsConsistentWithAbsence("audit journal", export.AuditHighWater, export.AuditShipped); err != nil {
			return err
		}
	}
	if export.PolicyState.Absent {
		if err := sidecarsConsistentWithAbsence("policy state journal", export.PolicyMark); err != nil {
			return err
		}
	}
	// BASENAME COLLISION: verification materialises journals and their sidecars in one
	// private directory by basename, so two present entries sharing a basename would
	// overwrite one another and one journal would be verified as the other. Refuse the
	// configuration rather than verifying the wrong bytes.
	seen := make(map[string]string)
	for _, named := range exportEntries(export) {
		if named.entry.Absent || named.entry.NotConfigured {
			continue
		}
		base := filepath.Base(named.entry.Path)
		if previous, clash := seen[base]; clash {
			return fmt.Errorf("controlplane: %s and %s share the basename %q — verification would conflate them; the site configuration must give each journal a distinct file name", previous, named.label, base)
		}
		seen[base] = named.label
	}

	// THE INVERSE OF AMPUTATION: a journal WITH content must carry its TRUNCATION mark.
	// The mark readers treat a missing mark as genesis, so a journal truncated with its
	// high-water mark deleted alongside the tail verifies clean — the attack the mark
	// exists to detect, replayed through a payload whose sidecar entries claim absence.
	//
	// ONLY .high-water IS REQUIRED, AND THE ASYMMETRY IS DELIBERATE. The high-water mark is
	// written on the synchronous append path ("called only AFTER the event is durable"),
	// so a journal with events and no mark is not a legitimate state. The .shipped mark is
	// written by the shipper's drain goroutine after the collector acknowledges — its own
	// comment calls losing it safe — so it is SHIPPING PROGRESS, not integrity: a host whose
	// collector is unreachable never produces one, and requiring it would permanently refuse
	// exports from exactly the host a recovery needs most (found when the rule turned the
	// Linux CI red after passing on macOS: the drain races Build). If .shipped IS present it
	// rides in the export and stays evidence — including against an absent journal below —
	// but its absence beside a present journal means nothing.
	if !export.AuditJournal.Absent && len(export.AuditJournal.Data) > 0 && export.AuditHighWater.Absent {
		return errors.New("controlplane: the audit journal carries events but its truncation mark is absent — the history is unverifiable against truncation, not empty")
	}
	if !export.PolicyState.Absent && len(export.PolicyState.Data) > 0 && export.PolicyMark.Absent {
		return errors.New("controlplane: the policy state journal carries reservations but its mark is absent — spent quota is unverifiable against truncation")
	}
	// Sidecar marks are JSON; the deployment version is short non-empty text.
	if err := checkSidecarJSON("audit high-water mark", export.AuditHighWater); err != nil {
		return err
	}
	if err := checkSidecarJSON("audit shipped mark", export.AuditShipped); err != nil {
		return err
	}
	if err := checkSidecarJSON("policy state mark", export.PolicyMark); err != nil {
		return err
	}
	if !export.SiteVersion.Absent && len(bytes.TrimSpace(export.SiteVersion.Data)) == 0 {
		return errors.New("controlplane: deployment version is blank")
	}
	// CHAINS: materialise present journals with their sidecars, then run the verifiers a
	// restored site will run.
	temporary, err := os.MkdirTemp("", "controlplane-verify-")
	if err != nil {
		return fmt.Errorf("controlplane: verify: %w", err)
	}
	defer os.RemoveAll(temporary)
	write := func(e Entry, name string) error {
		if e.Absent {
			return nil
		}
		return os.WriteFile(filepath.Join(temporary, name), e.Data, 0o600)
	}
	var journalChecks []struct {
		label    string
		entry    Entry
		name     string
		sidecars []struct {
			suffix string
			entry  Entry
		}
		verifier func(string) error
	}
	if export.AuditJournal.Path != "" {
		journalChecks = append(journalChecks, struct {
			label    string
			entry    Entry
			name     string
			sidecars []struct {
				suffix string
				entry  Entry
			}
			verifier func(string) error
		}{
			label: "audit journal", entry: export.AuditJournal, name: filepath.Base(export.AuditJournal.Path),
			sidecars: []struct {
				suffix string
				entry  Entry
			}{{highWaterSuffix, export.AuditHighWater}, {shippedSuffix, export.AuditShipped}},
			verifier: func(path string) error { _, err := audit.VerifyIntegrity(path); return err },
		})
	}
	if export.PolicyState.Path != "" {
		journalChecks = append(journalChecks, struct {
			label    string
			entry    Entry
			name     string
			sidecars []struct {
				suffix string
				entry  Entry
			}
			verifier func(string) error
		}{
			label: "policy state journal", entry: export.PolicyState, name: filepath.Base(export.PolicyState.Path),
			sidecars: []struct {
				suffix string
				entry  Entry
			}{{highWaterSuffix, export.PolicyMark}},
			verifier: func(path string) error { _, err := policy.VerifyState(path); return err },
		})
	}
	if export.FencingEpochs.Path != "" {
		journalChecks = append(journalChecks, struct {
			label    string
			entry    Entry
			name     string
			sidecars []struct {
				suffix string
				entry  Entry
			}
			verifier func(string) error
		}{
			label: "fencing epoch journal", entry: export.FencingEpochs, name: filepath.Base(export.FencingEpochs.Path),
			verifier: func(path string) error { _, _, err := fencing.VerifyEpochs(path); return err },
		})
	}
	for _, check := range journalChecks {
		if err := write(check.entry, check.name); err != nil {
			return fmt.Errorf("controlplane: verify: %w", err)
		}
		for _, sidecar := range check.sidecars {
			if err := write(sidecar.entry, check.name+sidecar.suffix); err != nil {
				return fmt.Errorf("controlplane: verify: %w", err)
			}
		}
	}
	for _, check := range journalChecks {
		if check.entry.Absent {
			continue
		}
		if err := check.verifier(filepath.Join(temporary, check.name)); err != nil {
			return fmt.Errorf("controlplane: %s failed integrity verification: %w", check.label, err)
		}
	}
	return nil
}

func checkSidecarJSON(label string, entry Entry) error {
	if entry.Absent || entry.NotConfigured {
		return nil
	}
	var mark map[string]any
	if err := json.Unmarshal(entry.Data, &mark); err != nil {
		return fmt.Errorf("controlplane: %s is not a valid sidecar mark: %w", label, err)
	}
	return nil
}

// sidecarsConsistentWithAbsence refuses the "journal deleted, sidecar remembers" pair.
// BOTH marks count here even though only .high-water is required beside a present journal:
// absence of .shipped is legitimate (a lossy writer), but PRESENCE of .shipped with a
// non-zero sequence beside an absent journal is amputation evidence all the same — the
// collector acknowledged events the payload no longer carries. Optional to write, binding
// to read.
func sidecarsConsistentWithAbsence(label string, sidecars ...Entry) error {
	for _, sidecar := range sidecars {
		if sidecar.Absent {
			continue
		}
		var mark struct {
			Sequence uint64 `json:"sequence"`
		}
		// AN UNREADABLE MARK IS NOT A CLEAN ONE. The first version read it with
		// `err == nil && mark.Sequence > 0`, which made an unparseable sidecar SKIP the
		// amputation refusal — so the same amputated state was refused as {"sequence":1}
		// and accepted as {"sequence":"1"}, one character apart (found on #219 review with
		// exactly that control). Being unparseable must fail the check, not remove it.
		if err := json.Unmarshal(sidecar.Data, &mark); err != nil {
			return fmt.Errorf("controlplane: %s is absent and its sidecar is not a readable mark (%w) — an unreadable history is not an empty one", label, err)
		}
		if mark.Sequence > 0 {
			return fmt.Errorf("controlplane: %s is absent but its sidecar records sequence %d — history was amputated, not never-written", label, mark.Sequence)
		}
	}
	return nil
}

// Inspect is the offline half of the pair: given a sealed envelope and the custody authority's
// private key, it opens the export and recomputes the same verdict Build reached, from bytes
// that have since lived on media the KMS does not control — which is the entire point of a
// restore drill.
func Inspect(encoded []byte, authorityPrivateKey *ecdh.PrivateKey) (*Export, error) {
	return InspectForSite(encoded, authorityPrivateKey, "")
}

// InspectForSite additionally binds the recovery point to the site it is being restored as.
func InspectForSite(encoded []byte, authorityPrivateKey *ecdh.PrivateKey, expectedSite string) (*Export, error) {
	payload, err := Open(encoded, authorityPrivateKey)
	if err != nil {
		return nil, err
	}
	var export Export
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&export); err != nil {
		return nil, fmt.Errorf("controlplane: export payload is not valid: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("controlplane: export payload has trailing data")
	}
	if export.Version != ExportFormatVersion {
		return nil, fmt.Errorf("controlplane: export version %d is not %d", export.Version, ExportFormatVersion)
	}
	if err := validateSiteName(export.Site); err != nil {
		return nil, err
	}
	// The inspector can BIND the file to the site it is being restored as: the payload's
	// self-declared site is attacker-controllable data (anyone can seal an envelope to the
	// authority's public key), and without the binding it reaches the operator report as if
	// it were verified. A mismatch is a refusal, not a display.
	if expectedSite != "" && export.Site != expectedSite {
		return nil, fmt.Errorf("controlplane: the export names site %q but was expected to be %q — a recovery point that names a different site is not this site's", export.Site, expectedSite)
	}
	if err := verifyExport(&export); err != nil {
		return nil, err
	}
	scanned := make(map[string][]byte)
	for _, named := range exportEntries(&export) {
		if !named.entry.Absent && len(named.entry.Data) > 0 {
			scanned[named.label] = named.entry.Data
		}
	}
	findings, err := armedScan(scanned)
	if err != nil {
		return nil, err
	}
	if len(findings) > 0 {
		return nil, fmt.Errorf("controlplane: restored state carries secret-shaped content: %s", findings[0])
	}
	return &export, nil
}

// SummaryLines renders the per-entry human report both commands print, so an operator holding
// the export file and the inspection output can compare them line by line.
func SummaryLines(export *Export) []string {
	lines := []string{
		fmt.Sprintf("site %s exported %s", export.Site, export.CreatedAt.Format(time.RFC3339)),
	}
	for _, named := range exportEntries(export) {
		e := named.entry
		if e.NotConfigured {
			lines = append(lines, fmt.Sprintf("  not configured %s", named.label))
			continue
		}
		if e.Absent {
			// %q throughout: validation is remembered per field and can be forgotten when
			// a fifth one appears; quoting is structural and covers whatever slips past.
			// The SHA256 field is only safe today because TWO different rules happen to
			// cover its two branches — relaxing either would make it the third injection.
			lines = append(lines, fmt.Sprintf("  absent        %q", e.Path))
		} else {
			// len guard: a malformed entry must not turn the report into a panic — found
			// while measuring the ordering, when a zero-valued Export crashed the printer.
			digest := e.SHA256
			if len(digest) > 12 {
				digest = digest[:12]
			}
			lines = append(lines, fmt.Sprintf("  %7d  %12s…  %q", len(e.Data), digest, e.Path))
		}
	}
	return lines
}
