package fencing

// The fencing authority's decision journal (#29 AC2): who promoted which site, when, and what
// the authority said about it — including the refusals.
//
// THE LEASES ARE THE ARTIFACT; THE DECISION WAS UNWITNESSED. Signed leases prove what a site
// may do, and the issuer's monotonic state proves no epoch repeats, but until this file nothing
// recorded WHICH OPERATOR promoted WHAT, WHEN, or that the authority had REFUSED an attempt to
// overlap two sites. "Promotion requires authenticated, auditable operator action" is not
// satisfied by validity artifacts: an auditor holding every lease ever issued still cannot see
// the split-brain attempt that was turned down, or who was holding the pen.
//
// AUTHENTICATION here is the key ceremony, and the journal makes actions attributable: the
// operator reaching this tool already holds the two-person custody item (the signing key); the
// recorded operator identity binds the decision to the accountable human. Attribution, not
// cryptography, is the journal's job — the cryptography is the chain.
//
// TRUNCATION IS BOUNDED BY THE ISSUER STATE, NOT A SIDECAR. A valid prefix of this journal
// verifies like any chain, so deleting the tail records is undetectable from the journal
// alone. What bounds it: every GRANTED record's epoch must exceed the previous one, and the
// issuer state records the highest epoch ever issued — a journal whose head epoch is below the
// issuer state's has lost records, and the next grant refuses on the epoch floor regardless.
// Deleting a REFUSED record costs only the refusal's visibility; the grant it refused never
// happened, which is the same shape #220 names one layer down: provenance is the missing
// layer, not a stronger hash.
//
// The record-before-publish discipline mirrors the issuer state's: a journaled grant that is
// never handed out costs an epoch number (free); a handed-out grant the journal has forgotten
// is an unwitnessed decision (not free, and now impossible from this tool's side).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// GrantRecordKinds. A refusal is as much the authority acting as a grant: the split-brain
// attempt someone made and the authority turned down is exactly what an auditor needs to see.
const (
	RecordGranted = "granted"
	RecordRefused = "refused"
)

// GrantRecord is one authority decision in the journal's hash chain.
type GrantRecord struct {
	Kind         string    `json:"kind"` // RecordGranted | RecordRefused
	Sequence     uint64    `json:"sequence"`
	Site         string    `json:"site"`
	Epoch        uint64    `json:"epoch"`
	Operator     string    `json:"operator"`
	NotBefore    time.Time `json:"not_before"`
	ExpiresAt    time.Time `json:"expires_at"`
	Reason       string    `json:"reason,omitempty"` // refusals carry the authority's message
	PreviousHash string    `json:"previous_hash"`
	Hash         string    `json:"hash"`
}

// AuthorityJournal is a handle on the decision journal: it verifies the existing chain on
// open, appends under the issuer lock's serialisation, and remembers the head.
type AuthorityJournal struct {
	path     string
	mu       sync.Mutex
	sequence uint64
	lastHash string
}

// OpenAuthorityJournal verifies the existing chain and returns a handle. A missing journal is
// the first decision, not an error — the same rule as the issuer state, for the same reason.
// The mode discipline is the issuer state's: a group- or world-writable journal (or one in a
// writable directory) is refused, because anyone with local access could otherwise rewrite the
// authority's decisions and re-sign them.
func OpenAuthorityJournal(path string) (*AuthorityJournal, error) {
	if path == "" {
		return nil, errors.New("fencing: authority journal path is required")
	}
	if err := requireUnwritableDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	sequence, head, err := verifyAuthorityJournal(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if head == "" {
		head = genesisHash
	}
	return &AuthorityJournal{path: path, sequence: sequence, lastHash: head}, nil
}

// Append writes one decision to the chain and fsyncs it. It is called with the issuer lock
// held (the caller took it before reading the previous grant), so appends are serialised
// against each other exactly as the state writes are.
func (journal *AuthorityJournal) Append(record GrantRecord) error {
	if journal == nil {
		return errors.New("fencing: authority journal is not open")
	}
	if record.Kind != RecordGranted && record.Kind != RecordRefused {
		return fmt.Errorf("fencing: journal record kind %q is neither granted nor refused", record.Kind)
	}
	if record.Operator == "" || record.Site == "" {
		return errors.New("fencing: a journal record names an operator and a site — an unattributed decision is not a record")
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	record.Sequence = journal.sequence + 1
	record.PreviousHash = journal.lastHash
	record.Hash = grantRecordHash(record)
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	file, err := os.OpenFile(journal.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("fencing: open authority journal: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("fencing: unsafe authority journal")
	}
	// WRAPPED, because these are I/O failures and not attacker-supplied input. This package
	// splits the two deliberately: validation of a lease or a record returns a uniform message
	// so a caller holding a file it cannot read learns nothing from which check fired, while
	// disk-full, permission and EIO are conditions an operator has to tell apart — and
	// OpenAuthorityJournal already wraps for exactly that reason.
	if _, err := file.Write(encoded); err != nil {
		return fmt.Errorf("fencing: append authority journal: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("fencing: sync authority journal: %w", err)
	}
	journal.sequence, journal.lastHash = record.Sequence, record.Hash
	return nil
}

// Head reports the sequence number of the last recorded decision — printed after a grant so
// the operator's transcript names the journal entry that carries the decision.
func (journal *AuthorityJournal) Head() uint64 {
	if journal == nil {
		return 0
	}
	journal.mu.Lock()
	defer journal.mu.Unlock()
	return journal.sequence
}

// AuthoritySummary is what an operator or auditor reads from a verified journal.
type AuthoritySummary struct {
	Records      uint64
	HeadSequence uint64
	HeadHash     string
	Grants       uint64
	Refusals     uint64
}

// VerifyAuthorityJournal walks the whole chain and reports what the authority did. It is the
// exported form for the CLI's verify mode; unlike Open, a missing journal is an error, because
// the person asking is asking about a record that is supposed to exist.
func VerifyAuthorityJournal(path string) (AuthoritySummary, error) {
	sequence, head, err := verifyAuthorityJournal(path)
	if err != nil {
		return AuthoritySummary{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return AuthoritySummary{}, err
	}
	defer file.Close()
	// NOT INDEPENDENTLY TESTABLE TODAY, and kept anyway — TESTING.md §17. VerifyAuthorityJournal
	// runs verifyAuthorityJournal first, which reads the same file and refuses an unknown field
	// before this loop starts, so no input reaches here carrying one: removing this line leaves
	// the suite green. It stays because the two readers are independently callable and the
	// masking is an ordering accident, not a property — a later caller that summarises without
	// verifying first would otherwise inherit the permissive decoder silently.
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	summary := AuthoritySummary{HeadSequence: sequence, HeadHash: head}
	for {
		var record GrantRecord
		if err := decoder.Decode(&record); errors.Is(err, io.EOF) {
			return summary, nil
		} else if err != nil {
			return AuthoritySummary{}, errors.New("fencing: authority journal is unreadable")
		}
		summary.Records++
		switch record.Kind {
		case RecordGranted:
			summary.Grants++
		case RecordRefused:
			summary.Refusals++
		}
	}
}

func verifyAuthorityJournal(path string) (uint64, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return 0, "", errors.New("fencing: unsafe authority journal")
	}
	// THE HASH CANNOT SEE A FIELD THE STRUCT DOES NOT HAVE. grantRecordHash marshals the PARSED
	// record, so a field added to the file by anyone who can edit it is dropped at Decode and
	// never reaches the chain — the record still verifies, and the extra content rides along
	// invisibly in the artifact that exists to make decisions auditable. gate.go's lease
	// verifier already refuses unknown fields for this reason.
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	previous, sequence := genesisHash, uint64(0)
	for {
		var record GrantRecord
		if err := decoder.Decode(&record); errors.Is(err, io.EOF) {
			return sequence, previous, nil
		} else if err != nil || record.Sequence != sequence+1 || record.PreviousHash != previous ||
			record.Hash != grantRecordHash(record) ||
			(record.Kind != RecordGranted && record.Kind != RecordRefused) {
			return 0, "", errors.New("fencing: authority journal integrity failure")
		}
		sequence, previous = record.Sequence, record.Hash
	}
}

func grantRecordHash(record GrantRecord) string {
	record.Hash = ""
	encoded, _ := json.Marshal(record)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}
