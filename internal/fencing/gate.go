// Package fencing enforces externally authorized active/passive site leases.
package fencing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

const maxLeaseBytes = 16 << 10

var ErrFenced = errors.New("KMS site is fenced")

type leaseDocument struct {
	Version        int    `json:"version"`
	Site           string `json:"site"`
	Epoch          uint64 `json:"epoch"`
	NotBefore      string `json:"not_before"`
	ExpiresAt      string `json:"expires_at"`
	RegistryDigest string `json:"registry_digest"`
	Signature      string `json:"signature"`
}

type signedLease struct {
	Version        int    `json:"version"`
	Site           string `json:"site"`
	Epoch          uint64 `json:"epoch"`
	NotBefore      string `json:"not_before"`
	ExpiresAt      string `json:"expires_at"`
	RegistryDigest string `json:"registry_digest"`
}

type epochRecord struct {
	Epoch        uint64 `json:"epoch"`
	PreviousHash string `json:"previous_hash"`
	Hash         string `json:"hash"`
}

type Gate struct {
	mu             sync.Mutex
	leasePath      string
	statePath      string
	publicKey      ed25519.PublicKey
	site           string
	registryDigest string
	now            func() time.Time
	maxEpoch       uint64
	lastHash       string
	lastHeld       bool
	checkedAt      time.Time
}

func Open(leasePath, statePath, site, registryDigest string, publicKey ed25519.PublicKey, now func() time.Time) (*Gate, error) {
	if leasePath == "" || statePath == "" || site == "" || registryDigest == "" || len(publicKey) != ed25519.PublicKeySize || now == nil {
		return nil, errors.New("invalid fencing configuration")
	}
	epoch, hash, err := verifyEpochJournal(statePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	gate := &Gate{leasePath: leasePath, statePath: statePath, publicKey: append(ed25519.PublicKey(nil), publicKey...), site: site, registryDigest: registryDigest, now: now, maxEpoch: epoch, lastHash: hash}
	if gate.lastHash == "" {
		gate.lastHash = genesisHash
	}
	if !gate.refreshLocked(context.Background()) {
		return nil, ErrFenced
	}
	return gate, nil
}

func (gate *Gate) Ready(ctx context.Context) bool {
	if gate == nil {
		return false
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.refreshLocked(ctx)
}

// refreshLocked evaluates the lease and records the outcome as the gate's
// observable snapshot. The state of the lease is therefore readable without
// performing the read: every operation and every readiness check already pays for
// the evaluation, and a metrics scrape must not be a third caller that moves the
// lease file or the epoch journal.
func (gate *Gate) refreshLocked(ctx context.Context) bool {
	held := gate.evaluateLocked(ctx)
	gate.lastHeld = held
	gate.checkedAt = gate.now().UTC()
	return held
}

// snapshot returns the last evaluation: whether the lease was held, the high-water
// epoch (which survives a later loss), and when the evaluation happened.
func (gate *Gate) snapshot() (held bool, epoch uint64, checked time.Time) {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.lastHeld, gate.maxEpoch, gate.checkedAt
}

func (gate *Gate) evaluateLocked(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	lease, err := readLease(gate.leasePath)
	if err != nil || lease.Site != gate.site || lease.RegistryDigest != gate.registryDigest || lease.Epoch < gate.maxEpoch {
		return false
	}
	now := gate.now().UTC()
	notBefore, beforeErr := time.Parse(time.RFC3339Nano, lease.NotBefore)
	expiresAt, expiryErr := time.Parse(time.RFC3339Nano, lease.ExpiresAt)
	if beforeErr != nil || expiryErr != nil || now.Before(notBefore) || !now.Before(expiresAt) || !expiresAt.After(notBefore) || expiresAt.Sub(notBefore) > MaxLeaseDuration {
		return false
	}
	if !verifyLease(lease, gate.publicKey) {
		return false
	}
	if lease.Epoch > gate.maxEpoch {
		hash, err := appendEpoch(gate.statePath, gate.lastHash, lease.Epoch)
		if err != nil {
			return false
		}
		gate.maxEpoch, gate.lastHash = lease.Epoch, hash
	}
	return true
}

func readLease(path string) (leaseDocument, error) {
	file, err := os.Open(path)
	if err != nil {
		return leaseDocument{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return leaseDocument{}, errors.New("unsafe fencing lease")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxLeaseBytes+1))
	if err != nil || len(contents) > maxLeaseBytes {
		return leaseDocument{}, errors.New("invalid fencing lease")
	}
	var lease leaseDocument
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&lease) != nil {
		return leaseDocument{}, errors.New("invalid fencing lease")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return leaseDocument{}, errors.New("invalid fencing lease")
	}
	if lease.Version != 1 || lease.Epoch == 0 || lease.Signature == "" {
		return leaseDocument{}, errors.New("invalid fencing lease")
	}
	return lease, nil
}

func verifyLease(lease leaseDocument, publicKey ed25519.PublicKey) bool {
	signature, err := base64.StdEncoding.Strict().DecodeString(lease.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	payload, err := json.Marshal(signedLease{Version: lease.Version, Site: lease.Site, Epoch: lease.Epoch, NotBefore: lease.NotBefore, ExpiresAt: lease.ExpiresAt, RegistryDigest: lease.RegistryDigest})
	return err == nil && ed25519.Verify(publicKey, payload, signature)
}

// MaxLeaseDuration is the longest lease the daemon will honour, and therefore the longest
// one the issuer may sign. It is short on purpose: a site that dies holds its authority
// only until the lease lapses, and that interval is the floor on how quickly another site
// can be promoted without two of them signing at once.
//
// It is exported because SignGrant enforces the same bound. It was a literal here and
// nothing else knew about it, so the first thing the issuer did was sign an hour-long lease
// that the daemon rejected without saying why -- a tool producing documents its only
// consumer refuses. One definition, two users.
const MaxLeaseDuration = 10 * time.Minute

const genesisHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

func appendEpoch(path, previous string, epoch uint64) (string, error) {
	record := epochRecord{Epoch: epoch, PreviousHash: previous}
	record.Hash = epochHash(record)
	encoded, _ := json.Marshal(record)
	encoded = append(encoded, '\n')
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("open fencing journal: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("unsafe fencing journal")
	}
	if _, err := file.Write(encoded); err != nil {
		return "", errors.New("append fencing journal")
	}
	if err := file.Sync(); err != nil {
		return "", errors.New("sync fencing journal")
	}
	return record.Hash, nil
}

func verifyEpochJournal(path string) (uint64, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return 0, "", errors.New("unsafe fencing journal")
	}
	// THE HASH CANNOT SEE A FIELD THE STRUCT DOES NOT HAVE. epochHash marshals the PARSED
	// record, so a field added to the file by anyone who can edit it is dropped at Decode and
	// never reaches the chain — the record still verifies and the extra content rides along
	// invisibly in the artifact that decides which site may sign. readLease above already
	// refuses unknown fields for the same reason; this is the matching refusal for the gate's
	// own state. (#261)
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	previous, maximum := genesisHash, uint64(0)
	for {
		var record epochRecord
		if err := decoder.Decode(&record); errors.Is(err, io.EOF) {
			return maximum, previous, nil
		} else if err != nil || record.Epoch <= maximum || record.PreviousHash != previous || record.Hash != epochHash(record) {
			return 0, "", errors.New("fencing journal integrity failure")
		}
		maximum, previous = record.Epoch, record.Hash
	}
}

// VerifyEpochs is the exported form of the chain check Gate runs on open: it walks every epoch
// record, verifies the hash chain from genesis, and reports the highest epoch and the head
// hash. It exists for tooling that must verify a journal's integrity without holding — or
// being — a lease: the control-plane export verifies the journal before carrying it out, and
// the offline restore inspection verifies it again over the decrypted bytes (#49). Unlike
// Gate.Open, which treats a missing journal as the first grant, a missing file here is the
// os.ErrNotExist the caller asked about; deciding whether absence is legitimate belongs to the
// caller, because the export and the live gate answer that question differently.
func VerifyEpochs(path string) (uint64, string, error) {
	return verifyEpochJournal(path)
}

func epochHash(record epochRecord) string {
	record.Hash = ""
	encoded, _ := json.Marshal(record)
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:])
}
