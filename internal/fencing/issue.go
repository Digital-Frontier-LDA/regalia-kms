package fencing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// LEASES ARE ISSUED HERE BECAUSE THEY ARE VERIFIED HERE.
//
// verifyLease checks the signature over json.Marshal(signedLease{...}). Any issuer that rebuilt that
// document independently would be a second statement of what a lease is, and the two would
// agree only until someone reordered a field -- at which point every lease this repository
// produced would be rejected by the daemon that asked for it, with nothing to say why. That
// pattern has produced five defects in this repository in a week, so the issuer and the
// verifier share one struct and one marshalling call rather than a written agreement.

// maxIssuerStateBytes bounds the record. It holds one small object; anything larger is a
// corrupted or hostile file and reading it into memory before parsing is not required.
const maxIssuerStateBytes = 4 << 10

// Grant is an operator's decision to make one site active for a window.
type Grant struct {
	Site           string
	Epoch          uint64
	NotBefore      time.Time
	ExpiresAt      time.Time
	RegistryDigest string
}

// PreviousGrant is the last lease the authority issued, as recorded by the issuer. The zero
// value means none has ever been issued.
type PreviousGrant struct {
	Site      string    `json:"site"`
	Epoch     uint64    `json:"epoch"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SignGrant produces the lease document a daemon will accept, or refuses to.
//
// TWO REFUSALS CARRY THE WHOLE SAFETY PROPERTY, and neither is enforceable by the daemon.
//
// The epoch must strictly increase. A repeated or lower epoch lets a superseded lease be
// replayed at a site that still has the file on disk.
//
// A lease for a DIFFERENT site may not begin before the previous lease expires. This is the
// one the daemon cannot check for itself, and it is the split-brain case: each daemon reads
// only its own lease file, so if site A holds a valid lease until 12:30 and the authority
// grants site B a lease starting at 12:00, both sites believe they are active for thirty
// minutes and ADR-0001 section 8 is violated by two documents that are each individually
// valid. Handover is measured by waiting the old lease out. Renewing the SAME site may
// overlap, because there is only ever one signer either way.
func SignGrant(key ed25519.PrivateKey, grant Grant, previous PreviousGrant) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("fencing: signing key must be an ed25519 private key")
	}
	if grant.Site == "" || grant.RegistryDigest == "" || grant.Epoch == 0 {
		return nil, errors.New("fencing: a grant needs a site, a registry digest and a non-zero epoch")
	}
	if !grant.ExpiresAt.After(grant.NotBefore) {
		return nil, errors.New("fencing: a grant must expire after it begins")
	}
	if grant.ExpiresAt.Sub(grant.NotBefore) > MaxLeaseDuration {
		// The daemon refuses anything longer, so signing it would produce a document the
		// only consumer rejects, with nothing anywhere saying why.
		return nil, fmt.Errorf("fencing: a lease may not run longer than %s; %s was requested",
			MaxLeaseDuration, grant.ExpiresAt.Sub(grant.NotBefore))
	}
	if grant.Epoch <= previous.Epoch {
		return nil, fmt.Errorf("fencing: epoch %d does not exceed the last issued epoch %d, so a superseded lease could be replayed",
			grant.Epoch, previous.Epoch)
	}
	// The instants in this message are printed at nanosecond precision because an operator
	// copies the previous expiry straight into -not-before to schedule the handover. Printed
	// at second precision a sub-second expiry is truncated, the value pasted back is EARLIER
	// than the real boundary, and this same check refuses it -- correctly, and with a message
	// quoting the timestamp the operator just used. RFC3339Nano omits the fraction when it is
	// zero, so the common case reads exactly as before.
	if previous.Site != "" && previous.Site != grant.Site && grant.NotBefore.Before(previous.ExpiresAt) {
		return nil, fmt.Errorf("fencing: %s would be active from %s while %s holds the lease until %s, so both sites would sign; handover waits the previous lease out",
			grant.Site, grant.NotBefore.UTC().Format(time.RFC3339Nano), previous.Site, previous.ExpiresAt.UTC().Format(time.RFC3339Nano))
	}

	payload := signedLease{
		Version: 1, Site: grant.Site, Epoch: grant.Epoch,
		NotBefore:      grant.NotBefore.UTC().Format(time.RFC3339Nano),
		ExpiresAt:      grant.ExpiresAt.UTC().Format(time.RFC3339Nano),
		RegistryDigest: grant.RegistryDigest,
	}
	signable, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	document := leaseDocument{
		Version: payload.Version, Site: payload.Site, Epoch: payload.Epoch,
		NotBefore: payload.NotBefore, ExpiresAt: payload.ExpiresAt,
		RegistryDigest: payload.RegistryDigest,
		Signature:      base64.StdEncoding.EncodeToString(ed25519.Sign(key, signable)),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	// The daemon refuses a lease file over maxLeaseBytes, so signing a larger one produces a
	// valid document its only consumer will not read. That is the third bound on this branch
	// where the issuer and the daemon had to be told the same number -- after the lease
	// duration and the file permissions -- and each time the tool would have emitted
	// something correct and unusable.
	if len(encoded) > maxLeaseBytes {
		return nil, fmt.Errorf("fencing: the lease is %d bytes and the daemon refuses anything over %d; "+
			"the site name or registry digest is implausibly long", len(encoded), maxLeaseBytes)
	}
	return encoded, nil
}

// LoadIssuerState reads the authority's record of the last lease it issued. A missing file
// is the first grant, not an error; anything else is refused rather than assumed to be the
// first, because losing the record is exactly how a repeated epoch gets signed.
//
// THE DIRECTORY IS CHECKED AS WELL AS THE FILE, BECAUSE THE FILE'S MODE IS NOT THE WHOLE
// GUARANTEE.
//
// Both monotonicity and non-overlap are decided entirely by this record, so a group- or
// world-writable one lets anyone with local access roll the epoch back. That check alone
// makes a WRITABLE record unusable and does nothing about a REPLACEABLE one: in a writable
// directory an attacker unlinks the record and writes their own, 0600, owned by them, valid
// JSON. IsRegular passes, the permission check passes, the parse passes, and the authority
// issues epoch 2 believing the last one was 1.
//
// This comment used to claim the file check prevented exactly that. It was right about the
// consequence and wrong about the remedy, which is worse than saying nothing: the next
// reader believes the property holds. Both are checked now, so the sentence is true.
func LoadIssuerState(path string) (PreviousGrant, error) {
	// The descriptor is stat-ed and read, not the path. Lstat-then-ReadFile checks one file
	// and reads whatever the name points at a moment later, and this record decides both
	// safety properties -- so a swap in that window buys an attacker the epoch rollback the
	// permission check exists to prevent. readLease already opens once and stats the handle;
	// this is the same shape and it did not follow it.
	if err := requireUnwritableDirectory(filepath.Dir(path)); err != nil {
		return PreviousGrant{}, err
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return PreviousGrant{}, nil
	}
	if err != nil {
		return PreviousGrant{}, fmt.Errorf("open issuer state: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return PreviousGrant{}, fmt.Errorf("stat issuer state: %w", err)
	}
	if !info.Mode().IsRegular() {
		return PreviousGrant{}, errors.New("issuer state must be a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return PreviousGrant{}, fmt.Errorf("issuer state is group- or world-writable (%04o); "+
			"anyone who can edit it can roll the epoch back or hide a live lease", info.Mode().Perm())
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxIssuerStateBytes+1))
	if err != nil || len(contents) > maxIssuerStateBytes {
		return PreviousGrant{}, errors.New("issuer state is unreadable or implausibly large")
	}
	var previous PreviousGrant
	if err := json.Unmarshal(contents, &previous); err != nil {
		return PreviousGrant{}, errors.New("issuer state is unreadable; refusing to issue rather than repeat an epoch")
	}
	// A RECORD THAT PARSES BUT SAYS NOTHING IS NOT "NO PREVIOUS GRANT".
	//
	// {} unmarshals happily into the zero value, and the zero value is exactly what a first
	// run looks like: epoch 0, no site, no expiry. Every check in SignGrant then passes
	// trivially against it, so a record truncated to a single brace -- by a full disk, an
	// interrupted write on a filesystem this code does not control, or someone editing it --
	// resets the authority's memory instead of stopping it. The refusal for an unreadable
	// record exists for that reason and this closed the other half of the same door.
	if previous.Site == "" || previous.Epoch == 0 || previous.ExpiresAt.IsZero() {
		return PreviousGrant{}, errors.New("issuer state exists but does not record a complete grant " +
			"(site, epoch and expiry); refusing to issue rather than treat a damaged record as a first run")
	}
	return previous, nil
}

// SaveIssuerState records a grant before the lease is handed out.
func SaveIssuerState(path string, grant Grant) error {
	encoded, err := json.Marshal(PreviousGrant{Site: grant.Site, Epoch: grant.Epoch, ExpiresAt: grant.ExpiresAt.UTC()})
	if err != nil {
		return err
	}
	// Writing a record the next run will refuse as "implausibly large" wedges the authority:
	// it cannot read its own memory and therefore cannot issue anything again. Refuse here,
	// where the operator still has a working tool and a fixable input.
	if len(encoded)+1 > maxIssuerStateBytes {
		return fmt.Errorf("fencing: the issuer record would be %d bytes and this tool refuses to read "+
			"more than %d, so writing it would wedge the authority", len(encoded)+1, maxIssuerStateBytes)
	}
	return writeAtomically(path, append(encoded, '\n'), 0o600)
}

// LockIssuer takes the authority's exclusive lock, and returns the function that releases it.
//
// WITHOUT THIS EVERY CHECK ABOVE IS ADVISORY. Two regalia-fence invocations read the same
// previous grant, both pass the monotonicity and overlap checks against it, and both sign.
// The result is exactly what the tool exists to prevent -- two valid leases, possibly for
// two sites, possibly at the same epoch -- produced by an authority that verified each one
// against a record neither had updated yet. Read-check-write on the state of a safety
// property is a race unless it is serialised.
//
// O_EXCL on a sibling file rather than flock: it needs no new dependency, and it fails
// closed. A crashed run leaves the lock behind and the next invocation refuses until a
// human removes it, which is the right bias for the component that decides who may sign.
func LockIssuer(statePath string) (func(), error) {
	// A lock in a directory others can write to is not a lock: they can hold it, or remove
	// it while it is held. Checked here as well as in LoadIssuerState because the lock is
	// taken first and its guarantee is what the rest of the run rests on.
	if err := requireUnwritableDirectory(filepath.Dir(statePath)); err != nil {
		return nil, err
	}
	lockPath := statePath + ".lock"
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("another regalia-fence holds %s, or a previous run left it behind; "+
			"two authorities issuing at once can grant overlapping leases, so this refuses rather "+
			"than races: %w", lockPath, err)
	}
	_ = file.Close()
	return func() { _ = os.Remove(lockPath) }, nil
}

// writeAtomically creates the file with the mode given rather than inheriting whatever an
// existing file already had.
//
// os.WriteFile does NOT apply its mode to a file that already exists, so writing a lease
// over a group-writable one leaves it group-writable and the daemon then refuses it as an
// unsafe fencing lease -- a tool producing documents its only consumer rejects, for the
// second time on this branch. The rename also makes the lease appear whole: a daemon polls
// this path, and a partial write is a lease it reads and rejects for a reason that will
// have disappeared by the time anyone looks.
func writeAtomically(path string, contents []byte, mode os.FileMode) error {
	// os.CreateTemp, not path+".tmp". A predictable temporary opened with O_TRUNC is a
	// symlink target: anyone who can create that name points it at a file of their choosing
	// and this process truncates and rewrites it with the authority's privileges. CreateTemp
	// uses O_EXCL and an unpredictable suffix, so a pre-created name cannot be hit and an
	// existing one cannot be followed. Same directory, so the rename below stays atomic.
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("create a temporary beside %s: %w", path, err)
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return fmt.Errorf("write %s: %w", temporary, err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync %s: %w", temporary, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", temporary, err)
	}
	// CreateTemp always makes the file 0600, so the mode is applied explicitly rather than
	// inherited from the open.
	if err := os.Chmod(temporary, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", temporary, err)
	}
	return os.Rename(temporary, path)
}

// WriteLease publishes a signed lease where the daemon will read it, atomically and with
// permissions the daemon will accept.
func WriteLease(path string, lease []byte) error {
	return writeAtomically(path, append(lease, '\n'), 0o644)
}

// requireUnwritableDirectory refuses a directory others may write to.
//
// Write permission on a directory is permission to unlink and recreate everything in it,
// whatever the modes of those files are. For this tool that is enough to defeat both safety
// properties -- replace the record, and the authority forgets what it issued -- and it also
// makes the O_EXCL lock forgeable, since the lock is a file in the same directory and
// anyone who can create it can hold it, or remove it while it is held.
func requireUnwritableDirectory(directory string) error {
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("stat the issuer directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", directory)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("the issuer directory %s is group- or world-writable (%04o); anyone who "+
			"can create files there can replace the record with one of their own and roll the epoch "+
			"back, whatever permissions the record itself carries", directory, info.Mode().Perm())
	}
	return nil
}
