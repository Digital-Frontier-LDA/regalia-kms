// RevocationList answers "is this serial revoked?" with a stat+ModTime cache.
//
// The list is backed by a flat text file of decimal serial numbers, one per line.
// A nil *RevocationList, or a list whose path is empty, means "revocation is not
// configured" — Check returns (false, nil) without touching the filesystem and the
// caller treats revocation as a no-op. This preserves the pre-revocation posture
// for hosts that have not opted in.
//
// The contract is:
//
//   - path empty / list nil                 -> (false, nil)   no-op
//   - file unreadable                       -> (false, err)   caller MUST reject
//   - file unparseable                      -> (false, err)   caller MUST reject
//   - file is not a regular file            -> (false, err)   caller MUST reject
//   - file is group- or world-writable      -> (false, err)   caller MUST reject
//   - file is a symlink                     -> (false, err)   caller MUST reject
//   - serial present in list                -> (true, nil)
//   - serial absent from list               -> (false, nil)
//
// "MUST reject" is the point: a revocation list that is currently empty because
// the file is unreadable is not "nobody is revoked" — it is "we cannot tell
// whether this serial is revoked", and the safe answer is to refuse. An
// unreadable list treated as empty is the fail-open version of this bug. The
// file-custody refusals matter for the same reason: a non-root local user who
// can write the revocation file can either revoke every certificate (DoS) or —
// more dangerously — remove a serial that was revoked precisely because the
// certificate was compromised. Both bypasses are invisible to the daemon, so
// they must be impossible at the I/O layer rather than trusted by policy.
//
// Caching is per-descriptor. Every Check opens the file with O_NOFOLLOW, runs
// the regular-file and permission checks on the *opened descriptor* (not on the
// path), and only then compares ModTime against the cached parse. The
// descriptor we validate is the descriptor we read from, so a TOCTOU swap
// between stat and open cannot smuggle in a different file or a looser mode
// than the one we accepted. The cache is safe to trust because the mode check
// runs every time, regardless of whether the file changed — a file which
// becomes group/world-writable later is still rejected on the next Check.
package auth

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// RevocationList is concurrency-safe.
type RevocationList struct {
	path string
	mu   sync.Mutex
}

// NewRevocationList creates a list backed by path. An empty path returns a
// no-op list (no filesystem access).
//
// A non-empty path is opened here and validated as a regular,
// non-group/world-writable file on the descriptor, so a misconfigured path
// fails loud at startup rather than on the first request — the daemon should
// never get past `run()` with a revocation file that is unsafe to read.
//
// The parse done for that validation is DISCARDED, deliberately. Check reads
// and parses the file on every call and keeps nothing, because a cached parse
// cannot be invalidated reliably: two writes inside one coarse mtime tick are
// indistinguishable, and believing the older of two identical parses is how a
// revoked serial went unseen. Construction proves the file is readable; it
// does not answer any question about its contents later.
func NewRevocationList(path string) (*RevocationList, error) {
	list := &RevocationList{path: path}
	if path == "" {
		return list, nil
	}
	if _, _, err := list.load(); err != nil {
		return nil, fmt.Errorf("revocation list %q: %w", path, err)
	}
	return list, nil
}

// Check returns (revoked, err). See the package comment for the full contract.
// The error from a configured-but-unreadable list is intentionally surfaced so
// the caller can refuse the request rather than admit because the list is
// "currently empty".
//
// Every call re-opens the file with O_NOFOLLOW, re-validates it on the opened
// descriptor, and uses that read — there is no cache. A permission change, a
// replaced file, or an edit within a single mtime tick all take effect on the
// very next request, because nothing older is consulted.
func (r *RevocationList) Check(serial string) (bool, error) {
	if r == nil || r.path == "" {
		return false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, serials, err := r.load()
	if err != nil {
		return false, fmt.Errorf("revocation list %q: %w", r.path, err)
	}
	// USE THE PARSE WE JUST DID.
	//
	// This used to compare the descriptor's ModTime against a cached one and, on a match, return
	// the CACHED map while discarding the map load() had already built. That discarded nothing but
	// correctness: load() parses unconditionally, so the cache saved no work, and two writes inside
	// a single coarse mtime tick were indistinguishable — a serial added in the same tick as a
	// previous write would never be seen.
	//
	// On a revocation list that is a fail-open window, and it is the narrow, racy kind that shows up
	// once and is never reproduced. The list is small and the file is already open and read by this
	// point, so there was never anything to trade away.
	_, revoked := serials[serial]
	return revoked, nil
}

// load opens the revocation file with O_NOFOLLOW, validates it on the opened
// descriptor, and (on a hit) returns the parsed serials with the descriptor's
// ModTime. The cache decision is made by the caller after seeing modTime.
//
// All three failure modes — not-a-regular-file, group/world-writable, and
// symlink — are observed via the descriptor we then read from. Checking the
// path and then opening the file is the TOCTOU window this design avoids.
func (r *RevocationList) load() (time.Time, map[string]struct{}, error) {
	descriptor, err := unix.Open(r.path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return time.Time{}, nil, fmt.Errorf("open: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), "revocation-list")
	if file == nil {
		_ = unix.Close(descriptor)
		return time.Time{}, nil, errors.New("open: descriptor wrap failed")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil {
		return time.Time{}, nil, fmt.Errorf("fstat: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return time.Time{}, nil, errors.New("must be a regular file")
	}
	if stat.Mode&0o022 != 0 {
		return time.Time{}, nil, errors.New("must not be group- or world-writable")
	}
	modTime := time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec)
	serials, err := parseRevocationList(file)
	if err != nil {
		return time.Time{}, nil, err
	}
	return modTime, serials, nil
}

// parseRevocationList reads newline-separated decimal serial numbers, ignoring
// blank lines and lines starting with '#'. A line that is neither blank nor a
// comment and cannot be parsed as a non-negative integer is a fatal error:
// dropping the line would silently narrow the operator's intent.
func parseRevocationList(reader io.Reader) (map[string]struct{}, error) {
	serials := make(map[string]struct{})
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// big.Int rather than strconv.Atoi: x509 serial numbers can exceed
		// int64 range, and big.Int.Text(10) is what Authenticator looks up.
		value, ok := new(big.Int).SetString(line, 10)
		if !ok || value.Sign() < 0 {
			return nil, fmt.Errorf("line %d: %q is not a non-negative integer serial", lineNumber, line)
		}
		serials[value.String()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return serials, nil
}
