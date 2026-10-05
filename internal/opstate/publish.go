package opstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// AppliedFile is what this server has applied of the operational state, for the processes that stamp or
// judge a lease's state_revision (regalia-admission's lease request, regalia-sync's revision floor; #432):
//
//	{"boot_id": …, "boottime_ns": …, "cluster_id": "<16 hex>", "revision": …}
//
// written by temp+rename, 0644, only while the watch is live. A cache that is not live stops writing, so
// the file goes stale and its readers refuse it: nothing ever writes "stale". Readers judge its age on their
// own CLOCK_BOOTTIME against boottime_ns, in the same boot (boot_id).
const AppliedFile = "applied.json"

var bootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$`)

type appliedDocument struct {
	BootID     string `json:"boot_id"`
	BoottimeNs int64  `json:"boottime_ns"`
	ClusterID  string `json:"cluster_id"`
	Revision   int64  `json:"revision"`
}

// Publisher writes AppliedFile from the cache's confirmations, at most once per Every.
type Publisher struct {
	Dir    string
	BootID string
	Every  time.Duration

	mu      sync.Mutex
	written time.Duration
	last    int64
	any     bool
	Err     func(error) // hears a write that failed; the next confirmation tries again
}

// NewPublisher checks the directory's path, the boot ID and the interval.
func NewPublisher(dir, bootID string, every time.Duration) (*Publisher, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || !bootIDPattern.MatchString(bootID) || every <= 0 {
		return nil, errors.New("opstate: the applied-revision file needs an absolute clean directory, the kernel's boot ID and an interval")
	}
	return &Publisher{Dir: dir, BootID: bootID, Every: every}, nil
}

// Applied is a Cache's OnApplied: a new revision is written at once, the same one again only once Every has
// passed since the last write (a progress notification confirming a quiet store).
func (p *Publisher) Applied(s Snapshot) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !s.Live || (p.any && s.Revision == p.last && s.ConfirmedAt-p.written < p.Every) {
		return
	}
	if err := writeApplied(p.Dir, appliedDocument{BootID: p.BootID, BoottimeNs: int64(s.ConfirmedAt), ClusterID: fmt.Sprintf("%016x", s.ClusterID), Revision: s.Revision}); err != nil {
		if p.Err != nil {
			p.Err(err)
		}
		return
	}
	p.written, p.last, p.any = s.ConfirmedAt, s.Revision, true
}

func writeApplied(dir string, document appliedDocument) error {
	encoded, err := json.Marshal(document)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, "."+AppliedFile+".")
	if err != nil {
		return fmt.Errorf("the applied-revision file cannot be written: %w", err)
	}
	name := temporary.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if _, err := temporary.Write(append(encoded, '\n')); err != nil {
		temporary.Close()
		return fmt.Errorf("the applied-revision file cannot be written: %w", err)
	}
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, filepath.Join(dir, AppliedFile)); err != nil {
		return fmt.Errorf("the applied-revision file cannot be replaced: %w", err)
	}
	ok = true
	return nil
}
