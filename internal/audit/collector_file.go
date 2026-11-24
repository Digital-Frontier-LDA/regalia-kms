package audit

import (
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const collectorOpenFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC

type collectorFileID struct {
	device, inode uint64
}

// collectorFileReader borrows its root and owns each descriptor opened under
// it. An alternate root and UID let component tests model trusted ownership
// in a private fixture. The production entry always uses "/" and UID 0.
type collectorFileReader struct {
	root  int
	owner uint32
	seen  map[collectorFileID]struct{}
}

func (r *collectorFileReader) trustedDir(fd int) bool {
	var stat unix.Stat_t
	return unix.Fstat(fd, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR &&
		r.trustedOwnerMode(stat)
}

func (r *collectorFileReader) trustedOwnerMode(stat unix.Stat_t) bool {
	return stat.Uid == r.owner && stat.Mode&0o022 == 0
}

// open takes an absolute path already validated by the descriptor or the
// fixed selector. It walks from the borrowed root without following links.
func (r *collectorFileReader) open(name string, max int, private bool) (*os.File, error) {
	if !r.trustedDir(r.root) {
		return nil, ErrCollectorRoleFile
	}
	parts := strings.Split(name[1:], "/")
	parent := r.root
	defer func() {
		if parent != r.root {
			unix.Close(parent)
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		child, err := unix.Openat(parent, part, collectorOpenFlags|unix.O_DIRECTORY, 0)
		if err != nil {
			return nil, ErrCollectorRoleFile
		}
		if parent != r.root {
			unix.Close(parent)
		}
		parent = child
		if !r.trustedDir(parent) {
			return nil, ErrCollectorRoleFile
		}
	}

	fd, err := unix.Openat(parent, parts[len(parts)-1], collectorOpenFlags, 0)
	if err != nil {
		return nil, ErrCollectorRoleFile
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		!r.trustedOwnerMode(stat) || (private && stat.Mode&0o007 != 0) ||
		stat.Nlink != 1 || stat.Size > int64(max) {
		unix.Close(fd)
		return nil, ErrCollectorRoleFile
	}
	id := collectorFileID{uint64(stat.Dev), uint64(stat.Ino)}
	if _, exists := r.seen[id]; exists {
		unix.Close(fd)
		return nil, ErrCollectorRoleFile
	}
	r.seen[id] = struct{}{}
	return os.NewFile(uintptr(fd), "collector material"), nil
}

func (r *collectorFileReader) read(name string, max int, private bool) ([]byte, error) {
	file, err := r.open(name, max, private)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readOpenedCollectorFile(file, max)
}

// readOpenedCollectorFile never resolves a path again and also bounds growth
// after fstat. The caller owns the checked descriptor.
func readOpenedCollectorFile(file *os.File, max int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if err != nil || len(data) > max {
		clear(data)
		return nil, ErrCollectorRoleFile
	}
	return data, nil
}
