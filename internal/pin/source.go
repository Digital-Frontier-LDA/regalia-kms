// Package pin retrieves short-lived device credentials without admitting PIN
// values into daemon configuration, environment variables, or command lines.
package pin

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const maximumCredentialBytes = 64

// LockedFileSource reads root- or process-owned credentials such as files
// materialized by systemd LoadCredentialEncrypted under /run/credentials.
// Symlinks and group/world access are rejected at the opened descriptor.
type LockedFileSource struct{ paths map[string]string }

func NewLockedFileSource(paths map[string]string) (*LockedFileSource, error) {
	if len(paths) == 0 {
		return nil, errors.New("PIN credential mappings are required")
	}
	copyPaths := make(map[string]string, len(paths))
	for deviceID, path := range paths {
		if strings.TrimSpace(deviceID) == "" || !filepath.IsAbs(path) {
			return nil, errors.New("invalid PIN credential mapping")
		}
		copyPaths[deviceID] = filepath.Clean(path)
	}
	return &LockedFileSource{paths: copyPaths}, nil
}

func (source *LockedFileSource) PIN(ctx context.Context, deviceID string) ([]byte, error) {
	if source == nil || ctx.Err() != nil {
		return nil, errors.New("PIN credential unavailable")
	}
	path, exists := source.paths[deviceID]
	if !exists {
		return nil, errors.New("PIN credential unavailable")
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("PIN credential unavailable")
	}
	file := os.NewFile(uintptr(descriptor), "credential")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("PIN credential unavailable")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(descriptor, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return nil, errors.New("PIN credential unavailable")
	}
	value, err := io.ReadAll(io.LimitReader(file, maximumCredentialBytes+1))
	if err != nil || len(value) < 6 || len(value) > maximumCredentialBytes || containsUnsafe(value) || ctx.Err() != nil {
		zero(value)
		return nil, errors.New("PIN credential unavailable")
	}
	if err := unix.Mlock(value); err != nil {
		zero(value)
		return nil, errors.New("PIN credential unavailable")
	}
	return value, nil
}

// Release zeroes a credential before unlocking its pages. Providers call this
// through the optional PINSource release interface after every operation.
func (*LockedFileSource) Release(value []byte) error {
	if len(value) == 0 {
		return nil
	}
	zero(value)
	if err := unix.Munlock(value); err != nil {
		return errors.New("PIN credential release failed")
	}
	return nil
}

func containsUnsafe(value []byte) bool {
	for _, item := range value {
		if item < 0x21 || item > 0x7e {
			return true
		}
	}
	return false
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
