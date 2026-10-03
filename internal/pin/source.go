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
// Symlinks and group/world access are rejected at the opened descriptor;
// the one ACL accepted is systemd's own, read for this process's user (ownerOnly).
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
	if err := unix.Fstat(descriptor, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || !ownerOnly(descriptor, uint32(stat.Mode)) || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
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

// POSIX ACL entry tags, as the kernel stores them in system.posix_acl_access (version 2: a 4-byte
// header, then 8-byte entries of tag, permissions and id, little-endian).
const (
	aclVersion  = 2
	aclUserObj  = 0x01
	aclUser     = 0x02
	aclGroupObj = 0x04
	aclGroup    = 0x08
	aclMask     = 0x10
	aclOther    = 0x20
	aclRead     = 0x4
)

// ownerOnly reports whether nobody but the file's owner, and this process's own user, can use the
// credential.
//
// Without an ACL that is the mode: no group and no other bit. With one, the mode's group bits are
// the ACL MASK, not the group's permission, so the mode alone cannot answer. systemd delivers a
// credential to a service that runs as its own user exactly that way: owned by root, mode 0400,
// plus an ACL entry granting that user read, which stat reports as 0440 (measured, systemd 255,
// LoadCredential= with User=). So the ACL itself is read, and must grant nothing to the owning
// group, to any named group, to others, or to any named user but this process's, and to that user
// read only. An ACL that cannot be read or understood is refused.
func ownerOnly(descriptor int, mode uint32) bool {
	if mode&0o007 != 0 {
		return false
	}
	buffer := make([]byte, 4+8*32)
	size, err := unix.Fgetxattr(descriptor, "system.posix_acl_access", buffer)
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
		return mode&0o070 == 0
	}
	if err != nil || size < 4 || (size-4)%8 != 0 || le32(buffer[0:4]) != aclVersion {
		return false
	}
	self := uint32(os.Geteuid())
	for entry := buffer[4:size]; len(entry) > 0; entry = entry[8:] {
		tag, permissions, id := uint16(entry[0])|uint16(entry[1])<<8, uint16(entry[2])|uint16(entry[3])<<8, le32(entry[4:8])
		switch tag {
		case aclUserObj, aclMask:
		case aclUser:
			if permissions != 0 && (id != self || permissions != aclRead) {
				return false
			}
		case aclGroupObj, aclGroup, aclOther:
			if permissions != 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func le32(value []byte) uint32 {
	return uint32(value[0]) | uint32(value[1])<<8 | uint32(value[2])<<16 | uint32(value[3])<<24
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
