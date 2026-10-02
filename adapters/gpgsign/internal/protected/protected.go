// Package protected holds the file handling regalia-sign and regalia-approve share: reading files
// the process must be able to trust, and writing an output whole or not at all.
package protected

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Read reads a file this process must be able to trust: a regular file, not reached
// through a symbolic link, owned by root or by this user, writable by nobody else, and — when it is
// a secret — readable by nobody else. The rule is the SOPS sidecar's, for the same reason: whoever
// can rewrite the configuration or the pinned key chooses what gets signed with.
func Read(path string, maximum int64, secret bool) ([]byte, error) {
	if !filepath.IsAbs(path) || maximum < 1 {
		return nil, errors.New("invalid protected file")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open protected file")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open protected file")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return nil, errors.New("unsafe protected file owner")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || (secret && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("unsafe protected file")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) > maximum {
		Zero(contents)
		return nil, errors.New("read protected file")
	}
	return contents, nil
}

// Zero overwrites a secret that has been used.
func Zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// PublicKey reads exactly one PEM "PUBLIC KEY" from a protected file. what and field name it in the
// two error texts.
func PublicKey(path, what, field string) (crypto.PublicKey, error) {
	contents, err := Read(path, 16<<10, false)
	if err != nil {
		return nil, errors.New(what + " is unavailable")
	}
	block, rest := pem.Decode(contents)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New(field + " must hold exactly one PEM PUBLIC KEY")
	}
	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New(field + " does not hold a public key")
	}
	return public, nil
}

// InstallNew puts contents at destination, whole or not at all, and never over an existing file.
//
// The contents are written to a temporary file in the same directory and then LINKED to the final
// name. A reader of that name — an apt client, a web server in front of the repository — therefore
// sees either no file or the complete one, never the first half of an InRelease. And link(2) fails
// when the name exists, so "never replace" is decided by the filesystem in one step, not by a check
// followed by a create.
func InstallNew(destination, contents string) error {
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".regalia-new-*")
	if err != nil {
		return errors.New("create the output file")
	}
	defer os.Remove(temporary.Name())
	if _, err := io.WriteString(temporary, contents); err != nil {
		_ = temporary.Close()
		return errors.New("write the output file")
	}
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return errors.New("write the output file")
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return errors.New("write the output file")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("write the output file")
	}
	if err := os.Link(temporary.Name(), destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; remove it first", filepath.Base(destination))
		}
		return errors.New("create the output file")
	}
	return nil
}
