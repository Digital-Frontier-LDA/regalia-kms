// Package askpass is the root volume's side of systemd's password-agent protocol (#70): the unlock
// client answers systemd-cryptsetup's request for the root volume's passphrase while the console agent
// shows the same request, the way Clevis does, and whichever answers first wins.
//
// The protocol, as systemd 257 implements it (src/shared/ask-password-api.c): a requester writes
// /run/systemd/ask-password/ask.<n>, an ini file whose [Ask] section names its reply Socket= (a datagram
// socket beside it, sck.<hex>), its PID=, its Id=, and NotAfter= (CLOCK_MONOTONIC microseconds, 0 or
// the maximum for none). An agent answers by sending one datagram to that socket: "+" and the password,
// with nothing stripped by the requester (so no newline), or "-" to decline. The requester takes an answer
// only from root (SCM_CREDENTIALS) and removes the file when it has one. systemd-cryptsetup names its
// request "cryptsetup:" and the volume's source device (crypttab's second field, as the generator resolves
// it): the root volume's is cryptsetup:/dev/disk/by-partlabel/regalia-root.
//
// Only that request is ever answered: matched by its Id= exactly, never the first request seen (another
// volume's, a PIN prompt), and only through a socket that is root's, in the protocol's directory.
package askpass

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// Dir is where requesters write their requests.
	Dir = "/run/systemd/ask-password"
	// RootID is the root volume's request: systemd-cryptsetup's id for crypttab's source device.
	RootID       = "cryptsetup:/dev/disk/by-partlabel/regalia-root"
	maxAskBytes  = 16 << 10
	maxPassBytes = 2048 // the requester reads at most LINE_MAX
)

// Request is one ask.* file, read.
type Request struct {
	Path     string // the ask.* file
	Socket   string
	PID      int
	ID       string
	NotAfter uint64 // CLOCK_MONOTONIC microseconds; 0 or math.MaxUint64: none
}

// Parse reads an [Ask] file. Keys it does not know are passed over; the ones it uses must be well formed.
func Parse(path string, raw []byte) (Request, error) {
	r := Request{Path: path}
	if len(raw) > maxAskBytes {
		return r, errors.New("the request is oversized")
	}
	section, seen := "", map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || section != "[Ask]" {
			continue
		}
		if seen[key] {
			return r, fmt.Errorf("%s is given twice", key)
		}
		seen[key] = true
		switch key {
		case "Socket":
			r.Socket = value
		case "PID":
			pid, err := strconv.Atoi(value)
			if err != nil || pid < 1 {
				return r, fmt.Errorf("PID=%q is not a process", value)
			}
			r.PID = pid
		case "Id":
			r.ID = value
		case "NotAfter":
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return r, fmt.Errorf("NotAfter=%q is not a time", value)
			}
			r.NotAfter = n
		}
	}
	if !seen["Socket"] {
		return r, errors.New("the request names no Socket=")
	}
	return r, nil
}

// Expired is whether the request's NotAfter has passed at monotonic time `now` (microseconds).
func (r Request) Expired(now uint64) bool {
	return r.NotAfter != 0 && r.NotAfter != math.MaxUint64 && now >= r.NotAfter
}

// FS is what Find and Answer need of the filesystem and the network: the real one in production, a fake in
// tests.
type FS struct {
	ReadDir  func(dir string) ([]string, error)
	ReadFile func(path string) ([]byte, error)
	Lstat    func(path string) (mode os.FileMode, uid uint32, err error)
	Send     func(socket string, datagram []byte) error
	Now      func() uint64 // CLOCK_MONOTONIC microseconds
}

// System is FS over the running system.
func System() FS {
	return FS{
		ReadDir: func(dir string) ([]string, error) {
			entries, err := os.ReadDir(dir)
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			return names, err
		},
		ReadFile: func(path string) ([]byte, error) {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			raw := make([]byte, maxAskBytes+1)
			n, err := f.Read(raw)
			if err != nil {
				return nil, err
			}
			return raw[:n], nil
		},
		Lstat: func(path string) (os.FileMode, uint32, error) {
			info, err := os.Lstat(path)
			if err != nil {
				return 0, 0, err
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return 0, 0, errors.New("no owner")
			}
			return info.Mode(), stat.Uid, nil
		},
		Send: func(socket string, datagram []byte) error {
			conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
			if err != nil {
				return err
			}
			defer conn.Close()
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Write(datagram)
			return err
		},
		Now: func() uint64 {
			var ts unix.Timespec // CLOCK_MONOTONIC: the clock NotAfter is in
			if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
				return math.MaxUint64 // unknown: every request with a deadline counts as expired, none is answered late
			}
			return uint64(ts.Sec)*1e6 + uint64(ts.Nsec)/1e3
		},
	}
}

// Find is the live request with id `id` in `dir`, if there is one: its file read and well formed, not
// expired, and its reply socket a socket of root's in `dir` itself. Requests for anything else are passed
// over. Two live requests with that id: the newest by name is not knowable, so neither is answered (the
// console still is).
func Find(fsys FS, dir, id string) (*Request, error) {
	names, err := fsys.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var found []Request
	for _, name := range names {
		if !strings.HasPrefix(name, "ask.") {
			continue
		}
		path := filepath.Join(dir, name)
		raw, err := fsys.ReadFile(path)
		if err != nil {
			continue // removed while being read: answered, or withdrawn
		}
		r, err := Parse(path, raw)
		if err != nil || r.ID != id || r.Expired(fsys.Now()) {
			continue
		}
		if filepath.Dir(r.Socket) != filepath.Clean(dir) || !strings.HasPrefix(filepath.Base(r.Socket), "sck.") {
			continue // a reply socket anywhere else is no requester's of this protocol
		}
		mode, uid, err := fsys.Lstat(r.Socket)
		if err != nil || mode&os.ModeSocket == 0 || uid != 0 {
			continue
		}
		found = append(found, r)
	}
	switch len(found) {
	case 0:
		return nil, nil
	case 1:
		return &found[0], nil
	}
	return nil, fmt.Errorf("%d requests for %s at once: none is answered", len(found), id)
}

// Pending is whether the request is still open: its file is there. When it is gone, it was answered (by the
// console, or by this agent) or withdrawn.
func Pending(fsys FS, r Request) bool {
	_, err := fsys.ReadFile(r.Path)
	return err == nil
}

// Answer sends the passphrase to the request: "+" and the passphrase, nothing after it.
func Answer(fsys FS, r Request, passphrase []byte) error {
	if len(passphrase) == 0 || len(passphrase) > maxPassBytes || bytes.ContainsAny(passphrase, "\x00\n") {
		return errors.New("not a passphrase this protocol carries")
	}
	datagram := make([]byte, 0, 1+len(passphrase))
	datagram = append(append(datagram, '+'), passphrase...)
	err := fsys.Send(r.Socket, datagram)
	clear(datagram)
	return err
}
