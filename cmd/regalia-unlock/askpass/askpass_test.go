package askpass

import (
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeFS: requests as files, reply sockets by mode and owner, and what was sent where.
type fakeFS struct {
	files   map[string][]byte
	sockets map[string]struct {
		mode os.FileMode
		uid  uint32
	}
	sent map[string][]byte
	now  uint64
}

func newFake() *fakeFS {
	return &fakeFS{files: map[string][]byte{}, sent: map[string][]byte{}, now: 1_000_000_000,
		sockets: map[string]struct {
			mode os.FileMode
			uid  uint32
		}{}}
}

func (f *fakeFS) fs() FS {
	return FS{
		ReadDir: func(dir string) ([]string, error) {
			var names []string
			for path := range f.files {
				if filepath.Dir(path) == dir {
					names = append(names, filepath.Base(path))
				}
			}
			if names == nil && dir != Dir {
				return nil, os.ErrNotExist
			}
			return names, nil
		},
		ReadFile: func(path string) ([]byte, error) {
			if raw, ok := f.files[path]; ok {
				return raw, nil
			}
			return nil, os.ErrNotExist
		},
		Lstat: func(path string) (os.FileMode, uint32, error) {
			if s, ok := f.sockets[path]; ok {
				return s.mode, s.uid, nil
			}
			return 0, 0, os.ErrNotExist
		},
		Send: func(socket string, datagram []byte) error {
			f.sent[socket] = append([]byte(nil), datagram...)
			return nil
		},
		Now: func() uint64 { return f.now },
	}
}

// ask puts a request in Dir as systemd's ask_password_agent writes it, its socket root's.
func (f *fakeFS) ask(n int, id string, notAfter uint64) Request {
	socket := fmt.Sprintf("%s/sck.%x", Dir, n)
	path := fmt.Sprintf("%s/ask.%d", Dir, n)
	f.files[path] = []byte(fmt.Sprintf("[Ask]\nPID=%d\nSocket=%s\nAcceptCached=0\nEcho=0\nNotAfter=%d\nSilent=0\n"+
		"Message=Please enter passphrase for disk regalia-root (root):\nIcon=drive-harddisk\nId=%s\n", 400+n, socket, notAfter, id))
	f.sockets[socket] = struct {
		mode os.FileMode
		uid  uint32
	}{os.ModeSocket | 0o600, 0}
	return Request{Path: path, Socket: socket, PID: 400 + n, ID: id, NotAfter: notAfter}
}

func TestOnlyTheRootVolumesRequestIsFound(t *testing.T) {
	f := newFake()
	f.ask(1, "cryptsetup:/dev/disk/by-partlabel/regalia-data", 0)  // another volume
	f.ask(2, "systemd-ask-password:pin", 0)                        // not cryptsetup at all
	f.ask(3, "cryptsetup:/dev/disk/by-partlabel/regalia-root2", 0) // a prefix of the id is not the id
	if r, err := Find(f.fs(), Dir, RootID); r != nil || err != nil {
		t.Fatalf("found %v, %v among other volumes' requests", r, err)
	}
	want := f.ask(4, RootID, 0)
	r, err := Find(f.fs(), Dir, RootID)
	if err != nil || r == nil || *r != want {
		t.Fatalf("found %+v, %v; not %+v", r, err, want)
	}
}

func TestARequestIsNotAnsweredThroughASocketThatIsNotRequesters(t *testing.T) {
	cases := map[string]func(f *fakeFS, r Request){
		"a socket elsewhere": func(f *fakeFS, r Request) {
			f.files[r.Path] = []byte(strings.Replace(string(f.files[r.Path]), r.Socket, "/tmp/sck.1", 1))
			f.sockets["/tmp/sck.1"] = f.sockets[r.Socket]
		},
		"a socket in a subdirectory": func(f *fakeFS, r Request) {
			f.files[r.Path] = []byte(strings.Replace(string(f.files[r.Path]), r.Socket, Dir+"/x/sck.1", 1))
			f.sockets[Dir+"/x/sck.1"] = f.sockets[r.Socket]
		},
		"a socket not named sck.": func(f *fakeFS, r Request) {
			f.files[r.Path] = []byte(strings.Replace(string(f.files[r.Path]), r.Socket, Dir+"/other", 1))
			f.sockets[Dir+"/other"] = f.sockets[r.Socket]
		},
		"a socket of another user's": func(f *fakeFS, r Request) {
			s := f.sockets[r.Socket]
			s.uid = 1000
			f.sockets[r.Socket] = s
		},
		"a file, not a socket": func(f *fakeFS, r Request) {
			s := f.sockets[r.Socket]
			s.mode = 0o600
			f.sockets[r.Socket] = s
		},
		"no socket": func(f *fakeFS, r Request) { delete(f.sockets, r.Socket) },
		"expired":   func(f *fakeFS, r Request) { f.now = 2_000_000_000 },
		"no Socket=": func(f *fakeFS, r Request) {
			f.files[r.Path] = []byte(strings.Replace(string(f.files[r.Path]), "Socket=", "Sock=", 1))
		},
		"Id= given twice": func(f *fakeFS, r Request) { f.files[r.Path] = append(f.files[r.Path], []byte("Id="+RootID+"\n")...) },
		"Id= outside [Ask]": func(f *fakeFS, r Request) {
			f.files[r.Path] = []byte(strings.Replace(string(f.files[r.Path]), "Id=", "[Other]\nId=", 1))
		},
	}
	for name, change := range cases {
		f := newFake()
		r := f.ask(1, RootID, 1_500_000_000)
		change(f, r)
		if found, _ := Find(f.fs(), Dir, RootID); found != nil {
			t.Errorf("%s: found %+v", name, found)
		}
	}
}

func TestNoDeadlineAndADeadlineToCome(t *testing.T) {
	for _, notAfter := range []uint64{0, math.MaxUint64, 1_000_000_001} {
		f := newFake()
		f.ask(1, RootID, notAfter)
		if r, err := Find(f.fs(), Dir, RootID); r == nil || err != nil {
			t.Errorf("NotAfter=%d: not found (%v)", notAfter, err)
		}
	}
}

// A clock that cannot be read counts as the latest time there is: a request with a deadline is not answered,
// one without (systemd-cryptsetup's default: no timeout) still is.
func TestAnUnreadableClockLeavesOnlyRequestsWithoutADeadline(t *testing.T) {
	for notAfter, live := range map[uint64]bool{0: true, math.MaxUint64: true, 1_500_000_000: false} {
		f := newFake()
		f.now = math.MaxUint64
		f.ask(1, RootID, notAfter)
		if r, _ := Find(f.fs(), Dir, RootID); (r != nil) != live {
			t.Errorf("NotAfter=%d with no clock: found %v", notAfter, r)
		}
	}
}

func TestTwoRequestsForTheRootAreNeitherAnswered(t *testing.T) {
	f := newFake()
	f.ask(1, RootID, 0)
	f.ask(2, RootID, 0)
	if r, err := Find(f.fs(), Dir, RootID); r != nil || err == nil {
		t.Errorf("found %v, %v", r, err)
	}
}

func TestNoDirectoryIsNoRequest(t *testing.T) {
	f := newFake()
	if r, err := Find(f.fs(), "/run/nothing", RootID); r != nil || err != nil {
		t.Errorf("%v, %v", r, err)
	}
}

func TestAPendingRequestIsGoneOnceAnswered(t *testing.T) {
	f := newFake()
	r := f.ask(1, RootID, 0)
	if !Pending(f.fs(), r) {
		t.Fatal("a request just made is not pending")
	}
	delete(f.files, r.Path) // the console answered: systemd-cryptsetup removed the file
	if Pending(f.fs(), r) {
		t.Fatal("an answered request is still pending")
	}
}

func TestTheAnswerIsAPlusAndThePassphraseOnly(t *testing.T) {
	f := newFake()
	r := f.ask(1, RootID, 0)
	key := []byte("dGhlIHJvb3Qgdm9sdW1lJ3Mga2V5LCA0NCBieXRlcy4=") // 44 bytes of base64, as the client's key is
	if err := Answer(f.fs(), r, key); err != nil {
		t.Fatal(err)
	}
	if got := f.sent[r.Socket]; string(got) != "+"+string(key) {
		t.Fatalf("sent %q", got)
	}
	for _, bad := range [][]byte{nil, []byte("a\nb"), []byte("a\x00b"), make([]byte, maxPassBytes+1)} {
		if err := Answer(f.fs(), r, bad); err == nil {
			t.Errorf("%q answered", bad)
		}
	}
}

// A request file reached through a link is not read: nothing follows a link in the protocol's directory.
func TestARequestThroughALinkIsNotRead(t *testing.T) {
	dir, err := os.MkdirTemp("", "ask")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("[Ask]\nSocket=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "ask.1")); err != nil {
		t.Fatal(err)
	}
	if _, err := System().ReadFile(filepath.Join(dir, "ask.1")); err == nil {
		t.Error("a request read through a link")
	}
	if raw, err := System().ReadFile(target); err != nil || len(raw) == 0 {
		t.Errorf("a plain request is not read: %v", err)
	}
}

// Over a real datagram socket, as systemd-cryptsetup's requester binds one: the bytes it receives.
func TestTheAnswerOverARealSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "ask")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "sck.1")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	key := []byte("dGhlIHJvb3Qgdm9sdW1lJ3Mga2V5LCA0NCBieXRlcy4=")
	if err := Answer(System(), Request{Socket: path}, key); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := listener.Read(buf)
	if err != nil || string(buf[:n]) != "+"+string(key) {
		t.Fatalf("received %q, %v", buf[:n], err)
	}
	if errors.Is(Answer(System(), Request{Socket: filepath.Join(dir, "none")}, key), nil) {
		t.Error("an answer to no socket did not fail")
	}
}
