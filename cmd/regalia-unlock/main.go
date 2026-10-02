// Command regalia-unlock gives systemd-cryptsetup the key of a KMS host's root disk before root
// exists: a key that needs the host's TPM and one peer, never the TPM alone (regalia-kms#67; the gap
// of #135).
//
// It is the pre-root half of deploy/baremetal/unlock.py, which defines the exchange and holds the
// peer's side. This program holds no decision about membership: it attests this boot to a peer, and
// the peer decides, under its own current manifest, whether this node on this boot image may be
// unlocked. What it checks itself is only that the answer is the one it asked for, from the peer it
// asked: the peer's TPM signature, this boot's session, this boot's key.
//
// It runs no other program and writes no secret anywhere. Three things reach it from systemd:
//
//   - the local half of the credential, unsealed by systemd with the TPM and passed as the unit's
//     credential regalia-unlock-local ($CREDENTIALS_DIRECTORY);
//   - the listening socket systemd-cryptsetup reads the volume key from (crypttab's key file is that
//     socket's path; the unit is socket-activated, LISTEN_FDS);
//   - the boot configuration (-config).
//
// It reads the LUKS2 header for the peer paths, asks the peers in turn, derives the credential, and
// writes it to the one connection waiting on the socket. Its code is this directory, the standard
// library, and go-tpm (github.com/google/go-tpm), the standard Go library for talking to a TPM: the
// transport, TPM2_Quote, and the parsing of TPM structures are go-tpm's, not written here.
//
// It runs for as long as the initrd lasts, with ONE boot session: a peer accepts one session per boot
// of this TPM. Each connection on the socket gets the key or nothing; systemd stops the program before
// the root filesystem takes over, and the local half and the session's private key end with it.
//
// What it leaves for the running system, under /run/regalia (which survives switch-root), none of it
// secret: boot-session and boot-session.pub, the ID and the public key of that session, written before
// its first quote is taken, and once a key was given key-given-through, the peer and keyslot. A client
// started again in the same boot (after a crash) finds that record and asks no peer: its session would
// be a second one. The runtime leases of this boot must be asked for
// under the same session (deploy/baremetal/lease.py); they need its public key, never its private one.
//
// When no peer helps, the connection is closed with nothing, each peer's reason is on standard error,
// and the console falls back to the recovery key (#77). With -once (tests) it answers one connection
// and exits: 0 when the key was given, 1 when not.
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ioTimeout     = 10 * time.Second
	handoffWait   = 60 * time.Second
	listenFDStart = 3 // sd_listen_fds(3): the first passed descriptor
)

func main() {
	err := run(os.Args[1:], os.Stdout, os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "regalia-unlock: "+err.Error())
		os.Exit(1)
	}
}

type options struct {
	tpm        string
	sessionDir string
	once       bool
	rounds     int
	wait       time.Duration
}

func run(arguments []string, out, diagnostics io.Writer) error {
	// The socket first, before anything that can fail. A start that cannot serve still answers whoever
	// waits on it, with nothing: systemd-cryptsetup then asks at the console, and systemd does not start
	// this program again for a connection left waiting. That holds for a bad flag or a bad configuration too.
	listener, listenerError := activatedListener()
	serving := false
	if listener != nil {
		defer listener.Close()
		defer func() {
			if !serving {
				giveNothing(listener)
			}
		}()
	}
	flags := flag.NewFlagSet("regalia-unlock", flag.ContinueOnError)
	flags.SetOutput(out)
	configPath := flags.String("config", "/etc/regalia/unlock.json", "the boot configuration (deploy/baremetal/unlock.py, boot_config)")
	var o options
	flags.StringVar(&o.tpm, "tpm", "/dev/tpmrm0", "the TPM: the resource-manager device, or unix:PATH for a software TPM in tests")
	flags.StringVar(&o.sessionDir, "session-dir", "/run/regalia", "where the boot session's ID and public key are left for the running system")
	flags.BoolVar(&o.once, "once", false, "answer one connection and exit (tests); without it the program serves until it is stopped")
	flags.IntVar(&o.rounds, "rounds", 5, "how many times to go round the peers before giving up")
	flags.DurationVar(&o.wait, "wait", 5*time.Second, "pause between rounds")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || o.rounds < 1 || o.rounds > 100 || o.wait < 0 {
		return errors.New("usage: regalia-unlock [-config FILE] [-tpm DEVICE] [-session-dir DIR] [-once] [-rounds N] [-wait DURATION]")
	}
	if listenerError != nil {
		return listenerError
	}
	// Everything that can be refused without a peer is refused first: nothing is asked of a peer, and no
	// boot session is spent, by a start that could not have used the answer.
	config, err := loadBootConfig(*configPath)
	if err != nil {
		return err
	}
	local, err := localContribution(os.Getenv("CREDENTIALS_DIRECTORY"))
	if err != nil {
		return err
	}
	defer wipe(local) // on every path that does not reach the serving loop; from there, unlocker.forget
	disk, err := os.Open(config.Device)
	if err != nil {
		return errors.New("cannot open " + config.Device)
	}
	paths, skipped, err := pathTokens(disk, config.NodeID)
	disk.Close()
	if err != nil {
		return fmt.Errorf("%s: %w", config.Device, err)
	}
	for _, reason := range skipped {
		fmt.Fprintln(diagnostics, "regalia-unlock: "+reason)
	}
	// Opened for each quote and closed again: the TPM has other users, and a software TPM serves one
	// connection at a time. A TPM that cannot be opened at all is reported before anything is asked.
	device, err := openTPM(o.tpm)
	if err != nil {
		return errors.New("cannot open the TPM " + o.tpm)
	}
	device.Close()
	quote := func(qualifying []byte) ([]byte, []byte, error) {
		device, err := openTPM(o.tpm)
		if err != nil {
			return nil, nil, errors.New("cannot open the TPM " + o.tpm)
		}
		defer device.Close()
		return tpmQuote(device, qualifying, config.PCRs)
	}
	boot, err := newSession(config.NodeID)
	if err != nil {
		return errors.New("cannot make this boot's session key")
	}
	serving = true
	u := &unlocker{config: config, o: o, paths: paths, local: local, boot: boot, dial: tcpTransport, quote: quote, sleep: time.Sleep,
		out: out, diagnostics: diagnostics}
	// systemd stops the unit with SIGTERM before the root filesystem takes over. What this process held
	// is zeroed first, and it does not wait for an attempt in progress: the boot is not held up.
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(stopped)
	go func() {
		<-stopped
		u.forget()
		os.Exit(0)
	}()
	defer u.forget()
	return u.serve(listener)
}

// unlocker is what ONE BOOT holds, in one process, for as long as the initrd lasts: the local half, the
// one boot session with its key, and, once a peer has answered, the volume's key. A peer accepts one
// session per boot of this TPM and records it when it verifies a quote, so every request of this boot, to
// every peer, however many times systemd-cryptsetup asks, is made under the same session: a retry after
// a lost reply is then answered, and the running system's leases can name the session every peer saw.
type unlocker struct {
	config      *bootConfig
	o           options
	paths       map[string][]pathToken
	local       []byte
	boot        *session
	dial        func(string) transport
	quote       quoter
	sleep       func(time.Duration)
	out         io.Writer
	diagnostics io.Writer

	presented bool   // a quote of this session was taken, to be sent to a peer
	earlier   bool   // ANOTHER session of this boot is on record: this process asks no peer
	key       []byte // the volume's key, from this boot's one response; given to each later connection
	peer      string
	slot      string
}

const earlierSession = "the disk stays locked: an earlier unlock client of this boot presented another session to the peers, " +
	"and a peer accepts one session per boot, so no peer is asked: reboot, or use the recovery key"

// serve answers each connection on the key socket: with the key, or with nothing. It ends when it is
// stopped (systemd stops the unit before the root filesystem takes over), or after one connection with -once.
func (u *unlocker) serve(listener *net.UnixListener) error {
	// boot-session is written before a session's first quote, and /run is empty at every boot: so if it
	// is there now, a client before this one, in this boot, presented a session whose key is gone with it.
	// A peer may hold that session and would refuse this one; another peer might accept this one, and the
	// record could then be right for one of them only. One session per boot is kept by asking nobody.
	if u.o.sessionDir != "" {
		if _, err := os.Lstat(filepath.Join(u.o.sessionDir, "boot-session")); err == nil {
			u.earlier = true
			fmt.Fprintln(u.diagnostics, "regalia-unlock: "+earlierSession)
		}
	}
	for {
		if u.o.once {
			_ = listener.SetDeadline(time.Now().Add(handoffWait))
		}
		connection, err := listener.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil // the listener was closed
			}
			if u.o.once {
				return errors.New("nobody asked for the key on the socket")
			}
			// Anything else (no descriptor, no memory) passes: leaving would start another process, and
			// with it another session, on the next connection.
			fmt.Fprintln(u.diagnostics, "regalia-unlock: the key socket could not accept a connection, trying again")
			u.sleep(time.Second)
			continue
		}
		if !sameUser(connection) {
			connection.Close() // not root's: answered with nothing, and it does not take the place of the next one
			continue
		}
		err = u.answer(connection)
		connection.Close()
		if u.o.once {
			return err
		}
		if err != nil {
			fmt.Fprintln(u.diagnostics, "regalia-unlock: "+err.Error())
		}
	}
}

// answer makes one attempt for one connection and writes the key to it. On any error nothing is
// written: the caller closes the connection, and systemd-cryptsetup asks at the console.
func (u *unlocker) answer(connection *net.UnixConn) error {
	if u.earlier {
		return errors.New(earlierSession)
	}
	// An asker that has gone (systemd-cryptsetup stopped or timed out while it waited in the queue) is not
	// worked for: the rounds can take minutes, and the next asker is waiting behind it.
	if gone(connection) {
		return errors.New("whoever asked for the key left before it was their turn")
	}
	if u.key == nil {
		key, peer, slot, err := deriveKey(u.config, u.o, u.paths, u.local, u.boot, u.dial, u.presenting, u.sleep, u.diagnostics)
		if err != nil {
			return err
		}
		// This boot's one response is used. The key is kept until the process ends, so that an asker who
		// left meanwhile does not cost the boot its unlock: the next one gets the same key.
		u.key, u.peer, u.slot = key, peer, slot
	}
	_ = connection.SetDeadline(time.Now().Add(ioTimeout))
	if _, err := connection.Write(u.key); err != nil {
		return errors.New("the key could not be written to the socket: it is kept for the next connection")
	}
	fmt.Fprintf(u.out, "regalia-unlock: gave the key of %s for keyslot %s, through %s\n", u.config.Device, u.slot, u.peer)
	// For the journal and the probe: whose half the key was made with. Whether it opened the volume is
	// systemd-cryptsetup's to say. Nothing in the protocol reads it, so failing to write it fails nothing.
	if u.o.sessionDir != "" {
		_ = writeFile(u.o.sessionDir, "key-given-through", fmt.Sprintf("%s %s\n", u.peer, u.slot))
	}
	return nil
}

// gone reports whether the other end has closed the connection. Not by reading: systemd-cryptsetup
// shuts down its sending side as soon as it has connected, so a read ends at once while it is still
// waiting for the key. A hang-up is both directions closed.
func gone(connection *net.UnixConn) bool {
	raw, err := connection.SyscallConn()
	if err != nil {
		return false
	}
	hungUp := false
	_ = raw.Control(func(fd uintptr) {
		state := []unix.PollFd{{Fd: int32(fd)}}
		if n, err := unix.Poll(state, 0); err == nil && n > 0 {
			hungUp = state[0].Revents&(unix.POLLHUP|unix.POLLERR) != 0
		}
	})
	return hungUp
}

// presenting is the quoter given to the session: it leaves this boot's session for the running system
// (publishSession) BEFORE its first quote is taken, and so before any peer can have verified one. A peer
// records the session when it verifies a quote, whether or not the unlock then succeeds, so the record
// must not wait for success. A process that never got as far as a quote (no peer answered its hello)
// leaves no record: no peer holds its session, and the running system makes its own.
//
// A record that cannot be written is said and is NOT a reason to leave the disk locked: the node then
// boots, its leases may be refused until the next boot, and that can be repaired without the recovery key.
func (u *unlocker) presenting(qualifying []byte) ([]byte, []byte, error) {
	if !u.presented {
		u.presented = true
		if u.o.sessionDir != "" {
			if err := publishSession(u.o.sessionDir, u.boot); err != nil {
				fmt.Fprintln(u.diagnostics, "regalia-unlock: "+err.Error()+
					": the running system will not find this boot's session, and its leases may be refused until the next boot")
			}
		}
	}
	return u.quote(qualifying)
}

// forget zeroes what this process held: the local half, the volume's key, and the session's private
// key as far as this package can reach it (Go's crypto keeps a copy of its own that it does not expose).
func (u *unlocker) forget() {
	wipe(u.local)
	wipe(u.key)
	if u.boot != nil && u.boot.key != nil {
		numbers := append([]*big.Int{u.boot.key.D, u.boot.key.Precomputed.Dp, u.boot.key.Precomputed.Dq, u.boot.key.Precomputed.Qinv}, u.boot.key.Primes...)
		for _, number := range numbers {
			if number != nil {
				words := number.Bits()
				for i := range words {
					words[i] = 0
				}
			}
		}
	}
}

// publishSession writes the boot session's ID and public key: boot-session (64 lowercase hex and a
// newline, what the KMS daemon reads) and boot-session.pub (the hex of the DER bytes that go into the
// quote's transcript). Never the private key. The public key first: boot-session is what says "a session
// was presented in this boot" (unlocker.serve), so it exists only with its key beside it. Both, or
// neither: a failure removes what is there.
func publishSession(directory string, boot *session) error {
	err := writeFile(directory, "boot-session.pub", hex.EncodeToString(boot.ephemeralPublic)+"\n")
	if err == nil {
		err = writeFile(directory, "boot-session", hex.EncodeToString(boot.id)+"\n")
	}
	if err != nil {
		os.Remove(filepath.Join(directory, "boot-session"))
		os.Remove(filepath.Join(directory, "boot-session.pub"))
	}
	return err
}

// writeFile replaces one file in the directory, whole or not at all, readable by everyone.
func writeFile(directory, name, content string) error {
	failed := errors.New("cannot record " + name + " in " + directory)
	temporary, err := os.CreateTemp(directory, "."+name+".")
	if err != nil {
		return failed
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.WriteString(content); err != nil {
		temporary.Close()
		return failed
	}
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return failed
	}
	if err := temporary.Close(); err != nil {
		return failed
	}
	if err := os.Rename(temporary.Name(), filepath.Join(directory, name)); err != nil {
		return failed
	}
	return nil
}

// activatedListener is the socket systemd passed (sd_listen_fds): exactly one, for this process.
func activatedListener() (*net.UnixListener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" {
		return nil, errors.New("no socket was passed: this program is socket-activated (LISTEN_FDS=1), and systemd-cryptsetup reads the key from that socket")
	}
	file := os.NewFile(listenFDStart, "key socket")
	defer file.Close() // FileListener duplicates it
	listener, err := net.FileListener(file)
	unix, ok := listener.(*net.UnixListener)
	if err != nil || !ok {
		return nil, errors.New("the passed descriptor is not a listening UNIX socket")
	}
	return unix, nil
}

// sameUser reports whether the other end of the connection is a process of this user (SO_PEERCRED).
func sameUser(connection *net.UnixConn) bool {
	raw, err := connection.SyscallConn()
	if err != nil {
		return false
	}
	var credentials *syscall.Ucred
	var credentialsError error
	if err := raw.Control(func(fd uintptr) {
		credentials, credentialsError = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || credentialsError != nil {
		return false
	}
	return credentials.Uid == uint32(os.Geteuid())
}

// giveNothing closes the connection waiting on the socket, if there is one, without writing to it.
func giveNothing(listener *net.UnixListener) {
	_ = listener.SetDeadline(time.Now().Add(time.Second))
	if connection, err := listener.AcceptUnix(); err == nil {
		connection.Close()
	}
}

// tcpTransport is one request per connection: the request ends when this side closes its half, and
// the reply is everything the peer sends before it closes, bounded in size and time. The network under
// it (WG-BOOT, #66) decides who can reach a peer; the exchange needs no secrecy from the transport.
func tcpTransport(endpoint string) transport {
	return func(request []byte) ([]byte, error) {
		connection, err := net.DialTimeout("tcp", endpoint, ioTimeout)
		if err != nil {
			return nil, errors.New("no connection")
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(ioTimeout))
		if _, err := connection.Write(request); err != nil {
			return nil, errors.New("the request was not sent")
		}
		if tcp, ok := connection.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		reply, err := io.ReadAll(io.LimitReader(connection, maxMessage+1))
		if err != nil {
			return nil, errors.New("the reply did not arrive")
		}
		return reply, nil
	}
}

// deriveKey is unlock.unlock up to the credential, with bounded retries: it goes round the peers of
// the boot configuration, newest path first, until one gives its contribution. It returns the keyslot
// credential, the peer and the keyslot, or an error after the last round. Every reason is written to
// diagnostics as it happens; none of them holds a secret. Whether the credential opens the keyslot is
// systemd-cryptsetup's to find out: this boot's one response is spent either way.
func deriveKey(config *bootConfig, o options, paths map[string][]pathToken, local []byte, boot *session, dial func(string) transport,
	quote quoter, sleep func(time.Duration), diagnostics io.Writer) (key []byte, peerID, slot string, err error) {
	asked := false
	for round := 1; round <= o.rounds; round++ {
		for _, peer := range config.Peers {
			for _, token := range paths[peer.NodeID] {
				asked = true
				contribution, err := boot.ask(peer, token.PathEpoch, dial(peer.Endpoint), quote)
				if err != nil {
					fmt.Fprintf(diagnostics, "regalia-unlock: round %d, %s (path epoch %d): %s\n", round, peer.NodeID, token.PathEpoch, err)
					continue
				}
				key, err := credential(local, contribution, config.NodeID, peer.NodeID, token.PathEpoch)
				wipe(contribution)
				if err != nil {
					return nil, "", "", err
				}
				return key, peer.NodeID, token.Keyslots[0], nil
			}
		}
		if !asked {
			return nil, "", "", errors.New("the disk stays locked: it has no path from any peer of the boot configuration")
		}
		if round < o.rounds {
			sleep(o.wait)
		}
	}
	return nil, "", "", fmt.Errorf("the disk stays locked: no peer helped in %d rounds", o.rounds)
}
