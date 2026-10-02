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
// What it leaves for the running system, under /run/regalia (which survives switch-root), none of it
// secret: boot-session and boot-session.pub, the ID and the public key of the boot session it presented
// to the peers, and after a successful run unlocked-through, the peer and keyslot. A peer accepts ONE
// session per boot of this TPM, so the runtime leases of this boot must be asked for under that same
// session (deploy/baremetal/lease.py); they need its public key and never its private one.
//
// Exit status 0: the key was given. 1: the disk stays locked; each peer's reason is on standard error,
// systemd-cryptsetup gets no key, and the console falls back to the recovery key (#77).
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
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
	rounds     int
	wait       time.Duration
}

func run(arguments []string, out, diagnostics io.Writer) error {
	// The socket first, before anything that can fail. A run that gives no key still answers whoever
	// waits on it, with nothing: systemd-cryptsetup then asks at the console, and systemd does not start
	// this program again for a connection left waiting. That holds for a bad flag or a bad configuration too.
	listener, listenerError := activatedListener()
	given := false
	if listener != nil {
		defer listener.Close()
		defer func() {
			if !given {
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
	flags.IntVar(&o.rounds, "rounds", 5, "how many times to go round the peers before giving up")
	flags.DurationVar(&o.wait, "wait", 5*time.Second, "pause between rounds")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || o.rounds < 1 || o.rounds > 100 || o.wait < 0 {
		return errors.New("usage: regalia-unlock [-config FILE] [-tpm DEVICE] [-rounds N] [-wait DURATION]")
	}
	if listenerError != nil {
		return listenerError
	}
	// Everything that can be refused without a peer is refused first: nothing is asked of a peer, and no
	// boot session is spent, by a run that could not have used the answer.
	config, err := loadBootConfig(*configPath)
	if err != nil {
		return err
	}
	local, err := localContribution(os.Getenv("CREDENTIALS_DIRECTORY"))
	if err != nil {
		return err
	}
	defer wipe(local)
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
	// Before any quote is sent: a peer records the session when it VERIFIES a quote, whether or not the
	// unlock then succeeds, and from then on accepts no other session in this boot. So the session this
	// run is about to present is on record here first, replacing an earlier run's.
	if err := publishSession(o.sessionDir, boot); err != nil {
		return err
	}
	key, peer, slot, err := deriveKey(config, o, paths, local, boot, tcpTransport, quote, time.Sleep, diagnostics)
	if err != nil {
		return err
	}
	defer wipe(key)
	given = true // one attempt: whatever happens to it, the connection is not answered twice
	if err := giveKey(listener, key, handoffWait); err != nil {
		return err
	}
	fmt.Fprintf(out, "regalia-unlock: gave the key of %s for keyslot %s, through %s\n", config.Device, slot, peer)
	// for the journal and the probe; nothing in the protocol reads it, so failing to write it fails nothing
	_ = writeFile(o.sessionDir, "unlocked-through", fmt.Sprintf("%s %s\n", peer, slot))
	return nil
}

// publishSession leaves the boot session's ID and public key for the running system: boot-session (64
// lowercase hex and a newline, what the KMS daemon reads) and boot-session.pub (the hex of the DER bytes
// that go into the quote's transcript). Never the private key.
func publishSession(directory string, boot *session) error {
	if err := writeFile(directory, "boot-session.pub", hex.EncodeToString(boot.ephemeralPublic)+"\n"); err != nil {
		return err
	}
	return writeFile(directory, "boot-session", hex.EncodeToString(boot.id)+"\n")
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

// giveKey writes the key to the first connection on the socket that comes from this user (root, before
// root exists), once, and to nobody else. A connection from another user is closed with nothing and
// does not take the place of the one behind it.
func giveKey(listener *net.UnixListener, key []byte, wait time.Duration) error {
	_ = listener.SetDeadline(time.Now().Add(wait))
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			return errors.New("nobody entitled asked for the key on the socket")
		}
		if !sameUser(connection) {
			connection.Close()
			continue
		}
		_ = connection.SetDeadline(time.Now().Add(ioTimeout))
		_, err = connection.Write(key)
		connection.Close()
		if err != nil {
			return errors.New("the key could not be written to the socket")
		}
		return nil
	}
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
