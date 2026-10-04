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
// It runs no other program and writes no secret anywhere. It is a systemd PASSWORD AGENT (#70, the
// Clevis way, agent.go): systemd-cryptsetup asks for the root volume's passphrase through the
// ask-password protocol, the console shows that request from the start, and this program answers the
// same request once a peer has given its half; whichever answers first wins. Until then it asks the
// peers again and again, at a capped backoff, for as long as the initrd lasts: a node that boots during
// a blackout unlocks by itself when a peer comes back. Two things reach it from systemd: the local half
// of the credential, unsealed with the TPM (the unit's credential regalia.unlock-local), and the boot
// configuration (-config).
//
// It reads the LUKS2 header for the peer paths, asks the peers in turn, derives the credential, and
// answers the request. Its code is this directory, the standard library, and go-tpm
// (github.com/google/go-tpm), the standard Go library for talking to a TPM: the transport, TPM2_Quote,
// and the parsing of TPM structures are go-tpm's, not written here.
//
// It runs with ONE boot session: a peer accepts one session per boot of this TPM. It stands down when the
// volume is open, or when systemd stops it before the root filesystem takes over; the local half, the
// session's private key and the volume's key end with it.
//
// What it leaves for the running system, under /run/regalia (which survives switch-root), none of it
// secret: boot-session and boot-session.pub, the ID and the public key of that session, written before
// its first quote is taken, and once a key was given key-given-through, the peer and keyslot. A client
// started again in the same boot (after a crash) finds that record and asks no peer: its session would
// be a second one. The runtime leases of this boot must be asked for under the same session
// (deploy/baremetal/lease.py); they need its public key, never its private one.
package main

import (
	"crypto/rsa"
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
	"sync"
	"syscall"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/askpass"
)

const ioTimeout = 10 * time.Second

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
	askDir     string // the ask-password protocol's directory
	requestID  string // the root volume's request: its Id=
	volume     string // the volume's node once open: then the agent stands down
	attempts   int    // attempts at the peers before giving up (tests); 0: for as long as the initrd lasts
}

func run(arguments []string, out, diagnostics io.Writer) error {
	if len(arguments) > 0 && arguments[0] == "-render" {
		return runRender(arguments, out, diagnostics)
	}
	flags := flag.NewFlagSet("regalia-unlock", flag.ContinueOnError)
	flags.SetOutput(out)
	configPath := flags.String("config", "", "the boot configuration (deploy/baremetal/unlock.py, boot_config)")
	var o options
	flags.StringVar(&o.tpm, "tpm", "/dev/tpmrm0", "the TPM: the resource-manager device, or unix:PATH for a software TPM in tests")
	flags.StringVar(&o.sessionDir, "session-dir", "/run/regalia", "where the boot session's ID and public key are left for the running system")
	flags.StringVar(&o.askDir, "ask-dir", askpass.Dir, "the ask-password protocol's directory")
	flags.StringVar(&o.requestID, "request", askpass.RootID, "the Id= of the request to answer: the root volume's")
	flags.StringVar(&o.volume, "volume", "/dev/mapper/root", "the volume's node once it is open: then the client stands down")
	flags.IntVar(&o.attempts, "attempts", 0, "attempts at the peers before giving up (tests); 0: for as long as the initrd lasts")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || o.attempts < 0 || o.askDir == "" || o.requestID == "" || o.volume == "" {
		return errors.New("usage: regalia-unlock [-config FILE] [-tpm DEVICE] [-session-dir DIR] [-ask-dir DIR] [-request ID] [-volume PATH] [-attempts N]")
	}
	// Everything that can be refused without a peer is refused first: nothing is asked of a peer, and no
	// boot session is spent, by a start that could not have used the answer. Any refusal leaves the
	// console's prompt, which is there from the start.
	config, err := loadBootConfig(*configPath)
	if err != nil {
		return err
	}
	local, err := localContribution(os.Getenv("CREDENTIALS_DIRECTORY"))
	if err != nil {
		return err
	}
	defer wipe(local) // on every path that does not reach the agent; from there, unlocker.forget
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
	quote := func(qualifying []byte) ([]byte, []byte, map[string]string, error) {
		device, err := openTPM(o.tpm)
		if err != nil {
			return nil, nil, nil, errors.New("cannot open the TPM " + o.tpm)
		}
		defer device.Close()
		return tpmQuote(device, qualifying, config.PCRs)
	}
	boot, err := newSession(config.NodeID)
	if err != nil {
		return errors.New("cannot make this boot's session key")
	}
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
	return u.agent(realAgentEnv(o.volume))
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
	dial        func(endpoint string, until time.Time) transport
	quote       quoter
	sleep       func(time.Duration)
	out         io.Writer
	diagnostics io.Writer

	presented bool       // a quote of this session was taken, to be sent to a peer
	key       []byte     // the volume's key, from this boot's one response; given to each request for the volume
	secrets   sync.Mutex // spent (the serving loop) and forget (the signal goroutine) zero the same memory
	peer      string
	slot      string
}

const earlierSession = "the disk stays locked: an earlier unlock client of this boot presented another session to the peers, " +
	"and a peer accepts one session per boot, so no peer is asked: reboot, or use the recovery key"

// presenting is the quoter given to the session: it leaves this boot's session for the running system
// (publishSession) BEFORE its first quote is taken, and so before any peer can have verified one. A peer
// records the session when it verifies a quote, whether or not the unlock then succeeds, so the record
// must not wait for success. A process that never got as far as a quote (no peer answered its hello)
// leaves no record: no peer holds its session, and the running system makes its own.
//
// A record that cannot be written is said and is NOT a reason to leave the disk locked: the node then
// boots, its leases may be refused until the next boot, and that can be repaired without the recovery key.
func (u *unlocker) presenting(qualifying []byte) ([]byte, []byte, map[string]string, error) {
	// Tried again before each quote until it is written: a full /run may have room a moment later.
	if !u.presented && u.o.sessionDir != "" {
		if err := publishSession(u.o.sessionDir, u.boot); err != nil {
			fmt.Fprintln(u.diagnostics, "regalia-unlock: "+err.Error()+
				": the running system will not find this boot's session, and its leases may be refused until the next boot")
		} else {
			u.presented = true
		}
	}
	return u.quote(qualifying)
}

// forget zeroes what this process held: the local half and the volume's key, and the session's private
// key only as far as this package can reach it: Go's crypto keeps its own copy, which it does not
// expose and which ends with the process. Called from the signal handler, it can race an answer in
// progress; that answer then gives a zeroed key, which the volume refuses: a failed attempt, never a
// secret written anywhere.
// spent drops what only served to obtain this boot's one response: the local half is zeroed, and the
// session's private key is zeroed where this package can reach it and then let go, so nothing in the
// process refers to it any more. That does NOT erase it: crypto/rsa keeps an internal copy this code
// cannot reach, and the Go runtime does not clear memory it frees. What it does is shorten how long the
// key is reachable, and leave its pages to be cleared when the process ends, by the kernel's
// init_on_free=1 on the signed command line (#221). The key the boot was given stays: the next asker
// in this boot gets it.
func (u *unlocker) spent() {
	u.secrets.Lock()
	defer u.secrets.Unlock()
	wipe(u.local)
	if u.boot != nil && u.boot.key != nil {
		zeroPrivate(u.boot.key)
		u.boot.key = nil
	}
}

// zeroPrivate zeroes the private numbers of an RSA key in place.
func zeroPrivate(key *rsa.PrivateKey) {
	numbers := append([]*big.Int{key.D, key.Precomputed.Dp, key.Precomputed.Dq, key.Precomputed.Qinv}, key.Primes...)
	for _, number := range numbers {
		if number != nil {
			words := number.Bits()
			for i := range words {
				words[i] = 0
			}
		}
	}
}

func (u *unlocker) forget() {
	u.secrets.Lock()
	defer u.secrets.Unlock()
	wipe(u.local)
	wipe(u.key)
	if u.boot != nil && u.boot.key != nil {
		zeroPrivate(u.boot.key)
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

// tcpTransport is one request per connection: the request ends when this side closes its half, and
// the reply is everything the peer sends before it closes, bounded in size and time. The network under
// it (WG-BOOT, #66) decides who can reach a peer; the exchange needs no secrecy from the transport.
// `until` (zero: none) bounds it too: the attempt's budget, so that its last ask cannot outlast it.
func tcpTransport(endpoint string, until time.Time) transport {
	limit := func() time.Time {
		deadline := time.Now().Add(ioTimeout)
		if !until.IsZero() && until.Before(deadline) {
			deadline = until
		}
		return deadline
	}
	return func(request []byte) ([]byte, error) {
		if !until.IsZero() && !time.Now().Before(until) {
			return nil, errors.New("the attempt's time is spent")
		}
		dialer := net.Dialer{Deadline: limit()}
		connection, err := dialer.Dial("tcp", endpoint)
		if err != nil {
			return nil, errors.New("no connection")
		}
		defer connection.Close()
		_ = connection.SetDeadline(limit())
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
