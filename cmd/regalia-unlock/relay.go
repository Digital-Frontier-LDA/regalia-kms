package main

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// keyBytes is the length of every key the client gives: the base64 of 32 bytes (credential).
var keyBytes = base64.StdEncoding.EncodedLen(secretBytes)

// relay serves the key socket that crypttab names, in front of the real client. It holds no credential,
// no TPM and no network, so its unit always starts: whatever happens to the real client (its credentials
// absent or refused, a hang, a crash), every connection on the key socket is answered, with the key or
// with nothing, and with nothing systemd-cryptsetup asks for the recovery key. Without it, a real client
// that cannot start leaves systemd-cryptsetup with a reset connection, and it fails without asking (#66).
//
// For each connection it asks the real client on `core` (its own socket, which starts it), waits at most
// `wait`, and passes on exactly one whole key or nothing. It never writes the key anywhere else.
func relay(listener keySocket, core string, wait time.Duration, diagnostics io.Writer) error {
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil // the unit is being stopped
			}
			fmt.Fprintln(diagnostics, "regalia-unlock: the key socket could not accept a connection, trying again")
			time.Sleep(time.Second)
			continue
		}
		if !sameUser(connection) {
			connection.Close()
			continue
		}
		if err := forward(connection, core, wait); err != nil {
			fmt.Fprintln(diagnostics, "regalia-unlock: "+err.Error()+": nothing is given, and the console asks for the recovery key")
		}
		connection.Close()
	}
}

// runRelay is the program as the relay: regalia-unlock -relay CORE -listen PATH [-relay-wait D]. It makes
// the key socket ITSELF rather than receive it from a systemd socket unit, because of what
// systemd-cryptsetup does with a key file it cannot read (systemd 257, src/cryptsetup/cryptsetup.c): a
// path that does not exist makes it ask for the recovery key, while a refused or reset connection makes it
// fail without asking. So if the relay cannot start, or is gone, there is no socket, and the console asks.
// It removes the socket when it is stopped, and tells systemd it is ready only once the socket listens.
func runRelay(arguments []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("regalia-unlock -relay", flag.ContinueOnError)
	flags.SetOutput(out)
	core := flags.String("relay", "", "the real client's socket")
	path := flags.String("listen", "", "the key socket to make, the one crypttab names")
	wait := flags.Duration("relay-wait", 330*time.Second, "the longest wait for the real client's answer")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *core == "" || *path == "" || *wait <= 0 || *wait > 30*time.Minute {
		return errors.New("usage: regalia-unlock -relay CORE-SOCKET -listen KEY-SOCKET [-relay-wait DURATION, at most 30m]")
	}
	_ = os.Remove(*path) // a socket left by a relay that died: its path would refuse connections
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: *path, Net: "unix"})
	if err != nil {
		return errors.New("cannot make the key socket " + *path)
	}
	listener.SetUnlinkOnClose(true)
	if err := os.Chmod(*path, 0o600); err != nil {
		listener.Close()
		return errors.New("cannot restrict the key socket " + *path)
	}
	// Stopped (shutdown, or switch-root): at once, whatever it waits on, and without its socket. An asker
	// in progress reads nothing, which is the relay's answer for every failure.
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-stopped
		_ = os.Remove(*path)
		os.Exit(0)
	}()
	notifyReady()
	return relay(listener, *core, *wait, diagnostics)
}

// notifyReady tells systemd the socket listens (sd_notify "READY=1"), when it runs under a Type=notify unit.
func notifyReady() {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return
	}
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + socket[1:]
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return
	}
	defer connection.Close()
	_, _ = connection.Write([]byte("READY=1"))
}

// forward asks the real client for one key and writes it to the asker. Any failure writes nothing.
func forward(asker *net.UnixConn, core string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	dialer := net.Dialer{Deadline: deadline}
	client, err := dialer.Dial("unix", core)
	if err != nil {
		return errors.New("the unlock client could not be reached")
	}
	defer client.Close()
	_ = client.SetDeadline(deadline)
	if unix, ok := client.(*net.UnixConn); ok {
		_ = unix.CloseWrite() // as systemd-cryptsetup does: it only listens
	}
	key, err := io.ReadAll(io.LimitReader(client, int64(keyBytes)+1))
	defer wipe(key)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Errorf("the unlock client gave no answer within %s", wait)
	}
	if err != nil {
		return errors.New("the unlock client's answer broke off")
	}
	if len(key) == 0 {
		return errors.New("the unlock client gave nothing")
	}
	if len(key) != keyBytes {
		return errors.New("the unlock client's answer is not one whole key")
	}
	_ = asker.SetDeadline(time.Now().Add(ioTimeout))
	if _, err := asker.Write(key); err != nil {
		return errors.New("the key could not be passed on")
	}
	return nil
}
