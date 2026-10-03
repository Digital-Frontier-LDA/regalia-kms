package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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
