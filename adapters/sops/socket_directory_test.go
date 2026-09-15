package sopsadapter

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// THE SOCKET'S PROTECTION WAS DECLARED IN THE UNIT AND DEPENDED ON HERE.
//
// net.Listen creates the socket with the process umask applied and the Chmod to 0600 runs after,
// so under umask 022 it is 0755 for that window — measured, not assumed — and a connection accepted
// during the window survives the Chmod. regalia-sops-kms.service sets UMask=0077 and
// RuntimeDirectoryMode=0700, which closes it in the shipped deployment.
//
// Nothing connected those two facts. Running the binary outside systemd — by hand during an
// incident, in a container, in a test — reopened the window with no diagnostic, which is the same
// shape as the custody rules that were enforced in CI and not in the daemon (#78).
//
// A writable directory is the worse half: the Lstat guard refuses to REPLACE an existing socket
// once, at start-up, and does nothing about an attacker who unlinks and rebinds afterwards.
//
// WHAT THIS CHECK DOES AND DOES NOT ESTABLISH. The adapter propagates no caller identity: every
// operation is authorized and audited as the SIDECAR's principal, which is honest only while one
// caller can reach the socket. That single trust domain comes from the socket being 0600 under a
// dedicated service account -- connect(2) needs write on the SOCKET, so a merely listable directory
// admits nobody.
//
// This check defends the other half: unlink(2) needs write on the DIRECTORY, so a writable one lets
// an attacker replace the socket with their own listener and answer unwrap requests. The threshold
// is writability rather than 0700 for that reason -- a 0755 directory is not private, but it is not
// replaceable either, and refusing it would reject legitimate deployments.
func TestServeUnixRefusesAWritableSocketDirectory(t *testing.T) {
	for _, mode := range []os.FileMode{0o777, 0o770, 0o702} {
		t.Run(mode.String(), func(t *testing.T) {
			directory := socketDir(t)
			// Control: the same directory at 0700 must get past this check, so a failure below is
			// about the mode and not about the path, the adapter, or the harness.
			if err := os.Chmod(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			socket := filepath.Join(directory, "s.sock")
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			if err := ServeUnix(ctx, socket, New(nil)); err != nil && strings.Contains(err.Error(), "group- or world-writable") {
				t.Fatalf("the control at 0700 was refused as writable: %v", err)
			}

			if err := os.Chmod(directory, mode); err != nil {
				t.Fatal(err)
			}
			ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel2()
			err := ServeUnix(ctx2, filepath.Join(directory, "s2.sock"), New(nil))
			if err == nil {
				t.Fatalf("a %04o socket directory was accepted: anyone who can write it can unlink this "+
					"socket and bind their own, and every client then hands its ciphertext to them", mode.Perm())
			}
			if !strings.Contains(err.Error(), "group- or world-writable") {
				t.Fatalf("error = %v, want it to name the directory's permissions", err)
			}
		})
	}
}
