package sopsadapter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops/sopsrpc"
	"google.golang.org/grpc"
)

// ServeUnix exposes only the upstream SOPS key-service methods on a private
// local socket. The remote hop to Regalia KMS is separately authenticated TLS.
//
// THE SIDECAR IS A TRUSTED MULTIPLEXER, AND EVERYTHING THROUGH IT IS ONE IDENTITY.
//
// This socket carries no caller identity and the adapter propagates none. Every operation reaching
// the KMS is authorized as, and audited as, the SIDECAR's SPIFFE identity -- not the identity of
// whatever invoked SOPS. That is sound only because the socket has exactly one trust domain, and it
// is worth being exact about which permission buys which property, because they are different
// syscalls:
//
//	connect(2) needs write on the SOCKET     -- 0600 plus User=regalia-sops is what makes the
//	                                            domain single. A directory another account can
//	                                            list does not let them connect.
//	unlink(2)  needs write on the DIRECTORY  -- so a writable directory lets an attacker replace
//	                                            the socket with their own listener, which is what
//	                                            the check below refuses.
//
// The single trust domain therefore rests on the socket mode and the dedicated account;
// RuntimeDirectoryMode=0700 adds only that other accounts cannot enumerate what is there.
//
// AN OPERATOR CAN BREAK THAT WITHOUT TOUCHING THIS CODE. Relaxing the directory mode, or sharing
// one sidecar between services, merges those callers into a single principal -- and the audit
// journal will show one identity for all of them, with nothing anywhere reporting that the
// distinction was lost. The directory check below is what keeps the model true, which is why it
// refuses to start rather than warning.
//
// Propagating the caller's identity instead would mean the daemon accepting "acting on behalf of"
// assertions from a workload. That is a delegation model it does not have and a real trust grant;
// it is filed separately rather than decided here.
func ServeUnix(ctx context.Context, socketPath string, adapter *Server) error {
	if socketPath == "" || adapter == nil {
		return errors.New("invalid SOPS adapter configuration")
	}
	if _, err := os.Lstat(socketPath); err == nil || !os.IsNotExist(err) {
		return errors.New("refusing to replace existing SOPS socket path")
	}
	// THE DIRECTORY IS THE GATE, NOT THE CHMOD BELOW.
	//
	// net.Listen creates the socket with the process umask applied, and the Chmod that narrows it
	// to 0600 runs afterwards. Measured: under umask 022 the socket is 0755 for that window, and a
	// connection accepted during it survives the Chmod -- so one connect at start-up buys an
	// unauthenticated client a long-lived channel to a service whose whole purpose is unwrapping
	// data keys.
	//
	// regalia-sops-kms.service sets UMask=0077 and RuntimeDirectoryMode=0700, which closes this in
	// the shipped deployment. But nothing in this process knew that: the property was declared in
	// the unit and depended on here, with nothing connecting the two, so running the binary by hand
	// or in a container -- during an incident, in a test, anywhere systemd is not -- reopened it
	// silently. Checking the directory is what makes the guarantee local to the code that needs it.
	//
	// A directory the group or world can write is worse than a permissive window: the socket can be
	// unlinked and replaced by an attacker's own listener at any time, which the Lstat above only
	// prevents once, at start-up.
	directory := filepath.Dir(socketPath)
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("stat the SOPS socket directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("the SOPS socket's parent %s is not a directory", directory)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("the SOPS socket directory %s is group- or world-writable (%04o); "+
			"anyone who can write it can replace this socket with their own listener and answer "+
			"unwrap requests. systemd sets RuntimeDirectoryMode=0700 for this reason",
			directory, info.Mode().Perm())
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socketPath)
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return err
	}
	server := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxCiphertextBytes+(64<<10)),
		grpc.MaxSendMsgSize(maxCiphertextBytes+(64<<10)),
		grpc.MaxConcurrentStreams(16),
	)
	sopsrpc.RegisterKeyServiceServer(server, adapter)
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return err
	case <-ctx.Done():
		stopped := make(chan struct{})
		go func() { server.GracefulStop(); close(stopped) }()
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			server.Stop()
			<-stopped
		}
		err := <-result
		if errors.Is(err, grpc.ErrServerStopped) {
			return nil
		}
		return err
	}
}
