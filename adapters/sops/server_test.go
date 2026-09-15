package sopsadapter

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops/sopsrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestServeUnixUsesPrivateSocketAndPublishedRPCMethod(t *testing.T) {
	directory := socketDir(t)
	socket := filepath.Join(directory, "sops.sock")
	ctx, cancel := context.WithCancel(context.Background())
	// defer, because a t.Fatal between here and the explicit cancel below would leave this
	// goroutine running for the rest of the package's test binary, where it can fail an
	// unrelated test that runs afterwards.
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ServeUnix(ctx, socket, New(&mockKMS{wrapResult: []byte("wrapped")})) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if info, err := os.Stat(socket); err == nil {
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("socket mode = %o", info.Mode().Perm())
			}
			break
		}
		select {
		case err := <-done:
			t.Fatalf("ServeUnix() exited before socket became ready: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("Unix socket did not appear")
		}
		time.Sleep(5 * time.Millisecond)
	}
	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}
	connection, err := grpc.NewClient("passthrough:///sops", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(dialer))
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	response := new(sopsrpc.EncryptResponse)
	err = connection.Invoke(context.Background(), "/KeyService/Encrypt", &sopsrpc.EncryptRequest{Key: sopsKey(), Plaintext: []byte("data-key")}, response)
	if err != nil || string(response.Ciphertext) != "wrapped" {
		t.Fatalf("Invoke() = %q, %v", response.Ciphertext, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("ServeUnix() = %v", err)
	}
	if _, err := os.Stat(socket); !os.IsNotExist(err) {
		t.Fatalf("socket remains after shutdown: %v", err)
	}
}

func TestServeUnixRefusesExistingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "occupied")
	if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ServeUnix(context.Background(), path, New(&mockKMS{})); err == nil {
		t.Fatal("existing path accepted")
	}
	contents, _ := os.ReadFile(path)
	if string(contents) != "do not replace" {
		t.Fatalf("existing path changed: %q", contents)
	}
}
