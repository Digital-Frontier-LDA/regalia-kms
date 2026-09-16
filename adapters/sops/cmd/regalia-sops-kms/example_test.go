package main

import (
	"os"
	"path/filepath"
	"testing"
)

// THE SHIPPED EXAMPLE IS WHAT AN OPERATOR COPIES, SO IT IS TESTED LIKE CODE.
//
// config.example.json had no test at all. The daemon's own daemon.example.json was in the same
// state earlier in this work and turned out to be unusable — its audit_sink_url carried a path the
// sink appends itself, so the file the deployment guide says to copy could not start the service.
// Nothing caught it because no test had ever loaded it.
//
// This loads the shipped adapter example through the loader the binary uses and validates it the
// way the binary does. It does not read the certificate paths: those are runtime credentials that
// do not exist in a checkout, and validate() is the half that decides whether the document itself
// is coherent.
func TestShippedAdapterExampleLoadsAndValidates(t *testing.T) {
	// loadConfig refuses a group- or world-writable file, and a checked-out file carries whatever
	// mode the developer's umask left it (0664 under the 0002 umask common on user-private-group
	// systems), so stage the example at 0600 first. t.TempDir is absolute, which loadConfig also
	// requires — a relative credential path would resolve against whatever directory systemd
	// started the unit in.
	contents, err := os.ReadFile(filepath.Join("..", "..", "config.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := loadConfig(path)
	if err != nil {
		t.Fatalf("the shipped adapter example does not load: %v", err)
	}
	timeout, err := settings.validate()
	if err != nil {
		t.Fatalf("the shipped adapter example does not validate, so an operator copying it gets a service that will not start: %v", err)
	}
	if timeout <= 0 {
		t.Fatalf("the example produced a non-positive timeout: %v", timeout)
	}
	// Every path the example names must be absolute: a relative credential path resolves against
	// whatever directory systemd happens to start the unit in.
	for name, path := range map[string]string{
		"socket_path":      settings.SocketPath,
		"ca_path":          settings.CAPath,
		"certificate_path": settings.CertificatePath,
		"private_key_path": settings.PrivateKeyPath,
	} {
		if !filepath.IsAbs(path) {
			t.Errorf("%s is %q, which is relative: it would resolve against whatever directory the unit is started in", name, path)
		}
	}
}
