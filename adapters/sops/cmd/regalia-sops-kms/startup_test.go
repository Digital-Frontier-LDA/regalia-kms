package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run() wires the sidecar and calls ServeUnix LAST. That ordering is the property worth holding:
// every refusal before it must leave NO SOCKET BEHIND.
//
// A socket that exists but is not served is worse than none. SOPS finds it, connects, and gets a
// hang or a reset rather than "the sidecar is not running" — and an operator checking
// `ls /run/regalia` sees the sidecar as up. The refusals themselves are already covered by
// loadConfig, validate and identity; what is unproven is that none of them gets far enough to
// create the socket.

// runWithArgs calls run() with a fresh flag set, because run() defines flags on the package-level
// CommandLine and a second call would panic on redefinition.
func runWithArgs(t *testing.T, args ...string) error {
	t.Helper()
	savedArgs, savedFlags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = savedArgs, savedFlags })
	flag.CommandLine = flag.NewFlagSet(savedArgs[0], flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = append([]string{"regalia-sops-kms"}, args...)
	return run()
}

// shortSocketPath returns a socket path under /tmp rather than t.TempDir().
//
// A unix socket path is capped at 104 bytes on darwin (108 on Linux), and t.TempDir() embeds the
// test AND subtest name: "…/T/TestNoRefusalLeavesASocketBehind_identity_material_that_is_missing…/
// 001/sidecar.sock" is about 139. net.Listen then fails with "invalid argument" before it can
// create anything — so a mutation that opens the socket early would leave nothing behind and this
// test would pass while proving nothing about the ordering it exists for. Measured: that is exactly
// what happened to the first version.
func shortSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "rgl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "s.sock")
	if len(path) > 100 {
		t.Fatalf("socket path is %d bytes, too long for a unix socket: %s", len(path), path)
	}
	// The listener must actually be creatable here, or every assertion below is vacuous.
	probe, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("a socket cannot be created at %s at all (%v), so this test could not observe one being left behind", path, err)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return path
}

func writeConfig(t *testing.T, dir string, cfg config) string {
	t.Helper()
	path := filepath.Join(dir, "sidecar.json")
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNoRefusalLeavesASocketBehind(t *testing.T) {
	for _, test := range []struct {
		name  string
		build func(t *testing.T, dir, socket string) []string
	}{
		{"no configuration named", func(t *testing.T, dir, socket string) []string { return nil }},
		{"a configuration that does not exist", func(t *testing.T, dir, socket string) []string {
			return []string{"-config", filepath.Join(dir, "absent.json")}
		}},
		{"a relative configuration path", func(t *testing.T, dir, socket string) []string {
			return []string{"-config", "sidecar.json"}
		}},
		{"a configuration with an unknown field", func(t *testing.T, dir, socket string) []string {
			path := filepath.Join(dir, "extra.json")
			if err := os.WriteFile(path, []byte(`{"socket_path":"`+socket+`","surprise":1}`), 0o600); err != nil {
				t.Fatal(err)
			}
			return []string{"-config", path}
		}},
		{"identity material that is missing", func(t *testing.T, dir, socket string) []string {
			return []string{"-config", writeConfig(t, dir, config{
				SocketPath: socket, KMSURL: "https://kms.internal:8443", ServerName: "kms.internal",
				CAPath:          filepath.Join(dir, "absent-ca.crt"),
				CertificatePath: filepath.Join(dir, "absent.crt"),
				PrivateKeyPath:  filepath.Join(dir, "absent.key"),
				Timeout:         "5s",
			})}
		}},
		{"a private key readable by the group", func(t *testing.T, dir, socket string) []string {
			certPath, keyPath, caPath := writeIdentity(t, dir)
			if err := os.Chmod(keyPath, 0o640); err != nil {
				t.Fatal(err)
			}
			return []string{"-config", writeConfig(t, dir, config{
				SocketPath: socket, KMSURL: "https://kms.internal:8443", ServerName: "kms.internal",
				CAPath: caPath, CertificatePath: certPath, PrivateKeyPath: keyPath, Timeout: "5s",
			})}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			socket := shortSocketPath(t)

			err := runWithArgs(t, test.build(t, directory, socket)...)
			if err == nil {
				t.Fatalf("run() accepted %s", test.name)
			}
			// ONLY ErrNotExist COUNTS AS ABSENT. Accepting any stat error would let a permission
			// or I/O failure stand in for "no socket", which is the same defect this suite's own
			// journal-absence assertion had — fixed once today and reintroduced here.
			if _, statErr := os.Stat(socket); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("%s: stat %s = %v, want ErrNotExist. A socket left behind means SOPS connects to a sidecar that is not serving and gets a hang rather than a clear absence; any other error means this was never established",
					test.name, socket, statErr)
			}
		})
	}
}

// TestVersionNeedsNoConfigurationAndServesNothing. `-version` is what a deployment runs to record
// what it installed, often before any configuration exists. It must not require one, and it must
// not open a socket on the way to printing a string.
func TestVersionNeedsNoConfigurationAndServesNothing(t *testing.T) {
	socket := shortSocketPath(t)

	if err := runWithArgs(t, "-version"); err != nil {
		t.Fatalf("run(-version) error = %v: recording the installed version must not need a configuration", err)
	}
	if _, err := os.Stat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %s = %v, want ErrNotExist: -version must open no socket", socket, err)
	}
}

func TestAMissingConfigurationSaysSoRatherThanDefaulting(t *testing.T) {
	err := runWithArgs(t)
	if err == nil {
		t.Fatal("run() with no -config started")
	}
	// Named, because the alternative an operator will assume is that some default path was tried.
	if !strings.Contains(err.Error(), "configuration is required") {
		t.Fatalf("error = %q, want it to say the configuration is required", err)
	}
}
