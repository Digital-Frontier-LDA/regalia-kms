package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sopsadapter "github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops"
)

// EVERY REFUSAL HERE IS ASSERTED BY ITS OWN MESSAGE, NOT BY err != nil.
//
// Start-up is a chain of refusals -- read the file, decode it, validate it, load the identity,
// build the TLS client -- and almost any bad input errors somewhere along it. A test that only
// asks "did it error" therefore stays green when a guard stops working, because the next one down
// the chain answers for it. Each test below names the exact message it expects and its fixture is
// built so that one guard is the only thing that can produce it.
//
// One message is a prefix of another -- the mode refusal is "unsafe protected file" and the owner
// refusal is "unsafe protected file owner" -- so equality is used rather than strings.Contains
// wherever the two could be confused.

// TestLoadConfigNamesTheReadItCouldNotDo covers the wrapper loadConfig puts on readProtected's
// error.
//
// Without it loadConfig carries on with the nil buffer readProtected returns on every failure and
// hands it to the decoder, which fails on the empty input -- so a configuration that could not be
// OPENED (absent, unopenable, owned by another account, larger than 16 KiB, a relative path that
// never named a file at all) is reported as "invalid sidecar configuration". That sends an operator
// to hunt for a typo inside a file this process never managed to read. The wrapper is also the only
// place the cause survives: the decoder's own error is deliberately discarded on the line below it,
// so "read sidecar configuration: <cause>" is the entire diagnosis the operator gets.
func TestLoadConfigNamesTheReadItCouldNotDo(t *testing.T) {
	directory := t.TempDir()
	for _, test := range []struct {
		name  string
		path  string
		wants string
	}{
		{"a configuration that does not exist", filepath.Join(directory, "absent.json"), "read sidecar configuration: open protected file"},
		// A relative path is refused before any syscall, so this reaches the wrapper by a
		// different route than the one above and pins that the cause is passed through rather
		// than replaced by a fixed string.
		{"a relative configuration path", "sidecar.json", "read sidecar configuration: invalid protected file"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadConfig(test.path)
			if err == nil {
				t.Fatalf("loadConfig(%q) succeeded", test.path)
			}
			if err.Error() != test.wants {
				t.Fatalf("loadConfig(%q) error = %q, want %q. Anything mentioning the CONTENTS of the file is wrong: this file was never read, and an operator told the document is invalid will go looking for a typo in it",
					test.path, err, test.wants)
			}
		})
	}

	// KNOWN GOOD, LAST: a readable, well-formed configuration at the same kind of path loads, so
	// the refusals above are about the read and not about this fixture being unloadable anyway.
	// Placed after the assertions deliberately -- a t.Fatal here first would foreclose them.
	t.Run("known good: a readable configuration loads", func(t *testing.T) {
		path := writeConfig(t, t.TempDir(), validSidecarConfig(filepath.Join(directory, "s.sock"), directory))
		if _, err := loadConfig(path); err != nil {
			t.Fatalf("loadConfig(%q) error = %v", path, err)
		}
	})
}

// TestAConfigurationFileMustHoldExactlyOneDocument covers the second Decode, the one that requires
// io.EOF after the configuration object.
//
// encoding/json stops at the end of the first value. Without this guard everything after it is
// silently ignored, so `{...}{"socket_path":"/run/attacker.sock"}` loads as the first document and
// the file an operator (or a reviewer, or a diff) reads to the bottom is not the file the process
// obeyed. The disagreement is invisible from both ends: the loader never mentions the tail and the
// tail never reaches validate().
func TestAConfigurationFileMustHoldExactlyOneDocument(t *testing.T) {
	const wants = "sidecar configuration must contain one JSON document"
	first := encodeSidecarConfig(t, validSidecarConfig("/run/regalia-sops-kms/service.sock", "/run/credentials"))

	for _, test := range []struct {
		name string
		tail string
	}{
		{"a second configuration document", `{"socket_path":"/run/attacker.sock"}`},
		{"a second document that is only a fragment", `{`},
		{"trailing text that is not JSON at all", `and then some notes`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sidecar.json")
			if err := os.WriteFile(path, append(append([]byte{}, first...), []byte("\n"+test.tail+"\n")...), 0o600); err != nil {
				t.Fatal(err)
			}
			settings, err := loadConfig(path)
			if err == nil {
				t.Fatalf("loadConfig accepted a file with %s and returned socket_path %q: the first document won and the rest of the file was never looked at, so what an operator reads is not what the sidecar runs",
					test.name, settings.SocketPath)
			}
			if err.Error() != wants {
				t.Fatalf("%s: error = %q, want %q", test.name, err, wants)
			}
		})
	}

	// KNOWN GOOD, LAST: the same first document on its own -- with the trailing newline the tails
	// above were appended after -- loads. Otherwise every case above could be passing because the
	// document itself is unloadable.
	t.Run("known good: the first document alone loads", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sidecar.json")
		if err := os.WriteFile(path, append(append([]byte{}, first...), '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		settings, err := loadConfig(path)
		if err != nil {
			t.Fatalf("loadConfig(one document) error = %v", err)
		}
		if settings.SocketPath != "/run/regalia-sops-kms/service.sock" {
			t.Fatalf("socket_path = %q, want the value in the one document present", settings.SocketPath)
		}
	})
}

// TestACredentialOwnedByAnotherAccountIsRefused covers the Fstat owner check in readProtected.
//
// Without it the sidecar reads whatever is at the configured path as long as the MODE is tight
// enough -- and 0644 is a perfectly ordinary mode for a certificate or a CA bundle, so the mode
// check below cannot see this at all. Any account that can create a file where a credential path
// points (an unpacked archive, a shared /run tree, a compromised service account) then supplies the
// KMS trust roots: the sidecar accepts a CA of the attacker's choosing, and the mTLS handshake it
// performs afterwards verifies the impostor's certificate correctly. The owner check is the only
// thing between those two facts.
//
// THE FIXTURE NEEDS A PRIVILEGE THIS TEST MAY NOT HAVE. A file owned by a uid that is neither root
// nor the caller cannot be created by an unprivileged process -- chown(2) to another owner needs
// root -- so this skips when the chown is refused rather than pretending. Measured on darwin as uid
// 501: os.Chown returns "operation not permitted". Falsified as root on linux/arm64, where the
// fixture is buildable.
func TestACredentialOwnedByAnotherAccountIsRefused(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "ca.crt")
	const contents = "-----BEGIN CERTIFICATE-----\n"
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	// KNOWN GOOD FIRST, and unconditionally, because the refusal below is privilege-gated and
	// skips on an ordinary CI runner. Placed after the skip -- where it was -- the WHOLE test
	// became a no-op there: it neither proved the guard fires nor that it lets a legitimate file
	// through, while still reporting as a skip rather than as a gap. This half needs no
	// privilege and runs everywhere, so a guard that refused every file is caught even where the
	// owner arm cannot be exercised.
	if read, err := readProtected(path, 1<<10, false); err != nil || string(read) != contents {
		t.Fatalf("readProtected(a 0644 file we own) = %q, %v; want it read", read, err)
	}

	// A uid that is neither 0 (accepted by the guard) nor ours (also accepted). Only a third
	// account can reach the refusal, and creating a file owned by one needs privilege -- so on an
	// unprivileged runner this arm is unreachable, not merely untested. The skip says so.
	foreign := 12345
	if os.Geteuid() == foreign {
		foreign++
	}
	if err := os.Chown(path, foreign, -1); err != nil {
		t.Skipf("cannot give %s to uid %d (%v): the owner arm needs a file owned by a THIRD account (uid 0 and our own uid are both accepted by the guard), which is unreachable without privilege. The known-good above still ran; the refusal arm did not.", path, foreign, err)
	}

	// Equality, not strings.Contains: the mode refusal is "unsafe protected file", which is a
	// prefix of this one, and Contains could not tell a mode failure from an owner failure. The
	// mode here is 0644 -- no group or world write, and this is not a secret -- so the owner arm
	// is the only thing in readProtected that can refuse this file.
	const wants = "unsafe protected file owner"
	if _, err := readProtected(path, 1<<10, false); err == nil || err.Error() != wants {
		t.Fatalf("readProtected(a 0644 file owned by uid %d) error = %v, want %q: a credential planted by another account was accepted as this workload's own", foreign, err, wants)
	}

	// Given back to us it is read again -- so the refusal above was about the owner and not about
	// something the chown incidentally changed.
	if err := os.Chown(path, os.Geteuid(), -1); err != nil {
		t.Fatal(err)
	}
	if read, err := readProtected(path, 1<<10, false); err != nil || string(read) != contents {
		t.Fatalf("readProtected(the same file, owned by us again) = %q, %v; want it read", read, err)
	}
}

// TestRunSurfacesTheRefusalOfTheStageThatFailed covers the three `if err != nil { return err }` in
// run(): after loadConfig, after identity() and after NewMTLSHTTPClient.
//
// They look like boilerplate and they are not. Measured, with each one replaced by a constant:
// without the first, run() carries on with the ZERO config -- every path empty, no URL, no timeout
// -- and dies at the identity load, so a missing or unreadable configuration file is reported as
// "workload identity unavailable" and the operator reissues a certificate that was never the
// problem. Without the second, a missing certificate produces "invalid KMS TLS configuration" from
// the transport, which points at the wrong file again. Without the third, run() carries the nil
// client NewMTLSHTTPClient returned into NewHTTPClient and on into ServeUnix: on a host where the
// runtime directory exists, that is a sidecar that LISTENS -- SOPS connects, the socket is there,
// nothing in the journal says otherwise -- and refuses every wrap and unwrap it is given, because
// HTTPClient.call rejects a client with no transport. Refusing to start is the whole point; a
// socket that answers nothing is the failure TestNoRefusalLeavesASocketBehind exists to prevent.
//
// Each row's expectation is taken from the stage itself rather than written out as a literal, so
// what is pinned is "run() returns THIS STAGE's error", not the current wording of any message. A
// test that spelled the message out would go red when the loader's wording changes and stay green
// if run() started returning some other stage's error, which is precisely backwards.
func TestRunSurfacesTheRefusalOfTheStageThatFailed(t *testing.T) {
	for _, test := range []struct {
		name  string
		build func(t *testing.T, dir string) (configPath, want string)
	}{
		{"the configuration cannot be read", func(t *testing.T, dir string) (string, string) {
			path := filepath.Join(dir, "absent.json")
			_, err := loadConfig(path)
			if err == nil {
				t.Fatal("loadConfig accepted a path that does not exist, so this row cannot test what run() does with its refusal")
			}
			return path, err.Error()
		}},
		{"the workload identity cannot be loaded", func(t *testing.T, dir string) (string, string) {
			// The key and the CA are real and readable; only the certificate is missing, so the
			// stage that refuses is unambiguous.
			_, keyPath, caPath := writeIdentity(t, dir)
			settings := validSidecarConfig(filepath.Join(dir, "absent-dir", "s.sock"), dir)
			settings.CAPath, settings.PrivateKeyPath = caPath, keyPath
			settings.CertificatePath = filepath.Join(dir, "absent.crt")
			_, _, err := settings.identity()
			if err == nil {
				t.Fatal("identity() accepted a missing certificate, so this row cannot test what run() does with its refusal")
			}
			return writeConfig(t, dir, settings), err.Error()
		}},
		{"the TLS client cannot be built", func(t *testing.T, dir string) (string, string) {
			certPath, keyPath, caPath := writeIdentity(t, dir)
			settings := validSidecarConfig(filepath.Join(dir, "absent-dir", "s.sock"), dir)
			settings.CAPath, settings.CertificatePath, settings.PrivateKeyPath = caPath, certPath, keyPath
			// validate() forbids "/", ":" and "@" in server_name; ClientTLSConfig also forbids a
			// backslash. That gap is the only way a configuration that LOADS can still fail to
			// produce a TLS client, and it is the same shape of divergence the kms_url comment in
			// config.go describes: one rule, two implementations, two answers.
			settings.ServerName = `kms\internal`
			timeout, err := settings.validate()
			if err != nil {
				t.Fatalf("the fixture no longer loads (%v), so it never reaches the transport", err)
			}
			certificate, roots, err := settings.identity()
			if err != nil {
				t.Fatalf("the fixture's identity no longer loads (%v), so it never reaches the transport", err)
			}
			_, err = sopsadapter.NewMTLSHTTPClient(certificate, roots, settings.ServerName, timeout)
			if err == nil {
				t.Fatal("NewMTLSHTTPClient accepted the fixture, so this row cannot test what run() does with its refusal")
			}
			return writeConfig(t, dir, settings), err.Error()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			configPath, want := test.build(t, directory)
			err := runWithArgs(t, "-config", configPath)
			if err == nil {
				t.Fatalf("run() started with %s", test.name)
			}
			if err.Error() != want {
				t.Fatalf("%s: run() error = %q, want the stage's own error %q. A later stage answered for this one, so the message names the wrong file",
					test.name, err, want)
			}
		})
	}

	// KNOWN GOOD ANCHOR, LAST: the same builder with nothing spoiled gets all the way past the
	// loader, the identity and the transport, and stops only because the socket's parent directory
	// does not exist. That is what makes the rows above attributable: the fixture is refused by the
	// stage each row spoils and by nothing else on the way there.
	//
	// The missing directory is also what keeps this test bounded. run() ends in ServeUnix, which
	// blocks until the context is cancelled; a mutation that lets a refusal through would hang here
	// rather than fail, so every fixture in this test names a socket under a directory that is not
	// there and ServeUnix refuses immediately.
	t.Run("known good: every stage accepts and only the socket directory is missing", func(t *testing.T) {
		directory := t.TempDir()
		certPath, keyPath, caPath := writeIdentity(t, directory)
		settings := validSidecarConfig(filepath.Join(directory, "absent-dir", "s.sock"), directory)
		settings.CAPath, settings.CertificatePath, settings.PrivateKeyPath = caPath, certPath, keyPath
		err := runWithArgs(t, "-config", writeConfig(t, directory, settings))
		if err == nil {
			t.Fatal("run() returned no error: it cannot have reached ServeUnix, whose directory is missing")
		}
		if !strings.Contains(err.Error(), "SOPS socket directory") {
			t.Fatalf("run() error = %q, want the socket directory to be the only thing left to refuse a complete configuration", err)
		}
	})
}

// validSidecarConfig returns a configuration every check in validate() accepts. Credential paths
// are placed in dir but are NOT created: loadConfig and validate() never open them, so a row that
// wants them present writes them itself.
func validSidecarConfig(socketPath, dir string) config {
	return config{
		SocketPath:      socketPath,
		KMSURL:          "https://kms.internal:8443",
		ServerName:      "kms.internal",
		CAPath:          filepath.Join(dir, "ca.crt"),
		CertificatePath: filepath.Join(dir, "client.crt"),
		PrivateKeyPath:  filepath.Join(dir, "client.key"),
		Timeout:         "15s",
	}
}

func encodeSidecarConfig(t *testing.T, cfg config) []byte {
	t.Helper()
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var probe config
	if err := json.Unmarshal(encoded, &probe); err != nil || probe != cfg {
		t.Fatalf("the encoded configuration does not round-trip (%v), so the document under test is not the one described", err)
	}
	if _, err := probe.validate(); err != nil {
		t.Fatalf("the first document does not validate (%v): a test for the SECOND document would then be passing for the wrong reason", err)
	}
	return encoded
}
