package main

// Round two of the mutation sweep of this package (#237).
//
// 162 sites / 175 operands / 350 operand-directions, measured both directions against this
// package's own tests, which are the only detector — it is `package main`, so nothing else
// can see these symbols. 124 operands survived in at least one direction and 71 survived in
// BOTH, which is a different profile from every package swept so far and points at whole
// functions rather than at scattered operands:
//
//	run()                        34 both-direction survivors, and exactly ONE test drives it,
//	                             with one fixture (a bare invocation)
//	preflight()                  15, and it IS driven by 13 tests -- the fixtures do not
//	                             discriminate, which is a different defect from not being called
//	buildHardware()              10, called from NO test
//	exportControlPlaneState()     6, called from NO test
//	inspectControlPlaneExport()   5, called from NO test
//
// This file closes the reachable subset of that pool: the entrypoint's own refusals, which
// are what stand between a mistyped runbook step and a daemon that comes up misconfigured
// rather than refusing to come up.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// driveRun runs the real entry point with the given command line, restoring the globals it
// swaps. Same technique as TestABareInvocationIsRefusedRatherThanPanicking, and the same
// reason: run() declares its flags on the default flag.CommandLine, so a test that left
// either replaced would break every test that ran after it.
func driveRun(t *testing.T, args ...string) error {
	t.Helper()
	directory := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(directory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })

	savedArgs, savedFlags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = savedArgs, savedFlags })
	os.Args = append([]string{"regalia-kms"}, args...)
	flag.CommandLine = flag.NewFlagSet("regalia-kms", flag.ContinueOnError)
	flag.CommandLine.SetOutput(os.Stderr)

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("run(%v) panicked: %v — an operator who mistypes a runbook step must get a sentence, not a stack trace", args, recovered)
		}
	}()
	return run()
}

// TestTheEntrypointRefusesAFlagCombinationTheRunbookMustGetRight covers main.go:100
// (`*authorityKeyPEM == ""`), main.go:129 operand 1 (`*configPath == ""`) and main.go:147
// (`*exportRecipientPEM == ""`).
//
// A flag the binary requires must be a flag the runbook passes — the shape #256/#274 already
// found here once. All three of these guards survived the sweep in BOTH directions, meaning
// no test drove either arm: neither the refusal nor the acceptance was exercised.
//
// Each row names one flag pairing and asserts the message, because the message is what tells
// an operator which flag is missing. Deleting the operand does not make these calls succeed —
// it makes them fail LATER and differently, reading a path from an empty string, so an
// `err != nil` assertion would pass over the deletion in silence.
//
// Falsifier: `(false && (*authorityKeyPEM == ""))` and the equivalent for each other row.
func TestTheEntrypointRefusesAFlagCombinationTheRunbookMustGetRight(t *testing.T) {
	for _, row := range []struct {
		name string
		args []string
		want string
	}{
		{
			"inspecting an export without the key that opens it",
			[]string{"-inspect-export", "/nonexistent/export.bin"},
			"-inspect-export requires -authority-key-pem",
		},
		{
			"checking a configuration without naming one",
			[]string{"-check-config"},
			"-check-config requires -config",
		},
		{
			"exporting without the custody key to seal to",
			[]string{"-export-control-plane", "/nonexistent/out.bin"},
			"-export-control-plane requires -export-recipient-pem",
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := driveRun(t, row.args...)
			if err == nil {
				t.Fatalf("run(%v) was accepted", row.args)
			}
			if err.Error() != row.want {
				t.Fatalf("run(%v) = %q,\nwant %q — any other refusal means the flag-pairing guard "+
					"did not fire and this test is not checking what it names", row.args, err, row.want)
			}
		})
	}
}

func writeP256(t *testing.T, directory, name string, private bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if private {
		encoded, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "PRIVATE KEY", Bytes: encoded}
	} else {
		encoded, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		block = &pem.Block{Type: "PUBLIC KEY", Bytes: encoded}
	}
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestInspectingAnExportNamesWhichInputItCouldNotRead covers main.go:807 (`err != nil` on
// reading the authority key), :811 (parsing it), :815 (reading the export) and :819
// (InspectForSite).
//
// inspectControlPlaneExport is called from no test at all, so all five of its operands
// survived in both directions. It is the offline verdict a ceremony host runs before a
// restore, which makes "which input was wrong" the whole content of a failure: the operator
// is holding a key file and an export file and needs to know which one is the problem.
//
// Falsifier: `(false && (err != nil))` at each site. The refusal then moves to the next
// guard and the message names the wrong input — the read-key row starts reporting a parse
// failure over empty bytes.
func TestInspectingAnExportNamesWhichInputItCouldNotRead(t *testing.T) {
	directory := t.TempDir()
	goodKey := writeP256(t, directory, "authority.pem", true)
	garbage := filepath.Join(directory, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a pem file at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	goodExport := filepath.Join(directory, "export.bin")
	if err := os.WriteFile(goodExport, []byte("not an envelope"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name     string
		envelope string
		key      string
		want     string
	}{
		{"the authority key file is not there", goodExport, filepath.Join(directory, "absent.pem"), "read authority key:"},
		{"the authority key file is not a key", goodExport, garbage, "authority key"},
		{"the export file is not there", filepath.Join(directory, "absent.bin"), goodKey, "read export:"},
		{"the export file is not an envelope", goodExport, goodKey, "controlplane"},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := inspectControlPlaneExport(row.envelope, row.key, "")
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), row.want) {
				t.Fatalf("err = %q, want it to name %q — an operator holding two files needs to "+
					"know which one is the problem", err, row.want)
			}
		})
	}
}

// TestExportingNamesWhichInputItCouldNotRead covers main.go:765 (`err != nil` on reading the
// recipient key), :769 (parsing it) and :790 (writing the envelope).
//
// exportControlPlaneState is called from no test either. It runs as the kms user against the
// live journals, and a failure that does not say which side went wrong sends an operator to
// the wrong host.
//
// The write row is the one worth having: everything before it succeeded, so a run that
// cannot persist its output must say so rather than printing the summary lines that follow
// and letting the ceremony proceed on a file that is not there.
//
// Falsifier: `(false && (err != nil))` at each site.
func TestExportingNamesWhichInputItCouldNotRead(t *testing.T) {
	directory := t.TempDir()
	garbage := filepath.Join(directory, "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a pem file at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name      string
		recipient string
		want      string
	}{
		{"the recipient key file is not there", filepath.Join(directory, "absent.pem"), "read recipient key:"},
		{"the recipient key file is not a key", garbage, "recipient key"},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := exportControlPlaneState(config.Default(), filepath.Join(directory, "out.bin"), row.recipient, "")
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), row.want) {
				t.Fatalf("err = %q, want it to name %q", err, row.want)
			}
		})
	}
}
