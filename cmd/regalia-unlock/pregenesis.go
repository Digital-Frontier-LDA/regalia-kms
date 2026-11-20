package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

const stubCredentials = "/.extra/global_credentials"
const stubSiteCredential = stubCredentials + "/regalia.site.cred"
const espCredentials = "loader/credentials"

// The condition's environment factory is replaceable in tests; the real command always uses
// the same fixed paths and TPM transport as the renderer.
var renderEnvForCheck = realRenderEnv

// /run is volatile and shared across the initrd units. A skipped render loses its
// RuntimeDirectory, so keep the decision outside /run/regalia-boot.
var preGenesisMarker = "/run/regalia-pre-genesis"

// ExecCondition runs without credential setup in systemd v257, unlike ExecStart. Keep this
// separate from -render: a credential removed after this check must fail in ExecStart, not skip.
// Only exit 1 is an expected skip; errors MUST be 255 (1..254 are non-failing to systemd).
func runRenderCheck(arguments []string, diagnostics io.Writer) int {
	tpmPath := "/dev/tpmrm0"
	if len(arguments) == 3 && arguments[1] == "-tpm" && arguments[2] != "" {
		tpmPath = arguments[2]
	} else if len(arguments) != 1 {
		fmt.Fprintln(diagnostics, "regalia-unlock: usage: -render-check [-tpm DEVICE]")
		return 255
	}
	if err := os.Remove(preGenesisMarker); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(diagnostics, "regalia-unlock: cannot reset pre-genesis decision: %v; boot render refused\n", err)
		return 255
	}
	return renderCondition(renderEnvForCheck(tpmPath), diagnostics)
}

func renderCondition(env renderEnv, diagnostics io.Writer) int {
	skip, err := preGenesis(env)
	if err != nil {
		fmt.Fprintf(diagnostics, "regalia-unlock: %v; boot render refused\n", err)
		return 255
	}
	if skip {
		// O_EXCL publishes an empty marker atomically in the root-owned /run.
		marker, err := os.OpenFile(preGenesisMarker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			err = marker.Close()
		}
		if err != nil {
			fmt.Fprintf(diagnostics, "regalia-unlock: cannot publish pre-genesis decision: %v; boot render refused\n", err)
			return 255
		}
		fmt.Fprintln(diagnostics, "regalia-unlock: no site credential: expected pre-genesis skip (ESP/stub enrolment state and TPM anchors absent)")
		return 1
	}
	return 0
}

// Both consumers are ordered after render. A missing marker lets systemd proceed
// to credential setup. The consumer sandbox needs only a stat of the marker.
func runConsumerCheck(arguments []string, diagnostics io.Writer) int {
	if len(arguments) != 2 || (arguments[1] != "wg-boot" && arguments[1] != "unlock") {
		fmt.Fprintln(diagnostics, "regalia-unlock: usage: -consumer-check {wg-boot|unlock}")
		return 255
	}
	unit := "regalia-" + arguments[1]
	info, err := os.Lstat(preGenesisMarker)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(diagnostics, "%s: cannot read pre-genesis decision: %v\n", unit, err)
		return 255
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode() != 0o600 || info.Size() != 0 || stat.Uid != uint32(os.Geteuid()) {
		fmt.Fprintf(diagnostics, "%s: invalid pre-genesis decision marker\n", unit)
		return 255
	}
	fmt.Fprintf(diagnostics, "%s: expected pre-genesis skip (verified by boot render)\n", unit)
	return 1
}

// A missing site alone proves nothing. Only absent ESP/stub enrolment artifacts AND a successful
// TPM inventory with none of the reader's four anchor indices prove the expected initial state.
func preGenesis(env renderEnv) (bool, error) {
	present, err := env.present(stubSiteCredential)
	if err != nil {
		return false, errors.New("site credential presence cannot be checked")
	}
	if present {
		return false, nil // ExecStart's credential setup and site validation still fail closed.
	}
	stubState, err := directoryHasEntries(env, stubCredentials)
	if err != nil {
		return false, errors.New("missing site credential: stub enrolment state cannot be checked")
	}
	if stubState {
		return false, errors.New("missing site credential on an enrolled node: stub enrolment state is present")
	}
	device, err := espDevice(env)
	if err != nil {
		return false, errors.New("missing site credential: the ESP cannot be located; pre-genesis is unproven")
	}
	err = withESP(env, device, func(dir string) error {
		chain, err := env.present(filepath.Join(dir, chainOnESP))
		if err != nil {
			return errors.New("ESP membership presence cannot be checked")
		}
		if chain {
			return errors.New("missing site credential on an enrolled node: ESP membership state is present")
		}
		credentials, err := directoryHasEntries(env, filepath.Join(dir, espCredentials))
		if err != nil {
			return errors.New("ESP loader credentials cannot be checked")
		}
		if credentials {
			return errors.New("missing site credential on an enrolled node: ESP loader credentials are present")
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	nv, closeNV, err := env.nv()
	if err != nil {
		return false, errors.New("missing site credential: TPM cannot be opened; pre-genesis is unproven")
	}
	defer closeNV()
	anchor, err := membership.AnchorPresent(nv)
	if err != nil {
		return false, errors.New("missing site credential: TPM NV inventory cannot be read; pre-genesis is unproven")
	}
	if anchor {
		return false, errors.New("missing site credential on an enrolled node: TPM anchor state is present")
	}
	return true, nil
}

func directoryHasEntries(env renderEnv, path string) (bool, error) {
	present, err := env.present(path)
	if err != nil || !present {
		return false, err
	}
	entries, err := env.readDir(path)
	return len(entries) != 0, err // A dangling link or unreadable directory is an error, not absence.
}
