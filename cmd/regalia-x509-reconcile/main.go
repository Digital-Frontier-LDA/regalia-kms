// regalia-x509-reconcile checks synthetic PKI artifacts against a collector
// export and an independently authenticated collector head. It never signs.
package main

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
)

type artifactPaths []string

func (paths *artifactPaths) String() string { return "artifact files" }
func (paths *artifactPaths) Set(path string) error {
	if len(*paths) >= audit.MaxX509Artifacts {
		return errors.New("too many artifacts")
	}
	*paths = append(*paths, path)
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, output, diagnostics io.Writer) int {
	flags := flag.NewFlagSet("regalia-x509-reconcile", flag.ContinueOnError)
	// Flag parsing can echo invalid values. Keep operator inputs out of diagnostics.
	flags.SetOutput(io.Discard)
	var config audit.X509ReconcileConfig
	var paths artifactPaths
	streamPath := flags.String("audit-stream", "", "collector export from genesis")
	issuerPath := flags.String("issuer", "", "trusted issuing certificate (DER or one PEM block)")
	flags.Uint64Var(&config.ExpectedSequence, "expected-sequence", 0, "independently authenticated collector sequence")
	flags.StringVar(&config.ExpectedHash, "expected-hash", "", "independently authenticated collector head hash")
	flags.StringVar(&config.ProfileID, "profile", "", "expected server issuing profile")
	flags.StringVar(&config.ObjectID, "object", "", "expected CA object")
	flags.StringVar(&config.Purpose, "purpose", "", "expected signing purpose")
	flags.StringVar(&config.KeyFingerprint, "key-fingerprint", "", "expected sha256 issuing SPKI pin")
	flags.Var(&paths, "artifact", "certificate or CRL file; repeat for each artifact")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			flags.SetOutput(diagnostics)
			fmt.Fprintln(diagnostics, "Usage: regalia-x509-reconcile [flags]")
			flags.PrintDefaults()
			return 0
		}
		fmt.Fprintln(diagnostics, "command arguments refused; use -help for the input contract")
		return 2
	}
	if flags.NArg() != 0 || *streamPath == "" || *issuerPath == "" || config.ExpectedSequence == 0 || config.ExpectedHash == "" || config.ProfileID == "" || config.ObjectID == "" || config.Purpose == "" || config.KeyFingerprint == "" {
		fmt.Fprintln(diagnostics, "required: collector export, trusted issuer/profile/object/purpose/key pin and independently authenticated nonempty collector head")
		return 2
	}
	issuer, err := readDER(*issuerPath, "CERTIFICATE")
	if err != nil {
		fmt.Fprintln(diagnostics, "issuer input refused")
		return 2
	}
	config.IssuerDER = issuer
	artifacts := make([][]byte, len(paths))
	for i, path := range paths {
		artifacts[i], err = readDER(path, "CERTIFICATE", "X509 CRL")
		if err != nil {
			fmt.Fprintln(diagnostics, "artifact input refused")
			return 2
		}
	}
	stream, err := regularFile(*streamPath)
	if err != nil {
		fmt.Fprintln(diagnostics, "collector export input refused")
		return 2
	}
	defer stream.Close()
	report, err := audit.ReconcileX509(stream, config, artifacts)
	if err != nil {
		fmt.Fprintln(diagnostics, "reconciliation refused: collector anchor, signed artifact or input contract failed")
		return 2
	}
	if err := json.NewEncoder(output).Encode(report); err != nil {
		fmt.Fprintln(diagnostics, "report output failed")
		return 2
	}
	if report.Status != "consistent" {
		return 1
	}
	return 0
}

func regularFile(path string) (*os.File, error) {
	// A named pipe must not block before the regular-file check can refuse it.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("input must be a regular file")
	}
	return file, nil
}

func readDER(path string, types ...string) ([]byte, error) {
	file, err := regularFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, audit.MaxX509ArtifactBytes+1))
	if err != nil || len(data) == 0 || len(data) > audit.MaxX509ArtifactBytes {
		return nil, errors.New("invalid input size")
	}
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		block, rest := pem.Decode(trimmed)
		if block == nil || bytes.Count(trimmed, []byte("-----BEGIN")) != 1 || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
			return nil, errors.New("expected one PEM block")
		}
		for _, allowed := range types {
			if block.Type == allowed {
				return block.Bytes, nil
			}
		}
		return nil, errors.New("unexpected PEM type")
	}
	return data, nil
}
