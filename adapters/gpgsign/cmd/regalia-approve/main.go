// Command regalia-approve is the approver's half of a release signature made under a policy that
// requires approval (regalia#530). regalia-sign --prepare writes a pending record; this reads it,
// checks it against the approver's own copy of the file, signs its binding with the approver's
// Ed25519 key, and writes the approval regalia-sign --complete sends to the KMS.
//
// It holds no workload identity and never contacts the KMS.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/gpgsign"
	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/gpgsign/internal/protected"
)

const usage = `usage:
  regalia-approve [--config FILE] --pending PENDING --file FILE [--output APPROVAL]
  regalia-approve [--config FILE] --pending PENDING --unseen   [--output APPROVAL]
--file is the approver's own copy of what is being signed. The pending record is checked to be a
signature over exactly that file before anything is signed. A key export needs no file.
--unseen approves the record without that check: the file hash it shows is then only what the
preparer wrote.
--config defaults to $REGALIA_APPROVE_CONFIG. The approval is written to PENDING.approval, or to
--output; an existing file is never replaced.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv, time.Now))
}

// config is what the approver pins on their own machine. Nothing in it comes from the preparer.
type config struct {
	// ApproverID is the identity the KMS's approver_keys file maps to this key.
	ApproverID string `json:"approver_id"`
	// ApproverPublicKeyPath is the approver key's public half (PEM, "PUBLIC KEY", Ed25519). Whatever
	// the device returns is verified against it, so a device or applet that does not make a plain
	// Ed25519 signature with this key is refused here and not discovered as a denial at the KMS.
	ApproverPublicKeyPath string `json:"approver_public_key_path"`

	// Exactly one of the two. PKCS11 is a hardware key through OpenSC's pkcs11-tool; KeyFile is an
	// Ed25519 private key on disk (PEM, PKCS#8), which is a software approver: for tests and staging.
	PKCS11  *pkcs11Config `json:"pkcs11,omitempty"`
	KeyFile string        `json:"key_file,omitempty"`

	// What this approver approves for. A pending record for any other key, object, purpose or
	// environment is refused.
	ObjectID      string `json:"object_id"`
	Environment   string `json:"environment"`
	Purpose       string `json:"purpose"`
	PublicKeyPath string `json:"public_key_path"`
	KeyCreated    string `json:"key_created"`
	UserID        string `json:"user_id"`
}

type pkcs11Config struct {
	Tool       string `json:"tool"`        // absolute path of pkcs11-tool
	Module     string `json:"module"`      // absolute path of the PKCS#11 module
	TokenLabel string `json:"token_label"` // e.g. "OpenPGP card (User PIN (sig))"
	KeyID      string `json:"key_id"`      // CKA_ID, hex
}

func loadConfig(path string) (config, error) {
	contents, err := protected.Read(path, 16<<10, false)
	if err != nil {
		return config{}, fmt.Errorf("read the configuration: %w", err)
	}
	var result config
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return config{}, errors.New("the configuration is not the expected JSON document")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return config{}, errors.New("the configuration must contain one JSON document")
	}
	absolute := func(value string) bool { return filepath.IsAbs(value) && filepath.Clean(value) == value }
	if strings.TrimSpace(result.ApproverID) == "" || result.ObjectID == "" || result.Purpose == "" || result.Environment == "" || strings.TrimSpace(result.UserID) == "" {
		return config{}, errors.New("approver_id, object_id, environment, purpose and user_id are required")
	}
	if !absolute(result.ApproverPublicKeyPath) || !absolute(result.PublicKeyPath) {
		return config{}, errors.New("configuration paths must be absolute and clean")
	}
	if (result.PKCS11 == nil) == (result.KeyFile == "") {
		return config{}, errors.New("configure exactly one of pkcs11 and key_file")
	}
	if result.KeyFile != "" && !absolute(result.KeyFile) {
		return config{}, errors.New("configuration paths must be absolute and clean")
	}
	if device := result.PKCS11; device != nil {
		id, err := hex.DecodeString(device.KeyID)
		if !absolute(device.Tool) || !absolute(device.Module) || device.TokenLabel == "" || err != nil || len(id) == 0 {
			return config{}, errors.New("pkcs11 needs absolute tool and module paths, a token_label and a hex key_id")
		}
	}
	return result, nil
}

// releaseKey is the release key as the approver pins it, with no KMS behind it.
func (cfg config) releaseKey() (*gpgsign.Key, error) {
	created, err := time.Parse("2006-01-02T15:04:05Z", cfg.KeyCreated)
	if err != nil {
		return nil, errors.New("key_created must be a UTC time such as 2026-10-02T00:00:00Z")
	}
	public, err := protected.PublicKey(cfg.PublicKeyPath, "the release public key", "public_key_path")
	if err != nil {
		return nil, err
	}
	signer, err := gpgsign.NewOfflineSigner(public, gpgsign.Target{ObjectID: cfg.ObjectID, Environment: cfg.Environment, Purpose: cfg.Purpose})
	if err != nil {
		return nil, err
	}
	return gpgsign.NewKey(signer, created, cfg.UserID)
}

// approver returns the approver key as a crypto.Signer whose public half is the pinned one.
func (cfg config) approver(ctx context.Context, stdin io.Reader, stderr io.Writer, getenv func(string) string) (crypto.Signer, error) {
	pinned, err := protected.PublicKey(cfg.ApproverPublicKeyPath, "the approver public key", "approver_public_key_path")
	if err != nil {
		return nil, err
	}
	public, ok := pinned.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("the approver key must be Ed25519: the KMS verifies approvals with nothing else")
	}
	if cfg.KeyFile != "" {
		contents, err := protected.Read(cfg.KeyFile, 16<<10, true)
		if err != nil {
			return nil, errors.New("the approver key file is unavailable")
		}
		defer protected.Zero(contents)
		block, rest := pem.Decode(contents)
		if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, errors.New("key_file must hold exactly one PEM PRIVATE KEY")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		private, isEd25519 := parsed.(ed25519.PrivateKey)
		if err != nil || !isEd25519 || !private.Public().(ed25519.PublicKey).Equal(public) {
			return nil, errors.New("key_file is not the Ed25519 private key of approver_public_key_path")
		}
		return private, nil
	}
	return &tokenSigner{ctx: ctx, device: *cfg.PKCS11, public: public, stdin: stdin, stderr: stderr, pinInEnvironment: getenv(pinVariable) != ""}, nil
}

// pinVariable, when set, holds the token PIN for a run with nobody at the keyboard (the tests).
// pkcs11-tool reads it from the environment itself; it is never put on a command line. Unset, the
// usual case, pkcs11-tool asks for the PIN on the terminal.
const pinVariable = "REGALIA_APPROVE_PIN"

// tokenSigner signs with a key on a PKCS#11 token by running OpenSC's pkcs11-tool. This module has
// no cgo and so no PKCS#11 binding of its own, and the PIN goes from the keyboard to OpenSC without
// passing through this process. What the tool returns is trusted for nothing: Approve verifies it
// against the pinned approver key.
type tokenSigner struct {
	ctx              context.Context
	device           pkcs11Config
	public           ed25519.PublicKey
	stdin            io.Reader
	stderr           io.Writer
	pinInEnvironment bool
}

func (signer *tokenSigner) Public() crypto.PublicKey { return signer.public }

func (signer *tokenSigner) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	directory, err := os.MkdirTemp("", "regalia-approve-")
	if err != nil {
		return nil, errors.New("create a working directory")
	}
	defer os.RemoveAll(directory)
	input, output := filepath.Join(directory, "binding"), filepath.Join(directory, "signature")
	if err := os.WriteFile(input, message, 0o600); err != nil {
		return nil, errors.New("write the binding")
	}
	arguments := []string{"--module", signer.device.Module, "--token-label", signer.device.TokenLabel, "--login",
		"--sign", "--mechanism", "EDDSA", "--id", signer.device.KeyID, "--input-file", input, "--output-file", output}
	if signer.pinInEnvironment {
		arguments = append(arguments, "--pin", "env:"+pinVariable)
	}
	fmt.Fprintln(signer.stderr, "regalia-approve: signing on the token; enter the PIN if asked, and touch the key if it blinks")
	// The program and module are absolute paths from the approver's own protected configuration, and
	// the arguments are a vector: no shell, and nothing from the pending record reaches them.
	command := exec.CommandContext(signer.ctx, signer.device.Tool, arguments...)
	command.Stdin, command.Stdout, command.Stderr = signer.stdin, signer.stderr, signer.stderr
	if err := command.Run(); err != nil {
		return nil, errors.New("the token did not sign")
	}
	signature, err := os.ReadFile(output)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errors.New("the token did not return an Ed25519 signature")
	}
	return signature, nil
}

type invocation struct {
	configPath, pending, file, output string
	unseen                            bool
}

func parse(args []string) (invocation, error) {
	var result invocation
	for index := 0; index < len(args); index++ {
		name, inline, hasInline := strings.Cut(args[index], "=")
		take := func() (string, error) {
			if hasInline {
				return inline, nil
			}
			if index+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", name)
			}
			index++
			return args[index], nil
		}
		var err error
		switch {
		case name == "--config":
			result.configPath, err = take()
		case name == "--pending":
			result.pending, err = take()
		case name == "--file":
			result.file, err = take()
		case name == "--output":
			result.output, err = take()
		case args[index] == "--unseen":
			result.unseen = true
		default:
			return result, fmt.Errorf("unknown argument %q", args[index])
		}
		if err != nil {
			return result, err
		}
	}
	if result.pending == "" {
		return result, errors.New("--pending is required")
	}
	if result.unseen && result.file != "" {
		return result, errors.New("--file and --unseen exclude each other")
	}
	return result, nil
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string, now func() time.Time) int {
	fail := func(code int, err error) int {
		fmt.Fprintf(stderr, "regalia-approve: %v\n", err)
		return code
	}
	request, err := parse(args)
	if err != nil {
		fmt.Fprint(stderr, usage)
		return fail(2, err)
	}
	if request.configPath == "" {
		request.configPath = getenv("REGALIA_APPROVE_CONFIG")
	}
	if request.configPath == "" {
		return fail(2, errors.New("no configuration: pass --config or set REGALIA_APPROVE_CONFIG"))
	}
	cfg, err := loadConfig(request.configPath)
	if err != nil {
		return fail(1, err)
	}
	if err := approve(cfg, request, stdin, stdout, stderr, getenv, now()); err != nil {
		return fail(1, err)
	}
	return 0
}

func approve(cfg config, request invocation, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string, at time.Time) error {
	record, err := os.ReadFile(request.pending)
	if err != nil {
		return errors.New("open the pending-signature file")
	}
	pending, err := gpgsign.ReadPending(record)
	if err != nil {
		return err
	}
	key, err := cfg.releaseKey()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// What is checked, in the order an approver would ask: is it my key and my target, is it a
	// signature over my copy of the file, and only then is anything signed.
	seen := "a key export, checked against the pinned key"
	var document []byte
	switch {
	case pending.Mode == gpgsign.ModeExportKey:
		if request.file != "" {
			return errors.New("a key export signs no file; drop --file")
		}
	case request.file != "":
		if document, err = os.ReadFile(request.file); err != nil {
			return errors.New("open the file to approve")
		}
		sum := sha256.Sum256(document)
		seen = "checked against " + filepath.Base(request.file) + ", sha256 " + hex.EncodeToString(sum[:])
	case request.unseen:
		seen = "NOT CHECKED (--unseen). The preparer says: sha256 " + pending.DocumentSHA256
	default:
		return errors.New("pass --file with your own copy of what is being signed, or --unseen to approve without checking it")
	}
	if pending.Mode == gpgsign.ModeExportKey || request.file != "" {
		if err := key.Covers(ctx, pending, bytes.NewReader(document)); err != nil {
			return err
		}
	} else if pending.Fingerprint != key.Fingerprint() || pending.ObjectID != cfg.ObjectID || pending.Purpose != cfg.Purpose || pending.Environment != cfg.Environment {
		return errors.New("the pending signature is for another key or target than the one this approver approves for")
	}
	fmt.Fprintf(stdout, "approving as %s, valid until %s:\n  key          %s\n  object       %s (%s, %s)\n  what         %s\n  file         %s\n",
		cfg.ApproverID, pending.ExpiresAt, pending.Fingerprint, pending.ObjectID, pending.Purpose, pending.Environment, pending.Mode, seen)

	signer, err := cfg.approver(ctx, stdin, stderr, getenv)
	if err != nil {
		return err
	}
	approval, err := gpgsign.Approve(pending, cfg.ApproverID, signer, at)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(approval, "", "  ")
	if err != nil {
		return err
	}
	destination := request.output
	if destination == "" {
		destination = request.pending + ".approval"
	}
	if err := protected.InstallNew(destination, string(encoded)+"\n"); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "  approval     %s\n", destination)
	return nil
}
