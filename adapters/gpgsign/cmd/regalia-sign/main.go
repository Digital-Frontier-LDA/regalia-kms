// regalia-sign makes OpenPGP signatures with a key the Regalia KMS holds.
//
//	regalia-sign --config FILE --detach SHA256SUMS      writes SHA256SUMS.asc; check with gpg --verify
//	regalia-sign --config FILE --clearsign Release --output InRelease     an apt repository's InRelease
//	regalia-sign --config FILE --export-key             the public key verifiers import, on stdout
//	regalia-sign --config FILE --fingerprint            the key's fingerprint; no KMS call
//
// It is also a git signing program. With `git config gpg.program regalia-sign` and
// REGALIA_SIGN_CONFIG naming the configuration, `git commit -S` and `git tag -s` are signed by the
// KMS; verification (`--verify`) is handed to the real gpg, which needs no key of ours.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/gpgsign"
	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/gpgsign/internal/protected"
)

const usage = `usage:
  regalia-sign [--config FILE] --detach FILE [--output FILE] [--binary]
  regalia-sign [--config FILE] --clearsign FILE [--output FILE]
  regalia-sign [--config FILE] --export-key
  regalia-sign [--config FILE] --fingerprint
  regalia-sign --status-fd=2 -bsau KEY        (as git's gpg.program; signs stdin to stdout)
Under a policy that requires approval, any of --detach, --clearsign and --export-key is done in two
steps, with an approver signing the pending record in between (regalia-approve):
  regalia-sign [--config FILE] --prepare PENDING [--valid-for 5m] --detach FILE
  regalia-sign [--config FILE] --complete PENDING --approval FILE [--approval FILE …] --detach FILE
The configuration is --config, or the file named by REGALIA_SIGN_CONFIG.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, os.Getenv, time.Now))
}

type invocation struct {
	configPath  string
	detach      string // file to sign, or "-" for stdin
	clearsign   string // file to clear-sign, or "-" for stdin
	output      string
	binary      bool
	exportKey   bool
	fingerprint bool

	// The two-step form for a policy that requires approval.
	prepare   string   // the pending record to write
	complete  string   // the pending record to complete
	approvals []string // approval files, with --complete
	validFor  string   // how long the prepared request stays valid, with --prepare

	// The gpg-compatible form git uses: -b (detach) -s (sign) -a (armor) -u KEY.
	gpgDetach, gpgSign, gpgArmor bool
	localUser                    string
	statusFD                     int
	verify                       bool
}

// parse reads the command line. It is strict: an option it does not know is an error, never
// something to skip, because a skipped option on a signing tool is an instruction silently dropped.
func parse(args []string) (invocation, error) {
	result := invocation{statusFD: -1}
	// git verifies with `gpg --keyid-format=long --status-fd=1 --verify FILE -`. A line that asks for
	// verification is gpg's from its first word to its last, and is passed on untouched.
	for _, argument := range args {
		if argument == "--verify" {
			result.verify = true
			return result, nil
		}
	}
	value := func(index *int, name string) (string, error) {
		if *index+1 >= len(args) {
			return "", fmt.Errorf("%s needs a value", name)
		}
		*index++
		return args[*index], nil
	}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		name, inline, hasInline := strings.Cut(argument, "=")
		take := func() (string, error) {
			if hasInline {
				return inline, nil
			}
			return value(&index, name)
		}
		var err error
		switch {
		case name == "--config":
			result.configPath, err = take()
		case name == "--detach":
			result.detach, err = take()
		case name == "--clearsign":
			result.clearsign, err = take()
		case name == "--output":
			result.output, err = take()
		case argument == "--binary":
			result.binary = true
		case argument == "--export-key":
			result.exportKey = true
		case argument == "--fingerprint":
			result.fingerprint = true
		case name == "--prepare":
			result.prepare, err = take()
		case name == "--complete":
			result.complete, err = take()
		case name == "--valid-for":
			result.validFor, err = take()
		case name == "--approval":
			var file string
			if file, err = take(); err == nil {
				result.approvals = append(result.approvals, file)
			}
		case name == "--status-fd":
			var text string
			if text, err = take(); err == nil {
				if result.statusFD, err = strconv.Atoi(text); err != nil || (result.statusFD != 1 && result.statusFD != 2) {
					err = errors.New("--status-fd must be 1 or 2")
				}
			}
		case name == "--local-user":
			result.localUser, err = take()
		case argument == "--detach-sign":
			result.gpgDetach = true
		case argument == "--sign":
			result.gpgSign = true
		case argument == "--armor":
			result.gpgArmor = true
		case len(argument) > 1 && argument[0] == '-' && argument[1] != '-':
			// A cluster of gpg's short options, such as git's -bsau. Only u takes a value, so it
			// must come last.
			for position, letter := range argument[1:] {
				switch letter {
				case 'b':
					result.gpgDetach = true
				case 's':
					result.gpgSign = true
				case 'a':
					result.gpgArmor = true
				case 'u':
					if position != len(argument)-2 {
						return result, fmt.Errorf("in %s, -u must be the last letter", argument)
					}
					result.localUser, err = value(&index, "-u")
				default:
					return result, fmt.Errorf("unknown option -%c", letter)
				}
			}
		default:
			return result, fmt.Errorf("unknown argument %q", argument)
		}
		if err != nil {
			return result, err
		}
	}
	gpgForm := result.gpgDetach || result.gpgSign || result.gpgArmor || result.localUser != "" || result.statusFD != -1
	modes := 0
	for _, chosen := range []bool{result.detach != "", result.clearsign != "", result.exportKey, result.fingerprint, gpgForm} {
		if chosen {
			modes++
		}
	}
	if modes != 1 {
		return result, errors.New("choose exactly one of --detach, --clearsign, --export-key, --fingerprint, or gpg's -bsau form")
	}
	if gpgForm && !(result.gpgDetach && result.gpgSign && result.gpgArmor && result.localUser != "") {
		// git asks for exactly a detached, armored signature by a named key. Anything else in gpg's
		// vocabulary (a clear-signed or inline signature, an unnamed key) is not what this makes.
		return result, errors.New("the gpg form supported is a detached armored signature: -bsau KEY")
	}
	if result.prepare != "" || result.complete != "" {
		if result.prepare != "" && result.complete != "" {
			return result, errors.New("--prepare and --complete are two separate steps")
		}
		if result.fingerprint || gpgForm {
			return result, errors.New("--prepare and --complete go with --detach, --clearsign or --export-key")
		}
	}
	if (len(result.approvals) > 0) != (result.complete != "") {
		return result, errors.New("--complete needs at least one --approval, and --approval goes only with --complete")
	}
	if result.validFor != "" && result.prepare == "" {
		return result, errors.New("--valid-for goes with --prepare")
	}
	if result.prepare != "" && result.output != "" {
		return result, errors.New("--prepare writes only the pending record; --output goes with the completing step")
	}
	if result.output != "" && result.detach == "" && result.clearsign == "" && !(result.exportKey && result.complete != "") {
		return result, errors.New("--output goes with --detach or --clearsign")
	}
	if result.binary && result.detach == "" {
		// A cleartext signature is text by definition; there is no binary form of one.
		return result, errors.New("--binary goes with --detach")
	}
	return result, nil
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string, now func() time.Time) int {
	fail := func(code int, err error) int {
		fmt.Fprintf(stderr, "regalia-sign: %v\n", err)
		return code
	}
	request, err := parse(args)
	if err != nil {
		fmt.Fprint(stderr, usage)
		return fail(2, err)
	}
	if request.verify {
		return fail(1, verifyWithGPG(args, getenv))
	}
	if request.configPath == "" {
		request.configPath = getenv("REGALIA_SIGN_CONFIG")
	}
	if request.configPath == "" {
		return fail(2, errors.New("no configuration: pass --config or set REGALIA_SIGN_CONFIG"))
	}
	cfg, err := loadConfig(request.configPath)
	if err != nil {
		return fail(1, err)
	}
	key, timeout, err := cfg.key(now)
	if err != nil {
		return fail(1, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	switch {
	case request.fingerprint:
		fmt.Fprintln(stdout, key.Fingerprint())
		return 0
	case request.prepare != "":
		if err := prepare(ctx, key, request, stdin, stdout, now()); err != nil {
			return fail(1, err)
		}
		return 0
	case request.complete != "":
		if err := complete(ctx, key, request, stdin, stdout, now()); err != nil {
			return fail(1, err)
		}
		return 0
	case request.exportKey:
		if err := key.ExportPublic(ctx, stdout); err != nil {
			return fail(1, err)
		}
		return 0
	case request.detach != "" || request.clearsign != "":
		if err := signToFile(ctx, key, request, stdin, stdout, now()); err != nil {
			return fail(1, err)
		}
		return 0
	}

	// git's form. The key git names must be this key: signing with a key other than the one asked
	// for, and saying nothing, is how a misconfigured repository ends up trusted for the wrong reason.
	if !key.Matches(request.localUser) {
		return fail(1, fmt.Errorf("the key asked for (%s) is not the configured key %s", request.localUser, key.Fingerprint()))
	}
	// The whole signature is built before any of it is written: git reads stdout as the signature,
	// and half of one followed by an error is worse than none.
	var signature strings.Builder
	signed, err := key.DetachSign(ctx, &signature, stdin, now(), true)
	if err != nil {
		return fail(1, err)
	}
	if _, err := io.WriteString(stdout, signature.String()); err != nil {
		return fail(1, errors.New("write the signature"))
	}
	if request.statusFD != -1 {
		status := stderr
		if request.statusFD == 1 {
			status = stdout
		}
		// git looks for "\n[GNUPG:] SIG_CREATED " in the status output, so a line precedes it, as
		// one does from gpg. The fields are gpg's: type D(etached), public-key algorithm, hash
		// algorithm, signature class 00 (binary), creation time, fingerprint.
		fmt.Fprintf(status, "[GNUPG:] BEGIN_SIGNING H%d\n[GNUPG:] SIG_CREATED D %d %d 00 %d %s\n",
			signed.HashAlgo, signed.PubKeyAlgo, signed.HashAlgo, signed.Created.Unix(), key.Fingerprint())
	}
	return 0
}

// mode says what the command line asks to be signed, and where it comes from and goes by default.
func (request invocation) mode() (mode gpgsign.Mode, source, destination string) {
	switch {
	case request.exportKey:
		return gpgsign.ModeExportKey, "", request.output
	case request.clearsign != "":
		mode, source = gpgsign.ModeClearSign, request.clearsign
	case request.binary:
		mode, source = gpgsign.ModeDetachBinary, request.detach
	default:
		mode, source = gpgsign.ModeDetach, request.detach
	}
	destination = request.output
	if destination == "" && source != "-" {
		destination = source + ".asc"
		if mode == gpgsign.ModeDetachBinary {
			destination = source + ".sig"
		}
	}
	return mode, source, destination
}

// document reads what is to be signed, whole. Both steps hash it and feed it, so it is read once.
func document(source string, stdin io.Reader) ([]byte, error) {
	switch source {
	case "":
		return nil, nil // a key export signs no document
	case "-":
		return io.ReadAll(stdin)
	}
	contents, err := os.ReadFile(source)
	if err != nil {
		return nil, errors.New("open the file to sign")
	}
	return contents, nil
}

// prepare writes the pending record and tells the operator what an approver will be shown. It does
// not contact the KMS.
func prepare(ctx context.Context, key *gpgsign.Key, request invocation, stdin io.Reader, stdout io.Writer, at time.Time) error {
	validFor := 5 * time.Minute
	if request.validFor != "" {
		parsed, err := time.ParseDuration(request.validFor)
		if err != nil {
			return errors.New("--valid-for is a duration such as 5m")
		}
		validFor = parsed
	}
	mode, source, _ := request.mode()
	contents, err := document(source, stdin)
	if err != nil {
		return err
	}
	pending, err := key.Prepare(ctx, mode, bytes.NewReader(contents), at, validFor)
	if err != nil {
		return err
	}
	if source != "" {
		pending.SetDocument(contents)
	}
	encoded, err := json.MarshalIndent(pending, "", "  ")
	if err != nil {
		return err
	}
	if err := installNew(request.prepare, string(encoded)+"\n"); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "prepared, not signed. To be approved before %s:\n  key          %s\n  object       %s (%s, %s)\n  what         %s\n",
		pending.ExpiresAt, pending.Fingerprint, pending.ObjectID, pending.Purpose, pending.Environment, pending.Mode)
	if pending.DocumentSHA256 != "" {
		fmt.Fprintf(stdout, "  file sha256  %s\n", pending.DocumentSHA256)
	}
	fmt.Fprintf(stdout, "  record       %s\n", request.prepare)
	return nil
}

// complete reads the pending record and the approvals, and finishes the signature.
func complete(ctx context.Context, key *gpgsign.Key, request invocation, stdin io.Reader, stdout io.Writer, at time.Time) error {
	record, err := os.ReadFile(request.complete)
	if err != nil {
		return errors.New("open the pending-signature file")
	}
	pending, err := gpgsign.ReadPending(record)
	if err != nil {
		return err
	}
	mode, source, destination := request.mode()
	if mode != pending.Mode {
		return fmt.Errorf("the pending signature is a %s, and this command asks for a %s", pending.Mode, mode)
	}
	var approvals []gpgsign.Approval
	for _, file := range request.approvals {
		contents, err := os.ReadFile(file)
		if err != nil {
			return errors.New("open the approval file")
		}
		approval, err := gpgsign.ReadApproval(contents)
		if err != nil {
			return err
		}
		approvals = append(approvals, approval)
	}
	contents, err := document(source, stdin)
	if err != nil {
		return err
	}
	var signed strings.Builder
	if _, err := key.Complete(ctx, &signed, bytes.NewReader(contents), pending, approvals, at); err != nil {
		return err
	}
	if destination == "" || destination == "-" {
		_, err := io.WriteString(stdout, signed.String())
		return err
	}
	return installNew(destination, signed.String())
}

// signToFile signs request.detach or request.clearsign and writes the result beside the file (or to
// --output). The output is complete before its name exists (installNew), and an existing file is
// never replaced: a release directory with two different signatures for one artifact, at different
// times, is a question nobody should have to answer.
func signToFile(ctx context.Context, key *gpgsign.Key, request invocation, stdin io.Reader, stdout io.Writer, at time.Time) error {
	source, suffix := request.detach, ".asc"
	if request.clearsign != "" {
		source = request.clearsign
	} else if request.binary {
		suffix = ".sig"
	}
	var document io.Reader = stdin
	destination := request.output
	if source != "-" {
		file, err := os.Open(source)
		if err != nil {
			return errors.New("open the file to sign")
		}
		defer file.Close()
		document = file
		if destination == "" {
			destination = source + suffix
		}
	}
	var signed strings.Builder
	var err error
	if request.clearsign != "" {
		_, err = key.ClearSign(ctx, &signed, document, at)
	} else {
		_, err = key.DetachSign(ctx, &signed, document, at, !request.binary)
	}
	if err != nil {
		return err
	}
	if destination == "" || destination == "-" {
		_, err := io.WriteString(stdout, signed.String())
		return err
	}
	return installNew(destination, signed.String())
}

// installNew is shared with regalia-approve (internal/protected).
func installNew(destination, contents string) error {
	return protected.InstallNew(destination, contents)
}

// verifyWithGPG replaces this process with the real gpg, arguments unchanged. Verifying needs the
// public key and nothing else, and GnuPG is what a third party will verify with — so that is what
// answers, rather than a second verifier of our own that only we would ever run.
func verifyWithGPG(args []string, getenv func(string) string) error {
	program := getenv("REGALIA_SIGN_GPG")
	if program == "" {
		program = "gpg"
	}
	path, err := exec.LookPath(program)
	if err != nil {
		return errors.New("verification is done by gpg, which was not found (set REGALIA_SIGN_GPG)")
	}
	if self, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(path); err == nil && resolved == self {
			return errors.New("REGALIA_SIGN_GPG points back at regalia-sign")
		}
	}
	return syscall.Exec(path, append([]string{path}, args...), os.Environ())
}
