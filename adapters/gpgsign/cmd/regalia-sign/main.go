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
	"context"
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
)

const usage = `usage:
  regalia-sign [--config FILE] --detach FILE [--output FILE] [--binary]
  regalia-sign [--config FILE] --clearsign FILE [--output FILE]
  regalia-sign [--config FILE] --export-key
  regalia-sign [--config FILE] --fingerprint
  regalia-sign --status-fd=2 -bsau KEY        (as git's gpg.program; signs stdin to stdout)
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
	if result.output != "" && result.detach == "" && result.clearsign == "" {
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

// signToFile signs request.detach or request.clearsign and writes the result beside the file (or to
// --output). The output is complete before the file exists, and an existing file is never replaced:
// a release directory with two different signatures for one artifact, at different times, is a
// question nobody should have to answer.
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
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; remove it first", filepath.Base(destination))
		}
		return errors.New("create the output file")
	}
	if _, err := io.WriteString(output, signed.String()); err != nil {
		_ = output.Close()
		_ = os.Remove(destination)
		return errors.New("write the output file")
	}
	return output.Close()
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
