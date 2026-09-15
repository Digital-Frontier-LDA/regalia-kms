// Command regalia-fence is the fencing authority: it grants one site the right to sign.
//
// internal/fencing was built to enforce ADR-0001 section 8 -- never two simultaneous
// signers -- and the daemon has consumed leases since it was wired. Nothing produced them.
// The feature was configurable, tested, and unusable: an operator could turn fencing on and
// then had no way to make any site active. This is the missing half.
//
// It is deliberately a separate binary. The authority that decides which site signs must not
// be the daemon that signs, or a compromised daemon promotes itself.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/fencing"
)

func main() {
	err := run(os.Args[1:], os.Stdout)
	// -h is a request, not a failure. flag.ContinueOnError reports it as an error, and
	// treating it as one made `regalia-fence -h` print the usage, then an error prefix, then
	// exit non-zero -- which reads as a broken tool to a person and as a failed step to a
	// script. The usage has already been written to stdout by Parse.
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "regalia-fence: "+err.Error())
		os.Exit(1)
	}
}

func run(arguments []string, out *os.File) error {
	flags := flag.NewFlagSet("regalia-fence", flag.ContinueOnError)
	flags.SetOutput(out)
	keyPath := flags.String("key", "", "path to the base64 ed25519 lease signing key")
	statePath := flags.String("state", "", "path to the issuer's record of the last lease it granted")
	journalPath := flags.String("journal", "", "path to the authority's decision journal; every grant AND refusal is recorded with the operator who made it")
	operator := flags.String("operator", "", "identity of the accountable operator making this decision; recorded in the journal")
	verifyJournal := flags.String("verify-journal", "", "verify an authority decision journal and exit")
	leasePath := flags.String("out", "", "path to write the signed lease to")
	site := flags.String("site", "", "site to make active")
	digest := flags.String("registry-digest", "", "custody manifest digest the lease is bound to")
	epoch := flags.Uint64("epoch", 0, "lease epoch; must exceed every epoch previously issued")
	validFor := flags.Duration("valid-for", fencing.MaxLeaseDuration, "how long the lease is valid, measured from -not-before rather than from now; the daemon refuses more than fencing.MaxLeaseDuration")
	notBefore := flags.String("not-before", "", "RFC3339 start time, fractional seconds accepted; defaults to now")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	// THE AUDITOR'S VIEW OF THE AUTHORITY (#29 AC2). Verifying the journal needs nothing else:
	// no key, no lock — it is the one command an auditor runs, and reachability is the whole
	// point (the same rule as the daemon's --verify-audit).
	if *verifyJournal != "" {
		summary, err := fencing.VerifyAuthorityJournal(*verifyJournal)
		if err != nil {
			return fmt.Errorf("authority journal verification FAILED: %w", err)
		}
		fmt.Fprintf(out, "authority journal intact: %d decisions (%d granted, %d refused), head sequence %d, head hash %s\n",
			summary.Records, summary.Grants, summary.Refusals, summary.HeadSequence, summary.HeadHash)
		return nil
	}
	if *keyPath == "" || *statePath == "" || *leasePath == "" || *site == "" || *digest == "" {
		// NOT "all required": -operator and -journal are required too, enforced just below, and a
		// message that reads as an exhaustive list sends an operator round the loop twice.
		return errors.New("-key, -state, -out, -site and -registry-digest are required")
	}
	// An unattributed decision is not a record: without an operator and a journal, the tool
	// refuses to act at all. The leases prove what a site may do; these two flags are what
	// make the DECISION auditable — who promoted which site, and what the authority said
	// about every attempt, including the ones it turned down.
	if *operator == "" || *journalPath == "" {
		return errors.New("-operator and -journal are required: a promotion without an attributed, journaled decision is not auditable")
	}

	key, err := loadSigningKey(*keyPath)
	if err != nil {
		return err
	}
	start := time.Now().UTC()
	if *notBefore != "" {
		start, err = time.Parse(time.RFC3339Nano, *notBefore)
		if err != nil {
			return fmt.Errorf("parse -not-before: %w", err)
		}
	}
	// The lock is taken BEFORE the previous grant is read. Every safety check below compares
	// the new grant against that record, so read-check-write has to be serialised or two
	// invocations both pass against a record neither has updated and both sign.
	release, err := fencing.LockIssuer(*statePath)
	if err != nil {
		return err
	}
	defer release()

	previous, err := fencing.LoadIssuerState(*statePath)
	if err != nil {
		return err
	}
	// The journal is opened under the same lock: its chain head is part of the decision
	// state, so read-check-append has the same serialisation requirement as the grant
	// record itself.
	journal, err := fencing.OpenAuthorityJournal(*journalPath)
	if err != nil {
		return err
	}
	grant := fencing.Grant{
		Site: *site, Epoch: *epoch, NotBefore: start,
		ExpiresAt: start.Add(*validFor), RegistryDigest: *digest,
	}
	lease, err := fencing.SignGrant(key, grant, previous)
	if err != nil {
		// REFUSALS ARE DECISIONS TOO. The overlap attempt someone made and the authority
		// turned down is exactly the record an auditor needs; a journal with only grants
		// describes an authority that was never asked to do anything wrong.
		if appendErr := journal.Append(fencing.GrantRecord{
			Kind: fencing.RecordRefused, Site: *site, Epoch: *epoch, Operator: *operator,
			NotBefore: grant.NotBefore, ExpiresAt: grant.ExpiresAt, Reason: err.Error(),
		}); appendErr != nil {
			return fmt.Errorf("recording the refusal failed too: %v (refusal was: %v)", appendErr, err)
		}
		return err
	}
	// The issuer's record is written BEFORE the lease is handed out. A crash between the
	// two costs an epoch number, which is free. The other order can hand out a lease the
	// authority has no record of, and the next grant then repeats its epoch. The journal
	// rides the same side of the line: the decision is recorded before the artifact exists.
	if err := fencing.SaveIssuerState(*statePath, grant); err != nil {
		return err
	}
	if err := journal.Append(fencing.GrantRecord{
		Kind: fencing.RecordGranted, Site: *site, Epoch: *epoch, Operator: *operator,
		NotBefore: grant.NotBefore, ExpiresAt: grant.ExpiresAt,
	}); err != nil {
		return err
	}
	if err := fencing.WriteLease(*leasePath, lease); err != nil {
		return fmt.Errorf("write lease: %w", err)
	}
	fmt.Fprintf(out, "granted %s epoch %d, valid %s to %s\n", grant.Site, grant.Epoch,
		grant.NotBefore.UTC().Format(time.RFC3339Nano), grant.ExpiresAt.UTC().Format(time.RFC3339Nano))
	fmt.Fprintf(out, "recorded: operator %s, decision %d in %s\n", *operator, journal.Head(), *journalPath)
	if previous.Site != "" && previous.Site != grant.Site {
		fmt.Fprintf(out, "handover from %s, whose lease expired at %s\n",
			previous.Site, previous.ExpiresAt.UTC().Format(time.RFC3339Nano))
	}
	return nil
}

func loadSigningKey(path string) (ed25519.PrivateKey, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(contents)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing key must be a base64 ed25519 private key of %d bytes", ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), nil
}
