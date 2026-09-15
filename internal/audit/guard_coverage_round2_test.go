package audit

// #237 operand sweep, round two: three survivors outside the chain and the sink, each of a
// different kind, kept together because what they share is that the package's existing tests
// drive right past them.
//
//   - Close's idempotence is a contract nothing asserted.
//   - VerifyNow's context check is a REFUSAL-DIRECTION operand in reverse: losing it makes the
//     verifier report a journal it never read as intact.
//   - sequenceOf's empty-slice check is what stops an index running off the front of a slice.
//     A sweep reports it as a survivor exactly as it reports a redundant operand, and the
//     difference between those two is the difference between a message and a crash.

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
)

// CLOSE IS CALLED TWICE ROUTINELY — a deferred Close beside an explicit one is the pattern this
// package's own tests use — so the second call answering with the descriptor's "file already
// closed" turns an orderly shutdown into a reported failure. The flag is the only thing that
// makes the second call a no-op.
func TestClosingARecorderTwiceIsNotAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	record(t, recorder, "018f0000-0000-7000-8000-00000000000a")

	if err := recorder.Close(); err != nil {
		t.Fatalf("the first Close failed (%v), so the second says nothing about idempotence", err)
	}
	if err := recorder.Close(); err != nil {
		t.Fatalf("closing an already-closed recorder returned %v: a deferred Close beside an explicit one is the shape every caller uses, and the second one reporting the descriptor's own error makes a clean shutdown look like a failed one", err)
	}
}

// A VERIFICATION THAT NEVER RAN MUST NOT REPORT INTACT.
//
// VerifyNow seeds its state as unreadable and returns early when the context is already done,
// which is what makes "the verifier could not run" distinguishable from "the chain is fine". The
// distinction is the whole point of the outcome enum: unreadable pages operations, intact pages
// nobody, and a cancelled run that answers intact is a verifier reporting on bytes it never read.
func TestVerifyNowOnAnEndedContextIsUnreadableRatherThanIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recorder, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	record(t, recorder, "018f0000-0000-7000-8000-00000000000a")

	// The control first: with a live context and an untouched journal the answer is intact, so
	// the row below is about the cancellation rather than about a verifier that never says intact.
	if state := recorder.VerifyNow(context.Background()); state.Outcome != VerifyIntact {
		t.Fatalf("control: an untouched journal verified as %q, want intact", state.Outcome)
	}

	ended, cancel := context.WithCancel(context.Background())
	cancel()
	state := recorder.VerifyNow(ended)
	if state.Outcome != VerifyUnreadable {
		t.Fatalf("VerifyNow on an ended context reported %q: the run did not happen, and reporting it as intact makes a verifier that has stopped being able to run indistinguishable from one that is watching — which is the blind spot the periodic loop exists to close",
			state.Outcome)
	}
	if got := recorder.VerifyState(); got.Outcome != VerifyUnreadable {
		t.Fatalf("the recorded state is %q after a cancelled run, want unreadable: the metric is what an operator sees", got.Outcome)
	}
}

// THE COLLECTOR REMEMBERS EVENTS THIS HOST NO LONGER HOLDS.
//
// A journal with nothing in it and a collector that has committed through sequence 5 is the
// incident reconciliation exists for — the off-host copy holds history the host has lost. Getting
// there runs sequenceOf over an empty slice, and its length check is the only thing between that
// and an index of -1.
//
// The panic is recovered and reported as an assertion: a panicking run aborts the test binary, so
// letting it through would truncate the failing set and hide whatever else the same change broke.
func TestReconcileRefusesAJournalHoldingLessThanTheCollectorRemembers(t *testing.T) {
	reconcileRecovering := func(path string, sink Sink) (err error, panicked any) {
		defer func() { panicked = recover() }()
		return ReconcileContinuity(context.Background(), path, sink, "sitea"), nil
	}

	// The journal is never created: an empty history is the state a host has after the journal
	// was lost, which is precisely when the collector's memory is the only record left.
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	collector := &recordingCollector{sequence: 5, hash: chainedHash}

	err, panicked := reconcileRecovering(path, collector)
	if panicked != nil {
		t.Fatalf("reconciling an empty journal against a collector holding sequence 5 panicked (%v): the empty-slice check in sequenceOf is what keeps the head comparison from indexing off the front, and without it the daemon crashes on the exact state reconciliation exists to report", panicked)
	}
	if err == nil {
		t.Fatal("a host holding no journal at all reconciled clean against a collector that has committed five of its events: the off-host copy holds history this host has lost, and that is an incident rather than a fresh start")
	}
	if !strings.Contains(err.Error(), "holds less history than it already shipped") {
		t.Fatalf("refused by the wrong rule (%v): this row exists to reach the head-against-journal comparison, and a refusal from anywhere else leaves it unproven", err)
	}

	// KNOWN-GOOD: a collector that holds nothing against the same empty journal is a genuinely
	// fresh stream and must reconcile clean, so the refusal above is about the missing history
	// rather than about a reconciler that refuses every empty journal.
	if err, panicked := reconcileRecovering(path, &recordingCollector{}); panicked != nil || err != nil {
		t.Fatalf("a fresh stream against an empty journal was refused (err=%v panic=%v), so the row above proves nothing", err, panicked)
	}
}

// A CLIENT CERTIFICATE WITH NO CHAIN IS NOT AN IDENTITY.
//
// transport_test.go's "identity" row passes a zero tls.Certificate, which has no private key
// either — so the signer check refuses it and the chain-length operand never has to. This row
// supplies a real signer and an empty chain, which is what a caller assembling the certificate
// from a hardware key gets when the chain load silently returned nothing: the handshake would
// present no client certificate at all, and the collector would refuse the connection instead of
// the daemon refusing its own configuration.
func TestAnMTLSIdentityWithASignerButNoChainIsRefused(t *testing.T) {
	signer := ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))
	// PROVE THE FIXTURE: the key must satisfy the signer rule, or this row is refused by that
	// check and says nothing about the chain length.
	if _, ok := crypto.Signer(signer).(crypto.Signer); !ok {
		t.Fatal("fixture: the key is not a crypto.Signer, so the signer check would refuse this row first")
	}
	if _, err := NewMTLSHTTPClient(tls.Certificate{PrivateKey: signer}, x509.NewCertPool(), "audit.internal"); err == nil {
		t.Fatal("an mTLS identity carrying a usable private key and no certificate chain was accepted: the client would open the connection presenting nothing, and the refusal moves from this daemon's startup to the collector's handshake")
	}

	// KNOWN-GOOD: the same signer WITH a chain is accepted, so the refusal above is the empty
	// chain rather than anything else about this certificate.
	if _, err := NewMTLSHTTPClient(tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: signer}, x509.NewCertPool(), "audit.internal"); err != nil {
		t.Fatalf("the same identity with a chain was refused (%v), so the row above proves nothing", err)
	}
}
