package auth

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE TWO I/O REFUSALS ON THE PATH THE RBAC POLICY TAKES INTO THE DAEMON.
//
// A sweep of internal/auth on current main — 47 guard sites, 80 leaf operands, 80
// operand-directions, enumerated with tools/guardenum rather than a pattern — left seven operands
// that no test in the module detects. Five of those cannot be made the sole refuser by any input,
// and are named at the bottom of this comment so nobody spends a second afternoon on them. The two
// closed here are the ones a fixture can reach, and they sit on the same journey: LoadPolicyFile
// opens the operator's RBAC file, LoadPolicy reads it. Every guard BETWEEN them — regular-file,
// non-writable, size, JSON shape, schema version, principal canonicalisation, grant dimensions — was
// already pinned. The open and the read were not.
//
// They are not the same kind of defect and this file does not present them as one.
//
//	rbac.go:106  io.ReadAll error in LoadPolicy       ADMISSION. Measured with the operand
//	             neutralised: LoadPolicy(valid-bytes-then-error) returns policy=non-nil, err=nil,
//	             Ready()=true, GrantedObjects()=1 grant, and a digest. A read that FAILED becomes a
//	             policy in force.
//	rbac.go:90   os.Open error in LoadPolicyFile      ATTRIBUTION. Measured with the operand
//	             neutralised: a missing policy file is still refused — os.Open returns a nil *os.File,
//	             and (*os.File).Stat on nil returns fs.ErrInvalid, so the NEXT guard refuses. What is
//	             lost is which refusal: "open RBAC policy: … no such file or directory" (ErrNotExist)
//	             becomes "stat RBAC policy: invalid argument" (ErrInvalid). Nothing is admitted.
//
// Saying that plainly matters because the existing TestLoadPolicyFileRefusesWhatIsNotAFile already
// hands LoadPolicyFile an absent path — and still passes without the operand, because it asserts
// only that an error came back, and the downstream stat guard produces one. The input was exercised;
// the assertion could not tell the two refusals apart. A stat error is not absence.
//
// THE FIVE THAT ARE NOT CLOSED, and why a test for them would assert an outcome its siblings already
// produce rather than gate anything:
//
//   - auth.go:82  `err != nil` on url.Parse of the uriPrefix. Masked by canonicalURISAN's
//     `prefix == nil`: url.Parse returns a nil *url.URL alongside its error, so the nil reaches
//     canonicalURISAN and is refused there. Already recorded in canonical_uri_san_test.go on
//     TestAuthenticateRefusesEveryIdentityWhenTheURIPrefixDoesNotParse, which pins the PROPERTY the
//     pair implements without being able to pin either operand alone.
//   - auth.go:90  `candidate.Opaque != ""`. Enumerated across 16 URI forms: no input has both
//     Opaque != "" and Host != "", because url.Parse populates Opaque only for a URI with no "//"
//     authority. Reaching this operand with a matching host therefore needs prefix.Host == "", which
//     the EARLIER `prefix.Host == ""` operand refuses first.
//   - rbac.go:95  `err != nil` on file.Stat(). The descriptor came from an os.Open that had just
//     succeeded; no input to the exported LoadPolicyFile(path string) makes fstat fail on it.
//   - revocation.go:132  `file == nil` after os.NewFile. os.NewFile returns nil only when
//     int(fd) < 0, and unix.Open returned no error, so the descriptor is non-negative.
//   - revocation.go:138  `err != nil` on unix.Fstat of that same just-opened descriptor.
//
// The last three are defensive reads of values the preceding call has already constrained. They are
// correct code and they are unreachable in the §17 sense — there is no fixture, so there is no test,
// and pinning them would need an input that violates two rules at once.

// failingReader yields data in full and then fails.
//
// The ORDER is the whole fixture. A reader that fails immediately proves nothing here: contents
// would be empty, the JSON decode would refuse it, and the refusal would come from a guard four
// lines further down. By delivering a complete, valid policy document BEFORE the error, everything
// downstream of the read is satisfied, so the read error is the only thing left that can refuse —
// and when the operand is gone, nothing does.
//
// This is not a contrived shape. io.ReadAll returns the bytes it managed to read alongside the
// error, and a truncated read whose prefix happens to parse is exactly the case where discarding
// the error is invisible.
type failingReader struct {
	remaining []byte
	err       error
}

func (r *failingReader) Read(destination []byte) (int, error) {
	if len(r.remaining) > 0 {
		n := copy(destination, r.remaining)
		r.remaining = r.remaining[n:]
		return n, nil
	}
	return 0, r.err
}

// TestLoadPolicyRefusesAPolicyWhoseReadFailed pins the io.ReadAll error check in LoadPolicy.
//
// WHAT IS AT STAKE. The RBAC policy is the document deciding which workload may use which key, and
// the daemon reads it once at startup and never again. Without this operand the error from a failed
// read is discarded and whatever bytes arrived before the failure are parsed as the whole policy. If
// that prefix parses — which is the only case that gets this far — the daemon starts, reports "RBAC
// policy loads, digest sha256:…" in preflight, and serves. The digest is computed over the bytes
// that were read, so it is internally consistent and cannot reveal the truncation: every audit
// record then cites an authority that was never fully read. Grants living past the truncation point
// are simply absent, and the daemon has no way to know it is enforcing a fragment.
//
// Measured with the operand neutralised: policy=non-nil, err=nil, Ready()=true, one granted triple,
// digest sha256:dc21d89f…, from a reader that returned an error.
//
// Isolation: the bytes delivered are validPolicy in full — a single, complete, in-limit JSON
// document with schema_version 1, one canonical SPIFFE principal and one well-formed grant — so the
// size guard, both decode guards, the schema/principals guard, the principal-URI guards and
// compileGrant all pass. The read error is the only defect, which the positive control below proves
// by loading those same bytes successfully when the reader does not fail.
func TestLoadPolicyRefusesAPolicyWhoseReadFailed(t *testing.T) {
	readFailure := errors.New("input/output error")

	// Positive control first. If the same bytes could not load cleanly, a refusal below would only
	// prove the fixture is malformed, and would prove it about the wrong guard.
	control, err := LoadPolicy(strings.NewReader(validPolicy))
	if err != nil {
		t.Fatalf("control is broken, so the refusal below would prove nothing: the same bytes from a "+
			"reader that does not fail gave err=%v, want a loaded policy", err)
	}
	// The nil check is separate from the grant count and comes first. Policy.GrantedObjects has a
	// nil-receiver guard, so a (nil, nil) return would reach the count below and be reported as
	// "the fixture compiled to 0 granted triples" — a true sentence about the wrong cause, sending
	// whoever reads it to inspect validPolicy when the defect is in LoadPolicy.
	if control == nil {
		t.Fatal("control is broken: LoadPolicy returned (nil, nil) for a reader that does not fail — " +
			"no policy and no error, so there is nothing to compare the failing read against")
	}
	if len(control.GrantedObjects()) != 1 {
		t.Fatalf("control is broken: the fixture compiled to %d granted triples, want 1 — a fixture "+
			"that grants nothing cannot show that a failed read was admitted",
			len(control.GrantedObjects()))
	}

	policy, err := LoadPolicy(&failingReader{remaining: []byte(validPolicy), err: readFailure})

	// A FAILURE PATH MUST BE ABLE TO REPORT ITS OWN FAILURE.
	//
	// The admission message below reads Ready(), Digest() and GrantedObjects() off the returned
	// policy, which is only meaningful once the pointer is known non-nil. Policy.Digest is a plain
	// field read with no nil-receiver guard, so on a (nil, nil) regression the message written to
	// NAME the defect would instead panic, and whoever saw it would have to reconstruct what
	// happened from a stack trace. That the sibling accessors happen to tolerate nil today is not
	// something this test should depend on.
	//
	// (nil, nil) is also a DIFFERENT defect from the admission this test exists to catch — nothing
	// was admitted, but nothing was refused either — so it gets its own arm rather than being
	// folded into a message that would describe it wrongly.
	switch {
	case err == nil && policy == nil:
		t.Fatalf("DEFECT: LoadPolicy returned (nil, nil) for a reader that failed with %v — no policy "+
			"AND no error. This is not the admission this test guards against: nothing was admitted, "+
			"but the failed read was not refused either. LoadPolicyFile hands this value straight on "+
			"(`return LoadPolicy(file)`), so a caller that checks the error first carries a nil "+
			"*Policy forward, and preflight dereferences it for rbacPolicy.Digest()", readFailure)
	case err == nil:
		t.Fatalf("DEFECT: LoadPolicy discarded a read error (%v) and returned a usable policy: "+
			"Ready()=%v, digest=%s, %d granted triple(s). A policy read that FAILED is now the policy "+
			"in force, and its digest covers only the bytes that arrived — so every audit record "+
			"cites an authority the daemon never finished reading, and any grant past the truncation "+
			"point is silently unenforced",
			readFailure, policy.Ready(t.Context()), policy.Digest(), len(policy.GrantedObjects()))
	}
	if policy != nil {
		t.Fatalf("DEFECT: LoadPolicy returned both an error (%v) and a non-nil policy; a caller that "+
			"checks the policy first would enforce a document whose read failed", err)
	}
	if !errors.Is(err, readFailure) {
		t.Fatalf("LoadPolicy refused with %q, which does not wrap the reader's error — this test "+
			"pins the wrapping because it is the only thing distinguishing a failed READ from the "+
			"decode failure a truncated document would otherwise produce", err)
	}
	if want := "read RBAC policy: "; !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("LoadPolicy refused with %q, want the %q prefix: the operator's repair for a failing "+
			"read is not the repair for a malformed document", err, want)
	}
}

// TestLoadPolicyFileRefusesAMissingPolicyByTheOpenRatherThanTheStat pins the os.Open error check in
// LoadPolicyFile.
//
// THIS OPERAND ADMITS NOBODY, and claiming otherwise would overstate it. With the operand
// neutralised a missing policy file is still refused: os.Open returns a nil *os.File beside its
// error, (*os.File).Stat on a nil receiver returns fs.ErrInvalid rather than panicking, and the
// stat guard on the next line refuses. The daemon fails closed either way.
//
// What the operand decides is WHICH refusal the operator is handed. With it:
// "open RBAC policy: open /etc/regalia/rbac.json: no such file or directory", wrapping
// fs.ErrNotExist — a path that is wrong or a file that was never deployed. Without it:
// "stat RBAC policy: invalid argument", wrapping fs.ErrInvalid — which describes nothing that
// happened and sends whoever reads it looking at the descriptor rather than at the path. Preflight
// prints this string verbatim under "RBAC policy: %w", and it is the only account of why the daemon
// would not start.
//
// WHY THE EXISTING TEST DOES NOT COVER THIS. TestLoadPolicyFileRefusesWhatIsNotAFile already calls
// LoadPolicyFile on an absent path, and it passes with the operand gone, because it asserts only
// that some error came back — and the stat guard supplies one. The input was already exercised; the
// assertion could not distinguish the two refusals. So this test asserts the SENTINEL, not the
// prose: errors.Is(err, fs.ErrNotExist) is false the moment the refusal comes from anywhere else.
//
// Isolation: the parent directory exists and is readable, so nothing but the absent leaf can fail,
// and the positive control loads a real policy from that same directory.
func TestLoadPolicyFileRefusesAMissingPolicyByTheOpenRatherThanTheStat(t *testing.T) {
	directory := t.TempDir()

	// Positive control: a real policy in the very same directory must load, or a refusal below could
	// be about the directory rather than about the missing file. The returned policy is checked
	// rather than discarded — a control that only asserts "no error" passes vacuously on a
	// (nil, nil) return, and would then be establishing nothing at all.
	control, err := LoadPolicyFile(writePolicyFile(t, validPolicy, 0o600))
	if err != nil {
		t.Fatalf("control is broken, so the refusal below would prove nothing: a well-formed policy "+
			"file was refused with %v", err)
	}
	if control == nil {
		t.Fatal("control is broken: LoadPolicyFile returned (nil, nil) for a well-formed policy file — " +
			"no policy and no error, so the refusal below cannot be attributed to the missing file")
	}

	missing := filepath.Join(directory, "absent.json")
	if _, err := os.Stat(missing); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("fixture is broken: %q exists (stat err=%v), so the open cannot fail as this test "+
			"requires", missing, err)
	}

	policy, err := LoadPolicyFile(missing)

	// Same split as the read test, but NOT the same failure — measured, not assumed.
	//
	// The admission arm here reads only GrantedObjects, which has a nil-receiver guard, so a
	// (nil, nil) return does not panic the way the read test's Digest() call does. It does something
	// quieter and arguably worse: it reports "a missing RBAC policy file loaded, yielding 0 granted
	// triple(s)" — a sentence that is true of nothing that happened. Nothing loaded. The function
	// returned no policy and no error, and the reader is sent to look for a policy file that
	// admitted an empty grant set.
	//
	// So this arm exists to correct a MISDIAGNOSIS, not to prevent a crash, and saying so is the
	// point: the two sites in this file fail differently and a reader who assumes otherwise will
	// look for a nil dereference here that is not there.
	switch {
	case err == nil && policy == nil:
		t.Fatalf("DEFECT: LoadPolicyFile returned (nil, nil) for the absent path %q — no policy AND "+
			"no error. preflight checks the error and then prints rbacPolicy.Digest(), which is a "+
			"plain field read with no nil guard, so the daemon would panic during startup instead of "+
			"reporting that the policy file is missing", missing)
	case err == nil:
		t.Fatalf("DEFECT: a missing RBAC policy file loaded, yielding %d granted triple(s); the "+
			"daemon would start with whatever grants that is rather than refusing",
			len(policy.GrantedObjects()))
	}
	if policy != nil {
		t.Fatalf("DEFECT: LoadPolicyFile returned both an error (%v) and a non-nil policy", err)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("DEFECT: a missing RBAC policy file was refused with %q, which does not wrap "+
			"fs.ErrNotExist. The refusal is coming from a later guard reading a descriptor os.Open "+
			"never produced — so preflight tells the operator the descriptor is invalid when the "+
			"truth is that the path does not exist", err)
	}
	if want := "open RBAC policy: "; !strings.HasPrefix(err.Error(), want) {
		t.Fatalf("DEFECT: a missing RBAC policy file was refused with %q, want the %q prefix; this "+
			"string is what preflight prints and it is the operator's only account of why the daemon "+
			"will not start", err, want)
	}

	// The refusal must not be mistakable for the sibling it would otherwise become.
	if errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("DEFECT: the refusal for a missing file wraps fs.ErrInvalid (%q); that is the stat "+
			"guard's answer to a nil descriptor, not the open guard's answer to an absent path", err)
	}
}
