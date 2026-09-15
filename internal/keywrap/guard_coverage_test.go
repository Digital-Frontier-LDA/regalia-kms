package keywrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"testing"
)

// Every refusal in this package returns the same sentinel, ErrInvalid, so asserting the error
// alone cannot say WHICH guard refused. What names the guard is the fixture: each test below is
// built so that exactly one operand of one guard can reject it, and every other operand on the
// path is satisfied. Each test states, from a measured mutation of that operand to
// `if false && (<original>)`, what OpenFrame or RSAOAEP returns instead of ErrInvalid. That
// sentence is the reason the test exists; without it the tests below read as duplicates of
// TestRSAOAEPBindsContext and TestOpenFrameIgnoresTrailingBytes.

// setDeclaredLength overwrites the 4-byte big-endian length field of a v2 frame in place, leaving
// magic, digest and payload untouched. Written as a helper rather than rebuilt through
// buildV2Frame because buildV2Frame always writes a length field that agrees with the payload,
// which is precisely the agreement the length guard exists to check.
func setDeclaredLength(frame []byte, declared uint32) {
	binary.BigEndian.PutUint32(frame[len(frameMagic)+sha256.Size:frameHeaderLen], declared)
}

// TestOpenFrameRefusesALengthFieldLongerThanTheFrame holds the length-vs-size check in OpenFrame
// (`uint32(len(frame)-frameHeaderLen) < declared`). The length field is attacker-reachable: it is
// plaintext produced by the hardware module, and the exported callers in the nitrokey and yubikey
// providers hand OpenFrame whatever the module returned.
//
// WHAT THE CODE RETURNS WITHOUT THE GUARD, measured with the condition mutated to
// `if false && (...)`: for declared=33 OpenFrame returns 33 bytes -- the 32-byte payload plus one
// byte read from PAST len(frame) -- with err=nil, and for declared=56 it returns the payload plus
// 24 such bytes, again with err=nil. Those bytes are handed back as a data key. On a frame whose
// capacity does not run past its length the same input panics instead:
// `slice bounds out of range [:73] with capacity 72` at the final append in OpenFrame, and a
// declared of 0xFFFFFFFF panics with `[:4294967335]`.
//
// THE FIXTURE IS CARVED FROM AN OVERSIZED BACKING ARRAY ON PURPOSE. A frame whose cap equals its
// len makes the mutant panic, which fails this test but also aborts the test binary and hides
// every test scheduled after it -- the failure would be real but unattributable. With 24 spare
// bytes of 'X' past len(frame), the mutant instead returns a wrong answer quietly, so the mutation
// produces exactly one `--- FAIL:` line and the rest of the suite still runs.
//
// The guard under test is the ONLY thing that can refuse these rows: the frame is 72 bytes (past
// the header check), carries the real magic (past the version check), the label is non-empty, and
// the digest slot holds SHA256 of that same label (past the context check).
func TestOpenFrameRefusesALengthFieldLongerThanTheFrame(t *testing.T) {
	label := []byte("repository/path/environment/purpose")
	payload := []byte("0123456789abcdef0123456789abcdef")

	const spare = 24
	backing := make([]byte, frameHeaderLen+len(payload)+spare)
	for index := range backing {
		backing[index] = 'X'
	}
	copy(backing, buildV2Frame(label, payload))
	frame := backing[:frameHeaderLen+len(payload)]
	if len(frame) != 72 || cap(frame) != 96 {
		t.Fatalf("setup: frame is len %d cap %d, want len 72 cap 96", len(frame), cap(frame))
	}

	cases := []struct {
		name     string
		declared uint32
		// accepted marks the KNOWN-GOOD ANCHOR. Without it a guard that refused every frame --
		// or an OpenFrame that returned ErrInvalid unconditionally -- would pass this whole
		// table. It is an anchor, not a gate: it is the honest length field, so nothing here
		// should reject it.
		accepted bool
	}{
		{name: "honest length", declared: uint32(len(payload)), accepted: true},
		{name: "one byte past the payload", declared: uint32(len(payload)) + 1},
		{name: "eight bytes past the payload", declared: uint32(len(payload)) + 8},
		{name: "to the end of the backing array", declared: uint32(len(payload)) + spare},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			setDeclaredLength(frame, testCase.declared)
			got, err := OpenFrame(frame, label)
			if testCase.accepted {
				if err != nil {
					t.Fatalf("OpenFrame refused a frame whose length field matches its payload: %v", err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatalf("OpenFrame returned %q, want %q", got, payload)
				}
				return
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("OpenFrame returned %d bytes (%q) and err=%v for a frame declaring %d bytes of payload in %d bytes of frame; the surplus is read from past the end of the frame and returned as a data key",
					len(got), got, err, testCase.declared, len(frame)-frameHeaderLen)
			}
			if got != nil {
				t.Fatalf("OpenFrame refused the frame but still returned %d bytes: %q", len(got), got)
			}
		})
	}
}

// TestOpenFrameRefusesAFrameShorterThanItsHeader holds the FIRST operand of OpenFrame's three-term
// prefix guard, `len(frame) < frameHeaderLen`. The other two operands of that same guard are
// already held -- the magic term by TestOpenFrameRefusesAV1Frame -- which is exactly why this one
// hid from the mutation sweep: killing the whole line turns TestOpenFrameRefusesAV1Frame red, so
// only killing this operand alone exposes the gap.
//
// WHAT THE CODE RETURNS WITHOUT THE OPERAND, measured with it mutated to `if false && (...)`:
// nothing refuses a truncated frame. The digest compare reads frame[4:36], the length field is
// read from frame[36:40], and `uint32(len(frame)-frameHeaderLen)` underflows -- for a 20-byte
// frame that int is -20, which converts to 4294967276 and sails past the length check -- so
// OpenFrame returns frame[40:40+declared] with err=nil. On the fixture below that is the FULL
// 32-byte payload returned for a frame that is zero, four or twenty bytes long. Where the
// truncated frame's capacity does not reach, the same input panics instead:
// `slice bounds out of range [:4] with capacity 0` and `[:0] with capacity 4`.
//
// AS WITH THE LENGTH TEST, the truncated frames are prefixes of one intact 72-byte frame, so they
// share its backing array and the mutant returns a wrong answer rather than panicking and
// aborting the binary. That is also the more alarming shape to pin: a caller that hands OpenFrame
// a short read gets a full-length data key back.
//
// Nothing else on the path can refuse these rows: frame[:4] is the real magic (the slice is short,
// the array behind it is not), the label is non-empty, and the digest slot holds SHA256 of that
// label.
func TestOpenFrameRefusesAFrameShorterThanItsHeader(t *testing.T) {
	label := []byte("repository/path/environment/purpose")
	payload := []byte("0123456789abcdef0123456789abcdef")
	intact := buildV2Frame(label, payload)
	if len(intact) != frameHeaderLen+len(payload) {
		t.Fatalf("setup: intact frame is %d bytes, want %d", len(intact), frameHeaderLen+len(payload))
	}

	// The KNOWN-GOOD ANCHOR runs first: the intact frame these prefixes are cut from opens
	// cleanly. It is an anchor, not a gate -- it proves the refusals below are about length and
	// not about a fixture OpenFrame would have rejected anyway.
	opened, err := OpenFrame(intact, label)
	if err != nil {
		t.Fatalf("setup: the intact frame the truncations are cut from was refused: %v", err)
	}
	if !bytes.Equal(opened, payload) {
		t.Fatalf("setup: the intact frame opened to %q, want %q", opened, payload)
	}

	for _, length := range []int{0, 4, 20, frameHeaderLen - 1} {
		t.Run(lengthName(length), func(t *testing.T) {
			truncated := intact[:length]
			if cap(truncated) != len(intact) {
				t.Fatalf("setup: truncated frame has cap %d, want %d -- the prefix must share the intact frame's array or the mutant panics instead of answering",
					cap(truncated), len(intact))
			}
			got, err := OpenFrame(truncated, label)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("OpenFrame accepted a %d-byte frame (the header alone is %d bytes) and returned %d bytes (%q), err=%v",
					length, frameHeaderLen, len(got), got, err)
			}
			if got != nil {
				t.Fatalf("OpenFrame refused a %d-byte frame but still returned %d bytes: %q", length, len(got), got)
			}
		})
	}
}

// lengthName keeps the subtest names greppable; t.Run of a bare number reads as a gap in the
// output the way an empty name does in TestAnUnnamedAlgorithmIsRefused.
func lengthName(length int) string {
	switch length {
	case 0:
		return "empty frame"
	case len(frameMagic):
		return "magic only"
	case frameHeaderLen - 1:
		return "one byte short of the header"
	default:
		return "truncated mid-digest"
	}
}

// TestOpenFrameRefusesAnEmptyContext holds the SECOND operand of OpenFrame's prefix guard,
// `len(label) == 0`. Its sibling operands hide it: an honest frame opened with an empty label is
// caught by the digest compare on the next line, so the operand only earns its keep against a
// frame whose digest slot holds SHA256 of the empty string -- a frame anything that can hand
// OpenFrame bytes is able to build, since the nitrokey and yubikey providers pass raw module
// output and a raw aad straight through.
//
// WHAT THE CODE RETURNS WITHOUT THE OPERAND, measured with it mutated to `if false && (...)`:
// OpenFrame(forged, []byte{}) and OpenFrame(forged, nil) both return
// "FORGEDDATAKEY-32-bytes-exactly!!" with err=nil -- a verified open of a frame bound to no
// context at all. The whole point of the digest is that a data key cannot be moved between
// contexts; an empty context is the one value for which the binding is free to forge.
func TestOpenFrameRefusesAnEmptyContext(t *testing.T) {
	forgedPayload := []byte("FORGEDDATAKEY-32-bytes-exactly!!")
	// buildV2Frame(nil, ...) writes SHA256("") into the digest slot, which is what an empty label
	// hashes to -- so the digest compare CANNOT refuse this frame, and the empty-label operand is
	// the only guard left standing.
	forged := buildV2Frame(nil, forgedPayload)

	for _, label := range [][]byte{{}, nil} {
		name := "empty slice"
		if label == nil {
			name = "nil slice"
		}
		t.Run(name, func(t *testing.T) {
			got, err := OpenFrame(forged, label)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("OpenFrame opened a frame bound to SHA256(\"\") under an empty context and returned %d bytes (%q), err=%v; an empty context must never satisfy the binding",
					len(got), got, err)
			}
			if got != nil {
				t.Fatalf("OpenFrame refused the forged frame but still returned %d bytes: %q", len(got), got)
			}
		})
	}

	// An honest frame opened with an empty label. THIS ROW HAS TWO POSSIBLE REFUSERS -- the
	// empty-label operand and the digest compare, which rejects it whichever way the operand goes
	// -- so it is documentation of the boundary, not a gate: it stays green under the mutation.
	// It is here so a reader does not mistake the operand for the thing that protects honest
	// frames.
	honestLabel := []byte("repository/path/environment/purpose")
	honest := buildV2Frame(honestLabel, forgedPayload)
	if _, err := OpenFrame(honest, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("OpenFrame opened a context-bound frame under an empty context: %v", err)
	}

	// KNOWN-GOOD ANCHOR: the same honest frame under its own context. Without it, an OpenFrame
	// that refused everything would pass every assertion above.
	opened, err := OpenFrame(honest, honestLabel)
	if err != nil {
		t.Fatalf("OpenFrame refused an honest frame under its own context: %v", err)
	}
	if !bytes.Equal(opened, forgedPayload) {
		t.Fatalf("OpenFrame returned %q, want %q", opened, forgedPayload)
	}
}

// wrapRecoveringPanic calls RSAOAEP and turns a panic into this test's own failure.
//
// It exists for one guard only: with the `!ok` operand of RSAOAEP's key/input guard removed, the
// VERY NEXT operand dereferences key.N on a nil *rsa.PublicKey, so the measured mutant outcome is
// `invalid memory address or nil pointer dereference`, not a wrong return value. A bare panic
// fails the test but also aborts the test binary, which hides every test scheduled after it and
// makes the mutation unattributable. Recovering keeps the failure loud and local.
func wrapRecoveringPanic(t *testing.T, publicDER, plaintext, label []byte, algorithm string) ([]byte, error) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("RSAOAEP panicked instead of refusing: %v; the type assertion to *rsa.PublicKey is what stops the next operand dereferencing a nil key.N",
				recovered)
		}
	}()
	return RSAOAEP(publicDER, plaintext, label, algorithm)
}

// TestRSAOAEPRefusesANonRSAPublicKey holds the FIRST operand of RSAOAEP's four-term key/input
// guard, the `!ok` from the *rsa.PublicKey type assertion. The suite only ever fed RSAOAEP either
// real RSA DER or the string "not a key" -- and "not a key" is caught one line earlier by
// ParsePKIXPublicKey -- so nothing ever reached the assertion with a key that parses and is not
// RSA. That is the whole gap: a well-formed PKIX key of the wrong family.
//
// WHAT THE CODE DOES WITHOUT THE OPERAND, measured with it mutated to `if false && !ok`: an ECDSA
// P-256 key and an Ed25519 key each panic with `invalid memory address or nil pointer
// dereference` at the very guard that was supposed to reject them, because `key` is a nil
// *rsa.PublicKey and the next operand reads key.N.BitLen(). A key of the wrong family reaching
// RSAOAEP is not hypothetical: the algorithm string and the DER come from different places -- the
// manifest and the slot -- which is the same seam TestTheAlgorithmNameMustMatchTheKeyExactly
// covers for size.
//
// Both rows reach the assertion: ParsePKIXPublicKey succeeds on both (asserted below, so the
// parse guard is not credited with the refusal) and "rsa2048" is on the algorithm allowlist.
func TestRSAOAEPRefusesANonRSAPublicKey(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaDER, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	edPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edDER, err := x509.MarshalPKIXPublicKey(edPublic)
	if err != nil {
		t.Fatal(err)
	}

	for _, testCase := range []struct {
		name string
		der  []byte
	}{
		{name: "ecdsa P-256", der: ecdsaDER},
		{name: "ed25519", der: edDER},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			// Prove the parse guard is not the refuser before asserting on the assertion.
			parsed, err := x509.ParsePKIXPublicKey(testCase.der)
			if err != nil {
				t.Fatalf("setup: the %s key does not parse, so it never reaches the type assertion: %v", testCase.name, err)
			}
			if _, isRSA := parsed.(*rsa.PublicKey); isRSA {
				t.Fatalf("setup: the %s key parsed as *rsa.PublicKey", testCase.name)
			}
			wrapped, err := wrapRecoveringPanic(t, testCase.der, []byte("data-key"), []byte("repository/path/environment/purpose"), "rsa2048")
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("RSAOAEP accepted a %s key offered as rsa2048 and returned %d bytes, err=%v", testCase.name, len(wrapped), err)
			}
			if wrapped != nil {
				t.Fatalf("RSAOAEP refused the %s key but still returned %d bytes", testCase.name, len(wrapped))
			}
		})
	}

	// KNOWN-GOOD ANCHOR: a real RSA key of the declared size still wraps. Without it, an RSAOAEP
	// that refused every key would pass both rows above. It is an anchor, not a gate --
	// TestTheAlgorithmNameMustMatchTheKeyExactly is what holds the accepting path.
	wrapped, err := RSAOAEP(publicKeyOfSize(t, 2048), []byte("data-key"), []byte("repository/path/environment/purpose"), "rsa2048")
	if err != nil {
		t.Fatalf("RSAOAEP refused a genuine 2048-bit key: %v", err)
	}
	if len(wrapped) != 256 {
		t.Fatalf("wrapped output is %d bytes, want 256", len(wrapped))
	}
}

// TestRSAOAEPRefusesAnEmptyDataKey holds the THIRD operand of RSAOAEP's four-term key/input guard,
// `len(plaintext) == 0`. Its siblings are covered -- TestTheAlgorithmNameMustMatchTheKeyExactly
// holds the BitLen term and TestRSAOAEPRejectsAlgorithmAndKeyMismatch holds the empty-label term
// -- which is why this one hid inside the compound condition.
//
// WHAT THE CODE RETURNS WITHOUT THE OPERAND, measured with it mutated to
// `(false && (len(plaintext) == 0))`: RSAOAEP returns a 256-byte envelope and err=nil. The
// envelope is cryptographically valid and correctly context-bound; it just wraps nothing. It
// round-trips back through DecryptOAEP to a 40-byte frame and through OpenFrame to a ZERO-BYTE
// data key with err=nil. The refusal then surfaces three packages away as envelope.go's
// `len(dataKey) != 32`, which blames the envelope for what happened here.
func TestRSAOAEPRefusesAnEmptyDataKey(t *testing.T) {
	public := publicKeyOfSize(t, 2048)
	label := []byte("repository/path/environment/purpose")

	for _, testCase := range []struct {
		name      string
		plaintext []byte
	}{
		{name: "empty slice", plaintext: []byte{}},
		{name: "nil slice", plaintext: nil},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			wrapped, err := RSAOAEP(public, testCase.plaintext, label, "rsa2048")
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("RSAOAEP wrapped an empty data key into %d bytes, err=%v; the envelope is well-formed and context-bound and carries nothing, and the refusal moves to envelope.go's len(dataKey) != 32",
					len(wrapped), err)
			}
			if wrapped != nil {
				t.Fatalf("RSAOAEP refused an empty data key but still returned %d bytes", len(wrapped))
			}
		})
	}

	// KNOWN-GOOD ANCHOR: one non-empty byte is enough to be wrapped. It pins the refusal to
	// emptiness rather than to the key, the label or the algorithm, all of which are identical
	// across the rows above.
	wrapped, err := RSAOAEP(public, []byte{0x01}, label, "rsa2048")
	if err != nil {
		t.Fatalf("RSAOAEP refused a one-byte data key: %v", err)
	}
	if len(wrapped) != 256 {
		t.Fatalf("wrapped output is %d bytes, want 256", len(wrapped))
	}
}

// TestRSAOAEPRefusesAPlaintextTooLargeForTheModulus holds the error check on rsa.EncryptOAEP. The
// frame is header(40) + plaintext, and OAEP-SHA1 on a 2048-bit key can carry at most 214 bytes, so
// a plaintext past ~174 bytes makes the primitive refuse. Nothing in the suite wrapped a plaintext
// anywhere near that size.
//
// WHAT THE CODE RETURNS WITHOUT THE GUARD, measured with it mutated to `if false && (err != nil)`:
// `wrapped=nil, err=nil` -- a nil blob reported as a successful wrap. The three call sites
// (nitrokey's provider and PKCS#11 driver, yubikey's provider) each test only `err != nil` and
// then return the output, so the nil becomes an envelope body and the failure surfaces at
// decrypt time, far from here.
//
// The row below reaches the primitive: the key parses, is *rsa.PublicKey, is exactly 2048 bits,
// the plaintext and label are non-empty, and "rsa2048" is on the allowlist -- so
// rsa.EncryptOAEP's own refusal (`crypto/rsa: message too long for RSA key size`) is the only
// thing that can turn this into ErrInvalid.
func TestRSAOAEPRefusesAPlaintextTooLargeForTheModulus(t *testing.T) {
	public := publicKeyOfSize(t, 2048)
	label := []byte("repository/path/environment/purpose")

	oversized := bytes.Repeat([]byte{'A'}, 400)
	wrapped, err := RSAOAEP(public, oversized, label, "rsa2048")
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("RSAOAEP reported success for a %d-byte plaintext that OAEP-SHA1 on a 2048-bit key cannot carry: wrapped=%d bytes, wrapped==nil is %t, err=%v",
			len(oversized), len(wrapped), wrapped == nil, err)
	}
	if wrapped != nil {
		t.Fatalf("RSAOAEP refused the oversized plaintext but still returned %d bytes", len(wrapped))
	}

	// KNOWN-GOOD ANCHOR: a 32-byte data key on the same key and label wraps to a full modulus
	// worth of ciphertext. Without it, a mutation that broke every wrap -- or made RSAOAEP return
	// ErrInvalid unconditionally -- would pass the assertion above.
	control, err := RSAOAEP(public, bytes.Repeat([]byte{'A'}, 32), label, "rsa2048")
	if err != nil {
		t.Fatalf("RSAOAEP refused a 32-byte data key on the same key and label: %v", err)
	}
	if len(control) != 256 {
		t.Fatalf("wrapped output is %d bytes, want 256", len(control))
	}
}

// ---------------------------------------------------------------------------------------------
// WHAT A RE-SWEEP OF THIS FILE COULD NOT CLOSE, AND WHY (#237).
//
// Re-running the operand sweep over rsa.go -- 7 sites, 14 operands, 21 operand-directions -- left
// nothing detectable uncovered: every operand's neutralisation and every site's forced direction is
// killed by the scoped test set (this package plus nitrokey, yubikey, integration and
// cmd/regalia-kms, the packages whose `go list -deps -test` closure reaches it), except the two §17
// pairs already written up -- the allowlist, in TestAnUnnamedAlgorithmIsRefused, and the
// ParsePKIXPublicKey error check, beside that same test's last row. A second round of expression
// mutations -- the kind an operand sweep structurally cannot
// reach -- found these three, and none of them is closeable by a test as the code stands. They are
// recorded here rather than left as a green that looks like coverage.
//
// 1. `defer zero(frame)` IN RSAOAEP IS UNREACHABLE BY ANY FIXTURE. The frame holds the data key in
//    the clear, and wiping it is the only hygiene step on the wrap path. Deleting the defer, and
//    replacing it with a no-op that still references `frame`, both leave the entire package set
//    green. Nothing can close this: `frame` is a function-local whose backing array no test can
//    address once RSAOAEP has returned. It is not a §17 masking case -- there is no second guard --
//    it is an unobservable postcondition. secrets.Releaser's `zero(released)` is the same shape.
//
// 2. THE DECLARED-LENGTH BOUND IS NAMED ON ONE SIDE ONLY.
//    TestOpenFrameRefusesALengthFieldLongerThanTheFrame holds `declared` greater than the frame; nothing holds it smaller, and the guard
//    admits every such value by design, because a declared length below the available bytes is
//    exactly the RFC 5649 padding case the length field was introduced for. Measured on a 72-byte
//    frame carrying a 32-byte payload: declared=24 returns 24 bytes with err=nil, and declared=0
//    returns a NIL data key with err=nil. The zero case is a success that carries nothing, refused
//    three packages away by envelope.go's `len(dataKey) != 32` -- the same misleading refusal the
//    length field's own doc comment says it exists to remove. It is deliberately NOT pinned here:
//    asserting `(nil, nil)` is correct would fix the gap in place.
//
// 3. `OAEPHash` IS UNPINNED HERE, AND THAT IS THE DESIGN. Changing it to crypto.SHA256 leaves this
//    package green, because nitrokey's TestOAEPParametersExpressTheWrappingHash accepts SHA-1 or
//    SHA-256 and pins the PKCS#11 mechanism parameters to whichever is named. The constant's own
//    comment says the move is a one-line change plus a hardware interop run; the test enforces the
//    derivation, not the value. Recorded so the survivor is not re-found and re-filed as a gap.
// ---------------------------------------------------------------------------------------------
