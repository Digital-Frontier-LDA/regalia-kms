//go:build piv

package yubikey

// #215: the yubikey unwrap path had nothing asserting that a v1-framed artifact is refused.
// #206 made the frame magic a real compatibility boundary — keywrap.OpenFrame requires
// `RGK\x02` and refuses `RGK\x01` — and it is pinned for keywrap itself by
// TestOpenFrameRefusesAV1Frame. The yubikey backend reaches OpenFrame at provider.go's
// unwrap arm and had no equivalent, so a v1 artifact arriving through a YubiKey was
// unexamined.
//
// THE FORMAT IS `regalia-envelope-v2`, DELIBERATELY. That is the allowlisted format, so the
// third-format guard passes and OpenFrame is the only thing left that can refuse. Naming a
// v1 FORMAT string here would test the allowlist —
// TestUnwrapRefusesAFormatOutsideTheAllowlist already does — and would never reach the frame
// check this test exists for.
//
// The build constraint matches sweep_uncovered_test.go, whose framedUnwrapSession and
// framedUnwrapDriver this reuses. Redefining them untagged would collide with those on any
// `-tags piv` build, which is a duplicate-symbol failure git reports as no conflict at all.

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestUnwrapRefusesAV1FrameFromTheCard(t *testing.T) {
	aad := []byte("aad-for-the-v1-frame-test")

	// THE PLAINTEXT'S FIRST FOUR BYTES ARE THE FIXTURE'S WHOLE POINT, and getting them wrong
	// is how the keywrap version of this test originally passed for the wrong reason: its
	// plaintext began "0123", which a magic-disabled OpenFrame read as a declared length of
	// 808530483, so the LENGTH check rejected the frame and the version gate decided nothing.
	//
	// A v1 frame is magic(4) || sha256(label)(32) || plaintext — no length field. With the
	// magic check disabled, OpenFrame reads bytes 36..40 as the declared length, which are
	// the plaintext's first four. `\x00\x00\x00\x04` makes that 4, and 68-40 = 28 bytes
	// remain, so OpenFrame SUCCEEDS and returns four bytes. That is what makes the magic
	// check the sole detector: mutate it away and this test does not merely fail differently,
	// it flips from refusal to a returned key.
	plaintext := []byte{0x00, 0x00, 0x00, 0x04,
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
		'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b'}
	if declared := uint32(plaintext[0])<<24 | uint32(plaintext[1])<<16 | uint32(plaintext[2])<<8 | uint32(plaintext[3]); declared != 4 {
		t.Fatalf("the fixture's leading uint32 is %d, not 4 — a magic-disabled OpenFrame would reject it on LENGTH and this test would certify a gate it never reached", declared)
	}

	digest := sha256.Sum256(aad)
	v1Frame := make([]byte, 0, 4+sha256.Size+len(plaintext))
	v1Frame = append(v1Frame, 'R', 'G', 'K', 1)
	v1Frame = append(v1Frame, digest[:]...)
	v1Frame = append(v1Frame, plaintext...)

	session := &framedUnwrapSession{riggedSession: healthySession(), unwrapFrame: v1Frame}
	provider, err := New(&framedUnwrapDriver{session: session}, &fakePIN{value: []byte("123456")})
	if err != nil {
		t.Fatal(err)
	}
	unwrapRoute := route()
	unwrapRoute.Algorithm = "rsa2048"

	output, _, execErr := provider.Execute(context.Background(), unwrapRoute, "unwrap", "regalia-envelope-v2", "", []byte("any"), aad)
	if execErr == nil {
		t.Fatalf("a v1 frame from the card was unwrapped and returned %q — RGK\\x01 is a format this build does not speak, and accepting it means an envelope sealed under the old rules is opened under the new ones", output)
	}
	if !errors.Is(execErr, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", execErr)
	}

	// CONTROL, IN THE SAME TEST (§18). The identical fixture with the version byte bumped to 2
	// must succeed. Without it, every assertion above is satisfied by a path that refuses every
	// frame — and this whole file would be certifying nothing. It also proves the digest and
	// length fields are right, so the refusal above is attributable to the version byte alone.
	v2Frame := append([]byte(nil), v1Frame...)
	v2Frame[3] = 2
	// v2 carries an explicit length field where v1 has none, so the declared length is read
	// from the plaintext's leading bytes exactly as the mutation case reads it: 4.
	session.unwrapFrame = v2Frame
	if _, _, controlErr := provider.Execute(context.Background(), unwrapRoute, "unwrap", "regalia-envelope-v2", "", []byte("any"), aad); controlErr != nil {
		t.Fatalf("the same frame with version byte 2 was also refused (%v) — the fixture is not what this test thinks it is, and the v1 refusal above proves nothing", controlErr)
	}
}
