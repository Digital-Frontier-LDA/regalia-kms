package nitrokey

import (
	"context"
	"strings"
	"testing"

	"github.com/miekg/pkcs11"
)

// lookupToken answers the object-lookup calls and counts them.
//
// The embedded nil cryptoki is this package's convention and is kept deliberately: any method these
// tests do not stub PANICS rather than returning a usable zero value, so a guard that starts calling
// something new fails loudly here instead of quietly passing against an invented answer.
//
// What is stubbed is the lookup and operation path, and it reports NO matching object — so a guard
// defeated upstream reaches this and fails on a real refusal, which can be attributed, rather than
// on a panic that takes the binary down and leaves the operand unattributable.
//
// The counters separate "refused" from "refused after asking the token", which is the property these
// guards are for: malformed input must never reach the card.
type lookupToken struct {
	cryptoki
	findInits, finds, signs, decrypts, wraps, derives int
}

func (token *lookupToken) FindObjectsInit(pkcs11.SessionHandle, []*pkcs11.Attribute) error {
	token.findInits++
	return nil
}

func (token *lookupToken) FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
	token.finds++
	return nil, false, nil
}

func (token *lookupToken) FindObjectsFinal(pkcs11.SessionHandle) error { return nil }

func (token *lookupToken) SignInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
	token.signs++
	return nil
}

func (token *lookupToken) DecryptInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
	token.decrypts++
	return nil
}

func (token *lookupToken) WrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, pkcs11.ObjectHandle) ([]byte, error) {
	token.wraps++
	return nil, nil
}

func (token *lookupToken) DeriveKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	token.derives++
	return 0, nil
}

func authenticatedSession(token *lookupToken) *pkcs11Session {
	return &pkcs11Session{module: token, loggedIn: true}
}

// TestEveryCryptoEntryPointRefusesEmptyInputBeforeTheToken pins the empty-input operand on each of
// the four operations a caller can reach.
//
// They survive both detectors for the same structural reason: the SoftHSM battery drives well-formed
// requests end to end, so nothing has ever handed these functions an empty argument. The unit suite
// cannot reach them either, because it exercises the provider against a fakeSession rather than the
// concrete pkcs11Session — these are reachable here only because pkcs11Session is a struct this
// package's tests can build.
//
// Isolation: the session is authenticated and the context live, so the shared privateUsable operand
// cannot fire; each row leaves every other argument well-formed; and the token COUNTS its calls, so
// a defeated guard shows up as a request that reached the card rather than as a refusal from
// somewhere else.
func TestEveryCryptoEntryPointRefusesEmptyInputBeforeTheToken(t *testing.T) {
	// Each row names the message its guard produces. That is not decoration: for Derive the guard
	// is MASKED by ecPointFromPKIX, which refuses a nil key at the very next line with an error of
	// its own and without touching the token -- so "an error came back" and "the token was not
	// called" are both true with the operand deleted, and only the text distinguishes them.
	for _, test := range []struct {
		name    string
		call    func(*pkcs11Session) error
		operand string
		want    string
	}{
		{"Sign with no data", func(s *pkcs11Session) error {
			_, err := s.Sign(context.Background(), "01", "rsa2048", nil)
			return err
		}, "len(data) == 0", "PKCS#11 signing unavailable"},
		{"Unwrap with no ciphertext", func(s *pkcs11Session) error {
			_, err := s.Unwrap(context.Background(), "01", "rsa2048", nil, []byte("aad"))
			return err
		}, "len(ciphertext) == 0", "PKCS#11 unwrap unavailable"},
		{"Unwrap with no AAD", func(s *pkcs11Session) error {
			_, err := s.Unwrap(context.Background(), "01", "rsa2048", []byte("wrapped"), nil)
			return err
		}, "len(aad) == 0", "PKCS#11 unwrap unavailable"},
		{"Wrap with no plaintext", func(s *pkcs11Session) error {
			_, err := s.Wrap(context.Background(), "01", "rsa2048", nil, []byte("aad"))
			return err
		}, "len(plaintext) == 0", "PKCS#11 wrap unavailable"},
		{"Derive with no peer key", func(s *pkcs11Session) error {
			_, err := s.Derive(context.Background(), "01", "p256", nil)
			return err
		}, "len(peerPKIX) == 0", "PKCS#11 key agreement unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := &lookupToken{}
			err := test.call(authenticatedSession(token))
			if err == nil {
				t.Fatalf("DEFECT: %s was accepted; operand %s is the only thing refusing it",
					test.name, test.operand)
			}
			if err.Error() != test.want {
				t.Fatalf("DEFECT: %s was refused as %q, want %q. Operand %s did not fire; something "+
					"further in produced the refusal, which means the guard could be deleted and "+
					"this row would still see an error", test.name, err.Error(), test.want, test.operand)
			}
			if total := token.findInits + token.finds + token.signs + token.decrypts + token.wraps + token.derives; total != 0 {
				t.Fatalf("DEFECT: %s reached the token (%d calls) before being refused; these guards "+
					"exist so malformed input never gets to the card", test.name, total)
			}
		})
	}
}

// TestTheAlgorithmAllowlistsRefuseWhatIsNotInThem pins the three allowlist operands.
//
// wrappingAlgorithm admits rsa2048/3072/4096 and aes-256; agreementAlgorithm admits p256 and p384.
// Each guard is what stops a mechanism being selected for an algorithm the driver has not been
// taught, and the switch below it has no default that refuses — so defeating the guard falls through
// to whichever branch the switch does have, or past it.
//
// "opaque" is the row that matters rather than a nonsense string: it is a real algorithm value in
// this system, the one the registry gives an opaque secret, and it reaches this code whenever a
// route carries the object's algorithm instead of the KEK's. That mistake has been made before —
// internal/secrets carries a comment about it — so the refusal is not hypothetical.
//
// Isolation: every other argument is well-formed, so only the algorithm can account for the refusal,
// and each control uses an admitted algorithm to show the same call proceeds.
func TestTheAlgorithmAllowlistsRefuseWhatIsNotInThem(t *testing.T) {
	for _, test := range []struct {
		name, algorithm, want string
		call                  func(*pkcs11Session, string) error
	}{
		{"Unwrap", "opaque", "unwrap algorithm unavailable", func(s *pkcs11Session, a string) error {
			_, err := s.Unwrap(context.Background(), "01", a, []byte("wrapped"), []byte("aad"))
			return err
		}},
		{"Wrap", "opaque", "wrap algorithm unavailable", func(s *pkcs11Session, a string) error {
			_, err := s.Wrap(context.Background(), "01", a, []byte("plaintext"), []byte("aad"))
			return err
		}},
		{"Derive", "rsa2048", "key agreement algorithm unavailable", func(s *pkcs11Session, a string) error {
			_, err := s.Derive(context.Background(), "01", a, []byte("peer"))
			return err
		}},
	} {
		t.Run(test.name+" refuses "+test.algorithm, func(t *testing.T) {
			token := &lookupToken{}
			err := test.call(authenticatedSession(token), test.algorithm)
			if err == nil {
				t.Fatalf("DEFECT: %s accepted algorithm %q, which its allowlist does not admit; the "+
					"switch below the guard has no refusing default, so this falls through",
					test.name, test.algorithm)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("refusal is %q, want it to contain %q — the empty-input guard above returns "+
					"a different message, and only the text says which one refused",
					err.Error(), test.want)
			}
			if total := token.findInits + token.finds + token.decrypts + token.wraps + token.derives; total != 0 {
				t.Fatalf("DEFECT: an unlisted algorithm reached the token (%d calls)", total)
			}
		})
	}

	// Controls: an admitted algorithm gets PAST the allowlist, which is what shows the rows above
	// were not passing because the call is refused for some unrelated reason.
	//
	// The two get past it and then fail in DIFFERENT places, and saying so matters more than it
	// looks: a comment that names one outcome for both would be describing something the fixture
	// does not produce. Measured:
	//
	//	Unwrap rsa2048          -> "PKCS#11 object lookup failed"    findInits=1
	//	Derive p256, peer="peer" -> "peer public key is malformed"   findInits=0
	//
	// Derive never reaches the lookup because ecPointFromPKIX rejects "peer" as a PKIX key first.
	// That is still past the allowlist, which is all the control claims.
	for _, test := range []struct {
		name, algorithm, past string
		call                  func(*pkcs11Session, string) error
	}{
		{"Unwrap", "rsa2048", "PKCS#11 object lookup failed", func(s *pkcs11Session, a string) error {
			_, err := s.Unwrap(context.Background(), "01", a, []byte("wrapped"), []byte("aad"))
			return err
		}},
		{"Derive", "p256", "peer public key is malformed", func(s *pkcs11Session, a string) error {
			_, err := s.Derive(context.Background(), "01", a, []byte("peer"))
			return err
		}},
	} {
		t.Run(test.name+" admits "+test.algorithm, func(t *testing.T) {
			token := &lookupToken{}
			err := test.call(authenticatedSession(token), test.algorithm)
			if err != nil && strings.Contains(err.Error(), "algorithm unavailable") {
				t.Fatalf("control is broken: %q was refused by the allowlist (%v), so the rows above "+
					"prove nothing", test.algorithm, err)
			}
			if err == nil || err.Error() != test.past {
				t.Fatalf("control refused %q with %v, want %q — the control asserts WHERE it got to, "+
					"not merely that it got somewhere, so the comment above cannot drift from it",
					test.algorithm, err, test.past)
			}
		})
	}
}

// TestFindObjectRefusesAnObjectIdentifierItCannotUse pins the two length operands on the decoded id.
//
// The identifier arrives as hex from the binding and becomes CKA_ID in the search template. An empty
// one matches the attribute being absent rather than being empty, so the search would return
// whatever else the token holds; one longer than 64 bytes is longer than any CKA_ID a token will
// store, and the driver refuses it here rather than letting the search fail with a mechanism error
// that says nothing about the cause.
//
// Isolation: each row is valid hex, so the sibling decode-error operand cannot fire, and the token
// counts FindObjectsInit so a defeated guard is visible as a search that was actually issued.
func TestFindObjectRefusesAnObjectIdentifierItCannotUse(t *testing.T) {
	for _, test := range []struct {
		name, objectID, operand string
	}{
		{"an empty identifier", "", "len(id) == 0"},
		{"65 bytes, one over the bound", strings.Repeat("ab", 65), "len(id) > 64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			token := &lookupToken{}
			_, err := authenticatedSession(token).findObject(test.objectID, pkcs11.CKO_PRIVATE_KEY)
			if err == nil {
				t.Fatalf("DEFECT: object identifier %q (%d hex characters) was accepted; operand %s "+
					"is what refuses it", test.objectID, len(test.objectID), test.operand)
			}
			if token.findInits != 0 {
				t.Fatalf("DEFECT: the search was issued (%d FindObjectsInit calls) with an "+
					"identifier the driver cannot use", token.findInits)
			}
			if want := "invalid PKCS#11 object identifier"; err.Error() != want {
				t.Fatalf("refusal is %q, want %q", err.Error(), want)
			}
		})
	}

	// 64 bytes is the bound and must be ACCEPTED: it gets past the guard and fails in the search,
	// which is what makes this a bound rather than an assertion that long identifiers are bad.
	token := &lookupToken{}
	_, err := authenticatedSession(token).findObject(strings.Repeat("ab", 64), pkcs11.CKO_PRIVATE_KEY)
	if err == nil {
		t.Fatal("control is unexpectedly succeeding; it was written to reach the object search")
	}
	if token.findInits != 1 {
		t.Fatalf("control is broken: a 64-byte identifier, exactly the bound, issued %d searches; "+
			"the guard is `> 64`, so 64 must be accepted", token.findInits)
	}
}
