//go:build piv

package yubikey

// THE GUARDS THAT STAND BETWEEN A CALLER AND THE CARD.
//
// piv_driver.go is behind `//go:build piv`, so every sweep in this repository
// that ran a plain `go test ./...` compiled none of it and read the silence as
// "no mutation was detected". Its session methods were then assumed to need a
// reader: they take a *piv.YubiKey, and one cannot be built without a card.
//
// That is true of the card CALLS and false of the guards in front of them. Every
// method here refuses before it reaches the card, and a refusal that happens
// before the card is reached can be measured without one.
//
// THE FIXTURE. `&piv.YubiKey{}` is a card that cannot be spoken to: its
// connection handles are nil, so any transmission dereferences nil and panics.
// That makes it an instrument rather than a nuisance. The two outcomes are
// distinguishable, which is the whole difficulty with guards whose siblings
// refuse the same input:
//
//	ErrUnavailable   the guard refused, and the card was never asked
//	panic            control flow reached the card
//
// Without that separation, "something refused" is all a test can see, and a
// guard removed from in front of another guard changes nothing observable. The
// panic is caught in each case below, so a mutation surfaces as one named
// failing test instead of an aborted binary reporting the whole package.
//
// NO READER IS TOUCHED AND THE OUTCOME IS NOT PLATFORM-DEPENDENT. Nothing here
// calls piv.Cards or piv.Open, so PC/SC is never entered. Observed against
// piv-go v2.6.0, the panic is a Go nil pointer dereference of scTx.h — the
// transmit path's first statement on every platform it builds for — raised
// before any C call, so it does not depend on a daemon, a reader, or a card
// being present. A test that inferred a refusal from an absent reader would
// give a different verdict on the bench, which is the one thing an instrument
// may not do. What the instrument ASSERTS is stated at isCardContactPanic and
// is deliberately broader than this observation.

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

// unreachableCard is a YubiKey whose PC/SC handles are nil. Reaching it is an
// event this file can observe; talking to it is not possible by construction.
func unreachableCard() *piv.YubiKey { return &piv.YubiKey{} }

// pivModulePath is the module a card-contact panic must come from. Matching on
// the module rather than on a file and line makes this survive a patch release;
// what makes a BREAKING change loud instead of silent is
// TestTheUnreachableCardInstrumentSeparatesItsThreeOutcomes below, whose second
// arm requires a real contact to still be recognised.
const pivModulePath = "github.com/go-piv/piv-go"

// cardContact is what one call to a session method actually did.
type cardContact int

const (
	refusedBeforeTheCard cardContact = iota
	reachedTheCard
	panickedForAnotherReason
)

type attempt struct {
	contact   cardContact
	err       error
	recovered any
	stack     string
}

// attemptCall classifies one call into exactly three outcomes.
//
// THE FIRST VERSION OF THIS COUNTED ANY PANIC AS CARD CONTACT, which is the
// same defect this file exists to find: a signal broad enough to be true for
// reasons other than the one it names. A nil map write, an index out of range,
// or a nil dereference anywhere else in the path would all have reported
// "control reached the card" — the opposite of what happened — and every
// assertion built on it would have been reading noise.
//
// WHAT IS ASSERTED, WHICH IS BROADER THAN WHAT WAS OBSERVED. Read the code, not
// this paragraph, if the two ever disagree — but they should not, and an earlier
// version of this comment made them disagree, which is the same defect this file
// exists to find one level up: prose claiming a precision the implementation does
// not have, so a reader trusts a discrimination that is not being made.
//
//	asserted   a value satisfying runtime.Error, whose text contains "nil
//	           pointer dereference", raised ANYWHERE inside the module
//	           github.com/go-piv/piv-go
//
//	observed   against piv-go v2.6.0, that panic arrives as
//	           runtime.errorString, "runtime error: invalid memory address or
//	           nil pointer dereference", from piv.(*scTx).transmit at
//	           pcsc_unix.go:133, dereferencing t.h
//
// The frame is evidence, not the test. Pinning pcsc_unix.go:133 would be a
// narrower assertion and a WORSE one: a patch release that moves the line, or
// reaches the same nil handle from a neighbouring function, would stop matching
// and every "did not reach the card" assertion in this file would begin passing
// vacuously — a silent inversion toward green, which is the direction that does
// not announce itself.
//
// Module granularity is also the right granularity for the claim. What these
// tests assert is that a guard refused BEFORE the card was asked, and entering
// piv-go at all is being asked; the fixture's only route into that module is a
// card call, so a nil dereference inside it is card contact whatever function
// raises it.
//
// Both halves of the check are load-bearing. The runtime-error class alone would
// match a nil dereference of our own making; the module alone would match a
// deliberate panic raised inside piv-go. Everything else is reported as itself,
// and the arms of the instrument test below measure each of those cases rather
// than asserting them here.
func attemptCall(call func() error) (result attempt) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}
		stack := string(debug.Stack())
		contact := panickedForAnotherReason
		if isCardContactPanic(recovered, stack) {
			contact = reachedTheCard
		}
		result = attempt{contact: contact, recovered: recovered, stack: stack}
	}()
	return attempt{contact: refusedBeforeTheCard, err: call()}
}

func isCardContactPanic(recovered any, stack string) bool {
	if _, isRuntime := recovered.(runtime.Error); !isRuntime {
		return false
	}
	if !strings.Contains(fmt.Sprint(recovered), "nil pointer dereference") {
		return false
	}
	return strings.Contains(stack, pivModulePath)
}

// requireClassified fails the test when the call panicked for a reason that is
// not contact with the unreachable card. An unclassified panic is evidence of
// nothing, and silently counting it as contact — or as a refusal — would make
// every result in this file mean something other than what it says.
func (a attempt) requireClassified(t *testing.T) {
	t.Helper()
	if a.contact == panickedForAnotherReason {
		t.Fatalf("the call panicked for a reason that is not contact with the unreachable card: %v\n%s\n"+
			"this instrument recognises one kind of panic — a runtime nil pointer dereference raised inside %s — "+
			"and reports every other one as itself, because a panic counted as card contact would make "+
			"the verdict the opposite of what happened", a.recovered, a.stack, pivModulePath)
	}
}

// THE INSTRUMENT IS TESTED BEFORE ANYTHING IS MEASURED WITH IT.
//
// An instrument whose empty result is indistinguishable from a broken one
// certifies nothing, and this one has a specific way of going wrong: if a
// piv-go release stopped panicking on an unreachable card and returned an error
// instead, every "did not reach the card" assertion in this file would pass
// vacuously. That is a silent inversion toward green, so the second arm below
// pins the positive direction and turns it into a loud red instead.
//
// The third arm is the falsification the first version of this instrument could
// not survive: the SAME runtime error class, a nil pointer dereference, raised
// somewhere that is not the card. A discriminator matching on the panic's text
// alone calls it contact. This one must not.
func TestTheUnreachableCardInstrumentSeparatesItsThreeOutcomes(t *testing.T) {
	// THIS ARM DELIBERATELY DOES NOT CALL A SESSION METHOD. Its first version
	// used Identity on a cardless session, which is one of the operands this
	// file measures, so neutralising `session.card == nil` made the instrument
	// test fail alongside the test that names the defect — an instrument
	// sharing its subject's assumption. What is under test here is the
	// classifier's no-panic path, and a plain error exercises it without
	// coupling to any guard.
	t.Run("a refusal before the card", func(t *testing.T) {
		result := attemptCall(func() error { return ErrUnavailable })
		if result.contact != refusedBeforeTheCard {
			t.Fatalf("a call that returned an error was classified %v, want refusedBeforeTheCard", result.contact)
		}
		if !errors.Is(result.err, ErrUnavailable) {
			t.Fatalf("err = %v, want the error the call returned", result.err)
		}
	})

	t.Run("contact with the card", func(t *testing.T) {
		session := &pivSession{card: unreachableCard(), serial: "12345678"}
		result := attemptCall(func() error {
			return session.Login(context.Background(), []byte("123456"))
		})
		if result.contact != reachedTheCard {
			t.Fatalf("a PIN of an accepted length did not register as contact with the card "+
				"(classified %v, err %v, recovered %v) — either the guard under test changed or %s no longer "+
				"panics on an unreachable card, and in both cases every negative assertion in this file is "+
				"now passing for the wrong reason",
				result.contact, result.err, result.recovered, pivModulePath)
		}
	})

	t.Run("a panic that is not card contact", func(t *testing.T) {
		for name, call := range map[string]func() error{
			// Not a runtime error at all.
			"a deliberate panic": func() error { panic("this is not contact with a card") },
			// THE ARM THAT MATTERS: the identical runtime error class and text
			// as a real card contact, raised outside piv-go. Matching on the
			// message alone would classify this as contact.
			"a nil dereference of our own making": func() error {
				var absent *pivSession
				return errors.New(absent.serial)
			},
			// A different runtime error entirely.
			"an index out of range": func() error {
				empty := make([]byte, 0)
				_ = empty[1]
				return nil
			},
		} {
			t.Run(name, func(t *testing.T) {
				result := attemptCall(call)
				if result.contact == reachedTheCard {
					t.Fatalf("%q was classified as contact with the card — the discriminator is then true for "+
						"reasons other than the one it names, and every \"did not reach the card\" assertion "+
						"in this file rests on it", name)
				}
				if result.contact != panickedForAnotherReason {
					t.Fatalf("%q was classified %v, want panickedForAnotherReason", name, result.contact)
				}
			})
		}
	})
}

// ----------------------------------------------------------------------------
// piv_driver.go:240 op0, :245 op0, :245 op1 — usable
// piv_driver.go:101, :112, :127, :188, :207 op0 — every caller of usable
// ----------------------------------------------------------------------------

// A SESSION THAT IS NOT USABLE MUST REFUSE WITHOUT REACHING THE CARD.
//
// usable has three ways to say no and each was unmeasured. The three fixtures
// below make one of them the sole refuser: no card at all, a card behind a
// session that has been closed, and a card behind a cancelled context. Every
// read method is driven through all three, because usable is called from five
// places and a guard missing at one of them is invisible at the other four.
//
// Falsifiers, each producing this test as the failure:
//
//	:245 op1 -> `(false && session.card == nil)`   "no card" reaches the card
//	:245 op0 -> `(false && session.closed)`        "closed" reaches the card
//	:240 op0 -> `(false && ctx.Err() != nil)`      "cancelled" reaches the card
//	:101 op0 -> `(false && err != nil)`            Identity reaches the card
//	:112/:127/:188/:207 op0, likewise, one method each
func TestASessionThatIsNotUsableRefusesWithoutReachingTheCard(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	// EVERY FIXTURE CARRIES A VERIFIED PIN, and the first draft did not. Without
	// it, privateKey's `session.pin == ""` refuses Sign and Unwrap on its own,
	// so the usability check above it was never the sole refuser and the claim
	// against :207 op0 did not hold when it was measured. A session that has
	// logged in and then become unusable is also the case that matters: the
	// PIN is verified, the card is gone, and only usable stands in the way.
	for name, build := range map[string]func() (*pivSession, context.Context){
		// :245 op1 — closed is false, so the nil card is the only refuser.
		"no card at all": func() (*pivSession, context.Context) {
			return &pivSession{serial: "12345678", pin: "123456"}, context.Background()
		},
		// :245 op0 — the card is present, so `closed` is the only refuser.
		"a session already closed": func() (*pivSession, context.Context) {
			return &pivSession{card: unreachableCard(), serial: "12345678", pin: "123456", closed: true}, context.Background()
		},
		// :240 op0 — open and carrying a card, so the context is the only refuser.
		"a cancelled context": func() (*pivSession, context.Context) {
			return &pivSession{card: unreachableCard(), serial: "12345678", pin: "123456"}, cancelled
		},
	} {
		t.Run(name, func(t *testing.T) {
			for method, call := range map[string]func(*pivSession, context.Context) error{
				"Identity": func(s *pivSession, ctx context.Context) error {
					_, err := s.Identity(ctx)
					return err
				},
				"Policies": func(s *pivSession, ctx context.Context) error {
					_, _, err := s.Policies(ctx, "9c")
					return err
				},
				"PINRetries": func(s *pivSession, ctx context.Context) error {
					_, err := s.PINRetries(ctx)
					return err
				},
				"PublicKey": func(s *pivSession, ctx context.Context) error {
					_, err := s.PublicKey(ctx, "9c")
					return err
				},
				"Sign": func(s *pivSession, ctx context.Context) error {
					_, err := s.Sign(ctx, "9c", "p256", make([]byte, 32))
					return err
				},
				"Unwrap": func(s *pivSession, ctx context.Context) error {
					_, err := s.Unwrap(ctx, "9c", "rsa2048", []byte("ciphertext"), nil)
					return err
				},
			} {
				t.Run(method, func(t *testing.T) {
					session, ctx := build()
					result := attemptCall(func() error { return call(session, ctx) })
					result.requireClassified(t)
					if result.contact == reachedTheCard {
						t.Fatalf("%s reached the card through %s — the usability check is what stops an "+
							"operation being sent to a card this session has no right to speak to, and its "+
							"absence is a dereference, not a refusal", method, name)
					}
					if !errors.Is(result.err, ErrUnavailable) {
						t.Fatalf("%s on %s: err = %v, want ErrUnavailable", method, name, result.err)
					}
				})
			}
		})
	}
}

// ----------------------------------------------------------------------------
// piv_driver.go:207 op1 `session.pin == ""`
// ----------------------------------------------------------------------------

// NO PRIVATE-KEY OPERATION BEFORE A VERIFIED PIN.
//
// privateKey refuses a session that has not logged in. The session is usable in
// every other respect here — the card is present, the context live, the session
// open — so this operand is the only thing standing between an unauthenticated
// caller and the slot.
//
// Falsifier: :207 op1 -> `(false && session.pin == "")`. The slot is read and
// the key requested with an empty PIN; this test is the failure.
func TestNoPrivateKeyOperationHappensBeforeALogin(t *testing.T) {
	for method, call := range map[string]func(*pivSession) error{
		"Sign": func(s *pivSession) error {
			_, err := s.Sign(context.Background(), "9c", "p256", make([]byte, 32))
			return err
		},
		"Unwrap": func(s *pivSession) error {
			_, err := s.Unwrap(context.Background(), "9c", "rsa2048", []byte("ciphertext"), nil)
			return err
		},
	} {
		t.Run(method, func(t *testing.T) {
			session := &pivSession{card: unreachableCard(), serial: "12345678"}
			result := attemptCall(func() error { return call(session) })
			result.requireClassified(t)
			if result.contact == reachedTheCard {
				t.Fatalf("%s reached the card with no PIN verified on this session — the PIN is what authorises "+
					"private-key use, and a slot read followed by a key request with an empty PIN is the operation "+
					"this guard exists to refuse", method)
			}
			if !errors.Is(result.err, ErrUnavailable) {
				t.Fatalf("%s: err = %v, want ErrUnavailable", method, result.err)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// piv_driver.go:116 op0, :192 op0, :211 op0 — parseSlot
// ----------------------------------------------------------------------------

// AN OBJECT ID THAT IS NOT A SLOT MUST NOT BE SENT TO THE CARD.
//
// parseSlot is called from three methods and each result is checked separately.
// All three checks were unmeasured, because reaching them needs a session that
// is otherwise usable — which is what the unreachable card provides. Skipping
// any of them hands piv.Slot{} to the card, which is slot 0: not the requested
// slot, and not a refusal either.
//
// Falsifiers, one method each and each the sole failure:
//
//	:116 op0 -> `(false && err != nil)`   Policies reaches the card
//	:192 op0 -> `(false && err != nil)`   PublicKey reaches the card
//	:211 op0 -> `(false && err != nil)`   privateKey reaches the card
func TestAnObjectIDThatIsNotASlotNeverReachesTheCard(t *testing.T) {
	// "96" parses as hex and is outside every allowed slot range, so parseSlot
	// refuses it at its own boundary rather than at strconv. "zz" is refused by
	// strconv. Both must stop before the card.
	for _, objectID := range []string{"zz", "96", ""} {
		for method, call := range map[string]func(*pivSession, string) error{
			"Policies": func(s *pivSession, id string) error {
				_, _, err := s.Policies(context.Background(), id)
				return err
			},
			"PublicKey": func(s *pivSession, id string) error {
				_, err := s.PublicKey(context.Background(), id)
				return err
			},
			// privateKey is unexported; Sign is its only single-argument caller
			// that reaches it with the object id unchanged.
			"Sign": func(s *pivSession, id string) error {
				_, err := s.Sign(context.Background(), id, "p256", make([]byte, 32))
				return err
			},
		} {
			t.Run(method+"/"+objectID, func(t *testing.T) {
				// pin is set so Sign reaches parseSlot rather than stopping at
				// the login check above it.
				session := &pivSession{card: unreachableCard(), serial: "12345678", pin: "123456"}
				result := attemptCall(func() error { return call(session, objectID) })
				result.requireClassified(t)
				if result.contact == reachedTheCard {
					t.Fatalf("%s sent object id %q to the card — an id that names no slot becomes the zero "+
						"piv.Slot, which is a real slot number the card will happily answer for, so the refusal "+
						"has to happen here", method, objectID)
				}
				if !errors.Is(result.err, ErrUnavailable) {
					t.Fatalf("%s(%q): err = %v, want ErrUnavailable", method, objectID, result.err)
				}
			})
		}
	}
}

// ----------------------------------------------------------------------------
// piv_driver.go:138 op1 `len(pin) < 6`
// ----------------------------------------------------------------------------

// A PIN TOO SHORT IS NOT PRESENTED TO THE CARD, BECAUSE PRESENTING IT SPENDS A
// RETRY FROM A BUDGET OF THREE.
//
// The provider has this same bound and
// TestAPINOutsideTheAcceptedLengthNeverReachesTheCard pins both of its sides. The DRIVER's copy had neither side,
// and it is the copy that is one call away from the card.
//
// THE OTHER SIDE OF THIS BOUND CANNOT BE MEASURED, and that is a finding rather
// than an omission. piv-go's own encodePIN refuses a PIN longer than 8 bytes
// before any transmission, so `len(pin) > 64` cannot be the sole refuser of any
// input: with it neutralised a 65-byte PIN is still refused, without the card
// being reached, by a check inside the library. It is recorded in the ledger as
// cannot-be-sole-refuser, masked by piv.encodePIN, not as untested.
//
// Falsifier: :138 op1 -> `(false && len(pin) < 6)`. The five-byte PIN then
// passes encodePIN, which pads anything from 1 to 8 bytes, and is transmitted.
// This test is the failure.
func TestALoginPINBelowTheAcceptedLengthNeverReachesTheCard(t *testing.T) {
	session := &pivSession{card: unreachableCard(), serial: "12345678"}
	result := attemptCall(func() error {
		return session.Login(context.Background(), []byte("12345"))
	})
	result.requireClassified(t)
	if result.contact == reachedTheCard {
		t.Fatal("a five-byte PIN was presented to the card — piv-go pads any PIN of one to eight bytes and " +
			"transmits it, so nothing below this guard refuses a short one, and each attempt spends a retry " +
			"from a budget of three before the slot blocks and needs a PUK")
	}
	if !errors.Is(result.err, ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", result.err)
	}
	if session.pin != "" {
		t.Fatalf("a refused PIN was retained on the session as %q", session.pin)
	}

	// CONTROL, IN THE SAME TEST. A PIN of an accepted length MUST reach the
	// card. Without this the assertions above are satisfied by a Login that
	// refuses everything, and the guard could be widened to refuse every PIN
	// with nothing going red — the refusal direction this sweep exists to
	// catch.
	control := &pivSession{card: unreachableCard(), serial: "12345678"}
	controlResult := attemptCall(func() error {
		return control.Login(context.Background(), []byte("123456"))
	})
	controlResult.requireClassified(t)
	if controlResult.contact != reachedTheCard {
		t.Fatalf("a six-byte PIN did not reach the card either (err = %v) — the refusal above is not "+
			"attributable to the length, and this test certifies nothing", controlResult.err)
	}
}

// ----------------------------------------------------------------------------
// piv_driver.go:228 op0 `session.closed`, :233 op0 `session.card == nil`
// ----------------------------------------------------------------------------

// CLOSE IS IDEMPOTENT AND SURVIVES A SESSION THAT NEVER HELD A CARD.
//
// Execute closes its session in a deferred function and turns any error into a
// refused operation, so a Close that panicked would take the daemon down on the
// cleanup path of a successful signature. Both of its guards were unmeasured.
//
// Falsifiers, each the sole failure:
//
//	:233 op0 -> `(false && session.card == nil)`  Close derefs a nil card
//	:228 op0 -> `(false && session.closed)`       the second Close reaches the card
func TestCloseIsIdempotentAndSurvivesACardlessSession(t *testing.T) {
	t.Run("a session that never held a card", func(t *testing.T) {
		session := &pivSession{serial: "12345678", pin: "123456"}
		result := attemptCall(session.Close)
		result.requireClassified(t)
		if result.contact == reachedTheCard {
			t.Fatal("Close dereferenced a card the session never held — Execute closes in a deferred function " +
				"on every path, so this is a crash during the cleanup of an otherwise successful operation")
		}
		if result.err != nil {
			t.Fatalf("Close = %v, want nil for a session with no card", result.err)
		}
		if session.pin != "" {
			t.Fatalf("Close left the PIN on the session as %q", session.pin)
		}
	})

	t.Run("a session closed twice", func(t *testing.T) {
		// The first close is recorded directly rather than performed, because
		// closing an unreachable card is the very panic under test.
		session := &pivSession{card: unreachableCard(), serial: "12345678", closed: true}
		result := attemptCall(session.Close)
		result.requireClassified(t)
		if result.contact == reachedTheCard {
			t.Fatal("a second Close was sent to the card — the closed flag is what makes Close idempotent, and " +
				"Execute's deferred close can run after a caller has already closed the session")
		}
		if result.err != nil {
			t.Fatalf("the second Close = %v, want nil", result.err)
		}
	})
}

// ----------------------------------------------------------------------------
// piv_driver.go:292 op0, op2, op4 — the CARD's half of algorithmMatches
// ----------------------------------------------------------------------------

// ONE FIXTURE, TWO OPERANDS, AND ONLY ONE OF THEM PINNED.
//
// algorithmMatches pairs a card algorithm with a requested algorithm name, and
// both halves must agree. The matrix conformance tests sweep the NAME half
// thoroughly: every algorithm the matrix withholds is checked against every
// card algorithm the driver knows. The CARD half had nothing — the only
// existing negative, algorithmMatches(AlgorithmEC256, "ed25519"), varies the
// name, so the three card-algorithm operands survived neutralisation and a
// card holding a P-384 key would satisfy a request for p256.
//
// Falsifier: :292 op0 -> `(true || value == piv.AlgorithmEC256)`, which leaves
// `algorithm == "p256"` deciding alone. This test is the failure;
// TestPIVSlotAndAlgorithmAllowlist and both matrix conformance tests stay
// green, because none of them pairs one advertised name with a different
// advertised card algorithm. op2 and op4 likewise.
func TestAlgorithmMatchesRefusesACardAlgorithmThatIsNotTheOneRequested(t *testing.T) {
	for cardName, cardAlgorithm := range pivAlgorithms {
		for requested := range pivAlgorithms {
			if requested == cardName {
				continue
			}
			if algorithmMatches(cardAlgorithm, requested) {
				t.Errorf("algorithmMatches(%v, %q) = true, but that card holds a %s key — accepting it means a "+
					"digest is signed by a key of an algorithm the caller did not ask for, and the signature is "+
					"then verified against the wrong one", cardAlgorithm, requested, cardName)
			}
		}
	}

	// CONTROL. Errorf rather than Fatalf: a control that halts the test would
	// hide the cases above whenever the mutation under measurement breaks it
	// too, and this control's failure is exactly the shape that would.
	for name, algorithm := range pivAlgorithms {
		if !algorithmMatches(algorithm, name) {
			t.Errorf("algorithmMatches(%v, %q) = false for the matching pair — every refusal above would then "+
				"hold for a gate that refuses everything", algorithm, name)
		}
	}
}

// ----------------------------------------------------------------------------
// piv_driver.go:266 op0/op1 — RECORDED, NOT TESTED
// ----------------------------------------------------------------------------
//
// `number >= 0x82 && number <= 0x95` bounds the retired key-management slots.
// Both operands survived neutralisation and neither can be the sole refuser of
// any input: piv.RetiredKeyManagementSlot is a map lookup whose keys are
// exactly 0x82..0x95, so it returns ok == false for every number this bound
// excludes, and parseSlot falls through to the same "unsupported PIV slot"
// error either way. Neutralising the bound AND forcing the `ok` check below it
// is the only mutation that changes an outcome, which is two operands at once
// and therefore not a measurement of either.
//
// It is recorded as cannot-be-sole-refuser, masked by RetiredKeyManagementSlot,
// rather than closed. A test written for it would assert an outcome the guard
// does not produce alone.
//
// :267 op0 `ok` is unreachable-by-any-fixture in the forced direction for the
// same reason from the other side: within the bound above it the lookup always
// succeeds, so `(true || ok)` cannot be reached with ok false.

// ----------------------------------------------------------------------------
// piv_driver.go:253 op0 — RECORDED, NOT TESTED
// ----------------------------------------------------------------------------
//
// parseSlot returns strconv's error when the object id is not hex. Neutralised,
// the failed parse yields number == 0, which matches no case and no range, so
// the function still refuses — with a different error value that no caller ever
// sees, because Policies, PublicKey and privateKey all convert it to
// ErrUnavailable. cannot-be-sole-refuser, masked by the function's own final
// return.

// ----------------------------------------------------------------------------
// piv_driver.go:43, :47, :51, :56, :57, :63, :67, :71, :78, :85, :89
// OPEN/READY, NOW VIA THE SEAM  ::  piv_driver_seam_test.go
// ----------------------------------------------------------------------------
//
// These 15 operands sat around piv.Cards() and piv.Open(), which enumerate and
// claim PC/SC readers, and were RECORDED-as-unreachable above until #237 round
// two introduced the pivCards/pivOpen package-level seams. With those seams,
// pivCards decides which card names exist and pivOpen decides what each one
// yields — a card-shaped value that never panics, because the seams ARE the
// card surface in this process.
//
// TESTED THROUGH THE SEAM in piv_driver_seam_test.go — each entry has a
// falsifier the test names. The seam fixture falsifies the FALSE direction
// ('does anything notice if this operand stops refusing') but cannot, by
// itself, falsify the TRUE direction ('is this the sole refusal mechanism')
// for most of these — that needs a card-shaped seam (Serial(), pivOpen
// returning a successful card) the package does not yet provide. The ledger
// (sweep_survivor_ledger_test.go) records each entry's status: closedByTest
// means both directions, closedFalseDirectionOnly means the FALSE direction
// only, with whyTrueOpen naming the missing fixture.
//
//	:43 op1 driver == nil (Open)         TestOpenRefusesBeforeTouchingADriverThatIsNil
//	:47 target == "" (commission miss)   TestOpenDoesNotEnumerateReadersForADeviceIDThatIsNotCommissioned
//	:63 openErr != nil                   TestOpenContinuesPastACardThatFailsToOpen
//	:78 selected == nil                  TestOpenRefusesWhenNoCardMatchesTheCommissionedSerial
//	:85 op0 driver == nil (Ready)        TestReadyRefusesBeforeTouchingADriverThatIsNil
//	:85 op1 ctx.Err() (Ready)            TestReadyRefusesACancelledContextEvenWhenCardsArePresent
//	:89 op0 err == nil                   TestReadyReportsTruthfullyAcrossBothHalvesOfItsReturn/not_ready_when_pivCards_errors
//	:89 op1 len(cards) > 0               TestReadyReportsTruthfullyAcrossBothHalvesOfItsReturn/not_ready_when_no_cards_are_present
//
// STILL UNREACHABLE in the seam fixture (cannot-be-sole-refuser or needs a
// feature the seam does not provide):
//
//	:43 op0 ctx.Err()           masked by :56 — :56 fires only inside the loop,
//	                            and :43 op0 fires on every path that reaches
//	                            the loop, so :43 op0 cannot be the sole
//	                            refusal: pivCards would never be called with
//	                            :43 op0 alone neutralised, and the spy cannot
//	                            catch a call that did not happen because
//	                            pivCards was already short-circuited at :43.
//	:51 err != nil (pivCards)   cannot-be-sole-refuser in this fixture — both
//	                            err != nil and len(cards) == 0 leave :78 to
//	                            refuse, and the loop body never runs to
//	                            disambiguate. The seam fixture returns errors
//	                            with no cards, which is the same observable
//	                            outcome as returning no cards with no error.
//	:56 ctx.Err() in loop       masked by :43 op0 — pivOpen is synchronous in
//	                            the seam (it cannot observe a context cancel
//	                            that happens after the call enters), so :56
//	                            cannot fire under the seam. Real PC/SC
//	                            transmits CAN observe a cancel mid-call; the
//	                            seam cannot.
//	:57 selected != nil         cannot-be-sole-refuser — :57 only fires when a
//	                            previous iteration set `selected`, which
//	                            requires pivOpen to return a successful card,
//	                            which the seam does not. Would need a Serial()
//	                            seam to construct the pre-set selected state.
//	:67 op0, :67 op1            cannot-be-sole-refuser — both check the result
//	                            of candidate.Serial(), which on a nil-handed
//	                            card panics before returning. Reaching them
//	                            needs Serial() to return (uint32, error).
//	:71 selected != nil (dup)   needs TWO pivCards() results whose Serial()
//	                            both match the target serial — physically
//	                            impossible and not seam-reachable.

// ----------------------------------------------------------------------------
// piv_driver.go:105, :120, :131, :144, :153, :157, :161, :165, :173, :177,
// :181, :196, :200, :215, :219 — UNREACHABLE-BY-ANY-FIXTURE
// ----------------------------------------------------------------------------
//
// These are the operands BELOW the guards this file closes: they read what the
// card answered. Reaching them requires a card that answers, and the fixture
// above is a card that cannot. They are the genuine hardware surface of this
// package and the bench is the only instrument for them.
//
// :215 is worth naming, because it is the unattended-use contract itself —
// TouchPolicyNever, a PIN policy of Once or Always, and an algorithm that
// matches. Its algorithm operand is closed indirectly by the
// algorithmMatches test above; its touch and PIN policy operands are not, and
// no unit test in this process can reach them.
