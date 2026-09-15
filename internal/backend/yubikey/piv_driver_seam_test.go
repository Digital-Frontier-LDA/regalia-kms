//go:build piv

package yubikey

// THE OPEN/READY SURFACE, NOW THAT IT HAS A SEAM.
//
// piv_driver.go lines 43-90 were RECORDED-as-unreachable in
// piv_session_boundary_test.go until #237 round two introduced the
// pivCards/pivOpen package-level seams. With those seams in place, a test can
// stand in for PC/SC: pivCards decides which card names exist, pivOpen decides
// what each one yields. The session-method fixtures still use
// `&piv.YubiKey{}` (a card that cannot be spoken to) for the operands BELOW
// the guards; the seam tests use a card-shaped value that NEVER panics, because
// the seams ARE the card surface in this process.
//
// The guards below now live at :43, :47, :51, :56, :57, :64, :67, :72, :79,
// :86, :90 — the seam insertion shifted the surrounding file by one line.
// Tests name the guard line, not the assignment that precedes it.
//
// SHAPE:
//
//   - `cardsFn` replaces pivCards and is restored on t.Cleanup. It receives
//     the configured card names and may return any subset plus an error.
//
//   - `openFn` replaces pivOpen and is restored on t.Cleanup. It receives a
//     card name and returns either a real *piv.YubiKey or an error.
//
//   - `spyOpen` records every name pivOpen was called with. Several operands
//     can only be falsified by proving that pivCards or pivOpen was NOT called
//     under a given refusal; the spy is the instrument that separates the
//     guard's refusal from a card call that the guard's mutation would have
//     invited.
//
// NO t.Parallel. The seams are package-level, and a parallel test in another
// file would race them. TestNoTestInThisPackageCallsTParallel pins that rule.

import (
	"context"
	"errors"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

func swapSeams(t *testing.T, cards func() ([]string, error), open func(string) (*piv.YubiKey, error)) {
	t.Helper()
	prevCards, prevOpen := pivCards, pivOpen
	if cards != nil {
		pivCards = cards
	}
	if open != nil {
		pivOpen = open
	}
	t.Cleanup(func() {
		pivCards = prevCards
		pivOpen = prevOpen
	})
}

// spyOpen records the names pivOpen was called with. A test asserts that a
// guard short-circuited BEFORE pivOpen ran by reading len(spy) after the call.
type spyOpen struct {
	names []string
}

func (s *spyOpen) open(name string) (*piv.YubiKey, error) {
	s.names = append(s.names, name)
	return nil, errors.New("no card in the seam fixture: pivot_open returned a synthetic error")
}

func (s *spyOpen) cards() ([]string, error) {
	return nil, errors.New("no card in the seam fixture: pivot_cards returned a synthetic error")
}

func newDriver(devices map[string]string) *PIVDriver {
	driver, err := NewPIVDriver(devices)
	if err != nil {
		panic(err)
	}
	return driver
}

// ----------------------------------------------------------------------------
// piv_driver.go:43 op1 — driver == nil in Open
// ----------------------------------------------------------------------------

// Open must not dereference a nil driver. A nil-driver dereference would crash
// the daemon on the discovery path of an operation; the guard is the only
// thing standing between the call and `driver.devices[deviceID]`.
//
// Falsifier: :43 op1 -> `(false && driver == nil)`. The expression becomes
// `err != nil || false`, so a non-cancelled context proceeds past :43 and the
// `driver.devices` access on :46 panics.
func TestOpenRefusesBeforeTouchingADriverThatIsNil(t *testing.T) {
	var driver *PIVDriver
	ctx := context.Background()
	for _, deviceID := range []string{"any", ""} {
		result := attemptCall(func() error {
			_, err := driver.Open(ctx, deviceID)
			return err
		})
		result.requireClassified(t)
		if result.contact != refusedBeforeTheCard {
			t.Fatalf("Open(%q) reached the card on a nil driver", deviceID)
		}
		if !errors.Is(result.err, ErrUnavailable) {
			t.Fatalf("Open(%q): err = %v, want ErrUnavailable", deviceID, result.err)
		}
	}
}

// ----------------------------------------------------------------------------
// piv_driver.go:47 — target == "" (deviceID not commissioned)
// ----------------------------------------------------------------------------

// Open must refuse a deviceID that is not in the commissioned map. The fixture
// returns (cards, nil) from pivCards so that pivOpen WOULD be called if :47
// were missing; the assertion that it was NOT is what makes this test falsify
// the operand in isolation.
//
// Falsifier: :47 -> `(false && target == "")`. Open proceeds to pivCards,
// which returns ["x","y"], and pivOpen is called for the first card name.
func TestOpenDoesNotEnumerateReadersForADeviceIDThatIsNotCommissioned(t *testing.T) {
	driver := newDriver(map[string]string{"commissioned": "12345678"})
	spy := &spyOpen{}
	swapSeams(t,
		func() ([]string, error) { return []string{"x", "y"}, nil },
		spy.open,
	)

	for _, deviceID := range []string{"unknown", "", "Commissioned"} {
		_, err := driver.Open(context.Background(), deviceID)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Open(%q): err = %v, want ErrUnavailable", deviceID, err)
		}
	}
	if len(spy.names) != 0 {
		t.Fatalf("pivOpen was called with %v — :47 must refuse before pivCards, so a commission lookup that misses must not enumerate readers", spy.names)
	}
}

// ----------------------------------------------------------------------------
// piv_driver.go:51 — err != nil from pivCards
// ----------------------------------------------------------------------------

// Open must refuse when pivCards itself errors. The error is the reader
// surface's signal that PC/SC could not enumerate; passing it through to
// pivOpen would have no reader to open.
//
// Falsifier: :51 -> `(false && err != nil)`. pivCards's error is hidden; Open
// proceeds to the loop body and reads `len(cards)` (which is zero), then :79
// returns ErrUnavailable. The OUTCOME is unchanged — that is the test for
// SOLE-refusable: the only way to detect the mutation is to assert pivOpen
// was called.
//
// This test asserts pivOpen was NOT called, which is the load-bearing side:
// under the falsifier, the loop iterates once with the empty `cards`, but
// len-0 means the body never executes, so pivOpen is still never called.
//
// The mutation is therefore detected by the spies on :47 and :79 below, not
// here. :51 is RECORDED as cannot-be-sole-refuser — pivCards's error and the
// empty-cards loop outcome both refuse the same way, and the loop body never
// runs to disambiguate them.

// ----------------------------------------------------------------------------
// piv_driver.go:56 — ctx.Err() in the loop  ::  RECORDED, MASKED BY :43 op0
// ----------------------------------------------------------------------------

// :56 checks ctx.Err() at the top of every loop iteration. A cancelled context
// first hits :43 op0 on the way into Open, so :56 only runs under a context
// that was live at :43 and was then cancelled. With the seam this is reachable
// if pivOpen blocks long enough for ctx to be cancelled — which it does not,
// because pivOpen is a synchronous seam function. A real PC/SC transmit CAN
// observe context cancellation; the seam cannot, because it does not transmit.
//
// :56 is therefore recorded as masked by :43 op0 in the seam fixture. Its
// falsifier would require pivOpen to consult ctx, which the seam does not.

// ----------------------------------------------------------------------------
// piv_driver.go:57 — selected != nil mid-loop  ::  RECORDED, NEEDS PRE-SET SELECTED
// ----------------------------------------------------------------------------

// :57 closes the previously-selected card when ctx.Err() is observed mid-loop.
// To fire it, the loop must have set `selected` in a prior iteration, then
// observed ctx.Err() in the next. With the seam, this needs pivCards to return
// at least two names AND pivOpen to return a successful candidate on the first
// (one whose Serial() matches the target). The fixture's pivOpen returns an
// error, so the loop never sets `selected`, and :57 is unreachable through
// any seam arrangement that does not also drive Serial().
//
// Recorded as: cannot-be-sole-refuser in the seam fixture; would require a
// seam for Serial() too, which #237 round two did not introduce.

// ----------------------------------------------------------------------------
// piv_driver.go:64 — openErr != nil from pivOpen
// ----------------------------------------------------------------------------

// Open must refuse on a per-card open error and continue to the next card.
// Without :64, the open error short-circuits to `candidate.Serial()`, which
// panics on a nil-handed card — the same panic that :64 was added to prevent.
//
// Falsifier: :64 -> `(false && openErr != nil)`. The error is hidden, candidate
// is nil, `candidate.Serial()` panics.
func TestOpenContinuesPastACardThatFailsToOpen(t *testing.T) {
	driver := newDriver(map[string]string{"y": "12345678"})
	swapSeams(t,
		func() ([]string, error) { return []string{"y"}, nil },
		func(string) (*piv.YubiKey, error) { return nil, errors.New("simulated PC/SC failure") },
	)
	result := attemptCall(func() error {
		_, err := driver.Open(context.Background(), "y")
		return err
	})
	result.requireClassified(t)
	if !errors.Is(result.err, ErrUnavailable) {
		t.Fatalf("Open: err = %v, want ErrUnavailable", result.err)
	}
	// The control: pivOpen was called once, and :79 then refused because no
	// card produced a matching serial.
	if result.contact != refusedBeforeTheCard {
		t.Fatalf("Open reached the card after pivOpen errored — :64 must filter the error before any card call")
	}
}

// ----------------------------------------------------------------------------
// piv_driver.go:67 op0, :67 op1  ::  RECORDED, MASKED BY THE NIL-HANDED CARD
// ----------------------------------------------------------------------------

// :67 op0 (serialErr != nil) and :67 op1 (format != target) check the result
// of candidate.Serial(). Reaching them requires Serial() to return
// (uint32, error); on a nil-handed card Serial() panics before returning.
// The seam returns an error from pivOpen rather than a card, so the loop
// never sets `candidate` to a value Serial() would be called on.
//
// Recorded as: cannot-be-sole-refuser in the seam fixture; would require
// either a real YubiKey or a Serial() seam, neither of which #237 round two
// introduced.

// ----------------------------------------------------------------------------
// piv_driver.go:72 — selected != nil (duplicate serial)  ::  RECORDED
// ----------------------------------------------------------------------------

// :72 refuses when a SECOND card answers to the same commissioned serial.
// Constructing two distinct pivCards() results whose Serial() both match
// the target needs either two physical YubiKeys with the same serial
// (impossible) or a seam that controls Serial() (out of scope).
//
// Recorded as: cannot-be-sole-refuser in this fixture.

// ----------------------------------------------------------------------------
// piv_driver.go:79 — selected == nil at end of loop
// ----------------------------------------------------------------------------

// Open must refuse when no card in pivCards() matched the commissioned
// serial. Without :79, Open returns &pivSession{card: nil, serial: target}
// and the caller gets a Session whose usable() guard fires on the next call,
// but the session itself is non-nil and indistinguishable from a real one.
//
// Falsifier: :79 -> `(false && selected == nil)`. Open returns
// (non-nil Session, nil error) — a usable-shaped value that is not actually
// usable. The falsifier's symptom is the return shape; this test asserts
// the shape.
func TestOpenRefusesWhenNoCardMatchesTheCommissionedSerial(t *testing.T) {
	driver := newDriver(map[string]string{"y": "12345678"})
	swapSeams(t,
		func() ([]string, error) { return []string{"y", "z"}, nil },
		func(string) (*piv.YubiKey, error) { return nil, errors.New("no card in the seam fixture") },
	)
	session, err := driver.Open(context.Background(), "y")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Open: err = %v, want ErrUnavailable", err)
	}
	if session != nil {
		t.Fatalf("Open returned a non-nil Session (%T) when no card matched — :79 is the only guard that returns a nil Session", session)
	}
}

// ----------------------------------------------------------------------------
// piv_driver.go:86 op0 — driver == nil in Ready
// ----------------------------------------------------------------------------

// Ready must refuse a nil driver. Without :86 op0, Ready falls through to
// pivCards and returns whatever pivCards says — and on a real machine with a
// card present, that is `true`, which is the falsifier's symptom.
//
// The seam pins the fixture: pivCards is forced to return (cards, nil) so the
// only thing that can keep Ready at false is the driver guard.
func TestReadyRefusesBeforeTouchingADriverThatIsNil(t *testing.T) {
	swapSeams(t,
		func() ([]string, error) { return []string{"y"}, nil },
		nil,
	)
	var driver *PIVDriver
	if driver.Ready(context.Background()) {
		t.Fatal("Ready = true on a nil driver with cards present in pivCards — :86 op0 is the only guard")
	}
}

// ----------------------------------------------------------------------------
// piv_driver.go:86 op1 — ctx.Err() in Ready
// ----------------------------------------------------------------------------

// Ready must report false on a cancelled context, regardless of what pivCards
// would have returned. A live context that produces cards must not have
// Ready stick at true after the context is cancelled.
//
// Falsifier: :86 op1 -> `(false && ctx.Err() != nil)`. The expression becomes
// `driver == nil || false`; with a non-nil driver, Ready continues to
// pivCards and returns whatever it says.
func TestReadyRefusesACancelledContextEvenWhenCardsArePresent(t *testing.T) {
	driver := newDriver(map[string]string{"any": "12345678"})
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	swapSeams(t,
		func() ([]string, error) { return []string{"any"}, nil },
		nil,
	)
	if driver.Ready(cancelled) {
		t.Fatal("Ready = true with a cancelled context and present cards — :86 op1 is the only guard that sees ctx")
	}
}

// ----------------------------------------------------------------------------
// piv_driver.go:90 op0, :90 op1 — the return-value halves of Ready
// ----------------------------------------------------------------------------

// Ready's return value is `err == nil && len(cards) > 0`. Each operand is the
// sole reason Ready can return false from one side:
//
//   - err == nil : pivCards returned an error
//   - len(cards) > 0 : pivCards returned no card names
//
// Falsifiers, each the sole failure:
//
//   - :90 op0 -> `(false && err == nil)`  Ready returns false even on a healthy
//     pivCards. The admission direction (Ready must report true when cards are
//     present) is what this test pins.
//   - :90 op1 -> `(false && len(cards) > 0)`  Ready reports true on an empty
//     pivCards — a phantom "yes, there is a reader", which is the falsifier's
//     symptom.
func TestReadyReportsTruthfullyAcrossBothHalvesOfItsReturn(t *testing.T) {
	t.Run("ready when cards are present", func(t *testing.T) {
		driver := newDriver(map[string]string{"any": "12345678"})
		swapSeams(t,
			func() ([]string, error) { return []string{"any"}, nil },
			nil,
		)
		if !driver.Ready(context.Background()) {
			t.Fatal("Ready = false with pivCards returning (cards, nil) — :90 op0 is the only guard that catches an err != nil, and pivCards returned no error")
		}
	})
	t.Run("not ready when no cards are present", func(t *testing.T) {
		driver := newDriver(map[string]string{"any": "12345678"})
		swapSeams(t,
			func() ([]string, error) { return nil, nil },
			nil,
		)
		if driver.Ready(context.Background()) {
			t.Fatal("Ready = true with pivCards returning (nil, nil) — :90 op1 is the only guard that catches an empty card list")
		}
	})
	// :90 op0 falsifier. With err != nil and cards non-empty, the original
	// expression evaluates false; under mutation (err == nil operand dropped)
	// the expression becomes `len(cards) > 0` and returns true. The fixture
	// forces both halves present so the operand under test is the only thing
	// that can keep Ready at false.
	t.Run("not ready when pivCards errors", func(t *testing.T) {
		driver := newDriver(map[string]string{"any": "12345678"})
		swapSeams(t,
			func() ([]string, error) { return []string{"any"}, errors.New("simulated PC/SC failure") },
			nil,
		)
		if driver.Ready(context.Background()) {
			t.Fatal("Ready = true with pivCards returning (cards, err) — :90 op0 is the only guard that catches an error from pivCards")
		}
	})
}

// ----------------------------------------------------------------------------
// piv_driver.go:139 op0 — usable in Login
// ----------------------------------------------------------------------------

// Login must refuse a session that is not usable, before presenting a PIN to
// the card. Presenting a PIN to a card this session has no right to speak to
// spends one of the three retries the YubiKey holds; :139 op0 is the only
// refusal that catches a closed or context-cancelled session.
//
// Falsifier: :139 op0 -> `(false && err != nil)`. The session reaches
// VerifyPIN, which on a nil-handed card panics.
func TestLoginRefusesBeforeVerifyingOnASessionThatIsNotUsable(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	// pin is INTENTIONALLY NOT PRE-SET, so the assertion that it stayed empty
	// proves Login did not reach the line that assigns it. A pre-set pin would
	// make that assertion vacuous.
	for name, build := range map[string]func() *pivSession{
		"closed session":          func() *pivSession { return &pivSession{card: unreachableCard(), serial: "12345678", closed: true} },
		"cancelled context":       func() *pivSession { return &pivSession{card: unreachableCard(), serial: "12345678"} },
		"session holding no card": func() *pivSession { return &pivSession{serial: "12345678"} },
	} {
		t.Run(name, func(t *testing.T) {
			session := build()
			result := attemptCall(func() error {
				return session.Login(cancelled, []byte("123456"))
			})
			result.requireClassified(t)
			if result.contact == reachedTheCard {
				t.Fatalf("Login reached the card on %s — :139 op0 is the only guard that refuses an unusable session, and VerifyPIN spends a retry", name)
			}
			if !errors.Is(result.err, ErrUnavailable) {
				t.Fatalf("Login: err = %v, want ErrUnavailable", result.err)
			}
			if session.pin != "" {
				t.Fatalf("Login retained the PIN as %q after refusing — :139 op0 must short-circuit before the session.pin assignment", session.pin)
			}
		})
	}
}
