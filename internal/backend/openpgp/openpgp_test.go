package openpgp_test

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/openpgp"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// THE ADAPTER MUST BE USABLE WHERE THE DAEMON EXPECTS A PROVIDER.
//
// A constrained backend that does not satisfy backend.Provider is a package, not a backend. The
// assertion lives here rather than in the package so internal/backend/openpgp does not import
// internal/backend, which would be a dependency in the direction the manager already points.
var _ backend.Provider = (*openpgp.Provider)(nil)

const (
	testSerial = "01234567"
	testDevice = "yk-sitea-1"
)

func at(day int) time.Time { return time.Date(2026, time.September, day, 12, 0, 0, 0, time.UTC) }

func clockAt(day int) func() time.Time { return func() time.Time { return at(day) } }

// legacyRoute builds a route the adapter would admit if nothing else refused it. Every test starts
// from an admissible route and breaks exactly one thing, so a refusal names the thing that broke.
func legacyRoute(objectID, algorithm string) registry.Route {
	return registry.Route{
		ObjectID:  objectID,
		Algorithm: algorithm,
		Binding: registry.Binding{
			Site:              "sitea",
			Backend:           openpgp.BackendName,
			DeviceID:          testDevice,
			DeviceSerial:      testSerial,
			ObjectID:          objectID,
			PublicFingerprint: "SHA256:ZmFrZWZpbmdlcnByaW50Zm9ydGVzdGluZ29ubHk",
			State:             "active",
			PINPolicy:         "once",
			TouchPolicy:       "never",
		},
	}
}

// approvedException is a complete, unexpired record for one object.
func approvedException(objectID string) openpgp.Exception {
	return openpgp.Exception{
		ObjectID:        objectID,
		Reason:          "legacy sops consumer still decrypts with the card-backed gpg identity",
		ApprovedBy:      "security-review-2026-09",
		RemovalCriteria: "the consumer reads its data key from /v1/operations/unwrap on nitrokey-pkcs11",
		Expires:         at(30),
	}
}

// admissionFor builds an admission layer holding exceptions for every named object.
func admissionFor(t *testing.T, day int, objectIDs ...string) *openpgp.Admission {
	t.Helper()
	exceptions := make([]openpgp.Exception, 0, len(objectIDs))
	for _, objectID := range objectIDs {
		exceptions = append(exceptions, approvedException(objectID))
	}
	admission, err := openpgp.NewAdmission(exceptions, clockAt(day))
	if err != nil {
		t.Fatalf("building the admission layer: %v", err)
	}
	return admission
}

// ---------------------------------------------------------------------------------------------
// Test doubles. The card is MODELLED here. The real driver's physical qualification lives in
// openpgp/pcsc (TestOpenPGPPhysicalQualification), not in this file.
// ---------------------------------------------------------------------------------------------

// forbiddenDriver fails the test if anything opens a card. It is how "refused before a device
// handle exists" is asserted rather than assumed.
type forbiddenDriver struct{ t *testing.T }

func (driver forbiddenDriver) Open(context.Context, string) (openpgp.Card, error) {
	driver.t.Helper()
	driver.t.Fatal("a card was opened for a route that must have been refused before any device handle existed")
	return nil, nil
}

func (driver forbiddenDriver) Ready(context.Context) bool { return true }

type fakeCard struct {
	status     openpgp.CardStatus
	signature  []byte
	plaintext  []byte
	statusErr  error
	signErr    error
	decipherEr error
	closeErr   error
	calls      []string
}

func (card *fakeCard) Status(context.Context) (openpgp.CardStatus, error) {
	card.calls = append(card.calls, "status")
	return card.status, card.statusErr
}

func (card *fakeCard) Sign(_ context.Context, algorithm string, _ []byte) ([]byte, error) {
	card.calls = append(card.calls, "sign:"+algorithm)
	return append([]byte(nil), card.signature...), card.signErr
}

func (card *fakeCard) Decipher(_ context.Context, algorithm string, _ []byte) ([]byte, error) {
	card.calls = append(card.calls, "decipher:"+algorithm)
	return append([]byte(nil), card.plaintext...), card.decipherEr
}

func (card *fakeCard) Close() error {
	card.calls = append(card.calls, "close")
	return card.closeErr
}

type fakeDriver struct {
	card    *fakeCard
	openErr error
	opened  []string
}

func (driver *fakeDriver) Open(_ context.Context, deviceID string) (openpgp.Card, error) {
	driver.opened = append(driver.opened, deviceID)
	if driver.openErr != nil {
		return nil, driver.openErr
	}
	return driver.card, nil
}

func (driver *fakeDriver) Ready(context.Context) bool { return driver.openErr == nil }

// unattendedCard is a card that honours everything a binding can promise: no touch on either key,
// and PW1 valid for several signatures.
func unattendedCard() *fakeCard {
	return &fakeCard{
		status: openpgp.CardStatus{
			Serial:                                 testSerial,
			SignaturePINValidForMultipleSignatures: true,
		},
		signature: []byte("signature-bytes"),
		plaintext: []byte("recovered-data-key"),
	}
}

func providerWith(t *testing.T, card *fakeCard, admission *openpgp.Admission) *openpgp.Provider {
	t.Helper()
	provider, err := openpgp.New(&fakeDriver{card: card}, admission)
	if err != nil {
		t.Fatalf("building the provider: %v", err)
	}
	return provider
}

// ---------------------------------------------------------------------------------------------
// The slot limits.
// ---------------------------------------------------------------------------------------------

// THE APPLET HAS THREE FIXED SLOTS AND AN OPERATION CAN REACH ONLY TWO.
//
// The fixed roles are the property that makes this card unsuitable as the default abstraction
// (#21), so the count and the mapping are asserted rather than left to the card to enforce at the
// far end of a driver nobody has written.
//
// Falsifier: add a fourth constant to Slots(), or point slotForOperation at SlotAuthentication.
// Either fails here alone.
func TestTheAppletHasThreeFixedSlotsAndOnlyTwoAreReachable(t *testing.T) {
	slots := openpgp.Slots()
	if len(slots) != 3 {
		t.Fatalf("an OpenPGP card holds three keys; Slots() returned %d: %v", len(slots), slots)
	}
	distinct := map[openpgp.Slot]struct{}{}
	for _, slot := range slots {
		distinct[slot] = struct{}{}
	}
	if len(distinct) != 3 {
		t.Fatalf("the three slots must be distinct, got %v", slots)
	}
	admitted := openpgp.AdmittedOperations()
	if len(admitted) != 2 {
		t.Fatalf("sign and unwrap are the operations this adapter serves; got %v", admitted)
	}
	if admitted["sign"] != openpgp.SlotSignature {
		t.Errorf("sign must use the signature key, got %q", admitted["sign"])
	}
	if admitted["unwrap"] != openpgp.SlotDecryption {
		t.Errorf("unwrap must use the decryption key, got %q", admitted["unwrap"])
	}
}

// NO OPERATION REACHES THE AUTHENTICATION SLOT.
//
// The card has the key. ADR-0001 §4 and API.md put human administrator authentication outside the
// cryptographic-operation surface and /v1/operations has no route to reach it through, so the
// exclusion is real — and before this test it lived only in prose, which is TESTING.md 14.
//
// Falsifier: add "authenticate": SlotAuthentication to slotForOperation. This test fails and the
// served-operation contract below fails too, because the router serves no such operation.
func TestNoOperationReachesTheAuthenticationSlot(t *testing.T) {
	for operation, slot := range openpgp.AdmittedOperations() {
		if slot == openpgp.SlotAuthentication {
			t.Errorf("operation %q reaches the authentication key; this KMS does not operate it", operation)
		}
	}
	if _, err := openpgp.SlotFor("authenticate"); !errors.Is(err, openpgp.ErrOperationNotOnThisApplet) {
		t.Errorf("SlotFor(\"authenticate\") = %v, want a refusal: the authentication key is inventory, not an operation", err)
	}
}

// EVERY OPERATION THE ROUTER SERVES IS EITHER ADMITTED OR REFUSED WITH A REASON.
//
// The served set is derived from api.OperationPaths() rather than written down, so an operation
// added to the router cannot default into either answer — it arrives here as a failure asking
// somebody to decide. This is registry's TestEveryAdvertisedOperationIsServedOrDeclaredUnserved
// pointed at one backend's adapter.
//
// It also holds the two maps disjoint and free of entries the router does not serve: a reason
// recorded for an operation that no longer exists reads as a live decision and is not one.
//
// Falsifier: delete any entry from operationsNotOnThisApplet. This test names the uncovered
// operation and nothing else fails.
func TestEveryServedOperationIsAdmittedOrRefusedWithAReason(t *testing.T) {
	served := servedOperations(t)
	admitted := openpgp.AdmittedOperations()
	refused := openpgp.RefusedOperations()
	for operation := range served {
		_, isAdmitted := admitted[operation]
		reason, isRefused := refused[operation]
		switch {
		case isAdmitted && isRefused:
			t.Errorf("%q is both admitted and refused; one of the two maps is wrong", operation)
		case !isAdmitted && !isRefused:
			t.Errorf("the router serves %q and this adapter neither admits it nor records why it refuses it. "+
				"Decide: add it to slotForOperation with the applet key it must use, or to "+
				"operationsNotOnThisApplet with the reason it is not done here.", operation)
		case isRefused && strings.TrimSpace(reason) == "":
			t.Errorf("%q is refused with an empty reason, which is a refusal nobody can act on", operation)
		}
	}
	for operation := range admitted {
		if !served[operation] {
			t.Errorf("this adapter admits %q, which the router does not serve", operation)
		}
	}
	for operation := range refused {
		if !served[operation] {
			t.Errorf("this adapter records a refusal reason for %q, which the router does not serve; "+
				"a reason for an operation that does not exist reads as a live decision", operation)
		}
	}
}

// A REFUSAL NAMES THE RULE THAT FIRED, AND EVERY RULE IS THE SAME CLASS.
//
// Callers that want "was this refused rather than broken" match ErrRefused; callers that want to
// know which limit they hit match the specific error. Both only work if every refusal wraps the
// class, and the failure mode of forgetting is silent — the specific error still matches itself.
func TestEveryRefusalIsOfTheRefusedClass(t *testing.T) {
	for _, refusal := range []error{
		openpgp.ErrNotThisBackend, openpgp.ErrOperationNotOnThisApplet, openpgp.ErrNotAdvertised,
		openpgp.ErrExceptionRequired, openpgp.ErrExceptionExpired, openpgp.ErrInteractionRequired,
		openpgp.ErrCardContradictsBinding, openpgp.ErrLegacyMaterialRequired,
	} {
		if !errors.Is(refusal, openpgp.ErrRefused) {
			t.Errorf("%v does not wrap ErrRefused, so a caller cannot tell it from a hardware failure", refusal)
		}
	}
	// The counterpart: a failure is NOT a refusal. Reporting an outage as a policy decision sends
	// an operator to read config, and reporting a policy decision as an outage sends them to the
	// bench.
	if errors.Is(openpgp.ErrUnavailable, openpgp.ErrRefused) {
		t.Error("ErrUnavailable wraps ErrRefused; a hardware failure would read as a limit")
	}
}

// servedOperations is every operation /v1/operations serves, derived from the router's own paths.
//
// IT IS THE DENOMINATOR FOR BOTH CONFORMANCE TESTS, AND IT COMES FROM OUTSIDE THIS ADAPTER ON
// PURPOSE. The first version of TestTheAdapterAdmitsExactlyWhatTheMatrixAdvertises iterated the
// adapter's own two maps instead, which is TESTING.md 16: the corpus it counted was shrunk by the
// very defect it was looking for. Dropping "unwrap" from slotForOperation removed unwrap from the
// set being checked, so the test could not see that an advertised pair was no longer served — it
// passed, and the mutation was caught only by other tests. A denominator the bug can shrink
// measures whatever is left.
func servedOperations(t *testing.T) map[string]bool {
	t.Helper()
	const prefix = "/v1/operations/"
	served := map[string]bool{}
	for _, path := range api.OperationPaths() {
		operation, found := strings.CutPrefix(path, prefix)
		if !found || operation == "" {
			t.Fatalf("operation path %q is not %s<operation>, so no operation name can be derived from it", path, prefix)
		}
		served[operation] = true
	}
	if len(served) < 2 {
		t.Fatalf("derived %d served operations; every test using this denominator would be checking almost nothing", len(served))
	}
	return served
}

// sorted returns a copy so a comparison cannot depend on map iteration order.
func sorted(values []string) []string {
	copied := append([]string(nil), values...)
	sort.Strings(copied)
	return copied
}
