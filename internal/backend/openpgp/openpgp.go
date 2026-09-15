// Package openpgp is the admission layer for the YubiKey OpenPGP applet: the part of the
// constrained legacy adapter that decides what may be ASKED of the card, before anything reaches
// one.
//
// ADR-0001 §4 allocates this backend to "unavoidable legacy card integration" and to nothing else.
// That sentence was the entire design, and it was only a sentence. The registry advertises
// yubikey-openpgp in the capability matrix and will route to it; the daemon constructs no provider
// for it, so bindBackendToRegistry refuses such a manifest at startup. That is fail-closed, but it
// is an availability answer to a policy question — "this daemon cannot serve that backend" is not
// "that backend may not be used for this". The rules below are the policy answer, and they are
// enforced rather than described.
//
// # LIMITED IS A SET OF REFUSALS, NOT A SET OF FEATURES
//
// A compatibility backend described by what it can do grows, because every new caller reads the
// list and asks for the next entry. One described by what it refuses shrinks, because every
// refusal is a thing the caller must go and do on a supported backend instead. This package is
// written the second way. The refusals are:
//
//   - THE APPLET HAS THREE KEY SLOTS WITH FIXED, NON-REASSIGNABLE ROLES, and an operation can
//     reach only two of them. sign reaches the signature key, unwrap reaches the decryption key,
//     and no operation reaches the authentication key. See slotForOperation.
//   - EVERY OTHER OPERATION THIS KMS SERVES IS REFUSED BY NAME, with the reason recorded next to
//     the refusal rather than in prose somewhere else. See operationsNotOnThisApplet.
//   - THE ADAPTER ADMITS EXACTLY WHAT THE CAPABILITY MATRIX ADVERTISES, in both directions. An
//     advertised pair this adapter refuses is the #73 defect (the manifest validates, routing
//     succeeds, the failure arrives at the token); an admitted pair the matrix does not advertise
//     is a capability nobody reviewed. TestTheAdapterAdmitsExactlyWhatTheMatrixAdvertises holds
//     both halves.
//   - ANYTHING PIV OR THE NITROKEY CAN ALSO DO NEEDS A RECORDED, TIME-BOUNDED EXCEPTION. This is
//     the enforced form of "new use cases default to PIV or Nitrokey". The set that needs one is
//     computed from the capability matrix, not written down, so it cannot drift away from it.
//   - UNWRAP MUST PRESENT LEGACY MATERIAL. A regalia-envelope-v2 wrapped to this applet would be
//     new material bound to the backend this adapter exists to retire, which makes the removal
//     criteria in OPENPGP-COMPATIBILITY.md unreachable by construction.
//   - THE CARD MUST AGREE WITH THE BINDING ABOUT UNATTENDED OPERATION. See provider.go; this is
//     the one limit the registry cannot check, because it is a fact about the card.
//
// # WHAT THIS PACKAGE DOES NOT DO
//
// It does not talk to a card, and it must not. Both
// TestOnlyBackendPackagesImportDeviceLibraries and TestNoPackageShellsOut apply to it, and this
// package appears on neither allowlist — a name split across a line break is not a citation, so
// they are written out whole here on purpose (kms/tests/test_named_tests_exist.py matches exactly).
// The Driver and Card interfaces in provider.go are a SEAM that the daemon does not wire. Every
// card behaviour THIS package's tests reason about is MODELLED by a test double. The driver that
// implements the seam (openpgp/driver over openpgp/pcsc) is qualified separately against a real
// card, and only partly: see OPENPGP-COMPATIBILITY.md. ADR-0001 §4 requires a physical test before a
// (model, firmware, middleware, adapter) tuple is eligible at all.
//
// The daemon constructs no provider from this package. That is recorded as debt in
// internal/reachability_test.go's unwiredControls, which now also fails if the entry stops being
// true, so "we have an OpenPGP backend" cannot quietly become "the daemon serves OpenPGP".
package openpgp

import (
	"errors"
	"fmt"
	"sort"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// BackendName is the single backend identifier this adapter serves. A route naming anything else
// is refused rather than handled leniently: an adapter that accepts a backend name it was not
// built for is how one token's rules get applied to another token.
const BackendName = "yubikey-openpgp"

// Slot names one of the three key roles an OpenPGP card holds. The roles are FIXED IN THE APPLET
// and cannot be reassigned — this is the property that makes the card unsuitable as the default
// abstraction (issue #21) and it is why a slot is a closed type here rather than a free string
// the way a PIV slot identifier is.
//
// The values are the identifiers `ykman openpgp` uses, so a person comparing a refusal against
// what they typed at the card sees the same three words.
type Slot string

const (
	// SlotSignature holds the signature key (PSO:CDS). Its PIN behaviour differs from the other
	// two and is the reason unattended operation needs its own check; see provider.go.
	SlotSignature Slot = "sig"
	// SlotDecryption holds the decryption key (PSO:DEC). It is the slot that reads legacy
	// material, and therefore the only reason this backend exists.
	SlotDecryption Slot = "dec"
	// SlotAuthentication holds the authentication key. IT EXISTS AND IS NEVER REACHABLE.
	//
	// The card has it, an inventory record may name it, and this KMS never operates it: ADR-0001
	// §4 and API.md put human administrator authentication outside the cryptographic-operation
	// surface, and /v1/operations has no authenticate route to reach it through. It is declared
	// here so that "no operation reaches this slot" is a property a test can assert
	// (TestNoOperationReachesTheAuthenticationSlot) rather than a gap nobody wrote down — which
	// is TESTING.md 14.
	SlotAuthentication Slot = "aut"
)

// Slots returns the three fixed roles, in card order. Returned as a fresh slice rather than an
// exported array for the reason registry.DeviceManagedOperations is a function: a package-level
// slice can be appended to by any importer, and a fourth slot is exactly the kind of widening
// that should not be possible in one line from outside.
func Slots() []Slot { return []Slot{SlotSignature, SlotDecryption, SlotAuthentication} }

// slotForOperation is the fixed-role map: which applet key an operation would have to use.
//
// It has two entries and it is the reason this file is short. sign must use the signature key and
// unwrap must use the decryption key; the card will not let either use the other, so there is no
// routing decision to make and no configuration that could make one. Everything else this KMS
// serves is in operationsNotOnThisApplet with a reason.
var slotForOperation = map[string]Slot{
	"sign":   SlotSignature,
	"unwrap": SlotDecryption,
}

// operationsNotOnThisApplet are operations /v1/operations serves, that this adapter deliberately
// does not, mapped to why.
//
// This is registry.deviceManagedOperations' shape and it is deliberate: a thing that is
// deliberately missing needs a reason a test can read (TESTING.md 14). The reasons below are not
// "the card cannot" — for several of them the card can. They are "this backend is not where that
// is done", which is a policy claim, and a policy claim that lives only in an ADR is one nobody
// is holding.
//
// TestEveryServedOperationIsAdmittedOrRefusedWithAReason derives the served set from
// api.OperationPaths() and holds that this map plus slotForOperation covers it exactly, so a new
// operation added to the router cannot default into either answer.
var operationsNotOnThisApplet = map[string]string{
	"wrap": "wrap CREATES material under this key. This backend exists to retire legacy material, " +
		"not to accumulate more of it, and an envelope wrapped to an OpenPGP decryption key can be " +
		"opened only by the applet being retired — which makes the removal criteria in " +
		"OPENPGP-COMPATIBILITY.md unreachable by construction. The capability matrix advertises no " +
		"wrap here either.",
	"seal-envelope": "sealing creates a new envelope, for the reason given for wrap. #75 puts " +
		"symmetric KEK custody on nitrokey-pkcs11 alone and the capability matrix advertises no " +
		"seal-envelope here.",
	"certificate-sign": "certificate issuance is a Nitrokey or PIV role in ADR-0001 §4's allocation. " +
		"A CA key reached through a compatibility adapter is a NEW dependency on the thing being " +
		"removed, which is the opposite of a migration path. Not advertised here either.",
	"key-agreement": "the decryption key does ECDH for cv25519, so this is a refusal the card would " +
		"not make. key-agreement hands a shared secret back to a caller, and that is a new " +
		"capability rather than the ability to read something already encrypted. Not advertised here.",
	"release-secret": "release-secret unwraps a data key on the card and returns an opaque secret; " +
		"its binding names the wrapping key by kek_algorithm, and #75's decision puts symmetric KEK " +
		"custody on nitrokey-pkcs11 alone. Not advertised here.",
}

// Refusals used by this package. Every one of them wraps ErrRefused, so a caller that only wants
// to know "was this refused rather than broken" can ask that question without matching on which
// rule fired, and a test that wants to know WHICH rule fired can still ask.
//
// These carry detail — the operation, the object, the backends that would have served it — which
// is safe because backend.Manager.Execute collapses any provider error to its own ErrUnavailable
// before it can leave the process. API.md's "an error is not a channel" is enforced there, at the
// boundary that faces a client, and not by keeping this package's refusals uninformative. An
// operator reading a startup or audit line needs to know which limit they hit.
var (
	// ErrRefused is the class. Never returned bare.
	ErrRefused = errors.New("openpgp compatibility backend refused the route")

	// ErrNotThisBackend: the route names some other backend.
	ErrNotThisBackend = fmt.Errorf("%w: binding does not name %s", ErrRefused, BackendName)
	// ErrOperationNotOnThisApplet: a served operation this adapter does not do.
	ErrOperationNotOnThisApplet = fmt.Errorf("%w: operation is not served on the OpenPGP applet", ErrRefused)
	// ErrNotAdvertised: the capability matrix does not advertise this algorithm/operation pair.
	ErrNotAdvertised = fmt.Errorf("%w: the capability matrix does not advertise this pair for %s", ErrRefused, BackendName)
	// ErrExceptionRequired: a supported backend can also do this, and nothing approved doing it here.
	ErrExceptionRequired = fmt.Errorf("%w: no recorded exception approves using the legacy applet for this", ErrRefused)
	// ErrExceptionExpired: the approval lapsed. A time-bounded exception that outlives its date is
	// not an approval, it is a record of one.
	ErrExceptionExpired = fmt.Errorf("%w: the recorded exception has expired", ErrRefused)
	// ErrInteractionRequired: the route or the card wants a human present, and this is the
	// unattended boundary.
	ErrInteractionRequired = fmt.Errorf("%w: unattended operation requires touch_policy=never and a card that does not demand touch", ErrRefused)
	// ErrCardContradictsBinding: the card's own state does not honour what the binding promised.
	ErrCardContradictsBinding = fmt.Errorf("%w: the card contradicts the binding", ErrRefused)
	// ErrLegacyMaterialRequired: an unwrap presented something other than legacy material.
	ErrLegacyMaterialRequired = fmt.Errorf("%w: this backend opens legacy material and creates none", ErrRefused)
)

// SlotFor reports which applet key an operation would use, and refuses every operation that has
// no place here.
//
// The error names the reason from operationsNotOnThisApplet, because a refusal an operator cannot
// act on sends them to read the source. An operation in neither map is refused too — the maps are
// held to cover the router's set exactly, so reaching this is a bug rather than a new case.
func SlotFor(operation string) (Slot, error) {
	if slot, ok := slotForOperation[operation]; ok {
		return slot, nil
	}
	if reason, known := operationsNotOnThisApplet[operation]; known {
		return "", fmt.Errorf("%w: %s — %s", ErrOperationNotOnThisApplet, operation, reason)
	}
	return "", fmt.Errorf("%w: %s is not an operation this adapter classifies", ErrOperationNotOnThisApplet, operation)
}

// RefusedOperations returns the operations this adapter does not serve, mapped to why. A copy, for
// the reason registry.DeviceManagedOperations is a copy: a map exported directly is widened by one
// index assignment that appears in no diff.
func RefusedOperations() map[string]string {
	copied := make(map[string]string, len(operationsNotOnThisApplet))
	for operation, reason := range operationsNotOnThisApplet {
		copied[operation] = reason
	}
	return copied
}

// AdmittedOperations returns the operations this adapter serves, mapped to the fixed slot each
// must use. A copy, for the same reason.
func AdmittedOperations() map[string]Slot {
	copied := make(map[string]Slot, len(slotForOperation))
	for operation, slot := range slotForOperation {
		copied[operation] = slot
	}
	return copied
}

// OtherBackendsServing reports which OTHER backends the capability matrix says can do this
// (algorithm, operation) pair, sorted.
//
// THIS IS THE "DEFAULT TO PIV OR NITROKEY" RULE, COMPUTED RATHER THAN WRITTEN DOWN. A pair some
// supported backend already serves is a pair nobody needs the legacy applet for, so using the
// applet for it is a choice that somebody has to have approved. A pair no other backend serves —
// today that is cv25519/unwrap alone — is the unavoidable case ADR-0001 §4 carved this backend out
// for, and it needs no approval because there is no alternative to approve instead.
//
// Deriving it from registry.Capabilities() means adding cv25519 to the Nitrokey, or removing
// rsa3072 from PIV, moves this rule with it. A hand-written list would not move, and the
// direction it would fail in is the permissive one: it would keep saying "no alternative exists"
// after one appeared.
func OtherBackendsServing(algorithm, operation string) []string {
	var others []string
	for backend, algorithms := range registry.Capabilities() {
		if backend == BackendName {
			continue
		}
		if algorithms[algorithm][operation] {
			others = append(others, backend)
		}
	}
	sort.Strings(others)
	return others
}
