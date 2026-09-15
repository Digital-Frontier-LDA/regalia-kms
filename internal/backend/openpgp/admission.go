package openpgp

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// Exception is the recorded approval that lets a legacy consumer keep using the OpenPGP applet
// for something PIV or the Nitrokey already does.
//
// EVERY FIELD IS REQUIRED, INCLUDING RemovalCriteria. An exception without a reason is not
// reviewable, one without an approver is not attributable, one without an expiry is permanent, and
// one without removal criteria is a carve-out that nobody can ever close — which is the "permanent
// bypass" outcome issue #21 exists to prevent. A record that records nothing is refused at
// construction rather than at use, because the person who can fix it is reading the config, not
// the audit log.
//
// The shape matches the custody manifest's `exception` object (reason, expires, approved_by;
// tools/custody_manifest.py), plus the removal criteria, so an operator writing one is writing
// something they have seen before. It is NOT read from the manifest today: the manifest's
// exception record is bound to custody mode "exception", which means "deliberately single-homed",
// and overloading it to also mean "deliberately on the legacy backend" would make one field answer
// two unrelated questions. Which artifact carries these in production is settled by the consumer
// inventory (#21 work breakdown item 1), which found no consumer (OPENPGP-COMPATIBILITY.md).
type Exception struct {
	// ObjectID is the custody object this approval covers. Approval is per object, not per
	// operation: the thing being approved is "this legacy consumer keeps its key on the applet
	// for now", and an object whose key is on the applet is there for every operation it uses.
	ObjectID string
	// Reason is why the supported backend is not usable for this object yet.
	Reason string
	// ApprovedBy names who accepted that reason.
	ApprovedBy string
	// RemovalCriteria is what has to become true for this object to move to PIV or the Nitrokey.
	RemovalCriteria string
	// Expires bounds the approval. Compared against the clock at every admission, not once at
	// load: a daemon that has been up for a year would otherwise keep honouring an approval that
	// lapsed eleven months ago.
	Expires time.Time
}

// Admission decides whether a route may reach the OpenPGP applet at all.
//
// It holds no card and opens nothing. Everything it refuses is refused before a device handle
// exists, which is what TestARefusedRouteNeverReachesTheCard asserts with a card double that fails
// the test if any of its methods is called.
type Admission struct {
	exceptions map[string]Exception
	now        func() time.Time
}

// NewAdmission builds the admission layer from the approved exceptions and a clock.
//
// A nil clock is refused rather than defaulted to time.Now. The default would be correct, and that
// is the problem: an exception compared against a clock nobody passed is a time bound nobody chose,
// and the failure mode of getting it wrong is an approval that never expires. Tests need to move
// the clock anyway, so there is no call site that wants the default.
func NewAdmission(exceptions []Exception, now func() time.Time) (*Admission, error) {
	if now == nil {
		return nil, errors.New("a clock is required: an exception never compared to a date is not time-bounded")
	}
	indexed := make(map[string]Exception, len(exceptions))
	for _, exception := range exceptions {
		switch {
		case strings.TrimSpace(exception.ObjectID) == "":
			return nil, errors.New("exception requires an object_id: an approval that names no object approves everything or nothing, and neither is reviewable")
		case strings.TrimSpace(exception.Reason) == "":
			return nil, fmt.Errorf("exception for %q requires a reason", exception.ObjectID)
		case strings.TrimSpace(exception.ApprovedBy) == "":
			return nil, fmt.Errorf("exception for %q requires approved_by", exception.ObjectID)
		case strings.TrimSpace(exception.RemovalCriteria) == "":
			return nil, fmt.Errorf("exception for %q requires removal criteria: a carve-out nobody can close is a permanent bypass", exception.ObjectID)
		case exception.Expires.IsZero():
			return nil, fmt.Errorf("exception for %q requires an expiry", exception.ObjectID)
		}
		if _, duplicate := indexed[exception.ObjectID]; duplicate {
			// Two records for one object means the effective approval is whichever the loader
			// happened to read last, and the reviewed one may be the other.
			return nil, fmt.Errorf("object %q has more than one exception; the effective approval would be whichever was read last", exception.ObjectID)
		}
		indexed[exception.ObjectID] = exception
	}
	return &Admission{exceptions: indexed, now: now}, nil
}

// Admit reports which applet slot a route may use, or why it may not use one.
//
// The order of the checks is the order of the questions: is this even our backend, is the
// operation one the applet does here, does the matrix advertise it, is a supported backend
// available instead, and does the route ask for a human. Each refusal names the rule that fired.
func (admission *Admission) Admit(route registry.Route, operation string) (Slot, error) {
	// A nil receiver admits nothing. The alternative is a panic inside a provider, which
	// backend.Manager recovers into a generic unavailable — fail-closed but unattributable, and
	// the comment on Manager.Execute already says why that is the worst of the outcomes.
	if admission == nil || admission.now == nil {
		return "", fmt.Errorf("%w: admission layer is not configured", ErrRefused)
	}
	binding := route.Binding
	if binding.Backend != BackendName {
		return "", fmt.Errorf("%w: binding names %q", ErrNotThisBackend, binding.Backend)
	}
	slot, err := SlotFor(operation)
	if err != nil {
		return "", err
	}
	// THE MATRIX IS THE PROMISE AND THIS ADAPTER HONOURS EXACTLY IT.
	//
	// A custody manifest is validated against registry.Capabilities(), so anything listed there is
	// something an operator may commission and expect to work. #73 is what happens when the two
	// disagree: aes-256/unwrap was advertised for nitrokey-pkcs11 and gated out by the driver, so
	// the manifest validated, routing succeeded, and the failure arrived at the token when
	// somebody needed the key.
	if !registry.Capabilities()[BackendName][route.Algorithm][operation] {
		return "", fmt.Errorf("%w: %s/%s", ErrNotAdvertised, route.Algorithm, operation)
	}
	if others := OtherBackendsServing(route.Algorithm, operation); len(others) > 0 {
		if err := admission.approved(route.ObjectID, route.Algorithm, operation, others); err != nil {
			return "", err
		}
	}
	// UNATTENDED IS THE ONLY MODE THIS BACKEND HAS.
	//
	// registry.validateBinding already refuses touch_policy != never for YubiKey backends at
	// manifest load, and this repeats it for the reason the PIV provider repeats it: a
	// registry.Route is a plain struct, every field exported, and a caller that builds one by
	// hand gets none of the loader's checks. The two are not independent — they read the same
	// field and share its assumptions — so this is depth, not a second opinion.
	if binding.TouchPolicy != "never" {
		return "", fmt.Errorf("%w: touch_policy is %q", ErrInteractionRequired, binding.TouchPolicy)
	}
	if binding.PINPolicy != "once" && binding.PINPolicy != "always" {
		return "", fmt.Errorf("%w: pin_policy is %q, which states nothing about how often the PIN is presented", ErrCardContradictsBinding, binding.PINPolicy)
	}
	return slot, nil
}

// approved reports whether an unexpired exception covers this object.
func (admission *Admission) approved(objectID, algorithm, operation string, others []string) error {
	exception, recorded := admission.exceptions[objectID]
	if !recorded {
		return fmt.Errorf("%w: %s/%s is served by %s, so %q must move there or record an approved exception",
			ErrExceptionRequired, algorithm, operation, strings.Join(others, " and "), objectID)
	}
	// Not After rather than Before: an exception that expires today has expired. The boundary
	// belongs on the strict side, because the alternative is an approval that is honoured for one
	// more day than the person who signed it agreed to.
	if !exception.Expires.After(admission.now()) {
		return fmt.Errorf("%w: approval for %q by %s expired at %s; removal criteria were %q",
			ErrExceptionExpired, objectID, exception.ApprovedBy, exception.Expires.UTC().Format(time.RFC3339), exception.RemovalCriteria)
	}
	return nil
}

// PairsRequiringAnException lists every advertised (algorithm, operation) pair on this backend
// that some other backend also serves, formatted "algorithm/operation", sorted.
//
// Exported so the limits can be reported — a startup line or a runbook table — from the same
// computation that enforces them, rather than from a second list that drifts. OPENPGP-COMPATIBILITY.md
// documents the rule and names this function; it does not restate the pairs.
func PairsRequiringAnException() []string {
	var pairs []string
	for algorithm, operations := range registry.Capabilities()[BackendName] {
		for operation, advertised := range operations {
			if !advertised {
				continue
			}
			if len(OtherBackendsServing(algorithm, operation)) > 0 {
				pairs = append(pairs, algorithm+"/"+operation)
			}
		}
	}
	sort.Strings(pairs)
	return pairs
}

// PairsNeedingNoException is the complement: advertised pairs no other backend serves. These are
// the unavoidable cases, and they are the only ones this adapter admits without an approval.
func PairsNeedingNoException() []string {
	var pairs []string
	for algorithm, operations := range registry.Capabilities()[BackendName] {
		for operation, advertised := range operations {
			if !advertised {
				continue
			}
			if len(OtherBackendsServing(algorithm, operation)) == 0 {
				pairs = append(pairs, algorithm+"/"+operation)
			}
		}
	}
	sort.Strings(pairs)
	return pairs
}
