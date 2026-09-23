// Package registry validates the custody manifest and deterministically maps a
// logical object to one commissioned hardware binding at the configured site.
package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"time"
)

const maxManifestBytes = 2 << 20

var (
	identifierPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
	fingerprintPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// kekVersionPattern must accept exactly what an envelope's KEK reference can carry, or a
	// manifest could name a generation no envelope could ever claim. envelope.keyVersionPattern is
	// the other half; TestManifestKEKVersionsAreNameableByAnEnvelope holds them together.
	kekVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
)

type Code string

const (
	CodeDenied                Code = "DENIED"
	CodeNotFound              Code = "NOT_FOUND"
	CodeDependencyUnavailable Code = "DEPENDENCY_UNAVAILABLE"
)

// Reason names the WHY of a CodeDenied, because the operator response depends on which one.
// A release refused because the matched KEK generation is in state `revoked` is a permanent
// data-loss event by design (#160); a release refused because routing found no binding at all is
// a configuration mistake. Both are CodeDenied (HTTP 403, non-retryable); only the audit
// record needs to tell them apart, and it does that through `Reason`.
type Reason string

const (
	// ReasonRevoked names a CodeDenied whose root cause is that every binding at the envelope's
	// KEK generation was excluded by UnwrapAllows because its state was `revoked`. This is the
	// audit outcome `denied-kek-revoked`: by design, the envelope becomes unopenable — the runbook
	// for setting `revoked` warns the operator that this is the consequence before they set the
	// state. See #160 and doc/RUNBOOK-KMS-INCIDENT.md §9 (KEK revocation).
	ReasonRevoked Reason = "kek-revoked"
)

type Error struct {
	Code   Code
	Reason Reason // populated only when the audit record needs the distinction; see ReasonRevoked
}

func (err *Error) Error() string {
	if err.Reason == "" {
		return "KMS routing failed"
	}
	return "KMS routing failed: " + string(err.Reason)
}

func IsCode(err error, code Code) bool {
	var registryErr *Error
	return errors.As(err, &registryErr) && registryErr.Code == code
}

// RefusalReason returns the Reason field of a registry Error, or "" if the error is not a
// registry Error or carries no reason. The caller decides what the reason MEANS — for #160 the
// only reason defined is ReasonRevoked, but the helper is reason-agnostic so a future split
// (e.g. revoked-vs-not-found-with-hint) does not need a new accessor per case.
func RefusalReason(err error) Reason {
	var registryErr *Error
	if !errors.As(err, &registryErr) {
		return ""
	}
	return registryErr.Reason
}

type Binding struct {
	Site               string `json:"site"`
	Backend            string `json:"backend"`
	DeviceID           string `json:"device_id"`
	DeviceSerial       string `json:"device_serial,omitempty"`
	DevAuthFingerprint string `json:"devaut_fingerprint,omitempty"`
	ObjectID           string `json:"object_id"`
	PublicFingerprint  string `json:"public_fingerprint,omitempty"`
	PublicKeySHA256    string `json:"public_key_sha256,omitempty"` // enforced; see nitrokeyIdentityPinned
	KeyCheck           string `json:"key_check,omitempty"`
	// KEKAlgorithm names the wrapping key in this slot for objects whose own algorithm is not a
	// key algorithm. See validateBinding.
	KEKAlgorithm string `json:"kek_algorithm,omitempty"`
	// KEKVersion is the generation of that wrapping key. It is what makes rotation mean something:
	// an envelope naming a superseded version is refused rather than opened on the key that replaced
	// it. See validateBinding.
	KEKVersion  string `json:"kek_version,omitempty"`
	State       string `json:"state"`
	PINPolicy   string `json:"pin_policy,omitempty"`
	TouchPolicy string `json:"touch_policy,omitempty"`
}

type custodyObject struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Kind           string          `json:"kind"`
	Classification string          `json:"classification"`
	Environment    string          `json:"environment"`
	Owner          string          `json:"owner"`
	Purpose        string          `json:"purpose"`
	Custody        string          `json:"custody"`
	Algorithm      string          `json:"algorithm"`
	Operations     []string        `json:"operations"`
	PolicyID       string          `json:"policy_id"`
	Bindings       []Binding       `json:"bindings"`
	Recovery       json.RawMessage `json:"recovery"`
	Rotation       json.RawMessage `json:"rotation"`
	Migration      json.RawMessage `json:"migration"`
	Verification   json.RawMessage `json:"verification"`
	Exception      json.RawMessage `json:"exception,omitempty"`
	Notes          string          `json:"notes,omitempty"`
}

type manifestDocument struct {
	SchemaVersion int             `json:"schema_version"`
	ManifestID    string          `json:"manifest_id"`
	GeneratedAt   string          `json:"generated_at"`
	Objects       []custodyObject `json:"objects"`
}

type BackendHealth interface {
	Healthy(context.Context, Binding) bool
}

type Route struct {
	ObjectID    string
	Purpose     string
	Algorithm   string
	PolicyID    string
	Environment string
	// KEKAlgorithm is the algorithm of the wrapping key the binding points at. It is what reaches
	// the token for a release-secret unwrap; Algorithm describes the object, which may be opaque.
	KEKAlgorithm string
	// KEKVersion is the generation of that key, which an envelope's KEK reference must match.
	KEKVersion string
	// EnvelopeMaxAge bounds how old an envelope may be at release. Zero means unbounded, which
	// is what a manifest that says nothing about it gets.
	EnvelopeMaxAge time.Duration
	Binding        Binding
}

// sealEligibleStates is the set of binding states seal-envelope accepts. The release path's
// Route() is active-only by design — only the active binding is "currently serving" — but seal
// writes a new envelope that the binding's slot will later need to open, and any binding the
// registry considers commissioned (qualified) or warmed up for handover (standby) is a valid
// seal target. planned has no key the seal could wrap against; retired produces a
// wrapped_data_key no current KEK can unwrap. See validateBinding for the Load-time refusal.
//
// The set is kept unexported and exposed only through the SealAllows function below. A
// package-level mutable map named SealAllowedStates would be an authorization surface an
// importer could silently widen with a write like
// registry.SealAllowedStates["retired"] = struct{}{} — a runtime mutation that shows up
// in no diff, fails no review, and is invisible to the static checks the project runs.
// A function turns the question "is state X eligible for seal?" into something index-
// assignment cannot answer.
var sealEligibleStates = map[string]struct{}{
	"qualified": {}, "active": {}, "standby": {},
}

// SealAllows reports whether a binding in `state` is permitted to seal. Authoritative source
// for the eligibility set is this file — rebinding the symbol or editing the map is reviewable
// here, where a re-exported mutable map would have been reviewable nowhere.
func SealAllows(state string) bool {
	_, ok := sealEligibleStates[state]
	return ok
}

// unwrapEligibleStates is the set of binding states that may OPEN an existing envelope. It is
// deliberately wider than sealEligibleStates, and `retired` is the whole reason it exists.
//
// A retired KEK is one that no longer wraps anything new. It is not one that has stopped being
// able to open what it already wrapped, and treating those as the same thing made rotation
// destroy data: the daemon does not store envelopes, it hands them to callers who put them in
// repositories, config stores and backups, so "rewrap everything before retiring" asks the
// registry to enumerate ciphertexts it has never held. Restore a backup taken before a rotation
// and every envelope in it names the retired version — under active-only resolution those are
// unopenable forever, which is #6's "backup and restore work without depending on the original
// token" failing by way of the rotation that was supposed to be routine.
//
// planned is excluded because there is no key in the slot yet, so nothing could have been
// wrapped against it. `revoked` (#160) is the SEPARATE fact that this KEK must refuse even to
// unwrap — a compromised or lost predecessor whose envelopes become unrecoverable by design.
// Adding `revoked` here would silently convert every ordinary rotation into a key-compromise
// response, which is the same defect in the opposite direction; the two states are siblings, not
// the same state overloaded. See #84 (parent issue) and #160 (the gap this comment was rewritten
// to name).
var unwrapEligibleStates = map[string]struct{}{
	"qualified": {}, "active": {}, "standby": {}, "retired": {},
}

// UnwrapAllows reports whether a binding in `state` may open an envelope already sealed against
// it. Exposed as a function for the same reason as SealAllows: an index assignment into an
// exported map is an authorization widening that appears in no diff.
func UnwrapAllows(state string) bool {
	_, ok := unwrapEligibleStates[state]
	return ok
}

type entry struct {
	route      Route
	operations map[string]struct{}
	assigned   bool
	// custody is the object's custody mode, carried past Load because it decides whether this
	// object is something the daemon operates or something the manifest merely records. See
	// isCustodyRecord.
	custody string
	// bindings carries the full set of configured bindings for this object. Route() uses route.Binding
	// (the active binding selected at Load) because release must always reach the same physical
	// device, but RouteForSeal re-selects at runtime from this slice because seal-eligibility is
	// not the same as routability: a standby KEK is not currently serving, yet may seal.
	bindings []Binding
	// rotateBy is the instant this object's declared rotation deadline passes. Zero means the
	// manifest set no enforceable deadline.
	rotateBy time.Time
}

// rotationPolicy is the manifest's declared rotation contract.
//
// It was parsed as an opaque blob and never interpreted, so maximum_age_days and last_rotated were
// documentation: an object past its own declared deadline kept serving indefinitely. A rotation
// policy nothing enforces is worse than none, because it reads like a control.
type rotationPolicy struct {
	MaximumAgeDays int        `json:"maximum_age_days"`
	LastRotated    *time.Time `json:"last_rotated"`
	// EnvelopeMaxAgeDays bounds how old an ENVELOPE may be, which is a different question from
	// how old the KEY may be. maximum_age_days is measured from last_rotated and governs the
	// object; this is measured from each envelope's own created_at and governs the ciphertext.
	// An object rotated on schedule can still be releasing envelopes sealed years ago.
	//
	// ABSENT MEANS UNBOUNDED, and that is the default deliberately. A lifetime bound is the one
	// control here that can cause an outage by working correctly -- every envelope past the bound
	// stops opening at once, on a clock nobody was watching. Deployments opt in.
	//
	// RAW, because three spellings must be told apart and Go's decoders collapse them.
	//
	// As a plain int, absent and 0 were the same value while the schema (minimum: 1) and
	// custody_manifest.py both refuse an explicit zero. As *int, absent and null became the same
	// value while the schema (type: integer) and custody_manifest.py both refuse null. Each time
	// the daemon would have started on a manifest CI rejects, which is the divergence this field
	// was added carefully to avoid.
	//
	// Absence is the only spelling of "no bound". Zero is a typo that would otherwise expire every
	// envelope at once, and null is a field someone began writing and did not finish.
	EnvelopeMaxAgeDays json.RawMessage `json:"envelope_max_age_days,omitempty"`
}

// rotationDeadline returns when the object falls out of compliance, or the zero time when the
// manifest does not establish one.
//
// last_rotated is nullable and a null means the object has never been rotated, so there is no
// instant to measure from. That is reported rather than enforced: refusing every never-rotated
// object would deny service for a fact the manifest itself records as unknown.
func rotationDeadline(raw json.RawMessage) (time.Time, error) {
	if len(raw) == 0 {
		return time.Time{}, nil
	}
	var policy rotationPolicy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return time.Time{}, errors.New("rotation policy is malformed")
	}
	if policy.MaximumAgeDays <= 0 || policy.LastRotated == nil {
		return time.Time{}, nil
	}
	return policy.LastRotated.AddDate(0, 0, policy.MaximumAgeDays), nil
}

// envelopeMaxAge is how old an envelope of this object may be, or zero for unbounded.
//
// Unlike rotationDeadline this is a DURATION rather than an instant: the deadline is per envelope
// and computed from the envelope's own created_at at release time, so there is no single moment
// the object falls out of compliance.
func envelopeMaxAge(raw json.RawMessage) (time.Duration, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	var policy rotationPolicy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return 0, errors.New("rotation policy is malformed")
	}
	if len(policy.EnvelopeMaxAgeDays) == 0 {
		return 0, nil
	}
	// Everything below shares one message, matching custody_manifest.py word for word: CI and the
	// daemon disagreeing about a single manifest is worse than either rule being wrong.
	const refusal = "envelope_max_age_days must be a positive integer of days; omit it to leave envelope lifetime unbounded"
	var days int
	if err := json.Unmarshal(policy.EnvelopeMaxAgeDays, &days); err != nil {
		// Covers null, a string, a float and a boolean alike. The schema says integer and so does
		// the Python validator; a value that is not one is not a bound of any length.
		return 0, errors.New(refusal)
	}
	if days < 1 {
		return 0, errors.New(refusal)
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

type Registry struct {
	digest  string
	site    string
	health  BackendHealth
	entries map[string]entry
	now     func() time.Time
}

// SetClock overrides the clock used for rotation deadlines. Tests use it; production keeps the
// default set in Load.
// SetBackendHealth attaches the probe Route and Ready consult before serving an object.
//
// The registry is loaded before the backend manager exists — buildHardware needs the registry to
// resolve device bindings — so the probe cannot be supplied at load time. Until it is attached,
// Route denies every object with DEPENDENCY_UNAVAILABLE and Ready is false, which is the correct
// fail-closed posture and also completely silent: a daemon that never attaches one looks exactly
// like a daemon whose hardware is down.
func (registry *Registry) SetBackendHealth(health BackendHealth) {
	if registry == nil {
		return
	}
	registry.health = health
}

// HasBackendHealth reports whether a probe has been attached. The daemon asserts this after wiring
// so the silent case above becomes a startup error instead of every request failing.
func (registry *Registry) HasBackendHealth() bool {
	return registry != nil && registry.health != nil
}

func (registry *Registry) SetClock(now func() time.Time) {
	if registry != nil && now != nil {
		registry.now = now
	}
}

// OverdueObjects lists objects whose declared rotation deadline has passed. Readiness stays true —
// an overdue key is a compliance failure, not an unavailable dependency — but it must be visible
// before it starts refusing work.
func (registry *Registry) OverdueObjects(at time.Time) []string {
	if registry == nil {
		return nil
	}
	overdue := make([]string, 0)
	for id, entry := range registry.entries {
		if !entry.rotateBy.IsZero() && at.After(entry.rotateBy) {
			overdue = append(overdue, id)
		}
	}
	sort.Strings(overdue)
	return overdue
}

// LoadFile rejects mutable or non-regular registry sources before parsing.
func LoadFile(path, site string, health BackendHealth) (*Registry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open registry: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat registry: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("registry must be a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("registry must not be group- or world-writable")
	}
	return Load(file, site, health)
}

// Load performs runtime-critical validation in addition to the repository's
// full JSON Schema/ceremony validator. It never invents a fallback binding.
func Load(reader io.Reader, site string, health BackendHealth) (*Registry, error) {
	if !identifierPattern.MatchString(site) {
		return nil, errors.New("registry site must be a lowercase identifier")
	}
	contents, err := io.ReadAll(io.LimitReader(reader, maxManifestBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read registry: %w", err)
	}
	if len(contents) > maxManifestBytes {
		return nil, errors.New("registry exceeds 2 MiB")
	}
	var document manifestDocument
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode registry: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("registry must contain exactly one JSON document")
	}
	if document.SchemaVersion != 1 || document.ManifestID == "" || document.GeneratedAt == "" || len(document.Objects) == 0 {
		return nil, errors.New("registry header is incomplete or unsupported")
	}

	result := &Registry{
		digest:  digest(contents),
		site:    site,
		health:  health,
		entries: make(map[string]entry, len(document.Objects)),
		now:     time.Now,
	}
	occupied := make(map[string]string)
	for index := range document.Objects {
		object := &document.Objects[index]
		if err := validateObject(object, site, occupied); err != nil {
			return nil, fmt.Errorf("registry object %q: %w", object.ID, err)
		}
		if _, exists := result.entries[object.ID]; exists {
			return nil, fmt.Errorf("duplicate registry object id %q", object.ID)
		}
		selected, found, err := selectBinding(object.Bindings, site)
		if err != nil {
			return nil, fmt.Errorf("registry object %q: %w", object.ID, err)
		}
		operations := make(map[string]struct{}, len(object.Operations))
		for _, operation := range object.Operations {
			operations[operation] = struct{}{}
		}
		rotateBy, err := rotationDeadline(object.Rotation)
		if err != nil {
			return nil, fmt.Errorf("registry object %q: %w", object.ID, err)
		}
		maxEnvelopeAge, err := envelopeMaxAge(object.Rotation)
		if err != nil {
			return nil, fmt.Errorf("registry object %q: %w", object.ID, err)
		}
		result.entries[object.ID] = entry{
			route: Route{
				ObjectID: object.ID, Purpose: object.Purpose, Algorithm: object.Algorithm,
				PolicyID: object.PolicyID, Environment: object.Environment,
				KEKAlgorithm: selected.KEKAlgorithm, KEKVersion: selected.KEKVersion,
				EnvelopeMaxAge: maxEnvelopeAge, Binding: selected,
			},
			operations: operations,
			assigned:   found,
			custody:    object.Custody,
			bindings:   append([]Binding(nil), object.Bindings...),
			rotateBy:   rotateBy,
		}
	}
	return result, nil
}

// THE DAEMON ENFORCES THE CUSTODY RULES, NOT ONLY CI.
//
// These sets and the redundancy rule below existed in tools/custody_manifest.py and nowhere
// else. That tool validates the manifest IN THE REPOSITORY during CI; the daemon loads whatever
// file registry_path points at, which need not be that one and is not re-checked. So "a production
// object requires at least 2 hardware bindings" — the rule that means losing one device does not
// lose the key — held for manifests that went through review and for no others.
//
// ADR-0001 §1 makes the KMS the only cryptographic boundary. A rule enforced in CI and absent at
// the boundary is a rule that anybody deploying without CI simply does not have, and its absence is
// silent: the daemon starts, routes, and signs.
//
// TestLoaderEnumsMatchThePublishedSchema keeps these aligned with
// config/custody-manifest.schema.json, which is the published contract and is already bound to the
// Python validator by its own test.
var (
	objectKinds = map[string]struct{}{
		"asymmetric-key": {}, "symmetric-key": {}, "opaque-secret": {}, "password": {},
		"api-token": {}, "seed": {}, "certificate": {}, "fido-credential": {}, "sops-recipient": {},
	}
	objectClassifications = map[string]struct{}{
		"public": {}, "internal": {}, "confidential": {}, "restricted": {}, "critical": {},
	}
	// EVERY BINDING STATE, AS A SET, BECAUSE THREE FILES HAVE TO AGREE ON IT.
	//
	// This was an inline `!=` chain. Adding "revoked" for #160 changed the chain and left both
	// config/custody-manifest.schema.json and tools/custody_manifest.py behind, so the daemon
	// loaded a manifest CI refused -- the feature's own state could not appear in any committed
	// manifest. Review caught it; nothing in the suite did, because a chain cannot be compared to
	// an enum. As a set it can be, and TestBindingStatesMatchThePublishedSchema does.
	bindingStates = map[string]struct{}{
		"planned": {}, "qualified": {}, "active": {}, "standby": {}, "retired": {}, "revoked": {},
	}
	// THE COMMISSIONED SUBSET: a binding that names real hardware and must therefore pin it.
	//
	// Separate from bindingStates because it answers a different question. "Is this a state?" is
	// spelled once; "does this state mean a device exists?" is spelled here, and the schema
	// encodes the same subset twice (binding.allOf[].if.properties.state) to require device_serial
	// and devaut_fingerprint. It appeared three times inline, which is three chances to add a
	// state to one list and not the other.
	commissionedStates = map[string]struct{}{
		"qualified": {}, "active": {}, "standby": {},
	}
	// EVERY CUSTODY MODE SAYS WHETHER THE DAEMON OPERATES THE OBJECT OR ONLY RECORDS IT.
	//
	// This was a plain set, with record-only membership kept in a second map beside it. A fifth mode
	// could then be added here and be operated by default, without anyone deciding it should be —
	// and the way that goes wrong is not subtle: an object nothing can serve makes the daemon refuse
	// to start, or pins /v1/health/ready at 503, both blaming a backend rather than the manifest.
	// That is the bug fixed in #130, waiting to be reintroduced by a mode that inherited a default.
	//
	// A map to a class means a new mode cannot be added without typing one, and custodyUnclassified
	// is the zero value, so a mode reached without a decision is refused at Load instead of assumed
	// operable. TestEveryCustodyModeIsClassified (internal/registry/custody_test.go) holds that
	// a key cannot sit in this map without picking a class; the key-set binding to the schema is
	// TestLoaderEnumsMatchThePublishedSchema, not this test.
	custodyModes = map[string]custodyClass{
		"direct-hardware":       custodyOperated,
		"hardware-envelope":     custodyOperated,
		"exception":             custodyOperated,
		"fido-multi-enrollment": custodyRecord,
	}
)

// custodyClass says whether the daemon operates an object or merely records it.
type custodyClass uint8

const (
	// custodyUnclassified is the zero value, so a mode absent from custodyModes reads as
	// undecided rather than as operable.
	custodyUnclassified custodyClass = iota
	// custodyOperated: the daemon routes to this object and must be able to reach its device.
	custodyOperated
	// custodyRecord: THE MANIFEST RECORDS WHERE CREDENTIALS LIVE, AND NOTHING HERE OPERATES THEM.
	//
	// A FIDO credential is inventory. ADR-0001 §4 and API.md put human administrator authentication
	// outside the cryptographic-operation surface, /v1/operations exposes no authenticate route, and
	// there is no fido2 provider to build. The manifest lists these objects so a person can find the
	// two enrollments after losing a token — nothing here ever calls one.
	//
	// Saying so in code, rather than leaving it as a convention, is what stops the daemon from
	// demanding a backend for them: see RequiredBackends. Before this existed, recording a real
	// enrollment as active at a deployment's own site made the daemon refuse to start, complaining
	// that operations on the object "would fail at signing time" — an object nothing signs. The
	// shipped example avoided that only by naming its sites custodian-a/custodian-b and leaving both
	// bindings planned, neither of which is a rule: site is a free identifier, and a custodian who
	// happens to sit at the SiteA site is the ordinary case, not a perverse one.
	custodyRecord
)

// isCustodyRecord reports whether this custody mode describes an object the daemon records but
// never operates.
//
// # SAFETY: the zero value is the unsafe direction
//
// `custodyModes` is a `map[string]custodyClass`, so a key absent from the map reads as the zero
// value `custodyUnclassified`. The zero value is not `custodyRecord`, so the equality below
// fails and this function returns `false` — which means *operated*: the daemon will route to it,
// sign for it, and refuse to come up if it has no backend. A typo in the manifest that names a
// custody mode nobody classified would silently treat the object as something the daemon
// operates on, which is the wrong direction for a credential whose custodian is not yet
// understood.
//
// The safety that prevents the zero-value path from being reachable lives at `validateCustody`
// above: `validateCustody` refuses a `custodyUnclassified` mode at load, so no `*custodyObject`
// that reaches this lookup can carry one. The two functions together mean "if you got past
// `validateCustody`, the lookup is safe; if you skipped it, the lookup lies." Every caller
// below goes through `Registry.Load` (and therefore `validateCustody`), but the gate is in a
// different function and nothing at the lookup says so — that is why this comment exists.
//
// Pin: `TestIsCustodyRecordReturnsFalseForUnclassifiedMode`.
func isCustodyRecord(custody string) bool {
	return custodyModes[custody] == custodyRecord
}

func validateCustody(object *custodyObject) error {
	if _, ok := objectKinds[object.Kind]; !ok {
		return fmt.Errorf("unsupported kind %q", object.Kind)
	}
	if _, ok := objectClassifications[object.Classification]; !ok {
		return fmt.Errorf("unsupported classification %q", object.Classification)
	}
	// An unclassified mode is one nobody decided about, and guessing on its behalf is how the
	// record-versus-operated confusion gets reintroduced. Refusing costs a manifest edit; guessing
	// costs a daemon that will not start or will not report ready, blaming the wrong thing.
	if custodyModes[object.Custody] == custodyUnclassified {
		return fmt.Errorf("unsupported custody mode %q", object.Custody)
	}
	// REDUNDANCY IS THE POINT OF THE SECOND BINDING. A production key held on one device is one
	// device failure away from being gone, and the manifest is where that is promised. "exception"
	// is the declared, reviewable way to say a key is deliberately single-homed.
	if object.Environment == "production" && object.Custody != "exception" && len(object.Bindings) < 2 {
		return errors.New("production object requires at least 2 hardware bindings, or custody \"exception\" to declare it single-homed")
	}
	devices := make(map[string]struct{}, len(object.Bindings))
	for _, binding := range object.Bindings {
		if _, duplicate := devices[binding.DeviceID]; duplicate {
			// Two bindings on one device is redundancy on paper only.
			return fmt.Errorf("bindings must use distinct devices, %q appears twice", binding.DeviceID)
		}
		devices[binding.DeviceID] = struct{}{}
	}
	return validateFIDOContinuity(object)
}

// validateFIDOContinuity enforces what "continuity by multi-enrollment" has to mean.
//
// A FIDO credential cannot be backed up, escrowed, or rebuilt from Shamir shares: the private key
// is born on the authenticator and never leaves it. The only continuity available is having
// enrolled a second credential BEFORE the first is lost, so these rules are the whole of the
// guarantee -- there is no recovery path behind them to fall back on.
//
// They lived in tools/custody_manifest.py and the JSON Schema, both of which run in CI against
// the manifest in this repository. The daemon loads whatever registry_path names, which need not be
// that file and was not re-checked, so a manifest could claim FIDO custody at the boundary while
// listing one enrollment, or two on the same desk. See the note on custodyModes above: a rule
// enforced only in CI is a rule that anybody deploying without CI does not have.
//
// The distinct-SITES rule is the one that carries the meaning, and it is deliberately stricter than
// the distinct-DEVICES rule above. Two tokens in one drawer are two devices and one fire.
func validateFIDOContinuity(object *custodyObject) error {
	usesFIDO := false
	for _, binding := range object.Bindings {
		if binding.Backend == "fido2" {
			usesFIDO = true
		}
	}
	if object.Custody != "fido-multi-enrollment" {
		if usesFIDO {
			return errors.New(`a fido2 binding requires custody "fido-multi-enrollment": no other custody mode describes a credential that cannot be exported or rebuilt`)
		}
		return nil
	}
	if object.Kind != "fido-credential" {
		return fmt.Errorf("custody %q requires kind \"fido-credential\", not %q", object.Custody, object.Kind)
	}
	sites := make(map[string]struct{}, len(object.Bindings))
	for _, binding := range object.Bindings {
		if binding.Backend != "fido2" {
			return fmt.Errorf("custody \"fido-multi-enrollment\" permits only fido2 bindings, not %q", binding.Backend)
		}
		sites[binding.Site] = struct{}{}
	}
	if len(sites) < 2 {
		// The first clause is byte-identical to tools/custody_manifest.py's message for this
		// rule, so an operator who meets one of them can find the other. CI rejects a manifest and
		// the daemon rejects the same manifest; reading those as two different problems is a wrong
		// turn that costs an afternoon.
		return errors.New("FIDO enrollments must be held in separate custody: at least two distinct sites — a credential that cannot be re-derived is only as redundant as the places it is kept")
	}
	var recovery struct {
		Mode string `json:"mode"`
	}
	if len(object.Recovery) > 0 {
		if err := json.Unmarshal(object.Recovery, &recovery); err != nil {
			return fmt.Errorf("recovery is not an object: %w", err)
		}
	}
	if recovery.Mode != "multi-enrollment" {
		return fmt.Errorf("custody \"fido-multi-enrollment\" requires recovery mode \"multi-enrollment\", not %q: a FIDO credential has no share-based path back", recovery.Mode)
	}
	return nil
}

func validateObject(object *custodyObject, site string, occupied map[string]string) error {
	if !identifierPattern.MatchString(object.ID) || !identifierPattern.MatchString(object.Purpose) {
		return errors.New("id and purpose must be lowercase identifiers")
	}
	if object.Algorithm == "" || object.PolicyID == "" || object.Environment == "" || object.Classification == "" || len(object.Verification) == 0 || len(object.Operations) == 0 {
		return errors.New("algorithm, policy, environment and operations are required")
	}
	if err := validateCustody(object); err != nil {
		return err
	}
	seenOperations := make(map[string]struct{}, len(object.Operations))
	for _, operation := range object.Operations {
		if operation == "" {
			return errors.New("operation must not be empty")
		}
		if _, exists := seenOperations[operation]; exists {
			return fmt.Errorf("duplicate operation %q", operation)
		}
		seenOperations[operation] = struct{}{}
	}
	for _, binding := range object.Bindings {
		if err := validateBinding(binding, object.Algorithm, object.Operations); err != nil {
			return err
		}
		slot := binding.Site + "\x00" + binding.DeviceID + "\x00" + binding.ObjectID
		if other, exists := occupied[slot]; exists && other != object.ID {
			return fmt.Errorf("hardware slot is also assigned to %q", other)
		}
		occupied[slot] = object.ID
	}
	// AN OBJECT THAT DECLARES seal-envelope MUST HAVE SOMETHING THAT CAN SEAL.
	//
	// This replaces the per-binding `retired` refusal removed from validateBinding, and is
	// stronger than what it replaces: that check could not see an object whose bindings were ALL
	// retired, because each one failed or passed on its own. Here the question is asked once of
	// the set, which is the only level at which "can this object still seal?" has an answer.
	for _, operation := range object.Operations {
		if operation != "seal-envelope" {
			continue
		}
		sealable := false
		for _, binding := range object.Bindings {
			if binding.Site == site && SealAllows(binding.State) {
				sealable = true
				break
			}
		}
		if !sealable {
			return fmt.Errorf("object declares seal-envelope but no binding at site %q is in a state that can seal; a retired KEK still opens old envelopes and cannot wrap new ones", site)
		}
	}
	_, _, err := selectBinding(object.Bindings, site)
	return err
}

func validateBinding(binding Binding, algorithm string, operations []string) error {
	if binding.Site == "" || binding.DeviceID == "" || binding.ObjectID == "" {
		return errors.New("binding site, device_id and object_id are required")
	}
	if binding.PublicFingerprint == "" && binding.KeyCheck == "" {
		return errors.New("binding needs a public fingerprint or key check")
	}
	if _, ok := bindingStates[binding.State]; !ok {
		return fmt.Errorf("unsupported binding state %q", binding.State)
	}
	_, commissioned := commissionedStates[binding.State]
	if binding.Backend == "nitrokey-pkcs11" && commissioned && !nitrokeyIdentityPinned(binding) {
		// A serial plus a DevAut fingerprint OR public_key_sha256: ADR-0002 D1, see below.
		return errors.New("commissioned Nitrokey requires pinned serial and DevAut fingerprint or public_key_sha256")
	}
	if binding.Backend == "yubikey-piv" || binding.Backend == "yubikey-openpgp" {
		if commissioned && binding.DeviceSerial == "" {
			return errors.New("commissioned YubiKey requires pinned serial")
		}
		if binding.TouchPolicy != "never" || (binding.PINPolicy != "once" && binding.PINPolicy != "always") {
			return errors.New("YubiKey requires PIN policy and touch_policy=never")
		}
	} else if binding.PINPolicy != "" || binding.TouchPolicy != "" {
		return errors.New("interaction policy is only valid for YubiKey backends")
	}
	releases := false
	seals := false
	for _, operation := range operations {
		if operation == "seal-envelope" {
			seals = true
		}
		if !supports(binding.Backend, algorithm, operation) {
			return fmt.Errorf("backend %q does not support %s/%s", binding.Backend, algorithm, operation)
		}
		if operation == "release-secret" {
			releases = true
		}
	}
	// AN OPAQUE SECRET HAS NO ALGORITHM OF ITS OWN; THE KEK THAT PROTECTS IT DOES.
	//
	// release-secret is advertised only for algorithm "opaque", because an API token is not a key.
	// Serving it still means unwrapping a data key ON THE CARD, and every driver gate is written in
	// terms of the key in the slot: PKCS#11 accepts rsa2048/3072/4096, PIV accepts rsa2048 alone.
	// Handing the object's algorithm to the token made every object of this shape fail at its first
	// release -- reported as a retryable backend error, so callers would retry a permanent condition
	// forever. The binding must name the wrapping key it actually points at, and that key must be one
	// this backend can unwrap with.
	if releases {
		if binding.KEKAlgorithm == "" {
			return errors.New("a release-secret binding must name the kek_algorithm of the wrapping key in its slot")
		}
		if !supports(binding.Backend, binding.KEKAlgorithm, "unwrap") {
			return fmt.Errorf("backend %q cannot unwrap with kek_algorithm %q, so this binding could never release a secret", binding.Backend, binding.KEKAlgorithm)
		}
		// A KEK VERSION THAT SELECTS NOTHING IS NOT ROTATION.
		//
		// The envelope names a KEK version, but the release path routed every version to this one
		// slot, so after rotating a key both old and new envelopes opened on whatever it now holds.
		// Retiring a KEK was impossible without retiring the object. Naming the generation here gives
		// the envelope's claim something to be checked against: rotate the key, bump this, and
		// envelopes wrapped under the old one are refused until they are rewrapped.
		if binding.KEKVersion == "" {
			return errors.New("a release-secret binding must name the kek_version of the wrapping key in its slot")
		}
		// A named-but-unusable version is a different mistake from an absent one. Telling an operator
		// to name a field they just named sends them looking in the wrong place, and CI and the
		// daemon must say the same thing about the same manifest.
		if !kekVersionPattern.MatchString(binding.KEKVersion) {
			return fmt.Errorf("kek_version %q must match %s to be nameable by an envelope's KEK reference", binding.KEKVersion, kekVersionPattern.String())
		}
	} else if !releases && !seals && (binding.KEKAlgorithm != "" || binding.KEKVersion != "") {
		return fmt.Errorf("kek_algorithm and kek_version are only meaningful for release-secret and seal-envelope; %s/%s already names the key in this slot", binding.Backend, algorithm)
	}
	// SEAL-ENVELOPE WRITES ENVELOPES THE CURRENT KEK MUST BE ABLE TO OPEN LATER.
	//
	// A planned binding has not been commissioned, so the slot has no key the seal could wrap;
	// the envelope would carry a wrapped_data_key nobody can ever unwrap. Failing at Load turns
	// the configuration mistake into a startup error rather than a release-time surprise.
	//
	// `retired` USED TO BE REFUSED HERE TOO, on the reasoning that it "will leave envelopes no
	// live KEK can open". That is exactly inverted for the retired predecessor of an active KEK:
	// it is the binding that lets already-sealed envelopes still open, and refusing it made a
	// rotated object unexpressible — the manifest could describe the state before a rotation and
	// the state after, but not the one every rotation passes through. Retired bindings are
	// refused at ROUTE time for seal (SealAllows excludes them) and admitted for unwrap
	// (UnwrapAllows includes them), which is the distinction this check was conflating.
	//
	// What that refusal was really protecting — "something here can still seal" — is now checked
	// per object in validateObject, where it belongs, since it is a property of the object's set
	// of bindings and not of any one of them.
	if seals {
		if binding.State == "planned" {
			return fmt.Errorf("a seal-envelope binding cannot be in state %q: it has nothing to wrap against", binding.State)
		}
		if binding.KEKAlgorithm == "" {
			return errors.New("a seal-envelope binding must name the kek_algorithm of the wrapping key in its slot")
		}
		if !supports(binding.Backend, binding.KEKAlgorithm, "wrap") {
			return fmt.Errorf("backend %q cannot wrap with kek_algorithm %q, so this binding could never seal an envelope", binding.Backend, binding.KEKAlgorithm)
		}
		if binding.KEKVersion == "" {
			return errors.New("a seal-envelope binding must name the kek_version of the wrapping key in its slot")
		}
		if !kekVersionPattern.MatchString(binding.KEKVersion) {
			return fmt.Errorf("kek_version %q must match %s to be nameable by an envelope's KEK reference", binding.KEKVersion, kekVersionPattern.String())
		}
	}
	return nil
}

// Capabilities is what each backend is advertised as able to do.
//
// It is a PROMISE: a custody manifest binding an object to (backend, algorithm, operation) is
// validated against this table, so anything listed here is something an operator may commission and
// expect to work. An entry the implementation does not honour is therefore worse than a missing
// one — the manifest validates, routing succeeds, and the failure arrives at the token, when
// somebody needs the key.
//
// It was exactly that for aes-256/unwrap on nitrokey-pkcs11: advertised here and gated out by the
// PKCS#11 driver, which wraps only with RSA. Its one other appearance was a Python test fixture,
// so the case was exercised in CI and unsupported in production at the same time.
//
// Exported so the backends can be tested against what they claim rather than against themselves,
// and so the Python custody-manifest validator can read one table instead of keeping a second.
//
// The fido2 row is the one entry that is NOT a promise about this daemon, and it is worth being
// exact about why it is allowed to stay. It describes what the credential does on the token, for a
// human, at an identity provider — the manifest needs it to validate a FIDO binding at all. Nothing
// here executes it: /v1/operations has no authenticate route and no fido2 provider is constructed.
// What keeps that from being the "advertised and unhonoured" defect described above is not this
// comment but isCustodyRecord, which makes Route refuse the object and keeps it out of
// RequiredBackends. TestRouteDeniesAFIDOCustodyRecordRatherThanReportingHardwareTrouble is the
// proof; delete the rule and that test fails.
// deviceManagedOperations are advertised in the capability matrix and deliberately NOT served by
// this API, mapped to why. The matrix describes what a device can do; it is not a promise that the
// KMS will do it on the device's behalf, and those are different claims that look identical to
// anyone reading backend-capabilities.json.
//
// THE EXCLUSION WAS TRUE AND UNCHECKED. API.md has said "FIDO2 `authenticate` is not part of this
// API" since it was written, and nothing enforced it: `authenticate` is in Capabilities(), in the
// published backend-capabilities.json, and in the shipped example manifest as
// `"operations": ["authenticate"]` — so an operator reading those three would reasonably conclude
// it is invocable. It is not. What saved it was that fido2 is the only backend advertising it and
// buildHardware constructs no fido2 provider, so the daemon refuses such a manifest at startup for
// an unrelated reason. Add a fido2 provider and the hole opens with nothing to catch it.
//
// Keeping the exception here, rather than as a sentence in API.md, is TESTING.md 14: a thing
// deliberately missing needs a reason that a test can read.
var deviceManagedOperations = map[string]string{
	"authenticate": "human administrator authentication is outside the cryptographic-operation " +
		"surface (API.md, ADR-0001 4). FIDO enrollments are inventory: the manifest records where " +
		"they live and nothing here operates them, which is what custodyRecord classification means.",
}

// MatchesIdentifier reports whether a value has the identifier shape the registry accepts, so a
// package that must accept exactly what the registry accepts shares one definition instead of a
// copy that drifts. The control-plane export's Site is the first caller.
//
// A FUNCTION, NOT THE EXPORTED *regexp.Regexp IT REPLACES, for the reason stated two functions
// down about DeviceManagedOperations: a package-level var can be reassigned by any importer, and
// `registry.IdentifierPattern = regexp.MustCompile(".*")` is one innocuous-looking line that
// widens identifier validation everywhere at once -- object IDs, purposes and the export's Site
// together, because the loader's own checks read the same value. Strictly worse than the map
// case, which at least required naming a key. Pinned by
// TestTheIdentifierShapeCannotBeWidenedByItsCaller.
func MatchesIdentifier(value string) bool { return identifierPattern.MatchString(value) }

// DeviceManagedOperations returns the advertised operations this API deliberately does not serve,
// mapped to the reason. Returned as a copy for the same reason SealAllows is a function: a map
// exported directly can be widened by an index assignment that appears in no diff.
func DeviceManagedOperations() map[string]string {
	copied := make(map[string]string, len(deviceManagedOperations))
	for operation, reason := range deviceManagedOperations {
		copied[operation] = reason
	}
	return copied
}

func Capabilities() map[string]map[string]map[string]bool {
	return map[string]map[string]map[string]bool{
		"nitrokey-pkcs11": {
			"secp256k1": {"sign": true}, "ed25519": {"sign": true},
			"p256":    {"sign": true, "certificate-sign": true, "key-agreement": true},
			"p384":    {"sign": true, "certificate-sign": true, "key-agreement": true},
			"rsa2048": {"sign": true, "wrap": true, "unwrap": true, "certificate-sign": true},
			"rsa3072": {"sign": true, "wrap": true, "unwrap": true, "certificate-sign": true},
			"rsa4096": {"sign": true, "wrap": true, "unwrap": true, "certificate-sign": true},
			// #75: a symmetric KEK is a single CKO_SECRET_KEY with no public half. The matrix lists
			// unwrap only because the wrap side is an open design question (#194): a wrap site
			// would have to hold the same secret the unwrap site holds, which conflicts with the
			// multi-site model the rest of the custody manifest assumes. Three open backends are
			// absent on purpose — yubikey-piv is behind the piv build tag, yubikey-openpgp and
			// fido2 do not implement CKM_AES_KEY_WRAP_PAD.
			"aes-256": {"unwrap": true},
			"opaque":  {"release-secret": true, "seal-envelope": true},
		},
		"yubikey-piv": {
			"p256": {"sign": true, "certificate-sign": true}, "p384": {"sign": true, "certificate-sign": true},
			"rsa2048": {"sign": true, "wrap": true, "unwrap": true, "certificate-sign": true},
		},
		"yubikey-openpgp": {
			"ed25519": {"sign": true}, "cv25519": {"unwrap": true},
			"rsa2048": {"sign": true, "unwrap": true}, "rsa3072": {"sign": true, "unwrap": true},
			"rsa4096": {"sign": true, "unwrap": true},
		},
		"fido2": {"device-managed": {"authenticate": true}},
	}
}

func supports(backend, algorithm, operation string) bool {
	algorithms, ok := Capabilities()[backend]
	if !ok {
		return false
	}
	return algorithms[algorithm][operation]
}

func selectBinding(bindings []Binding, site string) (Binding, bool, error) {
	var selected Binding
	found := false
	for _, binding := range bindings {
		if binding.Site != site || binding.State != "active" {
			continue
		}
		if found {
			return Binding{}, false, errors.New("multiple active bindings at configured site")
		}
		selected, found = binding, true
	}
	return selected, found, nil
}

// selectBindingForState returns the first binding at `site` whose state the `allowed` predicate
// accepts, or an error if zero or more than one match. The predicate is supplied by the caller —
// release uses active-only (via selectBinding), seal uses SealAllows — so the helper is the one
// repository of "what does eligible mean" between call sites. Predicates (rather than a map) keep
// the eligibility surface a function call rather than an index-assignable table.
func selectBindingForState(bindings []Binding, site string, allowed func(string) bool) (Binding, error) {
	var selected Binding
	found := false
	for _, binding := range bindings {
		if binding.Site != site {
			continue
		}
		if !allowed(binding.State) {
			continue
		}
		if found {
			return Binding{}, errors.New("multiple usable bindings at configured site")
		}
		selected, found = binding, true
	}
	if !found {
		return Binding{}, errors.New("no binding at configured site is in a state permitted for this operation")
	}
	return selected, nil
}

func (registry *Registry) clock() time.Time {
	if registry == nil || registry.now == nil {
		return time.Now()
	}
	return registry.now()
}

func (registry *Registry) Route(ctx context.Context, objectID, purpose, operation string) (Route, error) {
	entry, exists := registry.entries[objectID]
	if !exists {
		return Route{}, &Error{Code: CodeNotFound}
	}
	if entry.route.Purpose != purpose {
		return Route{}, &Error{Code: CodeDenied}
	}
	if _, allowed := entry.operations[operation]; !allowed {
		return Route{}, &Error{Code: CodeDenied}
	}
	// Denied, not unavailable: a custody record is not a device that happens to be down, and a
	// caller retrying until the hardware comes back would wait forever.
	if isCustodyRecord(entry.custody) {
		return Route{}, &Error{Code: CodeDenied}
	}
	if !entry.assigned || registry.health == nil || !safeHealthy(ctx, registry.health, entry.route.Binding) {
		return Route{}, &Error{Code: CodeDependencyUnavailable}
	}
	// An object past its declared rotation deadline is out of compliance with the manifest that
	// authorized it. Serving anyway would make maximum_age_days decorative.
	if !entry.rotateBy.IsZero() && registry.clock().After(entry.rotateBy) {
		return Route{}, &Error{Code: CodeDenied}
	}
	return entry.route, nil
}

// RouteForUnwrap selects the binding that holds the KEK an existing envelope names.
//
// Release used to take Route(), which serves the ACTIVE binding, and then refuse any envelope
// whose kek_version disagreed with it. That made a KEK rotation retroactive: the moment v2 became
// active, every envelope sealed under v1 stopped opening, everywhere, including in backups taken
// before the rotation. The daemon holds no envelope inventory and cannot rewrap what it has never
// seen, so the "rewrap everything first" alternative is not a procedure anyone was failing to
// follow — it is one the system cannot offer. See #84.
//
// So the envelope's own kek_version chooses the binding, among those UnwrapAllows admits.
//
// ROUTING ON A FIELD THAT HAS NOT BEEN AUTHENTICATED YET. kekVersion reaches here from caller
// bytes whose AEAD has not been verified — verification needs the data key, which needs the
// unwrap this call is routing. That grants a caller nothing: every candidate is a binding
// commissioned for THIS object at THIS site, so the choice is only ever between the object's own
// KEK generations, and an envelope that names one it was not sealed under simply fails to unwrap.
// The version equality check in the release path's UnwrapKey stays exactly where it was; routing
// now satisfies that check rather than contradicting it, so it still proves the pairing.
func (registry *Registry) RouteForUnwrap(ctx context.Context, objectID, purpose, kekVersion string) (Route, error) {
	entry, exists := registry.entries[objectID]
	if !exists {
		return Route{}, &Error{Code: CodeNotFound}
	}
	if entry.route.Purpose != purpose {
		return Route{}, &Error{Code: CodeDenied}
	}
	if _, allowed := entry.operations["release-secret"]; !allowed {
		return Route{}, &Error{Code: CodeDenied}
	}
	if isCustodyRecord(entry.custody) {
		return Route{}, &Error{Code: CodeDenied}
	}
	// The rotation deadline governs the OBJECT, not the generation: an object past its deadline
	// is out of compliance with the manifest that authorized it, and an old envelope is not the
	// exception that makes maximum_age_days negotiable.
	if !entry.rotateBy.IsZero() && registry.clock().After(entry.rotateBy) {
		return Route{}, &Error{Code: CodeDenied}
	}
	// An empty version cannot select: it would match the first eligible binding, which is how
	// "resolve by version" degrades back into "whatever happens to be there".
	if kekVersion == "" {
		return Route{}, &Error{Code: CodeDenied}
	}
	var selected Binding
	found := false
	// A BINDING EXISTS AT THIS VERSION+STATE BUT IS REVOKED. The candidate set for unwrap is
	// filtered by UnwrapAllows, which excludes `revoked`. If the only candidate at the envelope's
	// KEK generation was excluded for that reason, the release is refused not because the routing
	// failed but because the matched KEK is gone by deliberate operator decision (#160). The
	// operator must see the difference in the audit record: a routing denial is a configuration
	// mistake (fix the manifest); a revoked-KEK denial is data loss by design (the runbook row for
	// setting revoked warned about this before the state was set, and the consequence is the
	// envelope becoming unopenable). #160 named the same distinction.
	var revokedCandidateExists bool
	for _, binding := range entry.bindings {
		if binding.Site != registry.site || binding.KEKVersion != kekVersion {
			continue
		}
		if binding.State == "revoked" {
			revokedCandidateExists = true
			continue
		}
		if !UnwrapAllows(binding.State) {
			continue
		}
		if found {
			// Two bindings claiming one generation at one site means two different slots answer
			// to the same envelope. Picking either would make which key opened a secret depend on
			// the order the bindings happen to appear in the manifest.
			return Route{}, &Error{Code: CodeDenied}
		}
		selected, found = binding, true
	}
	if !found {
		if revokedCandidateExists {
			return Route{}, &Error{Code: CodeDenied, Reason: ReasonRevoked}
		}
		return Route{}, &Error{Code: CodeDenied}
	}
	if registry.health == nil || !safeHealthy(ctx, registry.health, selected) {
		return Route{}, &Error{Code: CodeDependencyUnavailable}
	}
	return Route{
		ObjectID:       entry.route.ObjectID,
		Purpose:        entry.route.Purpose,
		Algorithm:      entry.route.Algorithm,
		PolicyID:       entry.route.PolicyID,
		Environment:    entry.route.Environment,
		KEKAlgorithm:   selected.KEKAlgorithm,
		KEKVersion:     selected.KEKVersion,
		EnvelopeMaxAge: entry.route.EnvelopeMaxAge,
		Binding:        selected,
	}, nil
}

// RouteForSeal selects a binding for seal-envelope from the runtime state of the manifest, not
// from the Load-time active choice.
//
// It exists because Route() serves "currently serving" — only the active binding — and seal writes
// a new envelope whose lifecycle outlives the call. A binding in standby is currently not
// serving, yet its slot may seal today and rotate to active tomorrow; refusing at standby would
// require waiting on rotation before any new envelope could be sealed, which defeats the point of
// having both. By the same logic, a qualified binding (commissioned, not yet promoted) seals
// fine — it has a key the slot accepts and an envelope named for it can open once it is promoted.
// planned and retired are refused at Load time in validateBinding: they have no key today or no
// key tomorrow, so letting them through would only defer a refusal that the envelope then carries.
//
// The returned Route carries the binding's KEKAlgorithm and KEKVersion so the sealer can build
// the envelope's KEK reference server-side, mirroring how release reads the same fields.
func (registry *Registry) RouteForSeal(ctx context.Context, objectID, purpose string) (Route, error) {
	entry, exists := registry.entries[objectID]
	if !exists {
		return Route{}, &Error{Code: CodeNotFound}
	}
	if entry.route.Purpose != purpose {
		return Route{}, &Error{Code: CodeDenied}
	}
	if _, allowed := entry.operations["seal-envelope"]; !allowed {
		return Route{}, &Error{Code: CodeDenied}
	}
	if isCustodyRecord(entry.custody) {
		return Route{}, &Error{Code: CodeDenied}
	}
	// An object past its declared rotation deadline cannot accept new envelopes either: the very
	// reason the deadline exists is to limit how long any sealed envelope is allowed to live.
	if !entry.rotateBy.IsZero() && registry.clock().After(entry.rotateBy) {
		return Route{}, &Error{Code: CodeDenied}
	}
	binding, err := selectBindingForState(entry.bindings, registry.site, SealAllows)
	if err != nil {
		return Route{}, &Error{Code: CodeDenied}
	}
	if registry.health == nil || !safeHealthy(ctx, registry.health, binding) {
		return Route{}, &Error{Code: CodeDependencyUnavailable}
	}
	return Route{
		ObjectID:     entry.route.ObjectID,
		Purpose:      entry.route.Purpose,
		Algorithm:    entry.route.Algorithm,
		PolicyID:     entry.route.PolicyID,
		Environment:  entry.route.Environment,
		KEKAlgorithm: binding.KEKAlgorithm,
		KEKVersion:   binding.KEKVersion,
		// Carried on the seal route too, though seal does not consult it: an envelope is stamped
		// with the server's clock as it is created, so it is never born expired. Leaving the field
		// zero here would read as "this object has no bound" to anyone who looked.
		EnvelopeMaxAge: entry.route.EnvelopeMaxAge,
		Binding:        binding,
	}, nil
}

func (registry *Registry) Ready(ctx context.Context) bool {
	if len(registry.entries) == 0 || registry.health == nil {
		return false
	}
	operable := 0
	for _, entry := range registry.entries {
		// A custody record has no device here to be healthy. Readiness asks whether this daemon can
		// serve what it was given; an object it never serves cannot answer, and demanding an answer
		// took the daemon out of service for recording an enrollment correctly. Measured before this
		// skip existed: a manifest with one signing key and one FIDO record was Ready=false forever,
		// with the enrollments at custodian sites — the arrangement the continuity rules require.
		if isCustodyRecord(entry.custody) {
			continue
		}
		operable++
		if !entry.assigned || !safeHealthy(ctx, registry.health, entry.route.Binding) {
			return false
		}
	}
	// Skipping records must not turn a manifest of nothing but records into a ready daemon: it would
	// report healthy while able to serve no operation at all, which is the failure this function
	// exists to prevent.
	return operable > 0
}

func safeHealthy(ctx context.Context, health BackendHealth, binding Binding) (healthy bool) {
	defer func() {
		if recover() != nil {
			healthy = false
		}
	}()
	return health.Healthy(ctx, binding)
}

func (registry *Registry) Digest() string { return registry.digest }

// DeclaredPolicy is the policy binding a custody manifest states for one object.
type DeclaredPolicy struct {
	ObjectID   string
	PolicyID   string
	Operations []string
}

// DeclaredPolicies reports the policy each object CLAIMS to be governed by.
//
// The manifest requires a policy_id per object and the loader refuses one without it, so an
// operator reasonably reads it as the binding. It is not: the policy engine looks a policy up by
// (object_id, operation) and never consults this field. Whatever policy happens to name the object
// applies, whatever the manifest says it should be — and nothing reports the difference.
//
// This exists so the daemon can compare the claim against the enforced policy at startup.
func (registry *Registry) DeclaredPolicies() []DeclaredPolicy {
	if registry == nil {
		return nil
	}
	declared := make([]DeclaredPolicy, 0, len(registry.entries))
	for id, item := range registry.entries {
		operations := make([]string, 0, len(item.operations))
		for operation := range item.operations {
			operations = append(operations, operation)
		}
		sort.Strings(operations)
		declared = append(declared, DeclaredPolicy{ObjectID: id, PolicyID: item.route.PolicyID, Operations: operations})
	}
	sort.Slice(declared, func(i, j int) bool { return declared[i].ObjectID < declared[j].ObjectID })
	return declared
}

// RequiredBackends lists every backend this registry will route an object to.
//
// The registry accepts bindings to backends the daemon may not actually serve. It knows about
// yubikey-piv and yubikey-openpgp — it has capability entries for them and routes to them — while
// the daemon only ever constructs a nitrokey-pkcs11 provider. An operator could bind a key to a
// YubiKey, watch the manifest validate and the daemon start clean, and then have every operation on
// that key fail at signing time with a generic "unavailable". The routing table said yes and the
// backend table said nothing.
//
// This exists so the daemon can compare the two at startup instead of discovering the gap one
// request at a time.
func (registry *Registry) RequiredBackends() []string {
	if registry == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(registry.entries))
	for _, item := range registry.entries {
		// A custody record is not routed, so it requires nothing of this daemon. Counting it here
		// would make the startup check demand a provider for a backend the design says will never
		// exist, and the refusal would land on whoever recorded a real enrollment correctly.
		if isCustodyRecord(item.custody) {
			continue
		}
		if item.route.Binding.Backend != "" {
			seen[item.route.Binding.Backend] = struct{}{}
		}
	}
	backends := make([]string, 0, len(seen))
	for name := range seen {
		backends = append(backends, name)
	}
	sort.Strings(backends)
	return backends
}

func digest(contents []byte) string {
	sum := sha256.Sum256(contents)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// PublicKeySHA256 is "sha256:" + the SHA-256 of the bound object's public key EXACTLY as the backend's
// PublicKey returns it, recorded at commissioning after the card's attestation proved the key was
// generated on it. Unlike PublicFingerprint — an advisory record whose encoding was never defined —
// the Nitrokey backend ENFORCES it on every use (ADR-0002 D1). The bytes are the standard
// SubjectPublicKeyInfo DER, so the ceremony computes the pin with nothing proprietary — measured
// identical on DENK0404144 for the daemon, `pkcs11-tool --read-object --type pubkey | sha256sum` and
// an openssl round trip (regalia#448):
//
//	pkcs11-tool --module … --slot … --read-object --type pubkey --id <id> | sha256sum
//
// nitrokeyIdentityPinned: a commissioned Nitrokey pins its serial and, to prove it is the right card,
// its DevAut fingerprint or public_key_sha256, the commissioned public key of the bound object
// (ADR-0002 D1). A genuine
// SmartCard-HSM cannot expose the first through PKCS#11 (regalia#448), so requiring it made every real
// Nitrokey unbindable. A pin that is present must still be well formed — a malformed pin is a typo
// in the manifest, not an absent one. Kept out of line so the guard stays the four lines the sweep
// ledgers cite by number.
func nitrokeyIdentityPinned(binding Binding) bool {
	devAut := fingerprintPattern.MatchString(binding.DevAuthFingerprint)
	if binding.DeviceSerial == "" || (binding.DevAuthFingerprint != "" && !devAut) {
		return false
	}
	if binding.PublicKeySHA256 != "" && !fingerprintPattern.MatchString(binding.PublicKeySHA256) {
		return false
	}
	return devAut || binding.PublicKeySHA256 != ""
}
