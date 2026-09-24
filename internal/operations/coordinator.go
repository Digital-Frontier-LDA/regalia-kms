// Package operations coordinates authorization, policy, audit, bounded device
// execution, and safe API results in one fail-closed path.
package operations

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/approval"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/executor"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/secrets"
)

type Authorizer interface {
	Allowed(principal, object, operation, environment string) bool
	Digest() string
}

type Router interface {
	Route(context.Context, string, string, string) (registry.Route, error)
	// RouteForSeal selects the seal-envelope binding: seal writes an envelope whose
	// lifecycle outlives the call, so its eligibility is not the same as routability.
	RouteForSeal(context.Context, string, string) (registry.Route, error)
	// RouteForUnwrap selects the binding holding the KEK generation an existing envelope
	// names, which is not necessarily the active one — a retired KEK still opens what it
	// sealed. The trailing string is that kek_version.
	RouteForUnwrap(context.Context, string, string, string) (registry.Route, error)
	Digest() string
}

type Policy interface {
	Evaluate(context.Context, policy.Request) policy.Decision
}

type Auditor interface {
	Record(context.Context, audit.Draft, bool) error
}

type Runner interface {
	Run(context.Context, func(context.Context) error) error
}

// Hardware is the only interface allowed to touch device middleware. Backend
// implementations receive a server-selected binding, never client slot data.
type Hardware interface {
	Execute(context.Context, registry.Route, string, string, string, []byte, []byte) ([]byte, string, error)
}

type Coordinator struct {
	authorizer       Authorizer
	router           Router
	policy           Policy
	audit            Auditor
	runner           Runner
	hardware         Hardware
	policyDigest     string
	approvers        *approval.KeySet
	authorizerDigest string
	now              func() time.Time

	// droppedMu guards droppedRecords, which Execute writes from concurrent request
	// goroutines and the metrics handler reads.
	droppedMu      sync.Mutex
	droppedRecords map[string]uint64
}

// New constructs a Coordinator. It returns an error (not a panic) when any
// required dependency is nil or the authorizer reports an empty digest; the
// caller decides whether that error is fatal. Capturing the authorizer digest
// here, after the nil check, keeps a misconfigured Authorizer a handled
// startup failure rather than a constructor-time panic — a panic would be
// fail-unpredictable, while a returned error is fail-closed and the daemon's
// usual startup path will surface it.
//
// The empty-digest refusal is duplicated in Execute: a future code path that
// builds a Coordinator some other way must not be able to start with an
// authorizer that has no digest to stamp onto its drafts.
// approvers may be nil: a deployment with no dual-control policy configures no key set.
// A nil set verifies nothing and counts nobody, so RequiredApprovals stays unsatisfiable
// exactly as it is today. That is the safe direction, and it is why this is not a required
// dependency -- making it one would stop every existing deployment from starting in order
// to enable a feature none of them use.
func New(authorizer Authorizer, router Router, semantic Policy, recorder Auditor, runner Runner, hardware Hardware, policyDigest string, approvers *approval.KeySet, now func() time.Time) (*Coordinator, error) {
	if authorizer == nil || router == nil || semantic == nil || recorder == nil || runner == nil || hardware == nil || now == nil || policyDigest == "" {
		return nil, errors.New("operations: required dependency is missing")
	}
	digest := authorizer.Digest()
	if digest == "" {
		return nil, errors.New("operations: authorizer reports an empty digest")
	}
	return &Coordinator{authorizer: authorizer, router: router, policy: semantic, audit: recorder, runner: runner, hardware: hardware, policyDigest: policyDigest, authorizerDigest: digest, approvers: approvers, now: now}, nil
}

func (coordinator *Coordinator) Execute(ctx context.Context, request api.Request) (api.Result, error) {
	if coordinator == nil || coordinator.authorizer == nil || coordinator.router == nil || coordinator.policy == nil ||
		coordinator.audit == nil || coordinator.runner == nil || coordinator.hardware == nil || coordinator.now == nil ||
		coordinator.policyDigest == "" || coordinator.authorizerDigest == "" {
		return api.Result{}, failure("DEPENDENCY_UNAVAILABLE", http.StatusServiceUnavailable, true)
	}
	started := coordinator.now()
	if !coordinator.authorizer.Allowed(request.Principal, request.ObjectID, request.Operation, request.Context.Environment) {
		coordinator.recordOrCount(ctx, request, registry.Route{}, "deny", "rbac-denied", started, false, nil)
		return api.Result{}, failure("DENIED", http.StatusForbidden, false)
	}
	// Seal routes differently: RouteForSeal admits standby and qualified bindings, because an
	// envelope sealed today must open after tomorrow's rotation. Release routes differently
	// again: it must reach the KEK the envelope names, which after a rotation is not the active
	// one. Everything else takes the currently-serving route.
	var route registry.Route
	var err error
	switch request.Operation {
	case "seal-envelope":
		route, err = coordinator.router.RouteForSeal(ctx, request.ObjectID, request.Context.Purpose)
	case "release-secret":
		// The envelope is parsed here only to learn which KEK generation it claims. Its contents
		// are not trusted on the strength of this — the releaser parses it again and checks it
		// properly, and the unwrap fails unless the wrapped key really does unwrap under the key
		// in the slot this selects.
		//
		// A MALFORMED ENVELOPE IS A 400, NOT A ROUTING DENIAL. Reporting it as DENIED would tell
		// a caller with a corrupt envelope that they lack authorization, sending them to an
		// operator to widen a policy that was never the problem.
		var claimed envelope.KeyRef
		var sealedAt time.Time
		claimed, sealedAt, err = envelope.Peek(request.Data)
		if err != nil {
			coordinator.recordOrCount(ctx, request, registry.Route{}, "deny", "malformed-envelope", started, false, nil)
			return api.Result{}, failure("INVALID_ARGUMENT", http.StatusBadRequest, false)
		}
		route, err = coordinator.router.RouteForUnwrap(ctx, request.ObjectID, request.Context.Purpose, claimed.Version)
		if err == nil {
			// AN ENVELOPE OLDER THAN ITS OBJECT ALLOWS IS REFUSED, AND THE REFUSAL IS NAMED.
			//
			// created_at was authenticated and compared to nothing, so an envelope sealed years
			// ago released exactly like one sealed this morning -- the "bounded by lifetime" half
			// of #6 held only for the plaintext in memory, never for the ciphertext at rest.
			//
			// Checked AFTER routing on purpose: the bound belongs to the object, and until the
			// route resolves there is nothing to read it from. A caller cannot dodge it by naming
			// a generation, because an unroutable generation is already denied above.
			//
			// Recorded as its own outcome rather than folded into "routing-denied". An operator
			// woken by a release that stopped working needs to see that the envelope aged out --
			// which is fixed by re-sealing it -- and not go looking through RBAC for a grant
			// nobody removed.
			if route.EnvelopeMaxAge > 0 && coordinator.now().Sub(sealedAt) > route.EnvelopeMaxAge {
				coordinator.recordOrCount(ctx, request, route, "deny", "envelope-expired", started, false, nil)
				return api.Result{}, failure("DENIED", http.StatusForbidden, false)
			}
		}
	default:
		route, err = coordinator.router.Route(ctx, request.ObjectID, request.Context.Purpose, request.Operation)
	}
	if err != nil {
		// THE CALLER LEARNED WHICH OF THREE THINGS HAPPENED AND THE AUDIT DID NOT.
		//
		// This returned DENIED, NOT_FOUND or a retryable BACKEND_UNAVAILABLE, and then recorded
		// the single outcome "routing-denied" for all of them. So an unreachable HSM and a policy
		// refusal were byte-identical in the trail: same decision, same outcome, nothing else in
		// the event to separate them. An operator cannot count availability incidents, a spike of
		// denials caused by a dead card reads as an authorization problem, and real denials are
		// diluted by outage noise.
		//
		// This is the argument the envelope-expired branch above already makes -- an operator
		// woken by a failure needs to see which failure -- one branch further up and not applied.
		code, status, retryable := "DENIED", http.StatusForbidden, false
		outcome := "routing-denied"
		if registry.IsCode(err, registry.CodeNotFound) {
			code, status = "NOT_FOUND", http.StatusNotFound
			outcome = "routing-object-unknown"
		} else if registry.IsCode(err, registry.CodeDependencyUnavailable) {
			code, status, retryable = "BACKEND_UNAVAILABLE", http.StatusServiceUnavailable, true
			outcome = "routing-backend-unavailable"
		} else if registry.RefusalReason(err) == registry.ReasonRevoked {
			// #160: a release refused because the matched KEK generation is in state `revoked`
			// is data loss by deliberate operator decision, not a routing failure. The HTTP code
			// stays 403 (non-retryable: the state change is permanent), but the audit record names
			// the cause so the responder at 3am reads `denied-kek-revoked`, sees what the runbook
			// says happens next, and does not start widening RBAC grants.
			outcome = "denied-kek-revoked"
		}
		coordinator.recordOrCount(ctx, request, registry.Route{}, "deny", outcome, started, false, nil)
		return api.Result{}, failure(code, status, retryable)
	}
	contentType := request.ContentType
	if contentType == "" {
		contentType = DataKeyContentType
	}
	policyRequest := policy.Request{
		RequestID: request.RequestID, Principal: request.Principal, ObjectID: request.ObjectID,
		Purpose: request.Context.Purpose, Environment: request.Context.Environment, Operation: request.Operation,
		Algorithm: route.Algorithm, ContentType: contentType, PayloadBytes: payloadBytes(request),
		ExpiresAt: request.Context.ExpiresAt, Nonce: request.Context.Nonce,
	}
	// THE APPROVERS ARE VERIFIED HERE, NOT ASSERTED BY THE CALLER.
	//
	// request.Approvals is the raw header: attacker-controlled bytes. Verify returns only
	// the identities whose ed25519 signature over this exact request holds against the
	// operator-managed key set, deduplicated -- so two signatures from one key satisfy
	// RequiredApprovals: 1 and never 2. Evidence that fails any check is not an error; it
	// is simply not an approver, because rejecting the request on bad evidence would let
	// anyone who can reach the endpoint deny a valid request by appending garbage.
	policyRequest.VerifiedApprovers = coordinator.approvers.Verify(request.Approvals, approval.Binding{
		ObjectID: request.ObjectID, Purpose: request.Context.Purpose,
		Environment: request.Context.Environment, Nonce: request.Context.Nonce,
		ExpiresAt: request.Context.ExpiresAt, Payload: approvalPayload(request),
	})
	if contentType == "application/vnd.cosmos.tx+protobuf" {
		parsed, err := policy.ParseCosmosSignDoc(request.Data)
		if err != nil {
			coordinator.recordOrCount(ctx, request, route, "deny", "policy-cosmos-malformed", started, false, policyRequest.VerifiedApprovers)
			return api.Result{}, failure("INVALID_ARGUMENT", http.StatusBadRequest, false)
		}
		policyRequest.Cosmos = parsed
	}
	decision := coordinator.policy.Evaluate(ctx, policyRequest)
	if !decision.Allowed {
		// RECORD WHICH RULE, NOT ONLY THAT POLICY SAID NO.
		//
		// Decision.Rule names the specific rule that fired — replay, quota, durable-state,
		// unknown-object, invalid-context and the rest. It is set at every decision site in the
		// policy engine and, until now, read at none: the audit reason was "policy-" plus the
		// CODE, so every distinct denial reason collapsed into policy-DENIED.
		//
		// "Policy denied it" is not an answer anybody can act on. The engine already knew which
		// rule, and threw it away one line before it would have been recorded.
		coordinator.recordOrCount(ctx, request, route, "deny", policyReason(decision), started, false, policyRequest.VerifiedApprovers)
		code, status, retryable := "DENIED", http.StatusForbidden, false
		if decision.Code == policy.CodeStateUnavailable {
			code, status, retryable = "DEPENDENCY_UNAVAILABLE", http.StatusServiceUnavailable, true
		} else if decision.Code == policy.CodeReplay {
			code, status = "CONFLICT", http.StatusConflict
		} else if decision.Code == policy.CodeLimitExceeded {
			code, status, retryable = "RESOURCE_EXHAUSTED", http.StatusTooManyRequests, true
		}
		return api.Result{}, failure(code, status, retryable)
	}
	if err := coordinator.record(ctx, request, route, "allow", "authorized", started, true, policyRequest.VerifiedApprovers); err != nil {
		return api.Result{}, failure("DEPENDENCY_UNAVAILABLE", http.StatusServiceUnavailable, true)
	}
	var output []byte
	var outputType string
	err = coordinator.runner.Run(ctx, func(operationCtx context.Context) error {
		if request.Operation == "seal-envelope" {
			output, outputType, err = coordinator.seal(operationCtx, route, request)
			return err
		}
		var backendErr error
		data := request.Data
		if contentType == "application/vnd.cosmos.tx+protobuf" {
			digest := sha256.Sum256(data)
			data = digest[:]
		}
		output, outputType, backendErr = coordinator.hardware.Execute(operationCtx, route, request.Operation, request.Format, contentType, data, request.EnvelopeAAD)
		return backendErr
	})
	if err != nil {
		zero(output)
		// An integrity failure is the caller's bytes failing the AEAD proof — a 400, not a
		// backend fault; the distinction is what tells tampering apart from an outage.
		//
		// AND THE TRAIL HAS TO CARRY THAT DISTINCTION, NOT JUST THE RESPONSE. Both of these were
		// recorded as "failure", so a tampered envelope and an unreachable card produced the same
		// audit event in a system whose purpose is a tamper-evident record. Ciphertext failing its
		// AEAD proof is a security event someone should see as one; a backend fault is an
		// availability event. They are not the same thing to anyone reading this trail afterwards.
		if errors.Is(err, envelope.ErrInvalidEnvelope) {
			coordinator.recordOrCount(ctx, request, route, "allow", "integrity-failed", started, true, policyRequest.VerifiedApprovers)
			return api.Result{}, failure("INVALID_ARGUMENT", http.StatusBadRequest, false)
		}
		coordinator.recordOrCount(ctx, request, route, "allow", "backend-failed", started, true, policyRequest.VerifiedApprovers)
		return api.Result{}, classifyExecution(err)
	}
	if len(output) == 0 || outputType == "" {
		zero(output)
		// Neither the caller's fault nor the card's: the operation reported success and produced
		// nothing. Recorded as its own outcome because it is a defect in this daemon, and one
		// indistinguishable from an outage if it is filed under the same word.
		coordinator.recordOrCount(ctx, request, route, "allow", "empty-output", started, true, policyRequest.VerifiedApprovers)
		return api.Result{}, failure("INTERNAL", http.StatusInternalServerError, false)
	}
	if err := coordinator.record(ctx, request, route, "allow", "success", started, true, policyRequest.VerifiedApprovers); err != nil {
		zero(output)
		return api.Result{}, failure("DEPENDENCY_UNAVAILABLE", http.StatusServiceUnavailable, true)
	}
	operationID, err := randomID()
	if err != nil {
		zero(output)
		return api.Result{}, failure("INTERNAL", http.StatusInternalServerError, false)
	}
	return api.Result{OperationID: operationID, ContentType: outputType, Data: output}, nil
}

// approvers is the set the policy engine was actually given, passed in rather than
// re-derived here. Verifying a second time would put the same rule in two places and let
// the journal disagree with the decision it is supposed to record -- the audit would say
// who approved while the engine counted someone else.
// recordOrCount writes an audit record and, when the write fails, counts the drop instead of
// discarding the error. It replaces nine `_ = coordinator.record(...)` sites (#279).
//
// THE NINE DISCARDS ARE CORRECT AND STAY. The rule is output release, not deny-versus-allow --
// three `allow` paths discard too. The two sites that DO check gate bytes reaching the caller: the
// pre-operation `authorized` record refuses before the card is touched, and the post-operation
// `success` record zeroes the output. Every site below already returns an error, so a failed record
// here cannot produce an unrecorded release. Making them fail closed would convert an audit-sink
// outage into a denial of service on the refusal path and buy no integrity.
//
// WHAT WAS ACTUALLY WRONG IS THAT THE DROP WAS INVISIBLE. `Recorder.Record` advances its sequence
// only after Write and Sync both succeed, so a failed record leaves NO gap: the next event reuses
// the number, the hash chain stays valid, verification passes, and not one of the existing
// regalia_audit_* series moves -- every one of them describes events that reached the journal. A
// tamper-evident record cannot show an event that was never appended. So degrading the sink and
// then probing costs an attacker nothing: the refusals still happen, and the record of having
// probed does not exist. Counting the drop is what turns that into something an operator can alert
// on, without changing what the daemon does.
//
// Counted here rather than at the nine sites so the behaviour cannot drift apart between them.
func (coordinator *Coordinator) recordOrCount(ctx context.Context, request api.Request, route registry.Route, decision, outcome string, started time.Time, requireRemote bool, approvers []string) {
	// NOT EVERY ERROR IS A LOST RECORD. Record advances its sequence only after Write and Sync
	// both succeed, and three of its failure returns come after that: the high-water-mark write,
	// the no-shipper case under requireRemote, and a remote acknowledgement that does not arrive.
	// In all three the event is on disk and ships when the collector recovers -- the operation
	// still fails closed, but nothing was lost. Counting those would make this metric measure
	// collector latency and call it data loss, and three of the sites below pass requireRemote,
	// so it is reachable rather than theoretical. Raised in review on #315.
	if err := coordinator.record(ctx, request, route, decision, outcome, started, requireRemote, approvers); err != nil && !audit.Durable(err) {
		coordinator.droppedMu.Lock()
		if coordinator.droppedRecords == nil {
			coordinator.droppedRecords = make(map[string]uint64)
		}
		coordinator.droppedRecords[outcome]++
		coordinator.droppedMu.Unlock()
	}
}

// DroppedAuditRecords reports audit writes that never reached the journal, keyed by the outcome
// that was lost. Errors returned after the event became durable are excluded -- see audit.Durable.
//
// LABELLED BY OUTCOME, and the cardinality is bounded by construction rather than by hope: every
// value is a compile-time literal. Seven are fixed strings at the call sites, four come from the
// routing branch, and the policy reasons are `policy-<Code>:<Rule>` where Code is one of five
// constants and Rule one of twelve, all of them literals in internal/policy. None derives from
// request data, configuration, or anything a caller controls -- which is the property that makes an
// outcome label safe here and would not survive a rule name read from an operator's policy file.
//
// A copy, because the caller is the metrics handler on another goroutine.
func (coordinator *Coordinator) DroppedAuditRecords() map[string]uint64 {
	coordinator.droppedMu.Lock()
	defer coordinator.droppedMu.Unlock()
	dropped := make(map[string]uint64, len(coordinator.droppedRecords))
	for outcome, count := range coordinator.droppedRecords {
		dropped[outcome] = count
	}
	return dropped
}

func (coordinator *Coordinator) record(ctx context.Context, request api.Request, route registry.Route, decision, outcome string, started time.Time, requireRemote bool, approvers []string) error {
	return coordinator.audit.Record(ctx, audit.Draft{
		Timestamp: coordinator.now(), RequestID: request.RequestID, Principal: request.Principal,
		Decision: decision, ObjectID: request.ObjectID, Purpose: request.Context.Purpose,
		Operation: request.Operation, DeviceID: route.Binding.DeviceID, Outcome: outcome,
		LatencyMilliseconds: max(coordinator.now().Sub(started).Milliseconds(), 0),
		RegistryDigest:      coordinator.router.Digest(), PolicyDigest: coordinator.policyDigest,
		RBACDigest: coordinator.authorizerDigest, VerifiedApprovers: approvers,
	}, requireRemote)
}

// payloadBytes measures what policy's payload cap should govern: the ciphertext for a
// seal, the payload otherwise. Seal carries no Data — its three parts are sized at the
// boundary already, and the cap belongs on the bytes that actually arrived.
func payloadBytes(request api.Request) int64 {
	if request.Operation == "seal-envelope" {
		return int64(len(request.SealCiphertext))
	}
	return int64(len(request.Data))
}

// approvalPayload is the bytes an approver's signature commits to.
//
// THIS MUST BE ASKED OF EVERY OPERATION, NOT ASSUMED TO BE Request.Data.
//
// It was `request.Data` directly, which is correct for the five operations whose body arrives
// there and silently wrong for seal-envelope, whose parts arrive in their own fields: Data is
// empty for a seal, so every seal-envelope approval committed to sha256 of nothing and an
// approval issued for one ciphertext counted for any other under the same object, context and
// nonce. The approver believed they had approved sealing particular bytes and had approved
// sealing anything. Answering it here, beside payloadBytes, is what makes the next operation
// with a differently-named body a visible omission rather than a silent one.
//
// THE DATA KEY IS DELIBERATELY EXCLUDED. An approver has to be able to compute this digest to
// sign it, so everything named here is something they must be shown. Ciphertext and nonce are
// ciphertext. The data key is the secret being wrapped, and requiring an approver to hold it in
// order to authorise the wrap would defeat the point of wrapping it. Substituting the data key
// alone produces an envelope that opens to nothing -- it forges no content and spends the
// single-use nonce doing it -- so the exposure it leaves is not one worth showing the key to
// close.
func approvalPayload(request api.Request) []byte {
	if request.Operation != "seal-envelope" {
		return request.Data
	}
	// Length-framed, so that a nonce and ciphertext boundary cannot be shifted to produce the
	// same digest from different parts.
	payload := make([]byte, 0, 8+len(request.SealNonce)+len(request.SealCiphertext))
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(request.SealNonce)))
	payload = append(payload, length[:]...)
	payload = append(payload, request.SealNonce...)
	return append(payload, request.SealCiphertext...)
}

// seal assembles an envelope the KMS can later release. The KEK identity and the
// binding context are the SERVER's, taken from the route: the envelope's account of
// what protects it is checked against the manifest, not asserted by the caller, and
// the context digest is derived by the one function the release path uses.
func (coordinator *Coordinator) seal(ctx context.Context, route registry.Route, request api.Request) ([]byte, string, error) {
	wrapper, err := secrets.NewSealWrapper(coordinator.hardware, route)
	if err != nil {
		zero(request.SealDataKey)
		return nil, "", err
	}
	sealed, err := envelope.SealAssembled(ctx, wrapper,
		envelope.KeyRef{Backend: route.Binding.Backend, ID: route.ObjectID, Version: route.KEKVersion},
		route.ObjectID, envelope.ReleaseContext(route.ObjectID, route.Purpose, route.Environment),
		request.SealCiphertext, request.SealNonce, request.SealDataKey, coordinator.now())
	// SealAssembled zeroes the caller's data key on every path; the ciphertext and nonce
	// are not secret and are copied, not referenced.
	if err != nil {
		return nil, "", err
	}
	encoded, err := sealed.Marshal()
	if err != nil {
		return nil, "", err
	}
	return encoded, "application/vnd.regalia.envelope", nil
}

func classifyExecution(err error) error {
	var executionError *executor.Error
	if errors.As(err, &executionError) {
		status := http.StatusInternalServerError
		if executionError.Code == executor.CodeBusy {
			status = http.StatusTooManyRequests
		} else if executionError.Code == executor.CodeTimeout || executionError.Code == executor.CodeCanceled {
			status = http.StatusGatewayTimeout
		}
		return failure(string(executionError.Code), status, executionError.Retryable)
	}
	return failure("BACKEND_UNAVAILABLE", http.StatusServiceUnavailable, true)
}

func failure(code string, status int, retryable bool) error {
	return &api.Failure{Code: code, Status: status, Retryable: retryable}
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[0:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:32], nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// policyReason renders a denial as its code and the rule that produced it. The code stays first
// because it is the stable enum clients match on; the rule follows because it is what a reviewer
// reading the trail actually needs.
func policyReason(decision policy.Decision) string {
	reason := "policy-" + string(decision.Code)
	if decision.Rule != "" {
		reason += ":" + decision.Rule
	}
	return reason
}
