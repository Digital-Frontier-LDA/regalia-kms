// Package policy evaluates server-owned, purpose-bound rules before any
// hardware operation is invoked.
package policy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"
)

var (
	ErrReplay   = errors.New("request nonce already reserved")
	ErrLimit    = errors.New("durable quota exceeded")
	ErrSequence = errors.New("Cosmos account sequence is not the next expected value")
	// ErrEpoch is the stale-leader refusal (#428): a reservation whose fencing epoch is
	// below the highest the journal has already recorded comes from a site that was
	// promoted away from. The quota is a GLOBAL budget on one journal, so a leader that
	// was replaced mid-window must not keep spending from it.
	ErrEpoch     = errors.New("stale fencing epoch")
	noncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

type Code string

const (
	CodeAllowed          Code = "ALLOWED"
	CodeDenied           Code = "DENIED"
	CodeReplay           Code = "REPLAY"
	CodeLimitExceeded    Code = "LIMIT_EXCEEDED"
	CodeStateUnavailable Code = "STATE_UNAVAILABLE"
)

type Coin struct {
	Denom  string
	Amount uint64
}

type CosmosMessage struct {
	Type        string
	Source      string
	Destination string
	Amounts     []Coin
}

// CosmosTransaction must be produced by a trusted parser from the complete
// canonical sign bytes. It must never be populated from client assertions.
type CosmosTransaction struct {
	ChainID       string
	AccountNumber uint64
	Sequence      uint64
	Fee           []Coin
	GasLimit      uint64
	Messages      []CosmosMessage
}

type CosmosPolicy struct {
	ChainIDs          []string
	AccountNumbers    []uint64
	MessageTypes      []string
	Destinations      []string
	Sources           []string
	MaxGasLimit       uint64
	MaxFee            map[string]uint64
	MaxPerTransaction map[string]uint64
	MaxPerDay         map[string]uint64
}

type Policy struct {
	ID                string
	ObjectID          string
	Purpose           string
	Environment       string
	Operation         string
	Algorithm         string
	ContentTypes      []string
	MaxPayloadBytes   int64
	MaxFuture         time.Duration
	RequiredApprovals int
	Approvers         []string
	Cosmos            *CosmosPolicy
}

type Request struct {
	RequestID         string
	Principal         string
	ObjectID          string
	Purpose           string
	Environment       string
	Operation         string
	Algorithm         string
	ContentType       string
	PayloadBytes      int64
	ExpiresAt         time.Time
	Nonce             string
	VerifiedApprovers []string
	Cosmos            *CosmosTransaction
}

type Reservation struct {
	PolicyID string `json:"policy_id"`
	ObjectID string `json:"object_id"`
	// Epoch is the fencing lease epoch the site held when it made this reservation.
	// omitempty is load-bearing, not cosmetic: the field is part of the hashed event
	// bytes, so epoch-0 (unfenced) reservations must marshal exactly as pre-epoch
	// journals did or every existing journal stops verifying at the next open — the
	// RBACDigest lesson, applied at the field's birth rather than after the breakage.
	Epoch       uint64            `json:"epoch,omitempty"`
	Principal   string            `json:"principal"`
	Nonce       string            `json:"nonce"`
	UTCDate     string            `json:"utc_date"`
	Amounts     map[string]uint64 `json:"amounts"`
	DailyCaps   map[string]uint64 `json:"daily_caps"`
	Sequence    *uint64           `json:"sequence,omitempty"`
	SequenceKey string            `json:"sequence_key,omitempty"`
}

type State interface {
	// Reserve atomically consumes the nonce and quota before hardware use. It
	// must durably commit before returning nil.
	Reserve(context.Context, Reservation) error
}

type readyState interface {
	Ready(context.Context) bool
}

type Decision struct {
	Allowed  bool
	Code     Code
	PolicyID string
	Rule     string
}

type Engine struct {
	policies map[string]compiledPolicy
	state    State
	now      func() time.Time
	// epochSource names the fencing lease epoch this site currently holds, read PER
	// reservation: failover changes the epoch under a running daemon, and a value
	// captured at construction would stamp the old epoch onto the new leader's first
	// reservation. Nil means unfenced, which stamps 0.
	epochSource func() uint64
	// quotaRejections counts limit-exceeded decisions only: it is the operator's
	// "a workload hit its cap" signal, and counting any other denial class would
	// make it indistinguishable from the noise those classes already raise.
	quotaRejections atomic.Uint64
}

// QuotaRejections reports how many operations have been refused for exceeding a
// daily cap since the engine started.
func (engine *Engine) QuotaRejections() uint64 {
	if engine == nil {
		return 0
	}
	return engine.quotaRejections.Load()
}

type compiledPolicy struct {
	policy       Policy
	contentTypes map[string]struct{}
	approvers    map[string]struct{}
	chains       map[string]struct{}
	accounts     map[uint64]struct{}
	messages     map[string]struct{}
	destinations map[string]struct{}
	sources      map[string]struct{}
}

func New(policies []Policy, state State, now func() time.Time) (*Engine, error) {
	if len(policies) == 0 || state == nil || now == nil {
		return nil, errors.New("policy engine requires policies, durable state and a clock")
	}
	engine := &Engine{policies: make(map[string]compiledPolicy, len(policies)), state: state, now: now}
	seenIDs := make(map[string]struct{}, len(policies))
	for _, policy := range policies {
		if policy.ID == "" || policy.ObjectID == "" || policy.Purpose == "" || policy.Environment == "" ||
			policy.Operation == "" || policy.Algorithm == "" || policy.MaxPayloadBytes < 1 || policy.MaxFuture <= 0 {
			return nil, errors.New("policy contains an empty or unsafe required field")
		}
		if _, exists := seenIDs[policy.ID]; exists {
			return nil, fmt.Errorf("duplicate policy id %q", policy.ID)
		}
		key := policyKey(policy.ObjectID, policy.Operation)
		if _, exists := engine.policies[key]; exists {
			return nil, fmt.Errorf("object %q has ambiguous %s policies", policy.ObjectID, policy.Operation)
		}
		seenIDs[policy.ID] = struct{}{}
		compiled := compiledPolicy{
			policy: policy, contentTypes: stringSet(policy.ContentTypes), approvers: stringSet(policy.Approvers),
		}
		if len(compiled.contentTypes) != len(policy.ContentTypes) || len(policy.ContentTypes) == 0 ||
			len(compiled.approvers) != len(policy.Approvers) || policy.RequiredApprovals < 0 || policy.RequiredApprovals > len(compiled.approvers) {
			return nil, errors.New("policy lists are empty, duplicated or inconsistent")
		}
		if policy.Cosmos != nil {
			if _, generic := compiled.contentTypes["application/octet-stream"]; generic {
				return nil, errors.New("Cosmos policy cannot allow opaque content")
			}
			if _, canonical := compiled.contentTypes["application/vnd.cosmos.tx+protobuf"]; !canonical {
				return nil, errors.New("Cosmos policy requires canonical protobuf content")
			}
			compiled.chains = stringSet(policy.Cosmos.ChainIDs)
			compiled.accounts = uintSet(policy.Cosmos.AccountNumbers)
			compiled.messages = stringSet(policy.Cosmos.MessageTypes)
			compiled.destinations = stringSet(policy.Cosmos.Destinations)
			compiled.sources = stringSet(policy.Cosmos.Sources)
			if len(compiled.chains) == 0 || len(compiled.accounts) == 0 || len(compiled.messages) == 0 || len(compiled.destinations) == 0 || len(compiled.sources) == 0 ||
				policy.Cosmos.MaxGasLimit == 0 || len(policy.Cosmos.MaxFee) == 0 || len(policy.Cosmos.MaxPerTransaction) == 0 || len(policy.Cosmos.MaxPerDay) == 0 {
				return nil, errors.New("Cosmos policy dimensions must be explicit")
			}
			if len(compiled.chains) != len(policy.Cosmos.ChainIDs) || len(compiled.accounts) != len(policy.Cosmos.AccountNumbers) ||
				len(compiled.messages) != len(policy.Cosmos.MessageTypes) || len(compiled.destinations) != len(policy.Cosmos.Destinations) || len(compiled.sources) != len(policy.Cosmos.Sources) {
				return nil, errors.New("Cosmos policy dimensions must not contain duplicates or wildcards")
			}
			for denom, transactionCap := range policy.Cosmos.MaxPerTransaction {
				dailyCap, exists := policy.Cosmos.MaxPerDay[denom]
				if denom == "" || transactionCap == 0 || !exists || dailyCap < transactionCap {
					return nil, errors.New("Cosmos denomination caps are incomplete or inconsistent")
				}
			}
			for denom, feeCap := range policy.Cosmos.MaxFee {
				if denom == "" || feeCap == 0 {
					return nil, errors.New("Cosmos fee caps are incomplete")
				}
			}
			if len(policy.Cosmos.MaxPerTransaction) != len(policy.Cosmos.MaxPerDay) {
				return nil, errors.New("Cosmos daily and transaction denominations must match")
			}
		}
		engine.policies[key] = compiled
	}
	return engine, nil
}

func (engine *Engine) Ready(ctx context.Context) bool {
	if engine == nil || len(engine.policies) == 0 {
		return false
	}
	state, ok := engine.state.(readyState)
	return ok && state.Ready(ctx)
}

// GoverningPolicyID reports the id of the policy that would actually be applied to an operation on
// an object, or false when none exists. The daemon uses it to check the custody manifest's declared
// policy_id against the policy that is really enforced.
func (engine *Engine) GoverningPolicyID(objectID, operation string) (string, bool) {
	if engine == nil {
		return "", false
	}
	compiled, exists := engine.policies[policyKey(objectID, operation)]
	if !exists {
		return "", false
	}
	return compiled.policy.ID, true
}

func (engine *Engine) Evaluate(ctx context.Context, request Request) Decision {
	policy, exists := engine.policies[policyKey(request.ObjectID, request.Operation)]
	if !exists {
		return denied("unknown-object")
	}
	decision := Decision{PolicyID: policy.policy.ID}
	if request.Principal == "" || request.RequestID == "" || !noncePattern.MatchString(request.Nonce) {
		return decision.deny("invalid-context")
	}
	if request.Purpose != policy.policy.Purpose || request.Environment != policy.policy.Environment ||
		request.Operation != policy.policy.Operation || request.Algorithm != policy.policy.Algorithm {
		return decision.deny("binding-mismatch")
	}
	if _, ok := policy.contentTypes[request.ContentType]; !ok || request.PayloadBytes < 0 || request.PayloadBytes > policy.policy.MaxPayloadBytes {
		return decision.deny("content")
	}
	now := engine.now().UTC()
	if !request.ExpiresAt.After(now) || request.ExpiresAt.After(now.Add(policy.policy.MaxFuture)) {
		return decision.deny("freshness")
	}
	if !policy.approvalsSatisfied(request.VerifiedApprovers) {
		return decision.deny("approval")
	}
	amounts := map[string]uint64{}
	if policy.policy.Cosmos != nil {
		var valid bool
		amounts, valid = policy.validateCosmos(request.Cosmos)
		if !valid {
			return decision.deny("cosmos")
		}
	} else if request.Cosmos != nil {
		return decision.deny("unexpected-domain-data")
	}
	var sequence *uint64
	if request.Cosmos != nil {
		value := request.Cosmos.Sequence
		sequence = &value
	}
	sequenceKey := ""
	if request.Cosmos != nil {
		sequenceKey = request.Cosmos.ChainID + "\x00" + strconv.FormatUint(request.Cosmos.AccountNumber, 10)
	}
	err := engine.state.Reserve(ctx, Reservation{
		PolicyID: policy.policy.ID, ObjectID: request.ObjectID, Principal: request.Principal,
		Nonce: request.Nonce, UTCDate: now.Format(utcDateLayout), Amounts: amounts,
		Epoch:       engine.currentEpoch(),
		Sequence:    sequence,
		SequenceKey: sequenceKey,
		DailyCaps:   cloneAmounts(policy.dailyCaps()),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrReplay):
			return Decision{Code: CodeReplay, PolicyID: policy.policy.ID, Rule: "replay"}
		case errors.Is(err, ErrLimit):
			engine.quotaRejections.Add(1)
			return Decision{Code: CodeLimitExceeded, PolicyID: policy.policy.ID, Rule: "quota"}
		case errors.Is(err, ErrEpoch):
			return Decision{Code: CodeDenied, PolicyID: policy.policy.ID, Rule: "epoch"}
		case errors.Is(err, ErrSequence):
			return Decision{Code: CodeDenied, PolicyID: policy.policy.ID, Rule: "sequence"}
		default:
			return Decision{Code: CodeStateUnavailable, PolicyID: policy.policy.ID, Rule: "durable-state"}
		}
	}
	return Decision{Allowed: true, Code: CodeAllowed, PolicyID: policy.policy.ID, Rule: "allow"}
}

// SetEpochSource binds the fencing epoch the daemon stamps into every reservation. It is
// set after construction because the standby the epoch comes from is built later in the
// daemon's startup than the engine is. Calling it twice or after serving starts is a
// wiring error the daemon does not make; the engine does not defend against it.
func (engine *Engine) SetEpochSource(source func() uint64) {
	engine.epochSource = source
}

func (engine *Engine) currentEpoch() uint64 {
	if engine.epochSource == nil {
		return 0
	}
	return engine.epochSource()
}

func policyKey(objectID, operation string) string { return objectID + "\x00" + operation }

func (policy compiledPolicy) approvalsSatisfied(values []string) bool {
	if policy.policy.RequiredApprovals == 0 {
		return true
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, allowed := policy.approvers[value]; allowed {
			seen[value] = struct{}{}
		}
	}
	return len(seen) >= policy.policy.RequiredApprovals
}

func (policy compiledPolicy) validateCosmos(transaction *CosmosTransaction) (map[string]uint64, bool) {
	if transaction == nil || len(transaction.Messages) == 0 {
		return nil, false
	}
	if _, ok := policy.chains[transaction.ChainID]; !ok {
		return nil, false
	}
	if _, ok := policy.accounts[transaction.AccountNumber]; !ok {
		return nil, false
	}
	totals := make(map[string]uint64)
	for _, message := range transaction.Messages {
		if _, ok := policy.messages[message.Type]; !ok || len(message.Amounts) == 0 {
			return nil, false
		}
		if _, ok := policy.destinations[message.Destination]; !ok {
			return nil, false
		}
		if _, ok := policy.sources[message.Source]; !ok {
			return nil, false
		}
		for _, coin := range message.Amounts {
			maximum, known := policy.policy.Cosmos.MaxPerTransaction[coin.Denom]
			if !known || coin.Amount == 0 || coin.Amount > maximum || ^uint64(0)-totals[coin.Denom] < coin.Amount {
				return nil, false
			}
			totals[coin.Denom] += coin.Amount
			if totals[coin.Denom] > maximum {
				return nil, false
			}
		}
	}
	if transaction.GasLimit == 0 || transaction.GasLimit > policy.policy.Cosmos.MaxGasLimit {
		return nil, false
	}
	feeTotals := make(map[string]uint64)
	for _, coin := range transaction.Fee {
		maximum, known := policy.policy.Cosmos.MaxFee[coin.Denom]
		if !known || coin.Amount == 0 || ^uint64(0)-feeTotals[coin.Denom] < coin.Amount {
			return nil, false
		}
		feeTotals[coin.Denom] += coin.Amount
		if feeTotals[coin.Denom] > maximum {
			return nil, false
		}
	}
	return totals, true
}

func (policy compiledPolicy) dailyCaps() map[string]uint64 {
	if policy.policy.Cosmos == nil {
		return map[string]uint64{}
	}
	return policy.policy.Cosmos.MaxPerDay
}

func denied(rule string) Decision { return Decision{Code: CodeDenied, Rule: rule} }
func (decision Decision) deny(rule string) Decision {
	decision.Code, decision.Rule = CodeDenied, rule
	return decision
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || value == "*" {
			continue
		}
		result[value] = struct{}{}
	}
	return result
}

func uintSet(values []uint64) map[uint64]struct{} {
	result := make(map[uint64]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func cloneAmounts(values map[string]uint64) map[string]uint64 {
	result := make(map[string]uint64, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}
