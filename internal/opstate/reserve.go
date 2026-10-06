package opstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
)

// EtcdState is policy.State on the operational state (ADR-0002 D32, #432): one Reserve is ONE etcd transaction,
// committed by a majority BEFORE the HSM is used, all or nothing:
//
//   - the spend: nonces/<sha256(nonce)>, created only (version 0), binding D25's facts and the ONE server that
//     signs, its lease (digest and expiry) and the request's expiry; collected by an etcd lease once expired;
//   - the sequence, when the request has one: seq/<sha256(key)>, above the value it replaces (revision compare);
//   - one quota counter per amount: quota/<sha256(principal)>/<date>/<sha256(counter)>, its running total at most
//     the cap (revision compare); collected 48 h after its day.
//
// Every entry is signed by this daemon instance's session key. A transaction that loses a race is retried with
// a fresh read at most opstate.py's RETRIES times, then refused: fail closed, one round trip each.
type EtcdState struct {
	client  *clientv3.Client
	key     *SessionKey
	node    string
	lease   func(context.Context) (digest string, expires time.Time, ok bool)
	verify  func(key string, value []byte) (map[string]any, error)
	now     func() time.Time
	mu      sync.Mutex
	buckets map[int64]clientv3.LeaseID // hour bucket end (unix) -> the etcd lease that collects keys then
}

// Retries is opstate.py's RETRIES: a lost race is read again at most this often, then refused.
const Retries = 3

// ErrContention is a Reserve that lost its race Retries times: refused, fail closed.
var ErrContention = errors.New("the operational state kept changing under this reservation: refused")

// NewEtcdState is the state for one daemon instance: its node, its session key, the lease it serves under
// (from admission: digest and expiry), and how a value read back is verified (Judge's VerifyValue, without
// the transition: the transaction's compare does that part).
func NewEtcdState(client *clientv3.Client, node string, key *SessionKey, lease func(context.Context) (string, time.Time, bool),
	verify func(key string, value []byte) (map[string]any, error), now func() time.Time) (*EtcdState, error) {
	if client == nil || key == nil || lease == nil || verify == nil || now == nil || !nodePattern.MatchString(node) {
		return nil, errors.New("opstate: the state needs a client, its node, a session key, the lease, a verifier and a clock")
	}
	return &EtcdState{client: client, key: key, node: node, lease: lease, verify: verify, now: now, buckets: map[int64]clientv3.LeaseID{}}, nil
}

// Ready: the state answers when etcd answers. The Gate judges freshness; this only says the store is there.
func (s *EtcdState) Ready(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := s.client.Get(clientv3.WithRequireLeader(ctx), Prefix+"ready", clientv3.WithCountOnly())
	return err == nil
}

type planned struct {
	key     string
	entry   map[string]any
	modRev  int64 // 0: the key must not exist
	gcUntil time.Time
}

// Reserve is policy.State.Reserve.
func (s *EtcdState) Reserve(ctx context.Context, r policy.Reservation) error {
	for attempt := 0; attempt <= Retries; attempt++ {
		done, err := s.try(ctx, r)
		if err != nil || done {
			return err
		}
	}
	return ErrContention
}

func (s *EtcdState) try(ctx context.Context, r policy.Reservation) (bool, error) {
	digest, leaseEnd, held := s.lease(ctx)
	if !held {
		return false, errors.New("no serving lease: nothing is reserved without one")
	}
	now := s.now().UTC()
	at := now.Truncate(time.Second)
	nonce := hashName(r.Nonce)
	approvers := append([]string(nil), r.Approvers...)
	sort.Strings(approvers)
	set, counted := r.ApproverSet, r.ApprovalsSHA256
	if set == "" && counted == "" && len(approvers) == 0 {
		set, counted = UngatedSet, ApprovalsDigest(nil) // a purpose no approval gates
	}
	if set == "" || counted == "" {
		return false, errors.New("the reservation names approvers but not the set and the approvals they were counted under")
	}
	spend := map[string]any{"schema": EntrySchema, "kind": "spend", "at": stamp(at), "nonce_digest": nonce, "principal": r.Principal,
		"object_id": r.ObjectID, "purpose": r.Purpose, "environment": r.Environment, "payload_sha256": r.PayloadSHA256,
		"approvers": anyList(approvers), "approver_set": set, "approvals_sha256": counted, "node_id": s.node, "boot_id": s.key.BootID, "lease_digest": digest,
		"lease_expires_at": stamp(leaseEnd.UTC().Truncate(time.Second)), "expires_at": stamp(r.ExpiresAt.UTC().Truncate(time.Second))}
	plan := []planned{{entry: spend, gcUntil: r.ExpiresAt.Add(SkewS * time.Second)}}
	if r.Sequence != nil {
		plan = append(plan, planned{entry: map[string]any{"schema": EntrySchema, "kind": "sequence", "at": stamp(at),
			"sequence_key": sequenceName(r.SequenceKey), "value": json.Number(strconv.FormatUint(*r.Sequence, 10)),
			"nonce_digest": nonce, "node_id": s.node, "boot_id": s.key.BootID}})
	}
	counters := make([]string, 0, len(r.Amounts))
	for counter := range r.Amounts {
		counters = append(counters, counter)
	}
	sort.Strings(counters)
	date, err := time.Parse("2006-01-02", r.UTCDate)
	if err != nil {
		return false, fmt.Errorf("the reservation's date %q: %w", r.UTCDate, err)
	}
	for _, counter := range counters {
		plan = append(plan, planned{entry: map[string]any{"schema": EntrySchema, "kind": "quota", "at": stamp(at),
			"principal": r.Principal, "utc_date": r.UTCDate, "counter": counter, "cap": json.Number(strconv.FormatUint(r.DailyCaps[counter], 10)),
			"nonce_digest": nonce, "node_id": s.node, "boot_id": s.key.BootID}, gcUntil: date.Add(72 * time.Hour)})
	}
	if len(plan) > MaxBatch {
		return false, fmt.Errorf("a reservation of %d entries is over the %d one transaction holds", len(plan), MaxBatch)
	}
	// read what each key holds now, in one read, at one revision
	ops := make([]clientv3.Op, 0, len(plan))
	for i := range plan {
		if plan[i].entry["kind"] == "quota" {
			plan[i].entry["total"] = json.Number("0") // the running total is set once the current one is read
		}
		key, err := KeyFor(plan[i].entry)
		if err != nil {
			return false, fmt.Errorf("the reservation makes no valid entry: %w", err)
		}
		plan[i].key = key
		ops = append(ops, clientv3.OpGet(key))
	}
	read, err := s.client.Txn(clientv3.WithRequireLeader(ctx)).Then(ops...).Commit()
	if err != nil {
		return false, fmt.Errorf("the operational state cannot be read: %w", err)
	}
	writes := make([]Write, 0, len(plan))
	for i, response := range read.Responses {
		kvs := response.GetResponseRange().Kvs
		var previous map[string]any
		if len(kvs) == 1 {
			plan[i].modRev = kvs[0].ModRevision
			if previous, err = s.verify(plan[i].key, kvs[0].Value); err != nil {
				return false, fmt.Errorf("the entry at %s does not verify: %w", plan[i].key, err)
			}
		}
		entry := plan[i].entry
		switch entry["kind"] {
		case "spend":
			if previous != nil {
				return false, policy.ErrReplay
			}
		case "sequence":
			if previous != nil {
				was, _ := strconv.ParseUint(string(previous["value"].(json.Number)), 10, 64)
				if *r.Sequence <= was {
					return false, policy.ErrReplay
				}
			}
		case "quota":
			var total uint64
			if previous != nil {
				total, _ = strconv.ParseUint(string(previous["total"].(json.Number)), 10, 64)
			}
			counter := entry["counter"].(string)
			amount, limit := r.Amounts[counter], r.DailyCaps[counter]
			if amount == 0 || total+amount > limit || total+amount < total {
				return false, policy.ErrLimit
			}
			entry["total"] = json.Number(strconv.FormatUint(total+amount, 10))
		}
		writes = append(writes, Write{Key: plan[i].key, Entry: entry, Previous: previous})
	}
	if _, err := Batch(writes); err != nil {
		return false, fmt.Errorf("the reservation is not one transaction opstate accepts: %w", err)
	}
	compares, puts := make([]clientv3.Cmp, 0, len(plan)), make([]clientv3.Op, 0, len(plan))
	for _, p := range plan {
		if p.modRev == 0 {
			compares = append(compares, clientv3.Compare(clientv3.Version(p.key), "=", 0))
		} else {
			compares = append(compares, clientv3.Compare(clientv3.ModRevision(p.key), "=", p.modRev))
		}
		value, err := s.sign(p.entry)
		if err != nil {
			return false, err
		}
		var options []clientv3.OpOption
		if !p.gcUntil.IsZero() {
			collector, err := s.collector(ctx, p.gcUntil)
			if err != nil {
				return false, err
			}
			options = append(options, clientv3.WithLease(collector))
		}
		puts = append(puts, clientv3.OpPut(p.key, string(value), options...))
	}
	committed, err := s.client.Txn(clientv3.WithRequireLeader(ctx)).If(compares...).Then(puts...).Commit()
	if err != nil {
		return false, fmt.Errorf("the reservation was not committed: %w", err)
	}
	return committed.Succeeded, nil
}

func (s *EtcdState) sign(entry map[string]any) ([]byte, error) {
	if _, _, err := ValidateEntry(entry); err != nil {
		return nil, fmt.Errorf("the reservation makes no valid entry: %w", err)
	}
	sig, err := s.key.Sign(EntryDomain, membership.Canonical(entry))
	if err != nil {
		return nil, err
	}
	return membership.Canonical(map[string]any{"entry": entry, "signatures": []any{
		map[string]any{"party": s.node, "boot_id": s.key.BootID, "session_key": s.key.Hex(), "sig": hex.EncodeToString(sig)}}}), nil
}

// collector is the etcd lease that deletes keys in the hour bucket ending at or after `until`: one lease per
// hour, not one per key. A spend's `until` is its expiry + SkewS, so its key lives at least gc_ttl (opstate.py).
func (s *EtcdState) collector(ctx context.Context, until time.Time) (clientv3.LeaseID, error) {
	end := until.Truncate(time.Hour).Add(time.Hour).Unix()
	s.mu.Lock()
	id, ok := s.buckets[end]
	s.mu.Unlock()
	if ok {
		return id, nil
	}
	ttl := end - s.now().Unix()
	if ttl < 60 {
		ttl = 60
	}
	granted, err := s.client.Grant(clientv3.WithRequireLeader(ctx), ttl)
	if err != nil {
		return 0, fmt.Errorf("no collection lease could be granted: %w", err)
	}
	s.mu.Lock()
	s.buckets[end] = granted.ID
	for bucket := range s.buckets {
		if bucket < s.now().Unix() {
			delete(s.buckets, bucket)
		}
	}
	s.mu.Unlock()
	return granted.ID, nil
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func anyList(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

// sequenceName is a policy sequence key (chain ID NUL account number) as an opstate name: printable, no space.
// The NUL becomes "/", which no chain ID holds; anything else outside the name's alphabet is hex-escaped.
func sequenceName(key string) string {
	out := make([]byte, 0, len(key))
	for i := 0; i < len(key); i++ {
		c := key[i]
		switch {
		case c == 0:
			out = append(out, '/')
		case c > 0x20 && c < 0x7f && c != '%':
			out = append(out, c)
		default:
			out = append(out, fmt.Sprintf("%%%02x", c)...)
		}
	}
	if len(out) > 256 {
		sum := sha256.Sum256([]byte(key))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	return string(out)
}
