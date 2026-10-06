package opstate

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
)

// Two servers (a, b), each with its session key, reserving on one real etcd: the ONE transaction per Reserve,
// committed before the HSM, all or nothing (D32, #432).
type twoServers struct {
	client *clientv3.Client
	a, b   *EtcdState
	now    time.Time
}

func newTwoServers(t *testing.T) *twoServers {
	t.Helper()
	client := realEtcd(t)
	const boot = "0123abcd-0000-4000-8000-0123456789ab"
	keyA, _ := NewSessionKey(boot, 1)
	keyB, _ := NewSessionKey(boot, 1)
	sessions := func(node, bootID, key, _ string) bool {
		return bootID == boot && ((node == "a" && key == keyA.Hex()) || (node == "b" && key == keyB.Hex()))
	}
	verify := func(key string, value []byte) (map[string]any, error) {
		entry, err := Judge(sessions, func() map[string]ApproverSet { return nil })(key, value, nil)
		if err != nil {
			return nil, err
		}
		return entry.(map[string]any), nil
	}
	w := &twoServers{client: client, now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	lease := func(context.Context) (string, time.Time, bool) {
		return "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", w.now.Add(30 * time.Second), true
	}
	clock := func() time.Time { return w.now }
	var err error
	if w.a, err = NewEtcdState(client, "a", keyA, lease, verify, clock); err != nil {
		t.Fatal(err)
	}
	if w.b, err = NewEtcdState(client, "b", keyB, lease, verify, clock); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *twoServers) reservation(nonce string, amount uint64, sequence *uint64) policy.Reservation {
	return policy.Reservation{PolicyID: "p", ObjectID: "release-signing", Principal: "spiffe://regalia/ci/release", Nonce: nonce,
		UTCDate: "2026-10-05", Amounts: map[string]uint64{"signatures": amount}, DailyCaps: map[string]uint64{"signatures": 5},
		Sequence: sequence, SequenceKey: "cosmoshub-4\x007", Purpose: "sign", Environment: "production",
		PayloadSHA256: "abababababababababababababababababababababababababababababababab", Approvers: []string{"bob", "alice"},
		ApproverSet: "45b9f147d8be551181d248267ebb2d8f9d820bcccdb3f5fa97fbf7ad17603945", ApprovalsSHA256: "83b848a4788cd7ec78c556d81b4a4f1b4dbd5d9e60b40c647f3083986ab109f3",
		ExpiresAt: w.now.Add(5 * time.Minute)}
}

func TestOneNonceIsSpentOnceAcrossTwoServers(t *testing.T) {
	w := newTwoServers(t)
	ctx := context.Background()
	results := make([]error, 2)
	var wg sync.WaitGroup
	for i, s := range []*EtcdState{w.a, w.b} {
		wg.Add(1)
		go func(i int, s *EtcdState) {
			defer wg.Done()
			results[i] = s.Reserve(ctx, w.reservation("018f0000000070008000000000000001", 1, nil))
		}(i, s)
	}
	wg.Wait()
	spent, replays := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			spent++
		case errors.Is(err, policy.ErrReplay):
			replays++
		default:
			t.Fatalf("neither spent nor a replay: %v", err)
		}
	}
	if spent != 1 || replays != 1 {
		t.Fatalf("spent %d times, refused as a replay %d times: one nonce is spent once", spent, replays)
	}
	if err := w.a.Reserve(ctx, w.reservation("018f0000000070008000000000000001", 1, nil)); !errors.Is(err, policy.ErrReplay) {
		t.Fatalf("the same nonce again: %v", err)
	}
	// what was committed verifies, and names the one server that spent
	key := Prefix + "nonces/" + hashName("018f0000000070008000000000000001")
	got, err := w.client.Get(ctx, key)
	if err != nil || len(got.Kvs) != 1 || got.Kvs[0].Lease == 0 {
		t.Fatalf("the spend: %v %v (it must carry a collection lease)", got, err)
	}
	if _, err := w.a.verify(key, got.Kvs[0].Value); err != nil {
		t.Fatalf("the committed spend does not verify: %v", err)
	}
}

// Ten concurrent reservations of 1 against a cap of 5, on two servers: never more than the cap, and the stored
// total is exactly what was granted.
func TestAQuotaIsNeverOverspentByConcurrentServers(t *testing.T) {
	w := newTwoServers(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	var mu sync.Mutex
	granted, limited, contended := 0, 0, 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := w.a
			if i%2 == 1 {
				s = w.b
			}
			err := s.Reserve(ctx, w.reservation("018f00000000700080000000000001"+string(rune('a'+i))+"0", 1, nil))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				granted++
			case errors.Is(err, policy.ErrLimit):
				limited++
			case errors.Is(err, ErrContention):
				contended++
			default:
				t.Errorf("reservation %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	if granted > 5 || granted == 0 || granted+limited+contended != 10 {
		t.Fatalf("granted %d, over the cap %d, lost to contention %d", granted, limited, contended)
	}
	key := Prefix + "quota/" + hashName("spiffe://regalia/ci/release") + "/2026-10-05/" + hashName("signatures")
	got, err := w.client.Get(ctx, key)
	if err != nil || len(got.Kvs) != 1 {
		t.Fatalf("the quota: %v %v", got, err)
	}
	entry, err := w.a.verify(key, got.Kvs[0].Value)
	if err != nil {
		t.Fatal(err)
	}
	if total := entry["total"].(interface{ String() string }).String(); total != string(rune('0'+granted)) {
		t.Fatalf("the stored total is %s, %d were granted", total, granted)
	}
}

func TestASequenceOnlyMovesUp(t *testing.T) {
	w := newTwoServers(t)
	ctx := context.Background()
	seq := func(v uint64) *uint64 { return &v }
	if err := w.a.Reserve(ctx, w.reservation("018f0000000070008000000000000a01", 1, seq(7))); err != nil {
		t.Fatal(err)
	}
	if err := w.b.Reserve(ctx, w.reservation("018f0000000070008000000000000a02", 1, seq(7))); !errors.Is(err, policy.ErrReplay) {
		t.Fatalf("the same sequence on the other server: %v", err)
	}
	if err := w.b.Reserve(ctx, w.reservation("018f0000000070008000000000000a03", 1, seq(6))); !errors.Is(err, policy.ErrReplay) {
		t.Fatalf("a lower sequence: %v", err)
	}
	if err := w.b.Reserve(ctx, w.reservation("018f0000000070008000000000000a04", 1, seq(8))); err != nil {
		t.Fatalf("the next sequence: %v", err)
	}
	// ALL OR NOTHING: the refused reservations left neither their nonce nor their quota behind
	for _, nonce := range []string{"018f0000000070008000000000000a02", "018f0000000070008000000000000a03"} {
		if got, _ := w.client.Get(ctx, Prefix+"nonces/"+hashName(nonce)); len(got.Kvs) != 0 {
			t.Fatalf("a refused reservation spent its nonce %s", nonce)
		}
	}
	quota := Prefix + "quota/" + hashName("spiffe://regalia/ci/release") + "/2026-10-05/" + hashName("signatures")
	got, _ := w.client.Get(ctx, quota)
	entry, err := w.a.verify(quota, got.Kvs[0].Value)
	if err != nil || entry["total"].(interface{ String() string }).String() != "2" {
		t.Fatalf("the quota after two granted and two refused: %v %v", entry["total"], err)
	}
}

func TestNoLeaseNoReservation(t *testing.T) {
	w := newTwoServers(t)
	w.a.lease = func(context.Context) (string, time.Time, bool) { return "", time.Time{}, false }
	if err := w.a.Reserve(context.Background(), w.reservation("018f0000000070008000000000000b01", 1, nil)); err == nil {
		t.Fatal("reserved with no serving lease")
	}
}

// A collection lease gone early (revoked; lost across a force-new-cluster or a restore) is granted again, not
// reused for the rest of its hour: no hour of refused stateful operations (48 on #508).
func TestARevokedCollectionLeaseIsGrantedAgain(t *testing.T) {
	w := newTwoServers(t)
	ctx := context.Background()
	if err := w.a.Reserve(ctx, w.reservation("018f0000000070008000000000000c01", 1, nil)); err != nil {
		t.Fatal(err)
	}
	w.a.mu.Lock()
	var revoked []clientv3.LeaseID
	for _, id := range w.a.buckets {
		revoked = append(revoked, id)
	}
	w.a.mu.Unlock()
	if len(revoked) == 0 {
		t.Fatal("no collection lease was cached")
	}
	for _, id := range revoked {
		if _, err := w.client.Revoke(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.a.Reserve(ctx, w.reservation("018f0000000070008000000000000c02", 1, nil)); err != nil {
		t.Fatalf("a reservation after its collection lease was revoked: %v", err)
	}
	w.a.mu.Lock()
	defer w.a.mu.Unlock()
	for _, id := range w.a.buckets {
		for _, gone := range revoked {
			if id == gone {
				t.Fatal("the revoked lease is still cached")
			}
		}
	}
}
