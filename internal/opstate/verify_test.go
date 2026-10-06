package opstate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

// tests/vectors/opstate-v1.json (48's make-opstate-v1.py) holds opstate.py's decisions: every case is verify()
// then transition(previous, entry), every batch is batch() over entries already verified. Go decides each alike,
// with the same reason.
func opstateVector(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "vectors", "opstate-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	document, err := membership.Load(raw, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	return renamePublic(document).(map[string]any)
}

// renamePublic undoes the vector's spelling (as membership-v4.json's): every "public" is "key" again and every
// "session_public" "session_key", as the Python signed them.
func renamePublic(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range v {
			switch k {
			case "public":
				k = "key"
			case "session_public":
				k = "session_key"
			}
			out[k] = renamePublic(x)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = renamePublic(x)
		}
		return out
	}
	return value
}

func vectorResolvers(t *testing.T, v map[string]any) (Sessions, map[string]ApproverSet) {
	t.Helper()
	type window struct{ from, until string }
	sessions := map[string][]window{}
	for k, list := range v["sessions"].(map[string]any) {
		for _, value := range list.([]any) {
			w := value.(map[string]any)
			until, _ := w["valid_until"].(string)
			sessions[k+"|"+w["session_key"].(string)] = append(sessions[k+"|"+w["session_key"].(string)], window{w["issued_at"].(string), until})
		}
	}
	sets := map[string]ApproverSet{}
	for digest, value := range v["approver_sets"].(map[string]any) {
		object := value.(map[string]any)
		approvers := map[string]string{}
		for id, key := range object["approvers"].(map[string]any) {
			approvers[id] = key.(string)
		}
		required, err := strconv.Atoi(string(object["required"].(interface{ String() string }).String()))
		if err != nil {
			t.Fatal(err)
		}
		sets[digest] = ApproverSet{Approvers: approvers, Required: required}
	}
	return func(node, boot, key, at string) bool {
		for _, w := range sessions[node+"|"+boot+"|"+key] {
			if w.from <= at && (w.until == "" || at < w.until) {
				return true
			}
		}
		return false
	}, sets
}

func previousOf(value any) map[string]any {
	if value == nil {
		return nil
	}
	return value.(map[string]any)
}

func TestEveryOpstateDecisionIsTheSame(t *testing.T) {
	v := opstateVector(t)
	sessions, sets := vectorResolvers(t, v)
	for digest, set := range sets {
		if set.Digest() != digest {
			t.Fatalf("the approver set under %s digests to %s in Go", digest[:16], set.Digest()[:16])
		}
	}
	accepted, refused := 0, 0
	for _, value := range v["cases"].([]any) {
		c := value.(map[string]any)
		entry, err := VerifyValue(c["key"].(string), c["value"], sessions, sets)
		if err == nil {
			err = Transition(previousOf(c["previous"]), entry)
		}
		if c["accept"] == true {
			accepted++
			if err != nil {
				t.Errorf("%s: Python accepted, Go: %v", c["name"], err)
			}
			continue
		}
		refused++
		if err == nil {
			t.Errorf("%s: Python refused (%s), Go accepted", c["name"], c["python_reason"])
		} else if err.Error() != c["python_reason"] {
			t.Errorf("%s: refused for another reason:\nPython: %s\nGo:     %v", c["name"], c["python_reason"], err)
		}
	}
	batches := 0
	for _, value := range v["batches"].([]any) {
		b := value.(map[string]any)
		batches++
		var writes []Write
		var err error
		for _, w := range b["writes"].([]any) {
			write := w.(map[string]any)
			// batch() takes values verify() has already passed, as a Reserve does: its own rules only
			entry, _, verr := ValidateEntry(write["value"].(map[string]any)["entry"])
			if verr != nil {
				t.Fatalf("batch %s: a write's entry does not validate: %v", b["name"], verr)
			}
			writes = append(writes, Write{Key: write["key"].(string), Entry: entry, Previous: previousOf(write["previous"])})
		}
		if err == nil {
			_, err = Batch(writes)
		}
		if b["accept"] == true {
			if err != nil {
				t.Errorf("batch %s: Python accepted, Go: %v", b["name"], err)
			}
		} else if err == nil || err.Error() != b["python_reason"] {
			t.Errorf("batch %s: Python refused (%s), Go: %v", b["name"], b["python_reason"], err)
		}
	}
	if accepted+refused < 45 || accepted < 10 || refused < 30 || batches < 10 {
		t.Fatalf("%d accepted, %d refused, %d batches: the file is not the one this test was written for", accepted, refused, batches)
	}
	t.Logf("%d accepted and %d refused cases, %d batches, as the Python decided", accepted, refused, batches)
}

type absent struct{}

func replacedField(object map[string]any, key string, value any) map[string]any {
	out := map[string]any{}
	for k, v := range object {
		out[k] = v
	}
	if _, gone := value.(absent); gone {
		delete(out, key)
	} else {
		out[key] = value
	}
	return out
}

// A damaged value (every field of the entry and of each signature removed, or replaced by a value of another
// type) is refused, never a panic.
func TestADamagedOpstateValueIsRefusedNeverAPanic(t *testing.T) {
	v := opstateVector(t)
	sessions, sets := vectorResolvers(t, v)
	odd := []any{absent{}, nil, true, "x", "", []any{}, map[string]any{}, json.Number("-1"), json.Number("1"), json.Number("1.5")}
	tried := 0
	for _, value := range v["cases"].([]any) {
		c := value.(map[string]any)
		stored := c["value"].(map[string]any)
		entry := stored["entry"].(map[string]any)
		try := func(label string, changed any) {
			tried++
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s, %s: panicked: %v", c["name"], label, r)
				}
			}()
			if e, err := VerifyValue(c["key"].(string), changed, sessions, sets); err == nil {
				_ = Transition(previousOf(c["previous"]), e)
			}
		}
		for key := range entry {
			for _, o := range odd {
				try("entry."+key, replacedField(stored, "entry", replacedField(entry, key, o)))
			}
		}
		for _, o := range odd {
			try("signatures", replacedField(stored, "signatures", o))
			try("entry", replacedField(stored, "entry", o))
		}
		if sigs, ok := stored["signatures"].([]any); ok && len(sigs) > 0 {
			for key := range sigs[0].(map[string]any) {
				for _, o := range odd {
					try("signatures[0]."+key, replacedField(stored, "signatures", []any{replacedField(sigs[0].(map[string]any), key, o)}))
				}
			}
		}
	}
	if tried < 3000 {
		t.Fatalf("only %d damaged values tried", tried)
	}
	t.Logf("%d damaged values, none panicked", tried)
}

// A verifier's set held under a digest that is not its own is refused: the entry names the set it was signed
// under, and a different set filed under that name (a policy store gone wrong) must not judge it.
func TestAnApproverSetHeldUnderAnotherDigestIsRefused(t *testing.T) {
	v := opstateVector(t)
	sessions, sets := vectorResolvers(t, v)
	for _, value := range v["cases"].([]any) {
		c := value.(map[string]any)
		entry := c["value"].(map[string]any)["entry"].(map[string]any)
		if c["accept"] != true || entry["kind"] != "key-state" {
			continue
		}
		digest := entry["approver_set"].(string)
		swapped := map[string]ApproverSet{}
		for d, set := range sets {
			swapped[d] = set
		}
		real := sets[digest]
		swapped[digest] = ApproverSet{Approvers: real.Approvers, Required: real.Required + 1}
		_, err := VerifyValue(c["key"].(string), c["value"], sessions, swapped)
		if err == nil || err.Error() != "the approver set held under "+digest[:16]+" is not that set" {
			t.Fatalf("%s: %v", c["name"], err)
		}
		return
	}
	t.Fatal("the vector has no accepted key-state case")
}

// THE CACHE JUDGES EACH ENTRY AGAINST THE LAST GOOD ONE (#488 finding 4, 48's version and prev_digest). On the
// vector's key-state chain: v1 listed, v2 watched, the old v1 put back (refused, REPLAY), v3 still judged
// against v2 (a refused entry does not reset it), a delete kept as a refusal, and v1 listed again after a
// relist refused too.
func TestTheCacheRefusesAReplayedOrDeletedKeyState(t *testing.T) {
	v := opstateVector(t)
	sessions, sets := vectorResolvers(t, v)
	cases := v["cases"].([]any)
	raw := func(i int) []byte { return membership.Canonical(cases[i].(map[string]any)["value"]) }
	key := cases[6].(map[string]any)["key"].(string)
	r := newFakeSource()
	r.values[key], r.revision = raw(6), 10
	clk := &clock{now: time.Hour}
	cache, err := New(Options{Source: r, Prefix: Prefix, Boottime: clk.read, ProgressEvery: time.Hour, Retry: 10 * time.Millisecond,
		Verify: Judge(sessions, func() map[string]ApproverSet { return sets }), Tombstone: KeyStateTombstone})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { cache.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	stream := func() chan Update {
		select {
		case s := <-r.streams:
			return s
		case <-time.After(5 * time.Second):
			t.Fatal("no watch")
		}
		return nil
	}
	state := func(rev int64) (string, error) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if got, _, live := cache.Applied(); live && got >= rev {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("never reached revision %d (%s)", rev, cache.Reason())
			}
			time.Sleep(time.Millisecond)
		}
		parsed, ok, err := cache.Entry(key)
		if !ok {
			t.Fatal("the key is absent")
		}
		if err != nil {
			return "", err
		}
		return parsed.(map[string]any)["state"].(string), nil
	}
	s := stream()
	if got, err := state(10); err != nil || got != "enabled" {
		t.Fatalf("v1: %q %v", got, err)
	}
	s <- Update{Changes: []Change{{Key: key, Value: raw(7), ModRevision: 11}}}
	if got, err := state(11); err != nil || got != "disabled" {
		t.Fatalf("v2: %q %v", got, err)
	}
	s <- Update{Changes: []Change{{Key: key, Value: raw(6), ModRevision: 12}}}
	if _, err := state(12); err == nil || !strings.Contains(err.Error(), "REPLAY: the key release-signing is at version 2; this entry is version 1") {
		t.Fatalf("the old v1 put back was not refused as a replay: %v", err)
	}
	s <- Update{Changes: []Change{{Key: key, Value: raw(8), ModRevision: 13}}}
	if got, err := state(13); err != nil || got != "enabled" {
		t.Fatalf("v3 after a refused replay: %q %v", got, err)
	}
	s <- Update{Changes: []Change{{Key: key, Deleted: true, ModRevision: 14}}}
	if _, err := state(14); err == nil || !strings.Contains(err.Error(), "deleted after it was seen") {
		t.Fatalf("a deleted key state was not refused: %v", err)
	}
	// listed again with the key absent: still refused, not "no state"
	r.mu.Lock()
	delete(r.values, key)
	r.revision = 15
	r.mu.Unlock()
	s <- Update{Err: errors.New("leader changed")}
	s = stream()
	if _, err := state(15); err == nil || !strings.Contains(err.Error(), "deleted after it was seen") {
		t.Fatalf("a key state absent from a relist was not refused: %v", err)
	}
	// listed again with its first state back: still judged against v3
	r.mu.Lock()
	r.values[key], r.revision = raw(6), 20
	r.mu.Unlock()
	s <- Update{Err: errors.New("member restarted")}
	stream()
	if _, err := state(20); err == nil || !strings.Contains(err.Error(), "REPLAY") {
		t.Fatalf("v1 listed again after a relist was not refused: %v", err)
	}
}

// The vector's session, approval and sign checks: verify_session, check_approvals and may_sign, alike, with the
// same reasons; and gc_ttl.
func TestEverySessionApprovalAndSignCheckIsTheSame(t *testing.T) {
	v := opstateVector(t)
	_, sets := vectorResolvers(t, v)
	var chain []map[string]any
	for _, m := range v["chain"].([]any) {
		chain = append(chain, m.(map[string]any))
	}
	counts := map[string]int{}
	judge := func(kind, name string, accept bool, reason string, err error) {
		t.Helper()
		counts[kind]++
		if accept && err != nil {
			t.Errorf("%s %s: Python accepted, Go: %v", kind, name, err)
		} else if !accept && (err == nil || err.Error() != reason) {
			t.Errorf("%s %s: refused for another reason:\nPython: %s\nGo:     %v", kind, name, reason, err)
		}
	}
	for _, value := range v["session_checks"].([]any) {
		c := value.(map[string]any)
		_, until, err := VerifySession(c["key"].(string), c["value"], chain)
		judge("session", c["name"].(string), c["accept"] == true, c["python_reason"].(string), err)
		if c["accept"] == true && until != c["python_reason"] {
			t.Errorf("session %s: valid until %q, Python %q", c["name"], until, c["python_reason"])
		}
	}
	for _, value := range v["approval_checks"].([]any) {
		c := value.(map[string]any)
		_, err := CheckApprovals(c["spend"], c["approvals"], sets)
		judge("approval", c["name"].(string), c["accept"] == true, c["python_reason"].(string), err)
	}
	for _, value := range v["sign_checks"].([]any) {
		c := value.(map[string]any)
		now, _ := strconv.ParseInt(c["now"].(json.Number).String(), 10, 64)
		err := MaySign(c["spend"], now, c["held_lease_digest"].(string), c["held_lease_expires_at"].(string))
		judge("sign", c["name"].(string), c["accept"] == true, c["python_reason"].(string), err)
		if c["accept"] == true {
			if ttl, err := GCTTL(c["spend"]); err != nil || ttl != 300+SkewS {
				t.Errorf("gc_ttl %d %v", ttl, err)
			}
		}
	}
	for _, value := range v["fresh_checks"].([]any) {
		c := value.(map[string]any)
		now, _ := strconv.ParseInt(c["now"].(json.Number).String(), 10, 64)
		judge("fresh", c["name"].(string), c["accept"] == true, c["python_reason"].(string), Fresh(c["entry"], now))
	}
	if counts["fresh"] < 4 || counts["session"] < 10 || counts["approval"] < 13 || counts["sign"] < 4 {
		t.Fatalf("checks %v: the file is not the one this test was written for", counts)
	}
	if UngatedSet != (ApproverSet{Approvers: map[string]string{}}).Digest() {
		t.Fatal("UNGATED_SET")
	}
}

// A created entry observed by the watch is judged fresh on arrival; the initial list is not (its entries were
// created before this reader could see them).
func TestTheCacheJudgesACreatedEntryFreshOnArrival(t *testing.T) {
	v := opstateVector(t)
	sessions, sets := vectorResolvers(t, v)
	cases := v["cases"].([]any)
	first, listed := cases[0].(map[string]any), cases[2].(map[string]any) // a spend; a sequence's first value
	key, raw := first["key"].(string), membership.Canonical(first["value"])
	listedKey := listed["key"].(string)
	r := newFakeSource()
	r.values[listedKey], r.revision = membership.Canonical(listed["value"]), 5 // listed: not judged fresh
	wall := time.Date(2026, 10, 5, 12, 5, 0, 0, time.UTC)                      // five minutes after the entry's `at`
	clk := &clock{now: time.Hour}
	cache, err := New(Options{Source: r, Prefix: Prefix, Boottime: clk.read, ProgressEvery: time.Hour, Retry: 10 * time.Millisecond,
		Verify: Judge(sessions, func() map[string]ApproverSet { return sets }), Fresh: FreshAt(func() time.Time { return wall })})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { cache.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	s := <-r.streams
	waitRev := func(rev int64) {
		deadline := time.Now().Add(5 * time.Second)
		for {
			if got, _, live := cache.Applied(); live && got >= rev {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("never reached %d", rev)
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitRev(5)
	if _, ok, err := cache.Entry(listedKey); !ok || err != nil {
		t.Fatalf("a listed entry was judged fresh: %v", err)
	}
	s <- Update{Changes: []Change{{Key: key, Value: raw, Created: true, ModRevision: 6}}}
	waitRev(6)
	if _, _, err := cache.Entry(key); err == nil || !strings.Contains(err.Error(), "s from this reader's clock when it arrived") {
		t.Fatalf("a backdated entry created under the watch was taken: %v", err)
	}
}
