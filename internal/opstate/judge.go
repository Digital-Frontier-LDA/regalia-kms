package opstate

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

// Judge is the Cache's Verify for opstate-v1: the value verifies (VerifyValue) and may replace the last entry
// under its key that verified (Transition). So a direct write that regresses a sequence or a quota, or puts
// back an older approved key state, is refused on every server, whatever etcd's transactions were bypassed.
// `approverSets` is read at each judgement: the policy's sets, by digest, every one it has had.
// The state-epoch key is judged by VerifyStateEpoch against `chain` (the verified membership chain, oldest first),
// bound to where it was read, and above the epoch it replaces.
func Judge(sessions Sessions, approverSets func() map[string]ApproverSet, chain func() []map[string]any) func(key string, value []byte, previous any, at Origin) (any, error) {
	return func(key string, value []byte, previous any, at Origin) (any, error) {
		document, err := membership.Load(value, 2*MaxEntryBytes)
		if err != nil {
			return nil, refuse("the value is not JSON: %v", err)
		}
		before, _ := previous.(map[string]any)
		if key == StateEpochKey {
			var manifests []map[string]any
			if chain != nil {
				manifests = chain()
			}
			store := &StoreRef{ClusterID: fmt.Sprintf("%016x", at.ClusterID), ModRevision: at.ModRevision}
			entry, err := VerifyStateEpoch(key, document, manifests, nil, store)
			if err != nil {
				return nil, err
			}
			if before != nil && reflect.DeepEqual(entry, before) {
				return entry, nil // the same entry read again (a relist), not a new epoch
			}
			return VerifyStateEpoch(key, document, manifests, before, store)
		}
		entry, err := VerifyValue(key, document, sessions, approverSets())
		if err != nil {
			return nil, err
		}
		// A relist judges every value against the last good one under its key, which for an unchanged key IS
		// this entry: read again, it is not a replay of itself, a spend twice, or a sequence that did not rise.
		// Verified on its own first (above), so a revoked session or set still refuses it.
		if before != nil && reflect.DeepEqual(entry, before) {
			return entry, nil
		}
		if err := Transition(before, entry); err != nil {
			return nil, err
		}
		return entry, nil
	}
}

// KeyStateTombstone is the Cache's Tombstone for opstate-v1: a key's state, once seen, may never become
// absent (its delete, then its first state put back, would be a rollback). Nonces, sequences and quotas may be
// deleted: they are collected after they expire. So is the state epoch never absent once seen: its delete would
// read as genesis (0), another history (62's rule, agreed with 48 on #432).
func KeyStateTombstone(key string) bool {
	return key == StateEpochKey || strings.HasPrefix(key, Prefix+"keys/") && strings.HasSuffix(key, "/state")
}
