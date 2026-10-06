package opstate

import (
	"strings"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

// Judge is the Cache's Verify for opstate-v1: the value verifies (VerifyValue) and may replace the last entry
// under its key that verified (Transition). So a direct write that regresses a sequence or a quota, or puts
// back an older approved key state, is refused on every server, whatever etcd's transactions were bypassed.
// `approverSets` is read at each judgement: the policy's sets, by digest, every one it has had.
func Judge(sessions Sessions, approverSets func() map[string]ApproverSet) func(key string, value []byte, previous any) (any, error) {
	return func(key string, value []byte, previous any) (any, error) {
		document, err := membership.Load(value, 2*MaxEntryBytes)
		if err != nil {
			return nil, refuse("the value is not JSON: %v", err)
		}
		entry, err := VerifyValue(key, document, sessions, approverSets())
		if err != nil {
			return nil, err
		}
		before, _ := previous.(map[string]any)
		if err := Transition(before, entry); err != nil {
			return nil, err
		}
		return entry, nil
	}
}

// KeyStateTombstone is the Cache's Tombstone for opstate-v1: a key's state, once seen, may never become
// absent (its delete, then its first state put back, would be a rollback). Nonces, sequences and quotas may be
// deleted: they are collected after they expire.
func KeyStateTombstone(key string) bool {
	return strings.HasPrefix(key, Prefix+"keys/") && strings.HasSuffix(key, "/state")
}
