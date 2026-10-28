package operations

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/admission"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// countingState is a policy.State that keeps every reservation the engine makes: a Cosmos request reserves its
// account sequence there, so an empty list means no sequence was spent.
type countingState struct{ reservations []policy.Reservation }

func (state *countingState) Reserve(_ context.Context, reservation policy.Reservation) error {
	state.reservations = append(state.reservations, reservation)
	return nil
}

// A LONE SURVIVOR SIGNS NO SEQUENCE-BEARING REQUEST (ADR-0002 D32.6). A survivor under the owner's authorization
// may serve stateless operations only, and a Cosmos signature is stateful: it spends the account's next sequence.
// Until a stateless-only gate exists, a node whose admission is in recovery mode serves nothing (admission.go,
// #432). This holds it end to end, as the daemon wires it: the real admission gate reading a recovery-mode file,
// the admission runner over the executor and RequireAdmission on the same gate, the real policy engine and the
// reference SignDoc. Recovery refuses before policy, so no sequence is reserved and the token is never used; the
// same request under a lease is signed and reserves its sequence, so the refusal is the mode's and the request
// does bear a sequence.
func TestALoneSurvivorSignsNoSequenceBearingRequest(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("..", "policy", "testdata", "signdoc-akashnet2-msgsend.hex"))
	if err != nil {
		t.Fatal(err)
	}
	signDoc, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := policy.ParseCosmosSignDoc(signDoc)
	if err != nil || len(transaction.Messages) != 1 || len(transaction.Messages[0].Amounts) != 1 || len(transaction.Fee) != 1 {
		t.Fatalf("the reference SignDoc is not one MsgSend of one coin with one fee coin: %#v %v", transaction, err)
	}
	message, fee := transaction.Messages[0], transaction.Fee[0]
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	const (
		boot      = "0f3a9c1e-1111-4222-8333-444455556666"
		session   = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e"
		boottime  = int64(1_000_000)
		tokenSays = "signature"
	)
	for _, mode := range []string{admission.ModeRecovery, admission.ModeLease} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0o755); err != nil { // the suite's umask is not the gate's rule
				t.Fatal(err)
			}
			document, err := json.Marshal(map[string]any{
				"schema": admission.Schema, "node_id": "a", "session_id": session, "boot_id": boot, "epoch": 7,
				"manifest_digest": strings.Repeat("d1", 32), "hsm_serials": "DENK0404144", "lease_issued_at": "2026-10-02T09:00:00Z",
				"requested_boottime_ms": boottime - 5_000, "cluster_id": strings.Repeat("c1", 8), "state_epoch": 2, "state_revision": 41,
				"session_key": strings.Repeat("e7", 32), "serve_until_boottime_ms": boottime + 25_000, "mode": mode, "reason": "",
			})
			if err != nil {
				t.Fatal(err)
			}
			for name, contents := range map[string][]byte{"admission.json": document, "boot-session": []byte(session + "\n")} {
				if err := os.WriteFile(filepath.Join(directory, name), contents, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Join(directory, name), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			gate, err := admission.Open(admission.Options{
				Path: filepath.Join(directory, "admission.json"), NodeID: "a", SessionPath: filepath.Join(directory, "boot-session"),
				OwnerUID: uint32(os.Getuid()), SessionOwnerUID: uint32(os.Getuid()),
				Boottime: func() (int64, error) { return boottime, nil },
				BootID:   func() (string, error) { return boot, nil },
			})
			if err != nil {
				t.Fatal(err)
			}
			state := &countingState{}
			engine, err := policy.New([]policy.Policy{{
				ID: "wallet", ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production",
				Operation: "sign", Algorithm: "secp256k1", ContentTypes: []string{"application/vnd.cosmos.tx+protobuf"},
				MaxPayloadBytes: 10000, MaxFuture: time.Minute,
				Cosmos: &policy.CosmosPolicy{ChainIDs: []string{transaction.ChainID}, AccountNumbers: []uint64{transaction.AccountNumber},
					MessageTypes: []string{message.Type}, Sources: []string{message.Source}, Destinations: []string{message.Destination},
					MaxGasLimit: transaction.GasLimit, MaxFee: map[string]uint64{fee.Denom: fee.Amount},
					MaxPerTransaction: map[string]uint64{message.Amounts[0].Denom: message.Amounts[0].Amount},
					MaxPerDay:         map[string]uint64{message.Amounts[0].Denom: message.Amounts[0].Amount}},
			}}, state, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production",
				Algorithm: "secp256k1", PolicyID: "wallet", Binding: registry.Binding{DeviceID: "hsm-1"}}}
			recorder, hardware := &fakeAudit{}, &fakeHardware{output: []byte(tokenSays)}
			// as the daemon builds it (cmd/regalia-kms main.go): the admission runner and RequireAdmission on one gate
			coordinator, err := New(fakeAuthorizer{allowed: true, digest: "sha256:rbac"}, router, engine, recorder,
				admission.NewRunner(gate, directRunner{}), hardware, "sha256:policy", nil, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			coordinator.RequireAdmission(gate)
			request := operationRequest()
			request.Operation, request.Format, request.ContentType, request.Data = "sign", "", "application/vnd.cosmos.tx+protobuf", signDoc
			request.Context.ExpiresAt = now.Add(30 * time.Second)
			result, err := coordinator.Execute(context.Background(), request)

			if mode == admission.ModeLease {
				if err != nil || string(result.Data) != tokenSays || hardware.calls != 1 {
					t.Fatalf("under a lease the request was not signed: %v (token calls %d)", err, hardware.calls)
				}
				if len(state.reservations) != 1 || state.reservations[0].Sequence == nil || *state.reservations[0].Sequence != transaction.Sequence {
					t.Fatalf("under a lease the request reserved %#v, want its account sequence %d", state.reservations, transaction.Sequence)
				}
				return
			}
			wantNotAdmitted(t, result, err)
			if hardware.calls != 0 || len(state.reservations) != 0 || router.calls != 0 {
				t.Fatalf("in recovery: the token used %d times, %d reservation(s) made, routing asked %d times",
					hardware.calls, len(state.reservations), router.calls)
			}
			if status := gate.Check(context.Background()); status.Admitted || !strings.Contains(status.Reason, "recovery") {
				t.Fatalf("the gate's answer is %+v, want a refusal naming recovery", status)
			}
		})
	}
}
