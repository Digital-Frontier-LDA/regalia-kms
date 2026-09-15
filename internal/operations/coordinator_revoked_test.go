package operations

import (
	"context"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// revoked audit strings. #160 introduces a fourth refusal reason on the unwrap path — the
// matched KEK is in state `revoked`; envelopes sealed under it become unrecoverable by design.
// The coordinator must surface that as `denied-kek-revoked` so a responder at 3am sees the
// difference between an RBAC denial and a key-compromise refusal (which the runbook row for
// setting `revoked` warned about before the state was set).

// TestCoordinatorRecordsDeniedKekRevokedForRevokedRefusals pins the audit-side half of #160
// alongside TestAnEnvelopeUnderARevokedKEKIsRefusedWithTheDistinctReason, which pins the
// registry-side half. Together they hold the contract that a release refused because the matched
// KEK is revoked surfaces as audit outcome `denied-kek-revoked`, distinct from a routing failure.
//
// Falsified by: deleting the RefusalReason branch in the coordinator's refusal-mapping block
// (replacing it with the prior single outcome `routing-denied`). The test fails with
// "outcome = routing-denied, want denied-kek-revoked: a release refused because the matched KEK
// is revoked must not look like a routing failure" — which is the message an operator wakes up
// to if the distinction silently disappears.
func TestCoordinatorRecordsDeniedKekRevokedForRevokedRefusals(t *testing.T) {
	router := &fakeRouter{
		unwrapErr: &registry.Error{Code: registry.CodeDenied, Reason: registry.ReasonRevoked},
	}
	recorder := &fakeAudit{}
	coordinator := releaseCoordinator(t, router, &fakeHardware{output: []byte("must-not-run")})
	coordinator.audit = recorder

	request := releaseRequest(envelopeNaming(t, "1"))
	if _, err := coordinator.Execute(context.Background(), request); err == nil {
		t.Fatal("Execute() returned no error: a release refused for ReasonRevoked must surface as a 403")
	}
	if len(recorder.drafts) == 0 {
		t.Fatal("no audit draft recorded: the refusal must show up in the audit record")
	}
	got := recorder.drafts[0].Outcome
	if got != "denied-kek-revoked" {
		t.Fatalf("outcome = %q, want %q: a release refused because the matched KEK is revoked must not look like a routing failure",
			got, "denied-kek-revoked")
	}
}

// TestCoordinatorRecordsRoutingDeniedForNonRevokedDenials is the converse guard. The reason
// disambiguation is correct only if OTHER denied routings still record `routing-denied`, not
// the revoked-KEK outcome. A blanket replacement of the outcome would have passed the test
// above but broken every other routing denial in the audit record — which is why this test
// pins the other side of the distinction.
//
// Falsified by: always writing `denied-kek-revoked` regardless of reason. The test fails
// because the audit outcome for a CodeDenied without ReasonRevoked must remain `routing-denied`.
func TestCoordinatorRecordsRoutingDeniedForNonRevokedDenials(t *testing.T) {
	router := &fakeRouter{
		unwrapErr: &registry.Error{Code: registry.CodeDenied}, // no Reason
	}
	recorder := &fakeAudit{}
	coordinator := releaseCoordinator(t, router, &fakeHardware{output: []byte("must-not-run")})
	coordinator.audit = recorder

	request := releaseRequest(envelopeNaming(t, "1"))
	if _, err := coordinator.Execute(context.Background(), request); err == nil {
		t.Fatal("Execute() returned no error: a non-revoked routing denial must still surface as a 403")
	}
	if recorder.drafts[0].Outcome != "routing-denied" {
		t.Fatalf("outcome = %q, want %q: a denied routing without a Reason must keep the original outcome",
			recorder.drafts[0].Outcome, "routing-denied")
	}
}
