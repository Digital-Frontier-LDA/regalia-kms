package operations

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

func TestCoordinatorMalformedX509TBSRejectedBeforePolicyAndHardware(t *testing.T) {
	now := time.Now().UTC()
	router := &fakeRouter{route: registry.Route{ObjectID: "synthetic-ca", Purpose: "internal-pki", Environment: "development", Algorithm: "p256", PolicyID: "synthetic-profile-policy"}}
	semantic := &fakePolicy{decision: policy.Decision{Allowed: true}}
	recorder := &fakeAudit{}
	hardware := &fakeHardware{output: []byte("must-not-escape")}
	coordinator, err := New(fakeAuthorizer{allowed: true}, router, semantic, recorder, directRunner{}, hardware, "sha256:policy", nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	request := api.Request{RequestID: "018f0000-0000-7000-8000-000000000001", Principal: "spiffe://regalia/workload/synthetic-pki", ObjectID: "synthetic-ca", Operation: "sign", ContentType: "application/vnd.regalia.x509-tbs", Data: []byte{0x30, 0x80, 0x00, 0x00}, Context: api.OperationContext{Environment: "development", Purpose: "internal-pki", ExpiresAt: now.Add(time.Minute), Nonce: "nonce_000000000001"}}
	result, err := coordinator.Execute(context.Background(), request)
	var failure *api.Failure
	if len(result.Data) != 0 || !errors.As(err, &failure) || failure.Code != "INVALID_ARGUMENT" || failure.Status != http.StatusBadRequest || failure.Retryable || semantic.calls != 0 || hardware.calls != 0 {
		t.Fatal("malformed TBS reached policy or token instead of a terminal parser refusal", err, semantic.calls, hardware.calls)
	}
	if len(recorder.drafts) != 1 || recorder.drafts[0].Decision != "deny" {
		t.Fatal("malformed TBS did not produce a denial audit")
	}
}
