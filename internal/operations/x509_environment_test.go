package operations

import (
	"context"
	"net/http"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
)

func TestCoordinatorX509RequiresDevelopmentRegistryEnvironment(t *testing.T) {
	for _, environment := range []string{"production", "staging", "", "unknown"} {
		name := environment
		if name == "" {
			name = "empty"
		}
		for _, kind := range []string{"certificate", "crl"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				f := newX509CoordinatorFixture(t)
				data := f.leaf(t, nil)
				if kind == "crl" {
					data = f.crl(t)
				}
				f.router.route.Environment = environment
				refused := f.request(data, "application/vnd.regalia.x509-tbs")
				result, err := f.coordinator.Execute(context.Background(), refused)
				x509AssertCoordinatorFailure(t, result, err, "DENIED", http.StatusForbidden, false)
				if f.hardware.calls != 0 || len(f.auditor.drafts) != 1 {
					t.Fatal("non-development registry object reached signing or lost denial audit")
				}
				draft := f.auditor.drafts[0]
				if draft.Decision != "deny" || draft.Outcome != "policy-DENIED:x509-key" || draft.X509ProfileID != f.profile.ID || draft.ArtifactKind != kind || draft.KeyFingerprint != f.router.route.Binding.PublicKeySHA256 || draft.PayloadDigest == "" {
					t.Fatal("registry environment refusal lost server-derived signing intent")
				}
				summary, err := policy.VerifyState(f.path)
				if err != nil || summary.Reservations != 0 {
					t.Fatal("registry environment refusal spent a durable reservation", summary, err)
				}
				// Caller-supplied development context cannot authorize another registry
				// environment. Restoring the trusted route must leave the refused nonce
				// and the artifact's independent count available.
				f.router.route.Environment = "development"
				valid := f.request(data, "application/vnd.regalia.x509-tbs")
				valid.Context.Nonce = refused.Context.Nonce
				if _, err := f.coordinator.Execute(context.Background(), valid); err != nil || f.hardware.calls != 1 {
					t.Fatal("registry environment refusal consumed nonce or signing capacity", err)
				}
				summary, err = policy.VerifyState(f.path)
				if err != nil || summary.Reservations != 1 {
					t.Fatal("valid development signing lacks its durable reservation", summary, err)
				}
			})
		}
	}
}
