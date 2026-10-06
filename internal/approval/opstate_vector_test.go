package approval

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// The approvals behind a spend (deploy/baremetal/opstate.py, ADR-0002 D32) are re-verified by the collector in
// Python, over opstate.binding_bytes. That is only sound if it is byte for byte this package's CanonicalBytes: every
// approval the vector accepts must verify here, under the same keys, over the Binding built from the spend.
func TestOpstateVectorApprovalsVerifyOverThisPackagesBinding(t *testing.T) {
	raw, err := os.ReadFile("../../tests/vectors/opstate-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		PayloadHex   string `json:"payload_hex"`
		ApproverSets map[string]struct {
			Approvers map[string]string `json:"approvers"`
		} `json:"approver_sets"`
		ApprovalChecks []struct {
			Name   string `json:"name"`
			Accept bool   `json:"accept"`
			Spend  struct {
				ObjectID    string `json:"object_id"`
				Purpose     string `json:"purpose"`
				Environment string `json:"environment"`
				ExpiresAt   string `json:"expires_at"`
				ApproverSet string `json:"approver_set"`
			} `json:"spend"`
			Approvals []Approval `json:"approvals"`
		} `json:"approval_checks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	payload, err := hex.DecodeString(doc.PayloadHex)
	if err != nil {
		t.Fatal(err)
	}
	verified := 0
	for _, c := range doc.ApprovalChecks {
		if !c.Accept {
			continue
		}
		expires, err := time.Parse(time.RFC3339, c.Spend.ExpiresAt)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		for _, a := range c.Approvals {
			binding := Binding{ObjectID: c.Spend.ObjectID, Purpose: c.Spend.Purpose, Environment: c.Spend.Environment,
				Nonce: a.Nonce, ExpiresAt: expires, Payload: payload}
			key, _ := hex.DecodeString(doc.ApproverSets[c.Spend.ApproverSet].Approvers[a.ApproverID])
			sig, _ := base64.StdEncoding.DecodeString(a.Signature)
			if len(key) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(key), binding.CanonicalBytes(), sig) {
				t.Fatalf("%s: %s's approval does not verify over this package's Binding: opstate.binding_bytes has drifted", c.Name, a.ApproverID)
			}
			if a.PayloadDigest != binding.PayloadDigest() {
				t.Fatalf("%s: the payload digest differs from this package's", c.Name)
			}
			verified++
		}
	}
	if verified < 3 {
		t.Fatalf("only %d approvals verified: the vector lost its accepted cases", verified)
	}
}
