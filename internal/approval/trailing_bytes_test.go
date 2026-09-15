package approval

// ONE DOCUMENT, NOTHING AFTER IT -- the check LoadKeySet makes, which Verify's decoder skipped.
//
// approval.go has two json.NewDecoder sites. The key-set loader has the trailing-data check, with
// a comment explaining why. The approval-EVIDENCE decoder did not, so a header and the same
// header with bytes appended counted the same approvers. Measured before the fix: 392 and 420
// characters, one identical result.
//
// This is not an approver bypass and the test does not claim one: every approval is
// signature-verified against the binding, so a rider adds nobody. The exposure is identity -- an
// audit record naming an approval header by digest no longer names the evidence that was counted,
// and MaxHeaderBytes bounds how much can be appended without forbidding it.
//
// A per-FILE sweep for this defect reported approval.go as covered, because the file contains a
// trailing-data check; it is the wrong unit. Counting decoders is what found this one.

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestVerifyRefusesAnythingAppendedAfterTheApprovalArray(t *testing.T) {
	target := binding()
	id, private, public := approver(t, "spiffe://regalia/approver/a0")
	set := NewKeySet(map[string]ed25519.PublicKey{id: public})
	clean := header(t, sign(t, id, private, target, target))

	// ANCHOR: the clean header counts its signer, so a refusal below is about the appended bytes
	// and not about the evidence. Anchor, not a gate -- acceptance is covered elsewhere.
	if got := set.Verify(clean, target); len(got) != 1 || got[0] != id {
		t.Fatalf("anchor: the clean header must count %s, got %v", id, got)
	}

	decoded, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		t.Fatal(err)
	}
	for _, rider := range []struct {
		name   string
		suffix string
	}{
		{"a second JSON document", ` {"attacker":"rider"}`},
		{"a second array of approvals", ` [{"approver_id":"spiffe://regalia/approver/zz"}]`},
		{"a bare scalar", ` 1`},
	} {
		t.Run(rider.name, func(t *testing.T) {
			appended := base64.StdEncoding.EncodeToString(append(append([]byte(nil), decoded...), []byte(rider.suffix)...))
			if appended == clean {
				t.Fatal("fixture: the two headers must differ")
			}
			if len(appended) > MaxHeaderBytes {
				t.Fatalf("fixture: %d bytes exceeds MaxHeaderBytes (%d), so the size guard would "+
					"refuse this and the trailing check would never be reached", len(appended), MaxHeaderBytes)
			}
			// Verify returns approvers, never an error -- an approval that fails a check is not an
			// error, it is simply not an approver. So the assertion is the count, not a message.
			if got := set.Verify(appended, target); len(got) != 0 {
				t.Fatalf("Verify counted %v from a %d-character header where %d were signed: two "+
					"byte-different headers now count the same approvers, so a digest of the "+
					"evidence names nothing", got, len(appended), len(clean))
			}
		})
	}
}
