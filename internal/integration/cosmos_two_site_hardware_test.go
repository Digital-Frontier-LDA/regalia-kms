package integration_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
)

// TestCosmosSigningFailsOverBetweenTwoCards is the two-site version of
// TestCosmosSigningAcrossAnActivePassivePromotion. That test ran the promotion on ONE card, so "the
// promoted site" was the same token. Here each site has its own genuine card (REQUIREMENTS A3/A5: the
// same wallet key imported at each site under that site's OWN DKEK), and the promotion moves signing
// from one physical token to the other.
//
//	0 both cards expose the SAME public key: one wallet, two custodial devices
//	1 site A (epoch 7) reserves account sequence 41 and signs it on card A
//	2 promotion: site B (epoch 8) reserves sequence 42 and signs it on card B; the signature verifies
//	  under the one wallet key, so the chain sees no change of signer
//	3 the next sequence must be the NEXT one, and a spent one cannot be reserved again
//	4 THE POINT: site A still holds a working card and a valid PIN; its reservation at the stale
//	  epoch 7 is refused, so two sites can never spend the same sequence
//
// The journal stands in for the fencing authority's ledger shared by both sites (internal/fencing
// proves the lease rule in isolation). Driven by e2e/nitrokey-two-site-failover-drill.sh.
func TestCosmosSigningFailsOverBetweenTwoCards(t *testing.T) {
	module, objectID := os.Getenv("REGALIA_TWOSITE_MODULE"), os.Getenv("REGALIA_TWOSITE_OBJECT_ID")
	slotA, pinA := os.Getenv("REGALIA_TWOSITE_SLOT_A"), os.Getenv("REGALIA_TWOSITE_PIN_A")
	slotB, pinB := os.Getenv("REGALIA_TWOSITE_SLOT_B"), os.Getenv("REGALIA_TWOSITE_PIN_B")
	if module == "" || objectID == "" || slotA == "" || pinA == "" || slotB == "" || pinB == "" {
		t.Skip("driven by e2e/nitrokey-two-site-failover-drill.sh")
	}
	if slotA == slotB {
		t.Fatal("the two sites must be two different cards")
	}
	for _, tool := range []string{"pkcs11-tool", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is required", tool)
		}
	}
	siteA := &pkcs11Card{t: t, module: module, slot: slotA, objectID: objectID, pin: pinA}
	siteB := &pkcs11Card{t: t, module: module, slot: slotB, objectID: objectID, pin: pinB}

	// 0 ONE wallet, two devices.
	readPublic := func(c *pkcs11Card) []byte {
		out := filepath.Join(t.TempDir(), "pub.der")
		c.run(t, "--login", "--pin", "env:PKCS11_PIN", "--read-object", "--type", "pubkey", "--id", c.objectID, "--output-file", out)
		der, err := os.ReadFile(out)
		if err != nil || len(der) == 0 {
			t.Fatalf("read the public key on slot %s: %v", c.slot, err)
		}
		return der
	}
	if !bytes.Equal(readPublic(siteA), readPublic(siteB)) {
		t.Fatal("the two cards do not hold the same wallet key: a failover would change the signer")
	}
	t.Log("0 both cards expose the same secp256k1 public key")

	journal := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state, err := policy.OpenFileState(journal)
	if err != nil {
		t.Fatalf("open policy state: %v", err)
	}
	defer state.Close()
	const (
		epochA  = uint64(7)
		epochB  = uint64(8)
		account = "akashnet-2/42"
	)
	ctx := context.Background()

	// 1 site A, active. Reserve first: a signature is made only for a reserved sequence.
	if err := state.Reserve(ctx, reservationAt(epochA, "two-site-nonce-0041", account, 41)); err != nil {
		t.Fatalf("site A's reservation at its held epoch was refused: %v", err)
	}
	sig41 := siteA.sign(t, "signdoc-sequence-41")
	siteA.verify(t, "signdoc-sequence-41", sig41)
	siteB.verify(t, "signdoc-sequence-41", sig41) // the standby's key verifies it too: one wallet
	t.Log("1 site A signed sequence 41 on its card")

	// 2 promotion to site B.
	if err := state.Reserve(ctx, reservationAt(epochB, "two-site-nonce-0042", account, 42)); err != nil {
		t.Fatalf("site B's reservation of the NEXT sequence at the promoted epoch was refused: %v", err)
	}
	sig42 := siteB.sign(t, "signdoc-sequence-42")
	siteB.verify(t, "signdoc-sequence-42", sig42)
	siteA.verify(t, "signdoc-sequence-42", sig42)
	t.Log("2 site B, promoted, signed sequence 42 on ITS card; the signature verifies under the same wallet key")

	// 3 sequence discipline across the failover.
	if err := state.Reserve(ctx, reservationAt(epochB, "two-site-nonce-0044", account, 44)); err == nil {
		t.Fatal("a reservation that SKIPPED sequence 43 was accepted")
	}
	if err := state.Reserve(ctx, reservationAt(epochB, "two-site-nonce-0042b", account, 42)); err == nil {
		t.Fatal("sequence 42 was reserved twice")
	}

	// 4 the demoted site, with a working card and a valid PIN, is refused at its stale epoch.
	err = state.Reserve(ctx, reservationAt(epochA, "two-site-nonce-0043", account, 43))
	if err == nil {
		t.Fatal("DEFECT: site A reserved sequence 43 at the SUPERSEDED epoch — two sites could sign the same account")
	}
	t.Logf("4 demoted site A refused at stale epoch %d: %v", epochA, err)

	summary, err := policy.VerifyState(journal)
	if err != nil {
		t.Fatalf("verify state: %v", err)
	}
	if summary.HeadEpoch != epochB || summary.Reservations != 2 {
		t.Fatalf("journal head epoch %d with %d reservations; want %d and exactly 2", summary.HeadEpoch, summary.Reservations, epochB)
	}
	t.Logf("journal head: epoch %d, %d reservations", summary.HeadEpoch, summary.Reservations)
}
