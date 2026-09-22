package integration_test

import (
	"context"
	"crypto/sha256"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
)

// TestCosmosSigningAcrossAnActivePassivePromotion is regalia#435's last unchecked hardware line:
// "Repeat after active/passive promotion and verify the next account sequence plus stale-epoch
// refusal."
//
// internal/fencing and internal/policy already prove the epoch rule in isolation, and
// failover_drill_test.go runs the sub-drills that need no hardware. What is missing, and what #435
// asks for, is the sequence exercised END TO END with a REAL token in it: a Cosmos digest signed
// on the card before a promotion, the next sequence signed on the same card after it, and the old
// epoch refused afterwards. The parts being individually correct is not the same claim as having
// done it.
//
// Gated. Skips without a card, because the assertion is about one.
//
//	REGALIA_COSMOS_PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
//	REGALIA_COSMOS_PKCS11_SLOT=12 REGALIA_COSMOS_PKCS11_OBJECT_ID=31 \
//	REGALIA_COSMOS_PKCS11_PIN=… go test ./internal/integration/ -run Promotion -v
func TestCosmosSigningAcrossAnActivePassivePromotion(t *testing.T) {
	module := os.Getenv("REGALIA_COSMOS_PKCS11_MODULE")
	objectID := os.Getenv("REGALIA_COSMOS_PKCS11_OBJECT_ID")
	pin := os.Getenv("REGALIA_COSMOS_PKCS11_PIN")
	slot := os.Getenv("REGALIA_COSMOS_PKCS11_SLOT")
	if module == "" || objectID == "" || pin == "" || slot == "" {
		t.Skip("set REGALIA_COSMOS_PKCS11_MODULE, _SLOT, _OBJECT_ID and _PIN")
	}
	if _, err := exec.LookPath("pkcs11-tool"); err != nil {
		t.Skip("pkcs11-tool is not installed")
	}

	card := &pkcs11Card{t: t, module: module, slot: slot, objectID: objectID, pin: pin}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is needed to verify a secp256k1 signature (as e2e/ does)")
	}

	journal := filepath.Join(t.TempDir(), "policy-state.jsonl")
	state, err := policy.OpenFileState(journal)
	if err != nil {
		t.Fatalf("open policy state: %v", err)
	}
	defer state.Close()

	const (
		epochBefore = uint64(7)
		epochAfter  = uint64(8)
		account     = "akashnet-2/42"
	)
	ctx := context.Background()

	// --- before the promotion ------------------------------------------------------------------
	// Account sequence 41, signed on the card, reserved under the epoch this site holds.
	sigBefore := card.sign(t, "signdoc-sequence-41")
	if err := state.Reserve(ctx, reservationAt(epochBefore, "promotion-drill-nonce-0041", account, 41)); err != nil {
		t.Fatalf("reservation at the held epoch was refused: %v", err)
	}
	card.verify(t, "signdoc-sequence-41", sigBefore)

	// --- the promotion -------------------------------------------------------------------------
	// A new site takes the lease. Nothing about the CARD changes — it still holds the key and the
	// PIN still works — which is exactly why the journal has to be the thing that notices.
	sigAfter := card.sign(t, "signdoc-sequence-42")
	if err := state.Reserve(ctx, reservationAt(epochAfter, "promotion-drill-nonce-0042", account, 42)); err != nil {
		t.Fatalf("the NEXT account sequence was refused at the promoted epoch: %v", err)
	}
	card.verify(t, "signdoc-sequence-42", sigAfter)

	// --- the next sequence must be the NEXT one --------------------------------------------------
	// Skipping one would let a transaction be signed for a sequence the chain has not reached,
	// which sits in the mempool and reorders the ones after it.
	if err := state.Reserve(ctx, reservationAt(epochAfter, "promotion-drill-nonce-0044", account, 44)); err == nil {
		t.Fatal("a reservation that SKIPPED account sequence 43 was accepted")
	}
	// And replaying the one already spent must not be accepted either.
	if err := state.Reserve(ctx, reservationAt(epochAfter, "promotion-drill-nonce-0042b", account, 42)); err == nil {
		t.Fatal("account sequence 42 was reserved twice — that is a double-spend of one sequence")
	}

	// --- the stale epoch ------------------------------------------------------------------------
	// THE POINT OF THE WHOLE ARM. The demoted site still holds a working card and a valid PIN; the
	// only thing stopping it signing against the same account is that its lease is stale. If this
	// is accepted, two sites can spend the same account sequence.
	err = state.Reserve(ctx, reservationAt(epochBefore, "promotion-drill-nonce-0043", account, 43))
	if err == nil {
		t.Fatal("a reservation at the SUPERSEDED epoch was accepted — a demoted site could sign " +
			"against the same account as the promoted one")
	}
	t.Logf("stale epoch refused: %v", err)

	// The journal must show the advance, not merely have refused the old one.
	summary, err := policy.VerifyState(journal)
	if err != nil {
		t.Fatalf("verify state: %v", err)
	}
	if summary.HeadEpoch != epochAfter {
		t.Fatalf("head epoch = %d, want %d after promotion", summary.HeadEpoch, epochAfter)
	}
	if summary.Reservations != 2 {
		t.Fatalf("reservations = %d, want exactly the two that were accepted", summary.Reservations)
	}
	t.Logf("journal head: epoch %d, %d reservations, journal sequence %d",
		summary.HeadEpoch, summary.Reservations, summary.HeadSequence)
}

func reservationAt(epoch uint64, nonce, account string, sequence uint64) policy.Reservation {
	return policy.Reservation{
		PolicyID: "wallet", ObjectID: "wallet", Epoch: epoch,
		Principal: "ops", Nonce: nonce,
		UTCDate:     time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC).Format("2006-01-02"),
		Amounts:     map[string]uint64{"uakt": 1000},
		DailyCaps:   map[string]uint64{"uakt": 1000000},
		Sequence:    &sequence,
		SequenceKey: account,
	}
}

// pkcs11Card drives the real token through pkcs11-tool, the same way
// e2e/cosmos-hardware-sign-verify.sh does, so this test and that script agree about what a
// hardware signature is.
type pkcs11Card struct {
	t                           *testing.T
	module, slot, objectID, pin string
}

func (c *pkcs11Card) run(t *testing.T, args ...string) []byte {
	t.Helper()
	full := append([]string{"--module", c.module, "--slot", c.slot}, args...)
	cmd := exec.Command("pkcs11-tool", full...)
	cmd.Env = append(os.Environ(), "PKCS11_PIN="+c.pin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("pkcs11-tool %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (c *pkcs11Card) sign(t *testing.T, message string) []byte {
	t.Helper()
	dir := t.TempDir()
	digest := sha256.Sum256([]byte(message))
	in := filepath.Join(dir, "digest.bin")
	out := filepath.Join(dir, "sig.raw")
	if err := os.WriteFile(in, digest[:], 0o600); err != nil {
		t.Fatal(err)
	}
	c.run(t, "--login", "--pin", "env:PKCS11_PIN", "--sign", "--mechanism", "ECDSA",
		"--id", c.objectID, "--input-file", in, "--output-file", out)
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 64 {
		t.Fatalf("signature is %d bytes, expected raw r||s", len(raw))
	}
	return raw
}

// verify checks the card's signature against the card's OWN public key, read back from the token.
//
// It does this the way e2e/cosmos-hardware-sign-verify.sh does — python3 with `cryptography` —
// because the wallet curve is secp256k1 and crypto/elliptic has no secp256k1. Reimplementing the
// curve here to avoid a subprocess would be a second implementation of the thing being checked,
// which is the mistake internal/policy/testdata/README.md records about hand-written encoders.
//
// A signature nobody checks is not evidence, and the failure this guards against is specific: a
// promotion that silently left the card unable to sign for the account would otherwise show up as
// a green journal.
func (c *pkcs11Card) verify(t *testing.T, message string, signature []byte) {
	t.Helper()
	dir := t.TempDir()
	digest := sha256.Sum256([]byte(message))
	digestPath := filepath.Join(dir, "digest.bin")
	sigPath := filepath.Join(dir, "sig.raw")
	pubPath := filepath.Join(dir, "pub.der")
	if err := os.WriteFile(digestPath, digest[:], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, signature, 0o600); err != nil {
		t.Fatal(err)
	}
	c.run(t, "--login", "--pin", "env:PKCS11_PIN", "--read-object", "--type", "pubkey",
		"--id", c.objectID, "--output-file", pubPath)

	script := `
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, Prehashed
pub = serialization.load_der_public_key(open(sys.argv[1], "rb").read())
digest = open(sys.argv[2], "rb").read()
raw = open(sys.argv[3], "rb").read()
r = int.from_bytes(raw[:32], "big")
s = int.from_bytes(raw[32:], "big")
pub.verify(encode_dss_signature(r, s), digest, ec.ECDSA(Prehashed(hashes.SHA256())))
print(pub.curve.name)
`
	cmd := exec.Command("python3", "-c", script, pubPath, digestPath, sigPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: the card's signature did not verify against the card's own public key: %v\n%s",
			message, err, out)
	}
	t.Logf("%s: signature verifies against the token's %s key", message, strings.TrimSpace(string(out)))

	// LOW-S is what a Cosmos node requires; a raw token signature is high-S about half the time.
	// Recorded, not required — normalising is internal/backend/nitrokey/lows.go's job, and this
	// arm is about the promotion sequence, not about that fix.
	s := new(big.Int).SetBytes(signature[32:])
	if half := new(big.Int).Rsh(secp256k1Order(), 1); s.Cmp(half) > 0 {
		t.Logf("%s: token returned HIGH-S (a Cosmos node needs the normalised form)", message)
	}
}

func secp256k1Order() *big.Int {
	n, ok := new(big.Int).SetString(
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	if !ok {
		panic("secp256k1 order constant is not hexadecimal")
	}
	return n
}
