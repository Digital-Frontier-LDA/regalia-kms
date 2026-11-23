package operations

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secp256k1ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

const cosmosContentType = "application/vnd.cosmos.tx+protobuf"

// cosmosCard is a fake token holding a real secp256k1 key. It signs what it is handed as a
// pre-hashed digest (CKM_ECDSA) and answers "public-key" with an SPKI, as the Nitrokey provider
// does. The fields let a test make it sign with one key and report another, corrupt its answer, or
// hand back the high-S twin.
type cosmosCard struct {
	signer   *secp256k1.PrivateKey
	reported *secp256k1.PrivateKey
	corrupt  bool
	highS    bool
	signed   [][]byte
	calls    []string
}

func newCosmosCard(t *testing.T) *cosmosCard {
	t.Helper()
	key := testSigner(t)
	return &cosmosCard{signer: key, reported: key}
}

func (card *cosmosCard) Execute(_ context.Context, _ registry.Route, operation, _, _ string, data, _ []byte) ([]byte, string, error) {
	card.calls = append(card.calls, operation)
	if operation == "public-key" {
		return secp256k1SPKI(card.reported.PubKey()), "application/pkix", nil
	}
	card.signed = append(card.signed, append([]byte(nil), data...))
	signature := secp256k1ecdsa.Sign(card.signer, data)
	r, s := signature.R(), signature.S()
	if card.highS {
		s.Negate()
	}
	rBytes, sBytes := r.Bytes(), s.Bytes()
	raw := append(rBytes[:], sBytes[:]...)
	if card.corrupt {
		raw[40] ^= 0x01
	}
	return raw, "application/octet-stream", nil
}

func testSigner(t *testing.T) *secp256k1.PrivateKey {
	t.Helper()
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func secp256k1SPKI(key *secp256k1.PublicKey) []byte {
	curve, _ := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 132, 0, 10})
	point := key.SerializeUncompressed()
	encoded, err := asn1.Marshal(spki{
		Algorithm: spkiAlgorithm{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, Parameters: asn1.RawValue{FullBytes: curve}},
		PublicKey: asn1.BitString{Bytes: point, BitLength: 8 * len(point)},
	})
	if err != nil {
		panic(err)
	}
	return encoded
}

func spkiPin(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// cosmosFixture is the cosmpy-generated reference SignDoc: canonical by construction.
func cosmosFixture(t *testing.T) []byte {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("..", "policy", "testdata", "signdoc-akashnet2-msgsend.hex"))
	if err != nil {
		t.Fatal(err)
	}
	signDoc, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	return signDoc
}

func cosmosRoute(pin string) registry.Route {
	return registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "secp256k1",
		PolicyID: "wallet", Binding: registry.Binding{DeviceID: "hsm-1", PublicKeySHA256: pin}}
}

func cosmosRequest(signDoc []byte) api.Request {
	request := operationRequest()
	request.Operation, request.Format, request.ContentType, request.Data = "sign", "", cosmosContentType, signDoc
	return request
}

func allowingCoordinator(t *testing.T, route registry.Route, hardware Hardware) (*Coordinator, *fakeAudit) {
	t.Helper()
	recorder := &fakeAudit{}
	semantic := &fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "wallet", Rule: "allow"}}
	coordinator, err := New(fakeAuthorizer{allowed: true}, &fakeRouter{route: route}, semantic, recorder, directRunner{}, hardware, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, recorder
}

func outcomes(recorder *fakeAudit) []string {
	var named []string
	for _, draft := range recorder.drafts {
		named = append(named, draft.Outcome)
	}
	return named
}

// --- an ECDSA verifier written for this test alone -------------------------------------------
//
// Textbook secp256k1 ECDSA in math/big, affine coordinates. It shares no code with the signer
// (decred) or with verifyCosmosSignature, so a signature it accepts is one any conforming
// verifier accepts, and a digest computed over anything but the canonical bytes fails it.

var (
	textbookP  = mustHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
	textbookN  = mustHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	textbookGx = mustHex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	textbookGy = mustHex("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
)

func mustHex(text string) *big.Int {
	value, ok := new(big.Int).SetString(text, 16)
	if !ok {
		panic(text)
	}
	return value
}

type textbookPoint struct{ x, y *big.Int } // nil x is the point at infinity

func textbookAdd(a, b textbookPoint) textbookPoint {
	if a.x == nil {
		return b
	}
	if b.x == nil {
		return a
	}
	p := textbookP
	var slope *big.Int
	if a.x.Cmp(b.x) == 0 {
		if new(big.Int).Mod(new(big.Int).Add(a.y, b.y), p).Sign() == 0 {
			return textbookPoint{}
		}
		numerator := new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(a.x, a.x))
		denominator := new(big.Int).ModInverse(new(big.Int).Mul(big.NewInt(2), a.y), p)
		slope = new(big.Int).Mod(new(big.Int).Mul(numerator, denominator), p)
	} else {
		numerator := new(big.Int).Sub(b.y, a.y)
		denominator := new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Sub(b.x, a.x), p), p)
		slope = new(big.Int).Mod(new(big.Int).Mul(numerator, denominator), p)
	}
	x := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(slope, slope), a.x), b.x), p)
	y := new(big.Int).Mod(new(big.Int).Sub(new(big.Int).Mul(slope, new(big.Int).Sub(a.x, x)), a.y), p)
	return textbookPoint{x, y}
}

func textbookMul(k *big.Int, point textbookPoint) textbookPoint {
	result := textbookPoint{}
	for bit := k.BitLen() - 1; bit >= 0; bit-- {
		result = textbookAdd(result, result)
		if k.Bit(bit) == 1 {
			result = textbookAdd(result, point)
		}
	}
	return result
}

// textbookVerify checks a raw r||s signature over sha256(message) under the uncompressed point in
// an SPKI, the way the Cosmos SDK's secp256k1 VerifySignature does: low S only.
func textbookVerify(t *testing.T, publicKey, message, signature []byte) bool {
	t.Helper()
	var info struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(publicKey, &info); err != nil || len(info.PublicKey.Bytes) != 65 || info.PublicKey.Bytes[0] != 4 {
		t.Fatalf("public key is not an uncompressed EC SPKI: %v", err)
	}
	q := textbookPoint{new(big.Int).SetBytes(info.PublicKey.Bytes[1:33]), new(big.Int).SetBytes(info.PublicKey.Bytes[33:])}
	if len(signature) != 64 {
		return false
	}
	r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
	n := textbookN
	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(n) >= 0 || s.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		return false
	}
	digest := sha256.Sum256(message)
	z := new(big.Int).SetBytes(digest[:])
	w := new(big.Int).ModInverse(s, n)
	u1, u2 := new(big.Int).Mod(new(big.Int).Mul(z, w), n), new(big.Int).Mod(new(big.Int).Mul(r, w), n)
	point := textbookAdd(textbookMul(u1, textbookPoint{textbookGx, textbookGy}), textbookMul(u2, q))
	return point.x != nil && new(big.Int).Mod(point.x, n).Cmp(r) == 0
}

// TestCosmosSignatureVerifiesIndependently (regalia-kms-35b AC2): what the daemon returns for a
// canonical SignDoc verifies, under the object's registered key, against sha256 of the canonical
// bytes, by a verifier that shares nothing with the signing path.
func TestCosmosSignatureVerifiesIndependently(t *testing.T) {
	card := newCosmosCard(t)
	registered := secp256k1SPKI(card.signer.PubKey())
	signDoc := cosmosFixture(t)
	coordinator, recorder := allowingCoordinator(t, cosmosRoute(spkiPin(registered)), card)
	result, err := coordinator.Execute(context.Background(), cosmosRequest(signDoc))
	if err != nil {
		t.Fatalf("a canonical SignDoc signed by the registered key was refused: %v (audit %v)", err, outcomes(recorder))
	}
	if !textbookVerify(t, registered, signDoc, result.Data) {
		t.Fatal("DEFECT: the signature the daemon returned does not verify against sha256 of the canonical SignDoc under the registered key")
	}
	if got := outcomes(recorder); len(got) != 2 || got[1] != "success" {
		t.Fatalf("audit outcomes = %v, want authorized then success", got)
	}
}

// TestCosmosSignatureFromWrongKeyIsNotSuccess and the cases beside it (regalia-kms-35b AC4): a
// signature that does not verify under the registered key is an error, audited as
// "signature-unverified", with no bytes returned and no success record.
func TestCosmosSignatureFromWrongKeyIsNotSuccess(t *testing.T) {
	other, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	for name, setup := range map[string]func(card *cosmosCard) (pin string){
		// The card signs with one key and reports another, and the binding pins the one reported.
		"signed by another key": func(card *cosmosCard) string {
			card.reported = other
			return spkiPin(secp256k1SPKI(other.PubKey()))
		},
		// The card reports the key it signs with, but that is not the commissioned key.
		"public key is not the pinned key": func(card *cosmosCard) string {
			return spkiPin(secp256k1SPKI(other.PubKey()))
		},
		// A binding with no key pin (DevAut-only) still has its signature checked.
		"signed by another key, no pin": func(card *cosmosCard) string {
			card.reported = other
			return ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			card := newCosmosCard(t)
			assertUnverified(t, card, setup(card))
		})
	}
}

func TestCosmosCorruptedSignatureIsNotSuccess(t *testing.T) {
	for name, setup := range map[string]func(card *cosmosCard){
		"a flipped bit": func(card *cosmosCard) { card.corrupt = true },
		// Valid ECDSA, refused by every Cosmos node: the daemon must not call it success either.
		"the high-S twin": func(card *cosmosCard) { card.highS = true },
	} {
		t.Run(name, func(t *testing.T) {
			card := newCosmosCard(t)
			setup(card)
			assertUnverified(t, card, spkiPin(secp256k1SPKI(card.signer.PubKey())))
		})
	}
}

func assertUnverified(t *testing.T, card *cosmosCard, pin string) {
	t.Helper()
	coordinator, recorder := allowingCoordinator(t, cosmosRoute(pin), card)
	result, err := coordinator.Execute(context.Background(), cosmosRequest(cosmosFixture(t)))
	if err == nil || len(result.Data) != 0 {
		t.Fatalf("DEFECT: a signature that does not verify under the registered key was returned as success (%d bytes, err=%v, audit %v)", len(result.Data), err, outcomes(recorder))
	}
	failure, ok := err.(*api.Failure)
	if !ok || failure.Code != "INTERNAL" || failure.Retryable {
		t.Fatalf("error = %#v, want a non-retryable INTERNAL", err)
	}
	got := outcomes(recorder)
	if len(got) != 2 || got[0] != "authorized" || got[1] != "signature-unverified" {
		t.Fatalf("audit outcomes = %v, want authorized then signature-unverified", got)
	}
}

// TestCosmosVerificationRefusesAKeyTypeItCannotCheck: a Cosmos route on an algorithm the daemon
// has no verifier for fails closed rather than being reported as checked.
func TestCosmosVerificationRefusesAKeyTypeItCannotCheck(t *testing.T) {
	card := newCosmosCard(t)
	route := cosmosRoute("")
	route.Algorithm = "ed25519"
	coordinator, recorder := allowingCoordinator(t, route, card)
	if result, err := coordinator.Execute(context.Background(), cosmosRequest(cosmosFixture(t))); err == nil || len(result.Data) != 0 {
		t.Fatalf("an unverifiable key type was reported as success: %v", err)
	}
	if got := outcomes(recorder); len(got) != 2 || got[1] != "signature-unverified" {
		t.Fatalf("audit outcomes = %v", got)
	}
}

type recordingReservations struct{ reserved []policy.Reservation }

func (state *recordingReservations) Reserve(_ context.Context, reservation policy.Reservation) error {
	state.reserved = append(state.reserved, reservation)
	return nil
}

// TestAReorderedSignDocIsRefusedBeforeTheToken (regalia-kms-35b AC3, refuse route): the reference
// transaction with its top-level fields reversed means the same thing and hashes differently. The
// real policy engine admits the transaction it describes, so only the canonical check stands
// between it and the token: it must be refused as malformed, the token never called, and no
// reservation (nonce, sequence, quota) spent.
func TestAReorderedSignDocIsRefusedBeforeTheToken(t *testing.T) {
	signDoc := cosmosFixture(t)
	transaction, err := policy.ParseCosmosSignDoc(signDoc)
	if err != nil {
		t.Fatal(err)
	}
	// Split the four top-level fields by hand: a one-byte tag, then a varint (field 4) or a varint
	// length and that many bytes.
	readVarint := func(at int) (uint64, int) {
		var value uint64
		for index := 0; at+index < len(signDoc) && index < 10; index++ {
			value |= uint64(signDoc[at+index]&0x7f) << (7 * index)
			if signDoc[at+index]&0x80 == 0 {
				return value, index + 1
			}
		}
		t.Fatal("fixture carries a malformed varint")
		return 0, 0
	}
	var fields [][]byte
	for offset := 0; offset < len(signDoc); {
		value, consumed := readVarint(offset + 1)
		end := offset + 1 + consumed
		if signDoc[offset]&7 == 2 {
			end += int(value)
		}
		fields = append(fields, signDoc[offset:end])
		offset = end
	}
	if len(fields) != 4 {
		t.Fatalf("fixture has %d top-level fields, want 4", len(fields))
	}
	reordered := append(append(append(append([]byte(nil), fields[3]...), fields[2]...), fields[1]...), fields[0]...)
	if len(reordered) != len(signDoc) {
		t.Fatal("the reordered document is not a permutation of the fixture")
	}
	message, fee := transaction.Messages[0], transaction.Fee[0]
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	state := &recordingReservations{}
	engine, err := policy.New([]policy.Policy{{
		ID: "wallet", ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production",
		Operation: "sign", Algorithm: "secp256k1", ContentTypes: []string{cosmosContentType},
		MaxPayloadBytes: 10000, MaxFuture: time.Minute, Cosmos: &policy.CosmosPolicy{
			ChainIDs: []string{transaction.ChainID}, AccountNumbers: []uint64{transaction.AccountNumber},
			MessageTypes: []string{message.Type}, Sources: []string{message.Source}, Destinations: []string{message.Destination},
			MaxGasLimit: transaction.GasLimit, MaxFee: map[string]uint64{fee.Denom: fee.Amount},
			MaxPerTransaction: map[string]uint64{message.Amounts[0].Denom: message.Amounts[0].Amount},
			MaxPerDay:         map[string]uint64{message.Amounts[0].Denom: message.Amounts[0].Amount}},
	}}, state, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	card := newCosmosCard(t)
	recorder := &fakeAudit{}
	coordinator, err := New(fakeAuthorizer{allowed: true}, &fakeRouter{route: cosmosRoute(spkiPin(secp256k1SPKI(card.signer.PubKey())))}, engine, recorder, directRunner{}, card, "sha256:policy", nil, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	request := cosmosRequest(reordered)
	request.Context.ExpiresAt = now.Add(30 * time.Second)
	_, err = coordinator.Execute(context.Background(), request)
	failure, ok := err.(*api.Failure)
	if !ok || failure.Status != 400 || failure.Code != "INVALID_ARGUMENT" {
		t.Fatalf("DEFECT: a reordered SignDoc was not refused as malformed: err=%v, token calls %v, audit %v", err, card.calls, outcomes(recorder))
	}
	if len(card.calls) != 0 || len(state.reserved) != 0 {
		t.Fatalf("DEFECT: a refused SignDoc reached the token (%v) or spent a reservation (%d)", card.calls, len(state.reserved))
	}
	if got := outcomes(recorder); len(got) != 1 || got[0] != "policy-cosmos-malformed" {
		t.Fatalf("audit outcomes = %v, want policy-cosmos-malformed", got)
	}
	// The control: the canonical order, same engine shape, is signed and reserves once.
	request = cosmosRequest(signDoc)
	request.Context.ExpiresAt = now.Add(30 * time.Second)
	if _, err := coordinator.Execute(context.Background(), request); err != nil || len(state.reserved) != 1 {
		t.Fatalf("the canonical SignDoc was not signed (err=%v, reservations %d): the refusal above proves nothing", err, len(state.reserved))
	}
}
