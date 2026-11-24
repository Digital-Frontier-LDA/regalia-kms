package operations

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	api "github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// The review of PR #774 (regalia-kms-35b, council items A and B, review findings 1-4): the
// signature must verify under a key the token does not choose -- the SignDoc's own signer key, or
// the binding's pin -- and every guard in the verifier needs a test that fails without it.

const (
	secp256k1KeyType = "/cosmos.crypto.secp256k1.PubKey"
	secp256r1KeyType = "/cosmos.crypto.secp256r1.PubKey"
)

// --- a protobuf writer for this test alone: just enough to put a public key in a SignerInfo. ---

type pbField struct {
	number uint64
	wire   uint64
	value  []byte // wire 2
	varint uint64 // wire 0
}

func pbVarint(out []byte, value uint64) []byte {
	for value >= 0x80 {
		out = append(out, byte(value)|0x80)
		value >>= 7
	}
	return append(out, byte(value))
}

func pbReadVarint(t *testing.T, in []byte) (uint64, int) {
	t.Helper()
	var value uint64
	for index := 0; index < len(in) && index < 10; index++ {
		value |= uint64(in[index]&0x7f) << (7 * index)
		if in[index]&0x80 == 0 {
			return value, index + 1
		}
	}
	t.Fatal("malformed varint")
	return 0, 0
}

func pbDecode(t *testing.T, in []byte) []pbField {
	t.Helper()
	var fields []pbField
	for len(in) > 0 {
		tag, n := pbReadVarint(t, in)
		in = in[n:]
		field := pbField{number: tag >> 3, wire: tag & 7}
		value, n := pbReadVarint(t, in)
		in = in[n:]
		switch field.wire {
		case 0:
			field.varint = value
		case 2:
			field.value, in = in[:value], in[value:]
		default:
			t.Fatalf("wire type %d in a SignDoc", field.wire)
		}
		fields = append(fields, field)
	}
	return fields
}

func pbEncode(fields []pbField) []byte {
	var out []byte
	for _, field := range fields {
		out = pbVarint(out, field.number<<3|field.wire)
		if field.wire == 0 {
			out = pbVarint(out, field.varint)
			continue
		}
		out = append(pbVarint(out, uint64(len(field.value))), field.value...)
	}
	return out
}

func pbBytes(number uint64, value []byte) pbField {
	return pbField{number: number, wire: 2, value: value}
}

// withSignerKey returns signDoc with SignerInfo.public_key set to an Any of typeURL wrapping
// {bytes key = 1}, encoded canonically, so the daemon's canonical check still admits it.
func withSignerKey(t *testing.T, signDoc []byte, typeURL string, key []byte) []byte {
	t.Helper()
	document := pbDecode(t, signDoc)
	for index := range document {
		if document[index].number != 2 {
			continue
		}
		authInfo := pbDecode(t, document[index].value)
		for signer := range authInfo {
			if authInfo[signer].number != 1 {
				continue
			}
			anyKey := pbEncode([]pbField{pbBytes(1, []byte(typeURL)), pbBytes(2, pbEncode([]pbField{pbBytes(1, key)}))})
			fields := []pbField{pbBytes(1, anyKey)}
			for _, field := range pbDecode(t, authInfo[signer].value) {
				if field.number != 1 {
					fields = append(fields, field)
				}
			}
			authInfo[signer].value = pbEncode(fields)
		}
		document[index].value = pbEncode(authInfo)
	}
	out := pbEncode(document)
	parsed, err := policy.ParseCosmosSignDoc(out)
	if err != nil || parsed.SignerPublicKey == nil || parsed.SignerPublicKey.TypeURL != typeURL {
		t.Fatalf("the SignDoc built with a signer key does not parse with that key: %v", err)
	}
	return out
}

func compressed(key *secp256k1.PrivateKey) []byte { return key.PubKey().SerializeCompressed() }

// TestCosmosUnpinnedBindingSignsUnderTheSignDocSignerKey (council A): a DevAut-only binding (no
// public_key_sha256) signs when the SignDoc names the signer's key and the token's signature
// verifies under it. The SignDoc's key must be the compressed SEC1 form a chain decodes (33
// bytes); the token's SPKI carries the same point uncompressed, so the two compare equal as
// points, not bytes.
func TestCosmosUnpinnedBindingSignsUnderTheSignDocSignerKey(t *testing.T) {
	card := newCosmosCard(t)
	signDoc := withSignerKey(t, cosmosFixture(t), secp256k1KeyType, compressed(card.signer))
	coordinator, recorder := allowingCoordinator(t, cosmosRoute(""), card)
	result, err := coordinator.Execute(context.Background(), cosmosRequest(signDoc))
	if err != nil {
		t.Fatalf("the SignDoc's own signer key signed and was refused: %v (audit %v)", err, outcomes(recorder))
	}
	if !textbookVerify(t, secp256k1SPKI(card.signer.PubKey()), signDoc, result.Data) {
		t.Fatal("the returned signature does not verify under the SignDoc's signer key")
	}
}

// TestCosmosSignatureNotUnderTheSignDocSignerKeyIsNotSuccess (council A, review finding 1): the
// token's own report of its key is never enough. Before the fix the unpinned case verified under
// whatever key the token reported, so a token signing with, and reporting, the wrong key passed.
func TestCosmosSignatureNotUnderTheSignDocSignerKeyIsNotSuccess(t *testing.T) {
	other := testSigner(t)
	for name, setup := range map[string]func(card *cosmosCard) (pin string, signDoc []byte){
		// The review's probe: the card signs with a fresh key and reports it; nothing is pinned.
		"unpinned, card signs with and reports another key": func(card *cosmosCard) (string, []byte) {
			named := card.signer
			card.signer, card.reported = other, other
			return "", withSignerKey(t, cosmosFixture(t), secp256k1KeyType, compressed(named))
		},
		// The card signs with the SignDoc's key but reports another: the keys disagree.
		"unpinned, card reports a key other than the SignDoc's": func(card *cosmosCard) (string, []byte) {
			card.reported = other
			return "", withSignerKey(t, cosmosFixture(t), secp256k1KeyType, compressed(card.signer))
		},
		// Pinned and the pin holds, but the SignDoc names another signer: a chain would verify
		// under the SignDoc's key, so this signature is one it refuses.
		"pinned, SignDoc names another signer": func(card *cosmosCard) (string, []byte) {
			return spkiPin(secp256k1SPKI(card.signer.PubKey())), withSignerKey(t, cosmosFixture(t), secp256k1KeyType, compressed(other))
		},
	} {
		t.Run(name, func(t *testing.T) {
			card := newCosmosCard(t)
			pin, signDoc := setup(card)
			assertUnverifiedDoc(t, card, pin, signDoc)
		})
	}
}

// TestCosmosUnboundSignerIsRefusedBeforeTheToken (council A): with no pin and no usable signer key
// in the SignDoc there is nothing to check a signature against, so the request is refused before
// policy reserves anything and before the token is called -- through the real policy engine, which
// would otherwise admit and reserve it.
func TestCosmosUnboundSignerIsRefusedBeforeTheToken(t *testing.T) {
	transaction, err := policy.ParseCosmosSignDoc(cosmosFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, signDoc := range map[string]func(card *cosmosCard) []byte{
		"no pin, SignDoc carries no public key": func(*cosmosCard) []byte { return cosmosFixture(t) },
		"no pin, SignDoc key is of another curve's type": func(*cosmosCard) []byte {
			return withSignerKey(t, cosmosFixture(t), secp256r1KeyType, elliptic.MarshalCompressed(elliptic.P256(), p256.X, p256.Y))
		},
		"no pin, SignDoc key is not a point": func(card *cosmosCard) []byte {
			key := compressed(card.signer)
			key[0] = 0x05
			return withSignerKey(t, cosmosFixture(t), secp256k1KeyType, key)
		},
		"no pin, SignDoc key is a multisig": func(card *cosmosCard) []byte {
			return withSignerKey(t, cosmosFixture(t), "/cosmos.crypto.multisig.LegacyAminoPubKey", compressed(card.signer))
		},
	} {
		t.Run(name, func(t *testing.T) {
			card := newCosmosCard(t)
			coordinator, state, recorder, now := realEngineCoordinator(t, transaction, cosmosRoute(""), card)
			request := cosmosRequest(signDoc(card))
			request.Context.ExpiresAt = now.Add(30 * time.Second)
			result, err := coordinator.Execute(context.Background(), request)
			failure, ok := err.(*api.Failure)
			if !ok || failure.Status != 400 || failure.Code != "INVALID_ARGUMENT" || len(result.Data) != 0 {
				t.Fatalf("DEFECT: an unbound signer was not refused: err=%v, %d bytes, token calls %v, audit %v", err, len(result.Data), card.calls, outcomes(recorder))
			}
			if len(card.calls) != 0 || len(state.reserved) != 0 {
				t.Fatalf("DEFECT: an unbound signer reached the token (%v) or spent a reservation (%d)", card.calls, len(state.reserved))
			}
			if got := outcomes(recorder); len(got) != 1 || got[0] != "cosmos-signer-key-unbound" {
				t.Fatalf("audit outcomes = %v, want cosmos-signer-key-unbound", got)
			}
		})
	}
	// The control, same engine shape: with the signer's key in the SignDoc the unpinned binding
	// signs and reserves once, so the refusals above are about the key and nothing else.
	card := newCosmosCard(t)
	coordinator, state, _, now := realEngineCoordinator(t, transaction, cosmosRoute(""), card)
	request := cosmosRequest(withSignerKey(t, cosmosFixture(t), secp256k1KeyType, compressed(card.signer)))
	request.Context.ExpiresAt = now.Add(30 * time.Second)
	if _, err := coordinator.Execute(context.Background(), request); err != nil || len(state.reserved) != 1 {
		t.Fatalf("the bound control was not signed (err=%v, reservations %d)", err, len(state.reserved))
	}
}

// TestCosmosPublicKeyReadFailureIsTheBackendError (council B, mutant M10): the token signed but its
// public key could not be read. That is the token's outage -- audited backend-failed and retryable
// -- not a signature found to be bad, which would be non-retryable and send an operator looking
// for a defect.
func TestCosmosPublicKeyReadFailureIsTheBackendError(t *testing.T) {
	card := newCosmosCard(t)
	card.keyErr = errors.New("pkcs11: CKR_DEVICE_REMOVED")
	coordinator, recorder := allowingCoordinator(t, cosmosRoute(spkiPin(secp256k1SPKI(card.signer.PubKey()))), card)
	result, err := coordinator.Execute(context.Background(), cosmosRequest(cosmosFixture(t)))
	failure, ok := err.(*api.Failure)
	if !ok || failure.Code != "BACKEND_UNAVAILABLE" || !failure.Retryable || len(result.Data) != 0 {
		t.Fatalf("a failed public-key read answered err=%#v with %d bytes, want a retryable BACKEND_UNAVAILABLE and no bytes", err, len(result.Data))
	}
	if got := outcomes(recorder); len(got) != 2 || got[0] != "authorized" || got[1] != "backend-failed" {
		t.Fatalf("audit outcomes = %v, want authorized then backend-failed", got)
	}
}

// TestCosmosVerifierRefusesUnreducedScalars (council B, mutant M5): r and s must be below N, never
// reduced modulo N. A random s is almost never below 2^256-N, so s+N would not fit 32 bytes; the
// key here is chosen so that s = 1 is a valid signature, and then s = N+1 fits and is congruent to
// it. A verifier that reduced modulo N would accept bytes a chain refuses.
func TestCosmosVerifierRefusesUnreducedScalars(t *testing.T) {
	order := secp256k1.S256().N
	digest := sha256.Sum256(cosmosFixture(t))
	z := new(big.Int).Mod(new(big.Int).SetBytes(digest[:]), order)
	var key *secp256k1.PrivateKey
	var r *big.Int
	for key == nil {
		nonce := testSigner(t) // k: R = kG, r = R.x mod N
		r = new(big.Int).Mod(nonce.PubKey().X(), order)
		k := new(big.Int).SetBytes(nonce.Serialize())
		// s = k^-1 (z + r d) = 1  =>  d = (k - z) r^-1 mod N
		d := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Sub(k, z), new(big.Int).ModInverse(r, order)), order)
		if d.Sign() != 0 {
			key = secp256k1.PrivKeyFromBytes(d.FillBytes(make([]byte, 32)))
		}
	}
	registered := secp256k1SPKI(key.PubKey())
	signature := func(s *big.Int) []byte {
		raw := make([]byte, 64)
		r.FillBytes(raw[:32])
		s.FillBytes(raw[32:])
		return raw
	}
	if err := verifyCosmosSignature("secp256k1", spkiPin(registered), registered, nil, digest[:], signature(big.NewInt(1))); err != nil {
		t.Fatalf("the control signature (r, 1) does not verify: %v -- the test proves nothing", err)
	}
	unreduced := new(big.Int).Add(order, big.NewInt(1))
	if err := verifyCosmosSignature("secp256k1", spkiPin(registered), registered, nil, digest[:], signature(unreduced)); err == nil {
		t.Fatal("DEFECT: s = N+1 verified: the verifier reduced s modulo N and accepted bytes a chain refuses")
	}
}

// TestCosmosSignDocSignerKeyMustBeCompressed (council ruling 2026-11-24, R1-R5): the SignDoc's
// signer key must be exactly the 33-byte compressed SEC1 form (prefix 02 or 03, a point on the
// curve) on both curves, before the reservation and before any token call, on the pinned and the
// unpinned route alike. The Cosmos SDK refuses an uncompressed (65-byte) public_key at key decode,
// so accepting one here would spend the account's sequence on a transaction the chain refuses --
// the account-blocked bug class this PR exists to stop. A bad prefix (04, 00) is refused too, as
// is a prefix-02 key whose x coordinate is not on the curve. The control: a compressed key still
// signs, both curves.
func TestCosmosSignDocSignerKeyMustBeCompressed(t *testing.T) {
	offCurve := make([]byte, 32)
	for i := range offCurve {
		offCurve[i] = 0x41
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, setup := range map[string]func() (pin string, typeURL string, key []byte){
		// R3, secp256k1.
		"secp256k1 65-byte uncompressed key": func() (string, string, []byte) {
			card := newCosmosCard(t)
			return "", secp256k1KeyType, card.signer.PubKey().SerializeUncompressed()
		},
		"secp256k1 33-byte key with prefix 04": func() (string, string, []byte) {
			card := newCosmosCard(t)
			key := compressed(card.signer)
			key[0] = 0x04
			return "", secp256k1KeyType, key
		},
		"secp256k1 33-byte key with prefix 00": func() (string, string, []byte) {
			card := newCosmosCard(t)
			key := compressed(card.signer)
			key[0] = 0x00
			return "", secp256k1KeyType, key
		},
		"secp256k1 33-byte prefix-02 key not on the curve": func() (string, string, []byte) {
			return "", secp256k1KeyType, append([]byte{0x02}, offCurve...)
		},
		// R3, p256.
		"p256 65-byte uncompressed key": func() (string, string, []byte) {
			return "", secp256r1KeyType, elliptic.Marshal(elliptic.P256(), p256.X, p256.Y)
		},
		"p256 33-byte key with prefix 04": func() (string, string, []byte) {
			key := elliptic.MarshalCompressed(elliptic.P256(), p256.X, p256.Y)
			key[0] = 0x04
			return "", secp256r1KeyType, key
		},
		"p256 33-byte key with prefix 00": func() (string, string, []byte) {
			key := elliptic.MarshalCompressed(elliptic.P256(), p256.X, p256.Y)
			key[0] = 0x00
			return "", secp256r1KeyType, key
		},
	} {
		t.Run(name, func(t *testing.T) {
			card := newCosmosCard(t)
			pin, typeURL, key := setup()
			transaction, err := policy.ParseCosmosSignDoc(cosmosFixture(t))
			if err != nil {
				t.Fatal(err)
			}
			coordinator, state, recorder, now := realEngineCoordinator(t, transaction, cosmosRoute(pin), card)
			request := cosmosRequest(withSignerKey(t, cosmosFixture(t), typeURL, key))
			request.Context.ExpiresAt = now.Add(30 * time.Second)
			result, err := coordinator.Execute(context.Background(), request)
			failure, ok := err.(*api.Failure)
			if !ok || failure.Status != 400 || failure.Code != "INVALID_ARGUMENT" || len(result.Data) != 0 {
				t.Fatalf("DEFECT: a SignDoc signer key a chain would refuse was not refused before the token: err=%v, %d bytes, token calls %v, audit %v", err, len(result.Data), card.calls, outcomes(recorder))
			}
			if len(card.calls) != 0 || len(state.reserved) != 0 {
				t.Fatalf("DEFECT: a refused signer key reached the token (%v) or spent a reservation (%d)", card.calls, len(state.reserved))
			}
			if got := outcomes(recorder); len(got) != 1 || got[0] != "cosmos-signer-key-unbound" {
				t.Fatalf("audit outcomes = %v, want cosmos-signer-key-unbound", got)
			}
		})
	}
	// The same refusals hold when the binding pins the token's key: the SignDoc's own key is
	// still the key the chain verifies with, and the chain refuses an uncompressed one.
	t.Run("pinned route, secp256k1 65-byte uncompressed key", func(t *testing.T) {
		card := newCosmosCard(t)
		transaction, err := policy.ParseCosmosSignDoc(cosmosFixture(t))
		if err != nil {
			t.Fatal(err)
		}
		coordinator, state, recorder, now := realEngineCoordinator(t, transaction, cosmosRoute(spkiPin(secp256k1SPKI(card.signer.PubKey()))), card)
		request := cosmosRequest(withSignerKey(t, cosmosFixture(t), secp256k1KeyType, card.signer.PubKey().SerializeUncompressed()))
		request.Context.ExpiresAt = now.Add(30 * time.Second)
		if result, err := coordinator.Execute(context.Background(), request); err == nil || len(result.Data) != 0 {
			t.Fatalf("DEFECT: a pinned route signed an uncompressed SignDoc key: err=%v, token calls %v", err, card.calls)
		}
		if len(card.calls) != 0 || len(state.reserved) != 0 {
			t.Fatalf("DEFECT: a refused signer key reached the token (%v) or spent a reservation (%d)", card.calls, len(state.reserved))
		}
	})
	// The control, both curves: a compressed key still signs, on the unpinned route.
	t.Run("control, compressed secp256k1 key signs", func(t *testing.T) {
		card := newCosmosCard(t)
		coordinator, _ := allowingCoordinator(t, cosmosRoute(""), card)
		signDoc := withSignerKey(t, cosmosFixture(t), secp256k1KeyType, compressed(card.signer))
		if _, err := coordinator.Execute(context.Background(), cosmosRequest(signDoc)); err != nil {
			t.Fatalf("a compressed SignDoc key was refused: %v", err)
		}
	})
}

// TestCosmosP256SignatureMustBeLowS (review finding 4): the Cosmos SDK's secp256r1 key refuses an s
// above N/2, as its secp256k1 key does; crypto/ecdsa.Verify alone accepts both twins. The p256
// path is also bound to the SignDoc's signer key, compared as a point.
func TestCosmosP256SignatureMustBeLowS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registered, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(cosmosFixture(t))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	order := elliptic.P256().Params().N
	low, high := new(big.Int).Set(s), new(big.Int).Sub(order, s)
	if low.Cmp(new(big.Int).Rsh(order, 1)) > 0 {
		low, high = high, low
	}
	raw := func(s *big.Int) []byte {
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		return out
	}
	signer := &policy.CosmosPublicKey{TypeURL: secp256r1KeyType, Key: elliptic.MarshalCompressed(elliptic.P256(), key.X, key.Y)}
	if err := verifyCosmosSignature("p256", "", registered, signer, digest[:], raw(low)); err != nil {
		t.Fatalf("the low-S p256 signature under the SignDoc's compressed key does not verify: %v", err)
	}
	if err := verifyCosmosSignature("p256", spkiPin(registered), registered, nil, digest[:], raw(low)); err != nil {
		t.Fatalf("the low-S p256 signature under the pinned key does not verify: %v", err)
	}
	if err := verifyCosmosSignature("p256", spkiPin(registered), registered, signer, digest[:], raw(high)); err == nil {
		t.Fatal("DEFECT: a high-S p256 signature verified: a Cosmos node refuses it")
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stranger := &policy.CosmosPublicKey{TypeURL: secp256r1KeyType, Key: elliptic.MarshalCompressed(elliptic.P256(), other.X, other.Y)}
	if err := verifyCosmosSignature("p256", "", registered, stranger, digest[:], raw(low)); err == nil {
		t.Fatal("DEFECT: a p256 token key that is not the SignDoc's signer key was accepted")
	}
	// A p384 object has no Cosmos key type: refused even with a valid signature and a pin.
	key384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registered384, _ := x509.MarshalPKIXPublicKey(&key384.PublicKey)
	digest384 := sha256.Sum256(cosmosFixture(t))
	r384, s384, _ := ecdsa.Sign(rand.Reader, key384, digest384[:])
	if s384.Cmp(new(big.Int).Rsh(elliptic.P384().Params().N, 1)) > 0 {
		s384.Sub(elliptic.P384().Params().N, s384)
	}
	raw384 := make([]byte, 96)
	r384.FillBytes(raw384[:48])
	s384.FillBytes(raw384[48:])
	if err := verifyCosmosSignature("p384", spkiPin(registered384), registered384, nil, digest384[:], raw384); err == nil {
		t.Fatal("DEFECT: a p384 signature was reported as verified for the Cosmos content type")
	}
}
