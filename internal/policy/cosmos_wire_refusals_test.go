package policy

// The SignDoc parser is the policy boundary's only reader of the bytes a signature will cover, and
// its own comment says "unknown wire fields and unknown message types are rejected so a crafted
// extension cannot smuggle an additional transaction body past the policy boundary". A mutation
// sweep of the 43 refusal guards in cosmos.go and wire.go found 22 with no detector: replacing any
// of them with a constant left the policy suite green.
//
// The untested ones fall in two groups, and both are the same failure at different depths:
//
//   WIRE-TYPE guards, which are what makes "the field I read is the field you read" true. Remove
//   the one on account_number and a length-delimited field holding the ASCII "42" is read by this
//   decoder as the number 52, while every other reader of the same bytes sees a string. Two
//   parties disagreeing about one signed document is the whole class this file exists to close.
//
//   COMPLETENESS guards, which are what makes a parsed CosmosTransaction mean anything. Remove the
//   MsgSend one and a message with no Coin at all yields a transaction the spend cap approves by
//   having nothing to compare.
//
// Every case asserts the specific message: on a decoder this deep, `err != nil` is satisfied by
// almost any malformed input for almost any reason.

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func refuses(t *testing.T, input []byte, want string) {
	t.Helper()
	parsed, err := ParseCosmosSignDoc(input)
	if err == nil {
		t.Fatalf("parsed a document that should be refused (%+v); wanted %q", parsed, want)
	}
	if !errors.Is(err, ErrCosmosSignDoc) {
		t.Fatalf("err = %v, want it to wrap ErrCosmosSignDoc", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refused by the wrong rule: got %q, want a message containing %q", err, want)
	}
}

// THE KNOWN-GOOD DOCUMENT, asserted here as well as in the acceptance test, because every case
// below is the canonical document with exactly one thing changed. If this stops parsing, the
// refusals below are refusing the fixture rather than the change.
func TestTheCanonicalSignDocIsTheBaselineForEveryRefusal(t *testing.T) {
	if _, err := ParseCosmosSignDoc(canonicalSignDoc()); err != nil {
		t.Fatalf("the canonical SignDoc must parse, got %v", err)
	}
}

// EACH SIGNDOC FIELD MUST ARRIVE ON ITS DECLARED WIRE TYPE. Each row keeps every other field
// canonical, so the only thing that can refuse it is that field's own wire-type rule.
func TestASignDocFieldOnTheWrongWireTypeIsRefused(t *testing.T) {
	body := canonicalMsgSendTxBody()
	rows := []struct {
		name     string
		document []byte
		want     string
	}{
		{"body_bytes as a varint", func() []byte {
			var buf bytes.Buffer
			buf.Write(encodeTopVarint(1, 7))
			buf.Write(encodeLengthDelimited(2, encodeAuthInfo()))
			buf.Write(encodeString(3, "cosmoshub-4"))
			buf.Write(encodeTopVarint(4, 42))
			return buf.Bytes()
		}(), "body_bytes wire 0 not allowed"},
		{"auth_info_bytes as a varint", func() []byte {
			var buf bytes.Buffer
			buf.Write(encodeLengthDelimited(1, body))
			buf.Write(encodeTopVarint(2, 7))
			buf.Write(encodeString(3, "cosmoshub-4"))
			buf.Write(encodeTopVarint(4, 42))
			return buf.Bytes()
		}(), "auth_info_bytes wire 0 not allowed"},
		{"chain_id as a varint", func() []byte {
			var buf bytes.Buffer
			buf.Write(encodeLengthDelimited(1, body))
			buf.Write(encodeLengthDelimited(2, encodeAuthInfo()))
			buf.Write(encodeTopVarint(3, 7))
			buf.Write(encodeTopVarint(4, 42))
			return buf.Bytes()
		}(), "chain_id wire 0 not allowed"},
		// THE SHARPEST ROW. With this guard removed the parser does not fail — it reads the first
		// varint out of the string's bytes, so "42" (0x34 0x32) becomes account_number 52 here
		// while every conforming reader sees the string "42".
		{"account_number as a length-delimited string", func() []byte {
			var buf bytes.Buffer
			buf.Write(encodeLengthDelimited(1, body))
			buf.Write(encodeLengthDelimited(2, encodeAuthInfo()))
			buf.Write(encodeString(3, "cosmoshub-4"))
			buf.Write(encodeString(4, "42"))
			return buf.Bytes()
		}(), "account_number wire 2 not allowed"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) { refuses(t, row.document, row.want) })
	}
}

// TxBody carries repeated Any at field 1 and nothing else.
func TestATxBodyFieldOtherThanAMessageIsRefused(t *testing.T) {
	message := encodeAny("/cosmos.bank.v1beta1.MsgSend", encodeMsgSend("cosmos1source", "cosmos1dest", "uatom", 900_000))
	t.Run("an unexpected field number", func(t *testing.T) {
		refuses(t, encodeSignDoc("cosmoshub-4", 42, encodeLengthDelimited(2, message)),
			"TxBody.field 2 wire 2 not allowed")
	})
	t.Run("a message on the wrong wire type", func(t *testing.T) {
		refuses(t, encodeSignDoc("cosmoshub-4", 42, encodeTopVarint(1, 7)),
			"TxBody.field 1 wire 0 not allowed")
	})
}

// An Any missing either half is not a message: a type_url with no value names a type nothing
// carries, and a value with no type_url is bytes nothing identifies.
func TestAnIncompleteAnyIsRefused(t *testing.T) {
	inner := encodeMsgSend("cosmos1source", "cosmos1dest", "uatom", 900_000)
	t.Run("no value", func(t *testing.T) {
		any := encodeString(1, "/cosmos.bank.v1beta1.MsgSend")
		refuses(t, encodeSignDoc("cosmoshub-4", 42, encodeLengthDelimited(1, any)),
			"Any missing required field")
	})
	t.Run("no type_url", func(t *testing.T) {
		any := encodeLengthDelimited(2, inner)
		refuses(t, encodeSignDoc("cosmoshub-4", 42, encodeLengthDelimited(1, any)),
			"Any missing required field")
	})
	// walkLengthDelimited's own rule, reached through the Any walk: a varint where a nested
	// message belongs is a structural mismatch and must not be walked as bytes.
	t.Run("a varint field inside the Any", func(t *testing.T) {
		var any bytes.Buffer
		any.Write(encodeString(1, "/cosmos.bank.v1beta1.MsgSend"))
		any.Write(encodeTopVarint(2, 7))
		refuses(t, encodeSignDoc("cosmoshub-4", 42, encodeLengthDelimited(1, any.Bytes())),
			"not length-delimited")
	})
}

// A MsgSend with no destination, or with no amount at all, must not become a transaction. The
// second row is the one that matters for policy: a message carrying no Coin passes every spend
// cap by having nothing for the cap to compare.
func TestAMsgSendMissingItsDestinationOrAmountIsRefused(t *testing.T) {
	coin := func() []byte {
		var c bytes.Buffer
		c.Write(encodeString(1, "uatom"))
		c.Write(encodeString(2, "900000"))
		return c.Bytes()
	}()
	wrap := func(msg []byte) []byte {
		return encodeSignDoc("cosmoshub-4", 42,
			encodeTxBody([][2][]byte{{[]byte("/cosmos.bank.v1beta1.MsgSend"), msg}}))
	}
	t.Run("no to_address", func(t *testing.T) {
		var msg bytes.Buffer
		msg.Write(encodeString(1, "cosmos1source"))
		msg.Write(encodeLengthDelimited(3, coin))
		refuses(t, wrap(msg.Bytes()), "MsgSend missing source, destination or amount")
	})
	t.Run("no coin", func(t *testing.T) {
		var msg bytes.Buffer
		msg.Write(encodeString(1, "cosmos1source"))
		msg.Write(encodeString(2, "cosmos1dest"))
		refuses(t, wrap(msg.Bytes()), "MsgSend missing source, destination or amount")
	})
}

// A Coin is a denom and an amount. Either alone is not an amount of anything.
func TestAnIncompleteCoinIsRefused(t *testing.T) {
	wrap := func(coin []byte) []byte {
		var msg bytes.Buffer
		msg.Write(encodeString(1, "cosmos1source"))
		msg.Write(encodeString(2, "cosmos1dest"))
		msg.Write(encodeLengthDelimited(3, coin))
		return encodeSignDoc("cosmoshub-4", 42,
			encodeTxBody([][2][]byte{{[]byte("/cosmos.bank.v1beta1.MsgSend"), msg.Bytes()}}))
	}
	t.Run("no denom", func(t *testing.T) {
		refuses(t, wrap(encodeString(2, "900000")), "Coin missing denom or amount")
	})
	t.Run("no amount", func(t *testing.T) {
		refuses(t, wrap(encodeString(1, "uatom")), "Coin missing denom or amount")
	})
	// An amount field that is PRESENT and empty is a different condition from one that is absent,
	// and it has its own message so an operator is sent to the encoder rather than to the schema.
	t.Run("an empty amount string", func(t *testing.T) {
		var coin bytes.Buffer
		coin.Write(encodeString(1, "uatom"))
		coin.Write(encodeString(2, ""))
		refuses(t, wrap(coin.Bytes()), "Coin.amount is empty")
	})
}

// A TRUNCATED VARINT AT EACH OF THE THREE PLACES ONE APPEARS. The three refusals carry different
// sentences on purpose — a truncated tag, a truncated payload and a truncated length prefix send
// a reader to different parts of an encoder — and none of the three had a test, so nothing would
// have noticed the three collapsing into one.
func TestATruncatedVarintIsRefusedWhereverItAppears(t *testing.T) {
	t.Run("in the tag", func(t *testing.T) {
		refuses(t, []byte{0x80}, "tag varint")
	})
	t.Run("in a varint field's payload", func(t *testing.T) {
		refuses(t, append(encodeTag(4, 0), 0x80), "field 4 varint")
	})
	t.Run("in a length prefix", func(t *testing.T) {
		refuses(t, append(encodeTag(1, 2), 0x80), "field 1 length")
	})
}

// THE NESTED WIRE-TYPE RULES, which the first pass missed and mischaracterised.
//
// #233 said nine guards remained and called them "all error-propagation paths from nested
// decoders". Re-measured against main with that PR's tests in place, FOUR remained and three of
// them are wire-type rules — five of the nine had been closed as a side effect of the completeness
// tests, because a dropped error there falls through to a later refusal. The count and the
// classification were both wrong, which is what a coverage claim made from a stale sweep looks
// like.
//
// These three sit one and two levels below the SignDoc fields already covered, and they are the
// same property at depth: a field arriving on a wire type the schema does not declare means this
// decoder and every other reader of the signed bytes are reading different documents.
func TestANestedFieldOnTheWrongWireTypeIsRefused(t *testing.T) {
	wrap := func(msg []byte) []byte {
		return encodeSignDoc("cosmoshub-4", 42,
			encodeTxBody([][2][]byte{{[]byte("/cosmos.bank.v1beta1.MsgSend"), msg}}))
	}
	goodCoin := func() []byte {
		var c bytes.Buffer
		c.Write(encodeString(1, "uatom"))
		c.Write(encodeString(2, "900000"))
		return c.Bytes()
	}()

	t.Run("MsgSend.to_address as a varint", func(t *testing.T) {
		var msg bytes.Buffer
		msg.Write(encodeString(1, "cosmos1source"))
		msg.Write(encodeTopVarint(2, 7))
		msg.Write(encodeLengthDelimited(3, goodCoin))
		refuses(t, wrap(msg.Bytes()), "MsgSend.to_address wire 0 not allowed")
	})

	t.Run("the Coin field as a varint", func(t *testing.T) {
		var msg bytes.Buffer
		msg.Write(encodeString(1, "cosmos1source"))
		msg.Write(encodeString(2, "cosmos1dest"))
		msg.Write(encodeTopVarint(3, 7))
		refuses(t, wrap(msg.Bytes()), "Coin wire 0 not allowed")
	})

	t.Run("Coin.denom as a varint", func(t *testing.T) {
		var coin bytes.Buffer
		coin.Write(encodeTopVarint(1, 7))
		coin.Write(encodeString(2, "900000"))
		var msg bytes.Buffer
		msg.Write(encodeString(1, "cosmos1source"))
		msg.Write(encodeString(2, "cosmos1dest"))
		msg.Write(encodeLengthDelimited(3, coin.Bytes()))
		refuses(t, wrap(msg.Bytes()), "Coin.denom wire 0 not allowed")
	})
}

// THE FOURTH SURVIVOR HAS NO TEST BECAUSE IT HAS NO REACHABLE INPUT (§17), and this is the
// evidence rather than the assertion.
//
// ParseCosmosSignDoc re-decodes account_number's payload with decodeVarint after walkFields has
// already handed it over. walkFields decodes that same varint to find where the field ends, so
// any payload the second call could reject was rejected by the first. Three candidates were built
// and each was refused one layer up, by walkFields, never reaching the branch:
//
//	2^64 + 5 (0x85 80 80 80 80 80 80 80 80 02) -> "field 4 varint: varint exceeds 64 bits"
//	tenth byte 0x7f                            -> "field 4 varint: varint exceeds 64 bits"
//	truncated (0x80)                           -> "field 4 varint: truncated varint"
//
// The branch is a re-check of a decode that already succeeded on the same bytes. It is not dead —
// deleting it would leave an unchecked error — but it cannot be made to fail from the public path,
// so there is nothing to assert. If decodeVarint ever grows a rule walkFields does not apply, or
// account_number is ever read from bytes walkFields did not validate, this becomes constructible
// and wants a row above.
