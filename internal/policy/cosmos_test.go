package policy

import (
	"bytes"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// encodeTag returns the protobuf tag bytes for (fieldNumber, wireType).
func encodeTag(fieldNumber, wireType uint64) []byte {
	return encodeVarint((fieldNumber << 3) | wireType)
}

// encodeVarint emits a base-128 varint for v.
func encodeVarint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

// encodeLengthDelimited wraps body as a length-delimited field (fieldNumber,
// wireType 2).
func encodeLengthDelimited(fieldNumber uint64, body []byte) []byte {
	return append(encodeTag(fieldNumber, 2), append(encodeVarint(uint64(len(body))), body...)...)
}

// encodeString emits a length-delimited string field.
func encodeString(fieldNumber uint64, value string) []byte {
	return encodeLengthDelimited(fieldNumber, []byte(value))
}

// encodeTopVarint emits a wire type 0 varint field at the current level.
func encodeTopVarint(fieldNumber, value uint64) []byte {
	return append(encodeTag(fieldNumber, 0), encodeVarint(value)...)
}

// encodeAny wraps inner bytes as a google.protobuf.Any with the given
// type_url.
func encodeAny(typeURL string, inner []byte) []byte {
	var buf bytes.Buffer
	buf.Write(encodeString(1, typeURL))
	buf.Write(encodeLengthDelimited(2, inner))
	return buf.Bytes()
}

// encodeMsgSend emits a /cosmos.bank.v1beta1.MsgSend payload.
// encodeMsgSend now encodes Coin.amount as a DECIMAL STRING, which is what the upstream protos do.
//
// It used to write a varint, and that is why nothing here caught the decoder requiring one: this
// encoder and that decoder shared a single assumption and agreed with each other about a wire
// format neither matched. The moment the decoder was corrected against the generated descriptor,
// this function's output started being refused — which is the shape of the defect, visible only
// once one half stopped agreeing with the other.
//
// testdata/msgsend-uakt-1000000.bin is the independent check: bytes from the upstream encoder,
// so this helper can no longer define correctness by itself.
func encodeMsgSend(from, to, denom string, amount uint64) []byte {
	var coin bytes.Buffer
	coin.Write(encodeString(1, denom))
	coin.Write(encodeString(2, strconv.FormatUint(amount, 10)))
	var buf bytes.Buffer
	buf.Write(encodeString(1, from))
	buf.Write(encodeString(2, to))
	buf.Write(encodeLengthDelimited(3, coin.Bytes()))
	return buf.Bytes()
}

// encodeTxBody wraps a list of (typeURL, payload) pairs as a TxBody.
func encodeTxBody(messages [][2][]byte) []byte {
	var buf bytes.Buffer
	for _, pair := range messages {
		buf.Write(encodeLengthDelimited(1, encodeAny(string(pair[0]), pair[1])))
	}
	return buf.Bytes()
}

// encodeAuthInfo emits an AuthInfo with one signer, sequence 7, a uakt fee, and
// a positive gas limit so parser tests exercise the complete envelope shape.
func encodeAuthInfo() []byte {
	single := encodeTopVarint(1, 1)
	modeInfo := encodeLengthDelimited(1, single)
	signer := append(encodeLengthDelimited(2, modeInfo), encodeTopVarint(3, 7)...)
	coin := append(encodeString(1, "uatom"), encodeString(2, "1000")...)
	fee := append(encodeLengthDelimited(1, coin), encodeTopVarint(2, 200000)...)
	return append(encodeLengthDelimited(1, signer), encodeLengthDelimited(2, fee)...)
}

// encodeSignDoc produces a canonical Cosmos v1beta1 SignDoc.
func encodeSignDoc(chainID string, accountNumber uint64, txBody []byte) []byte {
	var buf bytes.Buffer
	buf.Write(encodeLengthDelimited(1, txBody)) // body_bytes
	buf.Write(encodeLengthDelimited(2, encodeAuthInfo()))
	buf.Write(encodeString(3, chainID))          // chain_id
	buf.Write(encodeTopVarint(4, accountNumber)) // account_number
	return buf.Bytes()
}

func canonicalMsgSendTxBody() []byte {
	msg := encodeMsgSend("cosmos1source", "cosmos1dest", "uatom", 900_000)
	return encodeTxBody([][2][]byte{{[]byte("/cosmos.bank.v1beta1.MsgSend"), msg}})
}

func canonicalSignDoc() []byte {
	return encodeSignDoc("cosmoshub-4", 42, canonicalMsgSendTxBody())
}

func TestParseCosmosSignDocAcceptsCanonicalMsgSend(t *testing.T) {
	got, err := ParseCosmosSignDoc(canonicalSignDoc())
	if err != nil {
		t.Fatalf("ParseCosmosSignDoc returned error: %v", err)
	}
	if got.ChainID != "cosmoshub-4" {
		t.Errorf("ChainID = %q, want cosmoshub-4", got.ChainID)
	}
	if got.AccountNumber != 42 {
		t.Errorf("AccountNumber = %d, want 42", got.AccountNumber)
	}
	if len(got.Messages) != 1 {
		t.Fatalf("Messages length = %d, want 1", len(got.Messages))
	}
	message := got.Messages[0]
	if message.Type != "/cosmos.bank.v1beta1.MsgSend" {
		t.Errorf("Message.Type = %q, want /cosmos.bank.v1beta1.MsgSend", message.Type)
	}
	if message.Destination != "cosmos1dest" {
		t.Errorf("Message.Destination = %q, want cosmos1dest", message.Destination)
	}
	if len(message.Amounts) != 1 || message.Amounts[0].Denom != "uatom" || message.Amounts[0].Amount != 900_000 {
		t.Errorf("Message.Amounts = %#v, want [{uatom 900000}]", message.Amounts)
	}
}

func TestParseCosmosSignDocRejectsEmptyAndTruncated(t *testing.T) {
	cases := map[string][]byte{
		"empty buffer":            {},
		"truncated length prefix": {0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, // field 1 length > buffer
		"truncated varint":        {0x0a, 0x01, 0xff},                         // length 1 then truncated varint (account_number)
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseCosmosSignDoc(input)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, ErrCosmosSignDoc) {
				t.Fatalf("error %v does not wrap ErrCosmosSignDoc", err)
			}
			if !strings.Contains(err.Error(), "malformed canonical Cosmos SignDoc") {
				t.Fatalf("error %q does not name the canonical-SignDoc defect", err.Error())
			}
		})
	}
}

func TestParseCosmosSignDocRejectsMissingRequiredFields(t *testing.T) {
	body := encodeLengthDelimited(1, canonicalMsgSendTxBody())
	auth := encodeLengthDelimited(2, encodeAuthInfo())
	chain := encodeString(3, "cosmoshub-4")
	acct := encodeTopVarint(4, 42)

	cases := map[string][]byte{
		"missing body":     append(append(append([]byte{}, auth...), chain...), acct...),
		"missing auth":     append(append(append([]byte{}, body...), chain...), acct...),
		"missing chain":    append(append(append([]byte{}, body...), auth...), acct...),
		"unknown field 99": append(append(append(append([]byte{}, body...), auth...), chain...), encodeString(99, "smuggled")...),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseCosmosSignDoc(input)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, ErrCosmosSignDoc) {
				t.Fatalf("error %v does not wrap ErrCosmosSignDoc", err)
			}
		})
	}
}

// An absent account_number is account 0, not a malformed document: proto3 omits zero scalars, so
// that is the only way a real SignDoc for account 0 can be written. (It was in the table above as a
// refusal; the live-node e2e in regalia#439 showed that refusal was a bug.)
func TestParseCosmosSignDocReadsAnAbsentAccountNumberAsZero(t *testing.T) {
	body := encodeLengthDelimited(1, canonicalMsgSendTxBody())
	auth := encodeLengthDelimited(2, encodeAuthInfo())
	chain := encodeString(3, "cosmoshub-4")
	got, err := ParseCosmosSignDoc(append(append(append([]byte{}, body...), auth...), chain...))
	if err != nil {
		t.Fatalf("a SignDoc with no account_number field was refused: %v", err)
	}
	if got.AccountNumber != 0 {
		t.Fatalf("absent account_number parsed as %d, want 0", got.AccountNumber)
	}
}

func TestParseCosmosSignDocRejectsUnknownMessageType(t *testing.T) {
	delegate := encodeMsgSend("cosmos1source", "cosmos1dest", "uatom", 900_000)
	body := encodeTxBody([][2][]byte{{[]byte("/cosmos.gov.v1beta1.MsgVote"), delegate}})
	signDoc := encodeSignDoc("cosmoshub-4", 42, body)
	_, err := ParseCosmosSignDoc(signDoc)
	if err == nil {
		t.Fatal("expected error for unsupported message type")
	}
	if !errors.Is(err, ErrCosmosSignDoc) {
		t.Fatalf("error %v does not wrap ErrCosmosSignDoc", err)
	}
	if !strings.Contains(err.Error(), "unsupported message type") {
		t.Fatalf("error %q does not name the unsupported-message defect", err.Error())
	}
}

func TestParseCosmosSignDocRejectsEmptyTxBody(t *testing.T) {
	signDoc := encodeSignDoc("cosmoshub-4", 42, encodeTxBody(nil))
	_, err := ParseCosmosSignDoc(signDoc)
	if err == nil {
		t.Fatal("expected error for empty TxBody")
	}
	if !errors.Is(err, ErrCosmosSignDoc) {
		t.Fatalf("error %v does not wrap ErrCosmosSignDoc", err)
	}
	if !strings.Contains(err.Error(), "no messages") {
		t.Fatalf("error %q does not name the empty-TxBody defect", err.Error())
	}
}
