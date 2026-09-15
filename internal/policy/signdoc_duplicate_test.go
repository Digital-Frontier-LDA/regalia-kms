package policy

import (
	"bytes"
	"errors"
	"testing"
)

// A REPEATED SIGNDOC FIELD IS REFUSED, AND body_bytes IS WHY.
//
// ParseCosmosSignDoc's own comment says unknown wire fields and message types are rejected "so a
// crafted extension cannot smuggle an additional transaction body past the policy boundary". A
// repeated field 1 smuggles one through the front door instead: the signature covers bytes carrying
// two bodies, and this function inspects whichever the walk happens to leave in the variable.
// chain_id is the same defect on the field that decides which network the signature is valid on.
//
// Proto3 last-wins makes a conforming decoder agree, so there is no differential today — but that
// depends on every party reading these bytes making the same choice about input that no canonical
// encoder produces, and one of those parties is whatever shows a human what they are approving.
func TestARepeatedSignDocFieldIsRefused(t *testing.T) {
	body := encodeTxBody([][2][]byte{{
		[]byte("/cosmos.bank.v1beta1.MsgSend"),
		encodeMsgSend("from", "to", "uakt", 1),
	}})
	other := encodeTxBody([][2][]byte{{
		[]byte("/cosmos.bank.v1beta1.MsgSend"),
		encodeMsgSend("from", "elsewhere", "uakt", 999999),
	}})

	// The control first: the same SignDoc without a duplicated field must parse, or every case
	// below is satisfied by ParseCosmosSignDoc refusing everything.
	if _, err := ParseCosmosSignDoc(encodeSignDoc("akashnet-2", 7, body)); err != nil {
		t.Fatalf("a well-formed SignDoc was refused: %v — nothing below would be attributable", err)
	}

	for _, duplicated := range []struct {
		what  string
		extra []byte
	}{
		{"body_bytes twice", encodeLengthDelimited(1, other)},
		{"auth_info_bytes twice", encodeLengthDelimited(2, []byte("auth"))},
		{"chain_id twice", encodeString(3, "cosmoshub-4")},
		{"account_number twice", encodeTopVarint(4, 99)},
	} {
		t.Run(duplicated.what, func(t *testing.T) {
			var doc bytes.Buffer
			doc.Write(encodeSignDoc("akashnet-2", 7, body))
			doc.Write(duplicated.extra)
			transaction, err := ParseCosmosSignDoc(doc.Bytes())
			if err == nil {
				t.Fatalf("accepted a SignDoc with %s and reported chain %q account %d: the policy "+
					"evaluated one value while another travelled under the same signature",
					duplicated.what, transaction.ChainID, transaction.AccountNumber)
			}
			if !errors.Is(err, ErrCosmosSignDoc) {
				t.Fatalf("error %v does not wrap ErrCosmosSignDoc", err)
			}
		})
	}
}

// TxBody.messages IS GENUINELY REPEATED and must stay so — a guard written one field too wide here
// would refuse every multi-message transaction, which is fail-closed and therefore invisible.
func TestATransactionWithSeveralMessagesStillParses(t *testing.T) {
	body := encodeTxBody([][2][]byte{
		{[]byte("/cosmos.bank.v1beta1.MsgSend"), encodeMsgSend("from", "to", "uakt", 1)},
		{[]byte("/cosmos.bank.v1beta1.MsgSend"), encodeMsgSend("from", "to2", "uakt", 2)},
	})
	transaction, err := ParseCosmosSignDoc(encodeSignDoc("akashnet-2", 7, body))
	if err != nil {
		t.Fatalf("a two-message transaction was refused: %v", err)
	}
	if len(transaction.Messages) != 2 {
		t.Fatalf("parsed %d messages, want 2", len(transaction.Messages))
	}
}
