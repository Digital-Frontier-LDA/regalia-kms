package policy

import (
	"errors"
	"fmt"
	"strconv"
)

// ErrCosmosSignDoc is returned when the canonical Cosmos SignDoc cannot be
// decoded into a trusted CosmosTransaction. The error wraps the cause so tests
// can assert on the rule that was rejected.
var ErrCosmosSignDoc = errors.New("malformed canonical Cosmos SignDoc")

// ParseCosmosSignDoc decodes a Cosmos SDK v1beta1 SignDoc into a
// server-validated CosmosTransaction. Unknown wire fields and unknown message
// types are rejected so a crafted extension cannot smuggle an additional
// transaction body past the policy boundary.
//
// SignDoc layout (cosmos-sdk v1beta1):
//
//	message SignDoc {
//	  bytes  body_bytes      = 1;
//	  bytes  auth_info_bytes = 2;
//	  string chain_id        = 3;
//	  uint64 account_number  = 4;
//	}
//
// TxBody.messages are length-delimited google.protobuf.Any; only
// /cosmos.bank.v1beta1.MsgSend is decoded today, and only enough of the Any
// envelope is read to confirm the type_url and lift the inner message bytes.
// A REPEATED SIGNDOC FIELD IS REFUSED, AND FIELD 1 IS WHY.
//
// Every field here was last-wins in silence. body_bytes twice means the signature covers bytes
// carrying TWO transaction bodies while this function inspects one of them -- which is precisely
// the smuggling the comment above says is prevented, arriving through a repeated field rather than
// an unknown one. chain_id twice means the allowlist is checked against one value while another
// travels alongside it.
//
// No canonical encoder emits a repeated scalar, so refusing costs nothing and does not depend on
// every other reader of these bytes resolving them the same way.
// ParseCosmosSignDoc parses caller-supplied wire bytes. THE RECOVER IS AT THE PARSER
// BOUNDARY, ON PURPOSE: the coordinator calls this directly on request data, upstream of
// the operation runner's recover, so a parser panic is a dropped connection with no
// refusal and no audit record (net/http recovers the connection, not the request — the
// process survives; the REQUEST does not). A wire parser's guards are enumerated one panic
// path at a time — the overflow operand at the length check was one, found by mutation —
// and this boundary is the net for the next one: any panic becomes ErrCosmosSignDoc, a
// 400 the coordinator can record, not a reset nobody can read.
func ParseCosmosSignDoc(input []byte) (*CosmosTransaction, error) {
	return withPanicToError(func() (*CosmosTransaction, error) {
		return parseSignDoc(input)
	})
}

// withPanicToError is the recover shape the exported parser uses, factored so the boundary
// conversion is testable with a deliberately-panicking body rather than by waiting for the
// next unenumerated panic path to arrive.
func withPanicToError(body func() (*CosmosTransaction, error)) (transaction *CosmosTransaction, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			transaction, err = nil, fmt.Errorf("%w: parser panic on malformed input: %v", ErrCosmosSignDoc, recovered)
		}
	}()
	return body()
}

func parseSignDoc(input []byte) (*CosmosTransaction, error) {
	var (
		chainID       string
		accountNumber uint64
		bodyBytes     []byte
		authBytes     []byte
		seenBody      bool
		seenAuth      bool
		seenChain     bool
		seenAccount   bool
	)
	err := walkFields(input, func(tag, wire uint64, value []byte) error {
		switch tag {
		case 1:
			if wire != 2 {
				return fmt.Errorf("%w: body_bytes wire %d not allowed", ErrCosmosSignDoc, wire)
			}
			if seenBody {
				return fmt.Errorf("%w: body_bytes appears twice", ErrCosmosSignDoc)
			}
			bodyBytes = append([]byte(nil), value...)
			seenBody = true
		case 2:
			if wire != 2 {
				return fmt.Errorf("%w: auth_info_bytes wire %d not allowed", ErrCosmosSignDoc, wire)
			}
			// auth_info_bytes is required by the schema. The KMS does not
			// extract anything from it today because policy uses
			// account_number from field 4, but a missing field must still
			// fail closed so a partial SignDoc cannot pass.
			if seenAuth {
				return fmt.Errorf("%w: auth_info_bytes appears twice", ErrCosmosSignDoc)
			}
			authBytes = append([]byte(nil), value...)
			seenAuth = true
		case 3:
			if wire != 2 {
				return fmt.Errorf("%w: chain_id wire %d not allowed", ErrCosmosSignDoc, wire)
			}
			if seenChain {
				return fmt.Errorf("%w: chain_id appears twice", ErrCosmosSignDoc)
			}
			chainID = string(value)
			seenChain = true
		case 4:
			if wire != 0 {
				return fmt.Errorf("%w: account_number wire %d not allowed", ErrCosmosSignDoc, wire)
			}
			parsed, _, err := decodeVarint(value)
			// FAULT INJECTION CLASS (#334) [cosmos.parseSignDoc/account-number-redecode]:
			// UNREACHABLE, and not for the reason first recorded here. The earlier note said a
			// varint that runs off the end of `value` would trigger it -- but walkFields decoded
			// this field itself and hands the visitor exactly the bytes it consumed, terminator
			// included, so such an input is refused one frame up and never arrives here. The
			// second decode is the first decode run again on its own output. The invariant that
			// makes that true is checked, not assumed, by the ledger row of this name in
			// fault_injection_leaves_test.go.
			if err != nil {
				return fmt.Errorf("%w: account_number: %v", ErrCosmosSignDoc, err)
			}
			if seenAccount {
				return fmt.Errorf("%w: account_number appears twice", ErrCosmosSignDoc)
			}
			accountNumber = parsed
			seenAccount = true
		default:
			return fmt.Errorf("%w: unexpected field %d", ErrCosmosSignDoc, tag)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// account_number IS NOT REQUIRED TO BE PRESENT, because proto3 does not encode a zero scalar: a
	// genuine SignDoc for account 0 has no field 4 at all, and the chain — which rebuilds the SignDoc
	// from its own state — reads that absence as 0. Requiring it refused every such document. What
	// can be signed for account 0 is still the policy's decision (AccountNumbers), not the parser's.
	// body, auth_info and chain_id stay required: none of them has a zero value a real transaction uses.
	if !seenBody || !seenAuth || !seenChain {
		return nil, fmt.Errorf("%w: missing required SignDoc field", ErrCosmosSignDoc)
	}
	sequence, fee, gasLimit, err := parseAuthInfo([]byte(authBytes))
	if err != nil {
		return nil, err
	}
	messages, err := parseTxBodyMessages(bodyBytes)
	if err != nil {
		return nil, err
	}
	return &CosmosTransaction{ChainID: chainID, AccountNumber: accountNumber, Sequence: sequence, Fee: fee, GasLimit: gasLimit, Messages: messages}, nil
}

func parseAuthInfo(input []byte) (uint64, []Coin, uint64, error) {
	// Empty AuthInfo is wire-valid protobuf but not spendable. Keep parsing it so
	// callers receive the canonical envelope's other diagnostics; policy rejects
	// the zero sequence/gas shape before hardware use.
	if len(input) == 0 {
		return 0, nil, 0, nil
	}
	var signerInfo, feeBytes []byte
	var seenSigner, seenFee bool
	err := walkFields(input, func(tag, wire uint64, value []byte) error {
		if wire != 2 {
			return fmt.Errorf("%w: AuthInfo.field %d wire %d not allowed", ErrCosmosSignDoc, tag, wire)
		}
		switch tag {
		case 1:
			if seenSigner {
				return fmt.Errorf("%w: AuthInfo.signer_infos must contain exactly one signer", ErrCosmosSignDoc)
			}
			signerInfo = append([]byte(nil), value...)
			seenSigner = true
		case 2:
			if seenFee {
				return fmt.Errorf("%w: AuthInfo.fee appears twice", ErrCosmosSignDoc)
			}
			feeBytes = append([]byte(nil), value...)
			seenFee = true
		default:
			return fmt.Errorf("%w: AuthInfo.field %d not allowed", ErrCosmosSignDoc, tag)
		}
		return nil
	})
	if err != nil {
		return 0, nil, 0, err
	}
	if !seenSigner || !seenFee {
		return 0, nil, 0, fmt.Errorf("%w: AuthInfo missing signer or fee", ErrCosmosSignDoc)
	}
	sequence, err := parseSignerInfo(signerInfo)
	if err != nil {
		return 0, nil, 0, err
	}
	fee, gasLimit, err := parseFee(feeBytes)
	if err != nil {
		return 0, nil, 0, err
	}
	return sequence, fee, gasLimit, nil
}

func parseSignerInfo(input []byte) (uint64, error) {
	var sequence uint64
	var seenMode, seenSequence bool
	err := walkFields(input, func(tag, wire uint64, value []byte) error {
		switch tag {
		case 1:
			if wire != 2 {
				return fmt.Errorf("%w: SignerInfo.public_key wire %d not allowed", ErrCosmosSignDoc, wire)
			}
		case 2:
			if wire != 2 {
				return fmt.Errorf("%w: SignerInfo.mode_info wire %d not allowed", ErrCosmosSignDoc, wire)
			}
			if seenMode {
				return fmt.Errorf("%w: SignerInfo.mode_info appears twice", ErrCosmosSignDoc)
			}
			seenMode = true
		case 3:
			if wire != 0 {
				return fmt.Errorf("%w: SignerInfo.sequence wire %d not allowed", ErrCosmosSignDoc, wire)
			}
			if seenSequence {
				return fmt.Errorf("%w: SignerInfo.sequence appears twice", ErrCosmosSignDoc)
			}
			var err error
			sequence, _, err = decodeVarint(value)
			if err != nil {
				return fmt.Errorf("%w: SignerInfo.sequence: %v", ErrCosmosSignDoc, err)
			}
			seenSequence = true
		default:
			return fmt.Errorf("%w: SignerInfo.field %d not allowed", ErrCosmosSignDoc, tag)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	// sequence 0 — every account's FIRST transaction — is encoded by omitting the field (proto3), so
	// its absence means 0, exactly as the chain reads it. mode_info is a message, not a scalar, and a
	// signer with no mode is genuinely malformed, so it stays required.
	if !seenMode {
		return 0, fmt.Errorf("%w: SignerInfo missing mode_info", ErrCosmosSignDoc)
	}
	return sequence, nil
}

func parseFee(input []byte) ([]Coin, uint64, error) {
	var amounts [][]byte
	var gasLimit uint64
	var seenGas bool
	err := walkFields(input, func(tag, wire uint64, value []byte) error {
		switch tag {
		case 1:
			if wire != 2 {
				return fmt.Errorf("%w: Fee.amount wire %d not allowed", ErrCosmosSignDoc, wire)
			}
			amounts = append(amounts, append([]byte(nil), value...))
		case 2:
			if wire != 0 {
				return fmt.Errorf("%w: Fee.gas_limit wire %d not allowed", ErrCosmosSignDoc, wire)
			}
			if seenGas {
				return fmt.Errorf("%w: Fee.gas_limit appears twice", ErrCosmosSignDoc)
			}
			var err error
			gasLimit, _, err = decodeVarint(value)
			if err != nil {
				return fmt.Errorf("%w: Fee.gas_limit: %v", ErrCosmosSignDoc, err)
			}
			seenGas = true
		case 3, 4:
			if wire != 2 {
				return fmt.Errorf("%w: Fee.field %d wire %d not allowed", ErrCosmosSignDoc, tag, wire)
			}
		default:
			return fmt.Errorf("%w: Fee.field %d not allowed", ErrCosmosSignDoc, tag)
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	if !seenGas || gasLimit == 0 {
		return nil, 0, fmt.Errorf("%w: Fee.gas_limit must be positive", ErrCosmosSignDoc)
	}
	coins := make([]Coin, 0, len(amounts))
	for _, raw := range amounts {
		denom, amount, err := decodeCoin(raw)
		if err != nil {
			return nil, 0, err
		}
		coins = append(coins, Coin{Denom: denom, Amount: amount})
	}
	return coins, gasLimit, nil
}

// parseTxBodyMessages decodes the TxBody envelope and lifts the inner message
// payloads out of each google.protobuf.Any. Only the message types that policy
// can meaningfully check (currently /cosmos.bank.v1beta1.MsgSend) are decoded.
func parseTxBodyMessages(input []byte) ([]CosmosMessage, error) {
	var messages []CosmosMessage
	err := walkFields(input, func(tag, wire uint64, value []byte) error {
		if tag != 1 || wire != 2 {
			return fmt.Errorf("%w: TxBody.field %d wire %d not allowed", ErrCosmosSignDoc, tag, wire)
		}
		typeURL, inner, err := decodeAny(value)
		if err != nil {
			return err
		}
		switch typeURL {
		case "/cosmos.bank.v1beta1.MsgSend":
			source, destination, amounts, err := decodeMsgSend(inner)
			if err != nil {
				return err
			}
			messages = append(messages, CosmosMessage{Type: typeURL, Source: source, Destination: destination, Amounts: amounts})
		case "/cosmos.staking.v1beta1.MsgDelegate":
			source, destination, amounts, err := decodeMsgDelegate(inner)
			if err != nil {
				return err
			}
			messages = append(messages, CosmosMessage{Type: typeURL, Source: source, Destination: destination, Amounts: amounts})
		default:
			return fmt.Errorf("%w: unsupported message type %q", ErrCosmosSignDoc, typeURL)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(messages) == 0 {
		return nil, fmt.Errorf("%w: TxBody carries no messages", ErrCosmosSignDoc)
	}
	return messages, nil
}

// decodeMsgDelegate lifts the delegator, validator, and one delegation Coin from
// a /cosmos.staking.v1beta1.MsgDelegate payload. The validator is the policy
// destination for this message type.
func decodeMsgDelegate(input []byte) (string, string, []Coin, error) {
	var source, destination string
	var amount []Coin
	var seenSource, seenDestination, seenAmount bool
	err := walkFields(input, func(tag, wire uint64, value []byte) error {
		if wire != 2 {
			return fmt.Errorf("%w: MsgDelegate.field %d wire %d not allowed", ErrCosmosSignDoc, tag, wire)
		}
		switch tag {
		case 1:
			if seenSource {
				return fmt.Errorf("%w: MsgDelegate.delegator_address appears twice", ErrCosmosSignDoc)
			}
			source, seenSource = string(value), true
		case 2:
			if seenDestination {
				return fmt.Errorf("%w: MsgDelegate.validator_address appears twice", ErrCosmosSignDoc)
			}
			destination, seenDestination = string(value), true
		case 3:
			if seenAmount {
				return fmt.Errorf("%w: MsgDelegate.amount appears twice", ErrCosmosSignDoc)
			}
			denom, valueAmount, err := decodeCoin(value)
			if err != nil {
				return err
			}
			amount, seenAmount = []Coin{{Denom: denom, Amount: valueAmount}}, true
		default:
			return fmt.Errorf("%w: MsgDelegate.field %d not allowed", ErrCosmosSignDoc, tag)
		}
		return nil
	})
	if err != nil {
		return "", "", nil, err
	}
	if !seenSource || !seenDestination || !seenAmount {
		return "", "", nil, fmt.Errorf("%w: MsgDelegate missing delegator, validator or amount", ErrCosmosSignDoc)
	}
	return source, destination, amount, nil
}

// decodeAny splits a google.protobuf.Any into its type_url and inner bytes.
// google.protobuf.Any:
//
//	message Any {
//	  string type_url = 1;
//	  bytes  value    = 2;
//	}
func decodeAny(input []byte) (string, []byte, error) {
	var (
		typeURL string
		value   []byte
		seenURL bool
		seenVal bool
	)
	err := walkLengthDelimited(input, func(tag uint64, field []byte) error {
		switch tag {
		case 1:
			typeURL = string(field)
			seenURL = true
		case 2:
			value = append([]byte(nil), field...)
			seenVal = true
		default:
			return fmt.Errorf("%w: Any.field %d not allowed", ErrCosmosSignDoc, tag)
		}
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	if !seenURL || !seenVal {
		return "", nil, fmt.Errorf("%w: Any missing required field", ErrCosmosSignDoc)
	}
	return typeURL, value, nil
}

// decodeMsgSend lifts the source, destination address and Coin amounts from a
// /cosmos.bank.v1beta1.MsgSend payload.
func decodeMsgSend(input []byte) (string, string, []Coin, error) {
	var (
		source      string
		destination string
		amounts     []Coin
		seenSource  bool
		seenDest    bool
	)
	err := walkFields(input, func(tag, wire uint64, value []byte) error {
		switch tag {
		case 1:
			if wire != 2 {
				return fmt.Errorf("%w: MsgSend.from_address wire %d not allowed", ErrCosmosSignDoc, wire)
			}
			if seenSource {
				return fmt.Errorf("%w: MsgSend.from_address appears twice", ErrCosmosSignDoc)
			}
			source = string(value)
			seenSource = true
		case 2:
			if wire != 2 {
				return fmt.Errorf("%w: MsgSend.to_address wire %d not allowed", ErrCosmosSignDoc, wire)
			}
			if seenDest {
				return fmt.Errorf("%w: MsgSend.to_address appears twice", ErrCosmosSignDoc)
			}
			destination = string(value)
			seenDest = true
		case 3:
			if wire != 2 {
				return fmt.Errorf("%w: Coin wire %d not allowed", ErrCosmosSignDoc, wire)
			}
			denom, amount, err := decodeCoin(value)
			if err != nil {
				return err
			}
			amounts = append(amounts, Coin{Denom: denom, Amount: amount})
		default:
			return fmt.Errorf("%w: MsgSend.field %d not allowed", ErrCosmosSignDoc, tag)
		}
		return nil
	})
	if err != nil {
		return "", "", nil, err
	}
	if !seenSource || !seenDest || len(amounts) == 0 {
		return "", "", nil, fmt.Errorf("%w: MsgSend missing source, destination or amount", ErrCosmosSignDoc)
	}
	return source, destination, amounts, nil
}

// decodeCoin reads a Coin (denom = string field 1, amount = uint64 field 2).
// decodeCoinAmount reads cosmos.base.v1beta1.Coin.amount, which is a DECIMAL STRING.
//
// This decoder required a varint, so it refused every genuine MsgSend. Nothing caught it because
// the only thing checking the claimed v1beta1 conformance was encodeMsgSend in this package's own
// test file, which encodes the amount as a varint too -- the fixture and the decoder shared one
// assumption and agreed with each other about a wire format neither matched. Settled against the
// generated upstream descriptor rather than a second hand-written encoder:
//
//	cosmos.base.v1beta1.Coin
//	  field 1 denom  -> TYPE_STRING (wire 2)
//	  field 2 amount -> TYPE_STRING (wire 2)
//
// AND THE STRING IS NOT AN ACCIDENT OF THE ENCODING. Cosmos amounts are arbitrary-precision Int
// precisely because they do not fit uint64, so this function has to decide what to do with one that
// does not.
//
// AN EARLIER VERSION OF THIS COMMENT SAID ParseUint WOULD "REINTRODUCE #198's TRUNCATION". That is
// false and the comment is corrected rather than annotated: measured, ParseUint("18446744073709551616")
// returns MaxUint64 AND an error, so it saturates only for a caller that ignores the error, and it
// does not truncate at all. The hazard #198 fixed was a decoder discarding high bits silently; this
// one reports.
//
// What the function actually does, and why: accept only uint64-representable values, and report an
// over-large one as its OWN condition rather than as a malformed string. Refusing it loses nothing,
// because MaxPerTransaction is map[string]uint64 -- any such amount already exceeds every
// expressible cap, so the refusal is the cap reached earlier. Keeping the two refusals distinct is
// the point: "larger than any cap can express" and "this is not a number" send an operator to
// different places, and only the second is a reason to inspect an encoder.
func decodeCoinAmount(text string) (uint64, error) {
	if text == "" {
		return 0, fmt.Errorf("%w: Coin.amount is empty", ErrCosmosSignDoc)
	}
	// BY BYTE, NOT BY RUNE. A protobuf string field is raw bytes on the wire, and ranging over a Go
	// string decodes UTF-8: an invalid sequence becomes U+FFFD, so the validation would depend on
	// that decoding and the offending text quoted in the error would not be the bytes received.
	// Indexing bytes rejects every non-ASCII byte deterministically and reports what actually
	// arrived.
	for index := 0; index < len(text); index++ {
		if text[index] < '0' || text[index] > '9' {
			// No sign, no decimal point, no exponent. Cosmos Int is a non-negative integer string;
			// anything else is a document no conforming encoder produces.
			return 0, fmt.Errorf("%w: Coin.amount %q is not a decimal integer", ErrCosmosSignDoc, text)
		}
	}
	if len(text) > 1 && text[0] == '0' {
		// Canonicality, for the same reason duplicate scalars are refused: two spellings of one
		// value are two documents that hash differently and mean the same thing, and only one of
		// them is what an encoder emits.
		return 0, fmt.Errorf("%w: Coin.amount %q has a leading zero", ErrCosmosSignDoc, text)
	}
	amount, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: Coin.amount %q exceeds the largest expressible per-transaction cap",
			ErrCosmosSignDoc, text)
	}
	return amount, nil
}

func decodeCoin(input []byte) (string, uint64, error) {
	// A REPEATED SCALAR IS REFUSED, NOT RESOLVED.
	//
	// These were last-wins in silence. Measured: a Coin carrying amount 999999 followed by
	// amount 1 decoded as 1, and denom "uakt" followed by "uusd" decoded as "uusd". Proto3 says
	// last wins for scalars, so a conforming decoder would agree -- but "we happen to agree with
	// one implementation's tolerance of non-canonical input" is a far weaker position than "we
	// refuse it", and it is the wrong one for a signing boundary. Nothing canonical emits a
	// repeated scalar, so refusing costs nothing and removes the need for every other party that
	// reads these bytes -- the chain, a relayer, an approver's display, this daemon's own audit
	// record -- to resolve them identically.
	var (
		denom     string
		amount    uint64
		seenAmt   bool
		seenDenom bool
	)
	err := walkFields(input, func(tag, wire uint64, value []byte) error {
		switch tag {
		case 1:
			if wire != 2 {
				return fmt.Errorf("%w: Coin.denom wire %d not allowed", ErrCosmosSignDoc, wire)
			}
			if seenDenom {
				return fmt.Errorf("%w: Coin.denom appears twice", ErrCosmosSignDoc)
			}
			denom = string(value)
			seenDenom = true
		case 2:
			if wire != 2 {
				return fmt.Errorf("%w: Coin.amount wire %d not allowed", ErrCosmosSignDoc, wire)
			}
			// DUPLICATE BEFORE PARSE. The rebase of #199 onto #198 left these the other way round,
			// and git merged it without a conflict. A Coin carrying a valid amount followed by a
			// malformed one then reported "not a decimal integer" — a true statement about the
			// second copy and the wrong diagnosis of the document, which is a repeated field. Same
			// shape as a truncated varint reported as exceeding 64 bits: right refusal, wrong
			// sentence, and the sentence is what an operator acts on.
			if seenAmt {
				return fmt.Errorf("%w: Coin.amount appears twice", ErrCosmosSignDoc)
			}
			parsed, err := decodeCoinAmount(string(value))
			if err != nil {
				return err
			}
			amount = parsed
			seenAmt = true
		default:
			return fmt.Errorf("%w: Coin.field %d not allowed", ErrCosmosSignDoc, tag)
		}
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	if denom == "" || !seenAmt {
		return "", 0, fmt.Errorf("%w: Coin missing denom or amount", ErrCosmosSignDoc)
	}
	return denom, amount, nil
}
