package policy

import "fmt"

// walkFields iterates over every tag/value pair in a protobuf message body.
// The visitor receives the field number (tag), the wire type, and either the
// raw bytes (wire type 2, length-delimited) or the unconsumed varint payload
// (wire type 0). Unknown wire types and malformed length prefixes are
// reported as errors so callers can fail closed.
//
// The decoder is intentionally minimal: only wire types 0 (varint) and 2
// (length-delimited) are recognised because the canonical Cosmos types used
// by the policy layer do not embed any other wire kind.
func walkFields(input []byte, visit func(tag, wire uint64, value []byte) error) error {
	offset := 0
	for offset < len(input) {
		tag, consumed, err := decodeVarint(input[offset:])
		if err != nil {
			return fmt.Errorf("%w: tag varint: %v", ErrCosmosSignDoc, err)
		}
		offset += consumed
		fieldNumber := tag >> 3
		wireType := tag & 0x7
		switch wireType {
		case 0:
			varintStart := offset
			_, consumed, err := decodeVarint(input[offset:])
			if err != nil {
				return fmt.Errorf("%w: field %d varint: %v", ErrCosmosSignDoc, fieldNumber, err)
			}
			offset += consumed
			if err := visit(fieldNumber, wireType, input[varintStart:offset]); err != nil {
				return err
			}
		case 2:
			length, consumed, err := decodeVarint(input[offset:])
			if err != nil {
				return fmt.Errorf("%w: field %d length: %v", ErrCosmosSignDoc, fieldNumber, err)
			}
			offset += consumed
			end := offset + int(length)
			if end < offset || end > len(input) {
				return fmt.Errorf("%w: field %d length %d exceeds buffer", ErrCosmosSignDoc, fieldNumber, length)
			}
			value := input[offset:end]
			offset = end
			if err := visit(fieldNumber, wireType, value); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%w: field %d wire type %d not allowed", ErrCosmosSignDoc, fieldNumber, wireType)
		}
	}
	return nil
}

// walkLengthDelimited iterates over every length-delimited field in a
// protobuf message body and exposes the inner bytes to the visitor. This is
// the common pattern for nested messages where the visitor does not need to
// inspect the wire type. Any varint field encountered aborts the walk so a
// structural mismatch cannot be silently ignored.
func walkLengthDelimited(input []byte, visit func(tag uint64, value []byte) error) error {
	return walkFields(input, func(tag, wire uint64, value []byte) error {
		if wire != 2 {
			return fmt.Errorf("%w: field %d wire %d not length-delimited", ErrCosmosSignDoc, tag, wire)
		}
		return visit(tag, value)
	})
}

// decodeVarint reads a single base-128 varint from the front of input and
// returns the decoded value plus the number of bytes consumed. Varints longer
// than 10 bytes or with continuation bits beyond 64 bits are rejected so
// crafted inputs cannot overflow the return value.
func decodeVarint(input []byte) (uint64, int, error) {
	var (
		shift    uint
		value    uint64
		consumed int
	)
	for consumed < len(input) {
		b := input[consumed]
		consumed++
		if shift >= 64 {
			return 0, 0, fmt.Errorf("%w: varint exceeds 64 bits", ErrCosmosSignDoc)
		}
		// THE TENTH BYTE CARRIES ONE USABLE BIT, AND THE REST WERE BEING DROPPED IN SILENCE.
		//
		// The guard above catches an eleventh byte. It does not catch high bits in the tenth:
		// at shift 63 the OR below shifts bits 64..69 straight out of the word, so the value
		// silently changes rather than being refused. Measured before this line existed:
		//
		//	2^64 + 5 -> 5, no error
		//	2^64     -> 0, no error
		//
		// A decoder that turns 18446744073709551621 into 5 without complaint is the worst
		// possible shape for one whose output is compared against a spend cap: the policy
		// authorises the small number, and anything that reads the same bytes differently sees
		// the large one. Refusing is the only safe answer, because there is no correct value to
		// report -- the bytes do not fit the type.
		//
		// The mask matters. Testing the whole byte would classify a tenth byte of 0x80 -- a
		// continuation bit over a payload of zero, which fits -- as "exceeds 64 bits", when what
		// is actually wrong with such an input is that it is truncated or has an eleventh byte.
		// Only the payload bits can overflow, so only they are checked, and the two existing
		// refusals keep their own meanings.
		if shift == 63 && b&0x7f > 1 {
			return 0, 0, fmt.Errorf("%w: varint exceeds 64 bits", ErrCosmosSignDoc)
		}
		value |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return value, consumed, nil
		}
		shift += 7
	}
	return 0, 0, fmt.Errorf("%w: truncated varint", ErrCosmosSignDoc)
}
