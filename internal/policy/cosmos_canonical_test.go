package policy

import (
	"bytes"
	"errors"
	"testing"
)

// signDocField is one top-level SignDoc field exactly as it appeared on the wire: tag bytes, then
// length or varint bytes, then the value. Split here by a test-local reader, not walkFields, so the
// variants below are built without the code under test.
type signDocField struct {
	number uint64
	raw    []byte
}

func testVarint(t *testing.T, input []byte) (uint64, int) {
	t.Helper()
	var value uint64
	for index := 0; index < len(input) && index < 10; index++ {
		value |= uint64(input[index]&0x7f) << (7 * index)
		if input[index]&0x80 == 0 {
			return value, index + 1
		}
	}
	t.Fatalf("fixture carries a malformed varint")
	return 0, 0
}

func splitSignDoc(t *testing.T, input []byte) []signDocField {
	t.Helper()
	var fields []signDocField
	for offset := 0; offset < len(input); {
		start := offset
		tag, consumed := testVarint(t, input[offset:])
		offset += consumed
		switch tag & 7 {
		case 0:
			_, consumed := testVarint(t, input[offset:])
			offset += consumed
		case 2:
			length, consumed := testVarint(t, input[offset:])
			offset += consumed + int(length)
		default:
			t.Fatalf("fixture carries wire type %d", tag&7)
		}
		fields = append(fields, signDocField{number: tag >> 3, raw: input[start:offset]})
	}
	return fields
}

func joinFields(fields ...signDocField) []byte {
	var out []byte
	for _, field := range fields {
		out = append(out, field.raw...)
	}
	return out
}

// TestCosmosSignDocRefusesNonCanonical (regalia-kms-35b AC1, AC3): THE BYTES THE TOKEN SIGNS MUST BE
// THE BYTES A VERIFIER RECOMPUTES. A chain rebuilds the SignDoc from its own state in field-number
// order with minimal encodings and proto3 defaults left out, and verifies against sha256 of that.
// Every variant below means the same transaction as the fixture and hashes differently, so a
// signature over it would verify nowhere. Each must be refused before signing.
func TestCosmosSignDocRefusesNonCanonical(t *testing.T) {
	canonical := readReferenceHex(t, "signdoc-akashnet2-msgsend.hex")
	fields := splitSignDoc(t, canonical)
	if len(fields) != 4 {
		t.Fatalf("fixture has %d top-level fields, want 4", len(fields))
	}
	for index, field := range fields {
		if field.number != uint64(index+1) {
			t.Fatalf("fixture field %d is number %d: the fixture itself is not canonical", index, field.number)
		}
	}
	body, auth, chain, account := fields[0], fields[1], fields[2], fields[3]
	// chain_id "akashnet-2" is 10 bytes; 0x8a 0x00 is 10 in two varint bytes.
	nonMinimalLength := signDocField{3, append([]byte{0x1a, 0x8a, 0x00}, chain.raw[2:]...)}
	// The tag 0x1a written as 0x9a 0x00.
	nonMinimalTag := signDocField{3, append([]byte{0x9a, 0x00}, chain.raw[1:]...)}
	// account_number 42 (0x2a) written as 0xaa 0x00.
	nonMinimalAccount := signDocField{4, []byte{0x20, 0xaa, 0x00}}
	for name, variant := range map[string][]byte{
		"reversed":                     joinFields(account, chain, auth, body),
		"auth_info before body":        joinFields(auth, body, chain, account),
		"account before chain_id":      joinFields(body, auth, account, chain),
		"non-minimal length":           joinFields(body, auth, nonMinimalLength, account),
		"non-minimal tag":              joinFields(body, auth, nonMinimalTag, account),
		"non-minimal account varint":   joinFields(body, auth, chain, nonMinimalAccount),
		"explicit account_number zero": joinFields(body, auth, chain, signDocField{4, []byte{0x20, 0x00}}),
	} {
		t.Run(name, func(t *testing.T) {
			if bytes.Equal(variant, canonical) {
				t.Fatal("variant is the canonical encoding; the test proves nothing")
			}
			if _, err := ParseCosmosSignDoc(variant); !errors.Is(err, ErrCosmosSignDoc) {
				t.Fatalf("DEFECT: a non-canonical SignDoc was accepted for signing (err=%v): the token would sign bytes no verifier recomputes", err)
			}
		})
	}
}

// TestCosmosSignDocAcceptsCanonicalFixtures: the refusal above must not reach a document an
// encoder actually emits, including the account-0, sequence-0 one whose field 4 is absent.
func TestCosmosSignDocAcceptsCanonicalFixtures(t *testing.T) {
	for _, name := range []string{"signdoc-akashnet2-msgsend.hex", "signdoc-akashnet2-msgdelegate.hex", "signdoc-akashnet2-msgsend-account0-sequence0.hex"} {
		if _, err := ParseCosmosSignDoc(readReferenceHex(t, name)); err != nil {
			t.Errorf("%s: generated canonical SignDoc refused: %v", name, err)
		}
	}
}
