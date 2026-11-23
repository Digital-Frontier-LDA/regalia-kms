package policy

import (
	"errors"
	"testing"
)

// TestCosmosSignDocKeepsTheSignerPublicKey (regalia-kms-35b review, council A): the parser keeps
// the single signer's SignerInfo.public_key -- the key a chain verifies the signature with -- so
// the daemon can check the token's signature under it. It used to be walked and dropped.
func TestCosmosSignDocKeepsTheSignerPublicKey(t *testing.T) {
	signDoc := readReferenceHex(t, "signdoc-akashnet2-msgsend.hex")
	key := append([]byte{0x02}, make([]byte, 32)...)
	key[32] = 0x07
	anyKey := func(typeURL string, inner []byte) []byte {
		return appendLengthDelimited(appendLengthDelimited(nil, 1, []byte(typeURL)), 2, inner)
	}
	keyMessage := appendLengthDelimited(nil, 1, key)

	parsed, err := ParseCosmosSignDoc(signDoc)
	if err != nil || parsed.SignerPublicKey != nil {
		t.Fatalf("the fixture carries no signer key: got %+v, err %v", parsed, err)
	}

	for name, test := range map[string]struct {
		publicKeys [][]byte
		wantType   string
		wantKey    []byte
		refused    bool
	}{
		"a secp256k1 key is kept":         {publicKeys: [][]byte{anyKey("/cosmos.crypto.secp256k1.PubKey", keyMessage)}, wantType: "/cosmos.crypto.secp256k1.PubKey", wantKey: key},
		"a secp256r1 key is kept":         {publicKeys: [][]byte{anyKey("/cosmos.crypto.secp256r1.PubKey", keyMessage)}, wantType: "/cosmos.crypto.secp256r1.PubKey", wantKey: key},
		"another type keeps only a URL":   {publicKeys: [][]byte{anyKey("/cosmos.crypto.multisig.LegacyAminoPubKey", []byte{0x08, 0x01})}, wantType: "/cosmos.crypto.multisig.LegacyAminoPubKey"},
		"public_key twice is refused":     {publicKeys: [][]byte{anyKey("/cosmos.crypto.secp256k1.PubKey", keyMessage), anyKey("/cosmos.crypto.secp256k1.PubKey", keyMessage)}, refused: true},
		"an empty key is refused":         {publicKeys: [][]byte{anyKey("/cosmos.crypto.secp256k1.PubKey", appendLengthDelimited(nil, 1, nil))}, refused: true},
		"key twice is refused":            {publicKeys: [][]byte{anyKey("/cosmos.crypto.secp256k1.PubKey", append(append([]byte(nil), keyMessage...), keyMessage...))}, refused: true},
		"an unknown key field is refused": {publicKeys: [][]byte{anyKey("/cosmos.crypto.secp256k1.PubKey", appendLengthDelimited(nil, 2, key))}, refused: true},
		"a malformed Any is refused":      {publicKeys: [][]byte{{0x0a, 0x05}}, refused: true},
	} {
		t.Run(name, func(t *testing.T) {
			parsed, err := ParseCosmosSignDoc(withSignerPublicKeys(t, signDoc, test.publicKeys))
			if test.refused {
				if !errors.Is(err, ErrCosmosSignDoc) {
					t.Fatalf("err = %v, want ErrCosmosSignDoc", err)
				}
				return
			}
			if err != nil || parsed.SignerPublicKey == nil {
				t.Fatalf("DEFECT: the signer key was not kept: %+v, err %v", parsed, err)
			}
			if parsed.SignerPublicKey.TypeURL != test.wantType || string(parsed.SignerPublicKey.Key) != string(test.wantKey) {
				t.Fatalf("signer key = %q %x, want %q %x", parsed.SignerPublicKey.TypeURL, parsed.SignerPublicKey.Key, test.wantType, test.wantKey)
			}
		})
	}
}

// withSignerPublicKeys rebuilds signDoc canonically with the given SignerInfo.public_key fields
// (each an encoded Any) in front of the signer's other fields.
func withSignerPublicKeys(t *testing.T, signDoc []byte, publicKeys [][]byte) []byte {
	t.Helper()
	var body, authInfo []byte
	var chainID string
	var account uint64
	if err := walkFields(signDoc, func(tag, _ uint64, value []byte) error {
		switch tag {
		case 1:
			body = value
		case 2:
			authInfo = value
		case 3:
			chainID = string(value)
		case 4:
			account, _, _ = decodeVarint(value)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var rebuiltAuth []byte
	if err := walkFields(authInfo, func(tag, _ uint64, value []byte) error {
		if tag != 1 {
			rebuiltAuth = appendLengthDelimited(rebuiltAuth, tag, value)
			return nil
		}
		var signer []byte
		for _, key := range publicKeys {
			signer = appendLengthDelimited(signer, 1, key)
		}
		if err := walkFields(value, func(tag, wire uint64, field []byte) error {
			switch {
			case tag == 1:
			case wire == 2:
				signer = appendLengthDelimited(signer, tag, field)
			default:
				signer = appendVarint(appendVarint(signer, tag<<3), mustVarint(t, field))
			}
			return nil
		}); err != nil {
			return err
		}
		rebuiltAuth = appendLengthDelimited(rebuiltAuth, 1, signer)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return canonicalSignDocBytes(body, rebuiltAuth, chainID, account)
}

func mustVarint(t *testing.T, field []byte) uint64 {
	t.Helper()
	value, _, err := decodeVarint(field)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
