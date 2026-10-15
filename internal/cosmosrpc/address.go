package cosmosrpc

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // Cosmos addresses are RIPEMD160(SHA256(pubkey)): the chain's definition
)

// THE SIGNER IS THE KEY (d9 on #499). A Cosmos account address is bech32(hrp, RIPEMD160(SHA256(compressed secp256k1
// public key))). The cosmos-account check compares the SignDoc with what the chain says of the messages' signer;
// without this, "the signer" would be whatever the request names. MatchesKey ties it to the key the KMS holds.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// Hash160 is RIPEMD160(SHA256(data)): a Cosmos account's 20 bytes from its compressed public key.
func Hash160(data []byte) []byte {
	sum := sha256.Sum256(data)
	h := ripemd160.New()
	h.Write(sum[:])
	return h.Sum(nil)
}

func bech32Polymod(values []byte) uint32 {
	generator := [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	checksum := uint32(1)
	for _, v := range values {
		top := checksum >> 25
		checksum = (checksum&0x1ffffff)<<5 ^ uint32(v)
		for i := 0; i < 5; i++ {
			if (top>>uint(i))&1 == 1 {
				checksum ^= generator[i]
			}
		}
	}
	return checksum
}

// DecodeBech32 is BIP-173's decode (bech32, not bech32m, as Cosmos addresses are), lowercase only. It returns the
// human-readable part and the data as 8-bit bytes.
func DecodeBech32(address string) (string, []byte, error) {
	if len(address) > 90 || strings.ToLower(address) != address {
		return "", nil, errors.New("not a lowercase bech32 string of at most 90 characters")
	}
	separator := strings.LastIndexByte(address, '1')
	if separator < 1 || separator+7 > len(address) {
		return "", nil, errors.New("no human-readable part, or no checksum")
	}
	hrp, data := address[:separator], address[separator+1:]
	values := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		index := strings.IndexByte(bech32Charset, data[i])
		if index < 0 {
			return "", nil, fmt.Errorf("%q is not a bech32 character", data[i])
		}
		values = append(values, byte(index))
	}
	expanded := make([]byte, 0, 2*len(hrp)+1+len(values))
	for i := 0; i < len(hrp); i++ {
		expanded = append(expanded, hrp[i]>>5)
	}
	expanded = append(expanded, 0)
	for i := 0; i < len(hrp); i++ {
		expanded = append(expanded, hrp[i]&31)
	}
	if bech32Polymod(append(expanded, values...)) != 1 {
		return "", nil, errors.New("the checksum does not verify")
	}
	values = values[:len(values)-6]
	// 5-bit groups to bytes, with no padding left over
	var out []byte
	accumulator, bits := uint32(0), uint(0)
	for _, v := range values {
		accumulator = accumulator<<5 | uint32(v)
		bits += 5
		for bits >= 8 {
			bits -= 8
			out = append(out, byte(accumulator>>bits))
		}
	}
	if bits >= 5 || (accumulator<<(8-bits))&0xff != 0 {
		return "", nil, errors.New("the data has padding a bech32 encoder would not leave")
	}
	return hrp, out, nil
}

// MatchesKey refuses unless `address` is the account of the compressed secp256k1 public key `key` (33 bytes).
func MatchesKey(address string, key []byte) error {
	if len(key) != 33 || (key[0] != 2 && key[0] != 3) {
		return errors.New("the key's pinned public key is not a compressed secp256k1 point")
	}
	_, data, err := DecodeBech32(address)
	if err != nil {
		return fmt.Errorf("the signer %q: %v", address, err)
	}
	if !bytes.Equal(data, Hash160(key)) {
		return fmt.Errorf("the signer %q is not this key's account", address)
	}
	return nil
}
