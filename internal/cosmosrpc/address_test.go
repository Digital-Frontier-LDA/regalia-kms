package cosmosrpc

import (
	"encoding/hex"
	"strings"
	"testing"
)

// The generator point G of secp256k1, compressed: its hash160 is BIP-173's own example, and its addresses were
// computed independently with Python's hashlib RIPEMD-160 and BIP-173's reference bech32 encoder.
var generator, _ = hex.DecodeString("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")

func TestTheSignerIsTheKeysAccount(t *testing.T) {
	if got := hex.EncodeToString(Hash160(generator)); got != "751e76e8199196d454941c45d1b3a323f1433bd6" {
		t.Fatalf("hash160(G) = %s", got)
	}
	for _, address := range []string{"cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c", "akash1w508d6qejxtdg4y5r3zarvary0c5xw7khx6akz"} {
		if err := MatchesKey(address, generator); err != nil {
			t.Fatalf("%s: %v", address, err)
		}
	}
	other := append([]byte{0x03}, generator[1:]...) // -G: another key
	for _, c := range []struct {
		address string
		key     []byte
		want    string
	}{
		{"cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c", other, "is not this key's account"},
		{"cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60d", generator, "checksum does not verify"},
		{"COSMOS1W508D6QEJXTDG4Y5R3ZARVARY0C5XW7K6AH60C", generator, "lowercase"},
		{"cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k7ah60c", generator, "checksum does not verify"},
		{"cosmos1b508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c", generator, "not a bech32 character"},
		{"cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c", generator[:32], "not a compressed secp256k1 point"},
		{"cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c", append([]byte{0x04}, generator[1:]...), "not a compressed secp256k1 point"},
		{"nohrp", generator, "no human-readable part"},
	} {
		if err := MatchesKey(c.address, c.key); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, not %q", c.address, err, c.want)
		}
	}
}
