package policy

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParseSignDocNeverPanicsAndRefusesAsSignDocErrors fuzzes the INNER parser, not
// ParseCosmosSignDoc. The exported function recovers any panic into ErrCosmosSignDoc, which is the
// right boundary for production and exactly wrong for fuzzing: it would turn every crash the fuzzer
// finds into a passing refusal. Here a panic fails the target, so the recover stays a net, not the
// only thing standing between a malformed transaction and a dropped request.
//
// It also pins the refusal class: every error must wrap ErrCosmosSignDoc, because the coordinator
// maps that sentinel to a recorded 400; any other error type is a refusal the audit trail cannot
// classify.
func FuzzParseSignDocNeverPanicsAndRefusesAsSignDocErrors(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join("testdata", "signdoc-*.hex"))
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			f.Fatal(err)
		}
		seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			f.Fatalf("%s: %v", file, err)
		}
		f.Add(seed)
	}
	f.Add(encodeSignDoc("akashnet-2", 7, []byte{0x0a, 0x00}))
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01})
	f.Fuzz(func(t *testing.T, input []byte) {
		transaction, err := parseSignDoc(input)
		if err != nil {
			if transaction != nil {
				t.Fatal("a refused SignDoc also returned a transaction")
			}
			if !errors.Is(err, ErrCosmosSignDoc) {
				t.Fatalf("refusal is not an ErrCosmosSignDoc: %v", err)
			}
			return
		}
		if transaction == nil {
			t.Fatal("accepted with a nil transaction")
		}
	})
}
