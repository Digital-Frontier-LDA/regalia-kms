package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func FuzzParseX509TBS(f *testing.F) {
	p, issuer, _, now, cert, crl := x509FixtureWithKeys(f, true)
	compiled, err := compileX509(p)
	if err != nil {
		f.Fatal(err)
	}
	for _, data := range [][]byte{cert, crl} {
		parsed, err := ParseX509TBS(data)
		if err != nil {
			f.Fatal("valid fuzz seed refused", err)
		}
		if _, rule := compiled.validate(parsed, now, x509Fingerprint(issuer)); rule != "" {
			f.Fatal("valid seed failed profile", rule)
		}
		f.Add(data)
		f.Add(append(bytes.Clone(data), 0))
		f.Add(data[:len(data)/2])
	}
	for _, tc := range x509DERRefusalCases {
		data := cert
		if tc.kind == "crl" {
			data = crl
		}
		f.Add(x509DERRefusalMutation(f, data, tc.kind, tc.mutation))
	}
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x80, 0, 0})
	f.Add(bytes.Repeat([]byte{0}, (32<<10)+1))
	fingerprint := x509Fingerprint(issuer)
	f.Fuzz(func(t *testing.T, data []byte) {
		parsed, err := ParseX509TBS(data)
		if err != nil {
			if !errors.Is(err, ErrX509Malformed) {
				t.Fatal("unexpected parser refusal class")
			}
			return
		}
		if len(data) == 0 || len(data) > 32<<10 || parsed == nil {
			t.Fatal("parser accepted unbounded input")
		}
		digest := sha256.Sum256(data)
		if parsed.Digest() != "sha256:"+hex.EncodeToString(digest[:]) {
			t.Fatal("parser digest differs from full input")
		}
		var full []byte
		switch parsed.Kind() {
		case "certificate":
			full = parsed.certificate.RawTBSCertificate
		case "crl":
			full = parsed.crl.RawTBSRevocationList
		default:
			t.Fatal("unknown parsed artifact kind")
		}
		if !bytes.Equal(full, data) {
			t.Fatal("parser failed to preserve full signing bytes")
		}
		if _, err := ParseX509TBS(append(bytes.Clone(data), 0)); !errors.Is(err, ErrX509Malformed) {
			t.Fatal("parser accepted appended DER")
		}
		if kind, rule := compiled.validate(parsed, now, fingerprint); rule == "" {
			if kind != parsed.Kind() {
				t.Fatal("profile changed artifact kind")
			}
			if kind == "certificate" && parsed.certificate.VerifyHostname(parsed.certificate.Subject.CommonName) != nil {
				t.Fatal("profile allowed unmatched subject name")
			}
		}
	})
}
