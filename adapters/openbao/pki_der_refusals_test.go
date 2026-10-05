package openbaopoc

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"strings"
	"testing"
)

var pocDERRefusalCases = []struct{ kind, mutation string }{
	{"certificate", "subject-attribute-extra-field"},
	{"certificate", "validity-extra-field"},
	{"certificate", "spki-extra-field"},
	{"certificate", "spki-algorithm-extra-field"},
	{"certificate", "usage-hidden-bit"},
	{"certificate", "value-trailing:2.5.29.14"},
	{"certificate", "value-trailing:2.5.29.15"},
	{"certificate", "value-trailing:2.5.29.17"},
	{"certificate", "value-trailing:2.5.29.19"},
	{"certificate", "value-trailing:2.5.29.35"},
	{"certificate", "value-trailing:2.5.29.37"},
	{"certificate", "authority-extra-field"},
	{"certificate", "extension-extra-field"},
	{"certificate", "explicit-wrapper-trailing"},
	{"crl", "value-trailing:2.5.29.20"},
	{"crl", "value-trailing:2.5.29.35"},
	{"crl", "authority-extra-field"},
	{"crl", "extension-extra-field"},
	{"crl", "explicit-wrapper-trailing"},
	{"crl", "entry-extra-field"},
	{"crl", "entry-empty-extensions"},
}

func TestPOCInspectionsRefuseIgnoredDER(t *testing.T) {
	issuer, now, cert, crl, _ := pocFuzzInputs(t)
	for _, tc := range pocDERRefusalCases {
		t.Run(tc.kind+"/"+tc.mutation, func(t *testing.T) {
			data := cert
			if tc.kind == "crl" {
				data = crl
			}
			mutated := pocDERRefusalMutation(t, data, tc.kind, tc.mutation)
			var err error
			if tc.kind == "certificate" {
				_, err = pocInspectCertificate(mutated, issuer, now)
			} else {
				_, err = pocInspectCRL(mutated, issuer, now)
			}
			if !errors.Is(err, errPOCProfile) {
				t.Fatal("inspector accepted ignored DER inside an otherwise valid structure")
			}
		})
	}
}

// These mutations preserve the surrounding DER while placing extra data where
// a permissive X.509 parser can stop early. The helper is also used for explicit
// fuzz corpus seeds, so known parser gaps remain covered after random fuzzing.
func pocDERRefusalMutation(t testing.TB, data []byte, kind, mutation string) []byte {
	t.Helper()
	encode := func(value any) []byte {
		t.Helper()
		encoded, err := asn1.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	decode := func(data []byte, target any) {
		t.Helper()
		if rest, err := asn1.Unmarshal(data, target); err != nil || len(rest) != 0 {
			t.Fatal("invalid structured DER mutation seed")
		}
	}
	fields, err := pocTBSFields(data)
	if err != nil {
		t.Fatal(err)
	}
	extra := asn1.RawValue{FullBytes: []byte{2, 1, 7}}
	if kind == "certificate" {
		switch mutation {
		case "subject-attribute-extra-field":
			var subject, set, attribute asn1.RawValue
			decode(fields[5].FullBytes, &subject)
			decode(subject.Bytes, &set)
			decode(set.Bytes, &attribute)
			var values []asn1.RawValue
			decode(attribute.FullBytes, &values)
			set = asn1.RawValue{Class: 0, Tag: 17, IsCompound: true, Bytes: encode(append(values, extra))}
			subject = asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: encode(set)}
			fields[5] = asn1.RawValue{FullBytes: encode(subject)}
			return encode(fields)
		case "validity-extra-field", "spki-extra-field", "spki-algorithm-extra-field":
			index := 6
			if mutation == "validity-extra-field" {
				index = 4
			}
			var values []asn1.RawValue
			decode(fields[index].FullBytes, &values)
			if mutation == "spki-algorithm-extra-field" {
				var algorithm []asn1.RawValue
				decode(values[0].FullBytes, &algorithm)
				values[0] = asn1.RawValue{FullBytes: encode(append(algorithm, extra))}
			} else {
				values = append(values, extra)
			}
			fields[index] = asn1.RawValue{FullBytes: encode(values)}
			return encode(fields)
		}
	}
	if strings.HasPrefix(mutation, "entry-") {
		if kind != "crl" || len(fields) != 7 {
			t.Fatal("entry mutation requires a CRL with revoked entries")
		}
		var entries, entry []asn1.RawValue
		decode(fields[5].FullBytes, &entries)
		if len(entries) != 1 {
			t.Fatal("entry seed requires exactly one revoked serial")
		}
		decode(entries[0].FullBytes, &entry)
		if len(entry) != 2 {
			t.Fatal("entry seed contains unexpected fields")
		}
		if mutation == "entry-empty-extensions" {
			extra = asn1.RawValue{FullBytes: []byte{0x30, 0}}
		} else if mutation != "entry-extra-field" {
			t.Fatal("unknown entry mutation")
		}
		entry = append(entry, extra)
		entries[0] = asn1.RawValue{FullBytes: encode(entry)}
		fields[5] = asn1.RawValue{FullBytes: encode(entries)}
		return encode(fields)
	}
	extensionIndex := len(fields) - 1
	var sequence asn1.RawValue
	decode(fields[extensionIndex].Bytes, &sequence)
	encoded := sequence.FullBytes
	switch {
	case mutation == "explicit-wrapper-trailing":
		encoded = append(append([]byte(nil), encoded...), extra.FullBytes...)
	case mutation == "extension-extra-field":
		var extensions, extension []asn1.RawValue
		decode(encoded, &extensions)
		if len(extensions) == 0 {
			t.Fatal("extension mutation requires a nonempty seed")
		}
		decode(extensions[0].FullBytes, &extension)
		extension = append(extension, extra)
		extensions[0] = asn1.RawValue{FullBytes: encode(extension)}
		encoded = encode(extensions)
	default:
		var extensions []pkix.Extension
		decode(encoded, &extensions)
		oid := "2.5.29.35"
		if strings.HasPrefix(mutation, "value-trailing:") {
			oid = strings.TrimPrefix(mutation, "value-trailing:")
		} else if mutation == "usage-hidden-bit" {
			oid = "2.5.29.15"
		} else if mutation != "authority-extra-field" {
			t.Fatal("unknown extension mutation")
		}
		matched := false
		for i := range extensions {
			if extensions[i].Id.String() != oid {
				continue
			}
			matched = true
			if mutation == "usage-hidden-bit" {
				// Go's semantic parser reads only the nine defined KU bits.
				// Include digitalSignature plus an undefined tenth bit.
				extensions[i].Value = encode(asn1.BitString{Bytes: []byte{0x80, 0x40}, BitLength: 10})
			} else if mutation == "authority-extra-field" {
				values, err := pocTBSFields(extensions[i].Value)
				if err != nil {
					t.Fatal(err)
				}
				extensions[i].Value = encode(append(values, extra))
			} else {
				extensions[i].Value = append(append([]byte(nil), extensions[i].Value...), extra.FullBytes...)
			}
		}
		if !matched && kind == "certificate" && oid == "2.5.29.14" {
			// Leaf SKI is optional in the valid seed. Insert its permitted
			// OCTET STRING value before appending the ignored trailing field.
			value := encode([]byte{1, 2, 3, 4})
			extensions = append(extensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: append(value, extra.FullBytes...)})
			matched = true
		}
		if !matched {
			t.Fatal("known-extension mutation seed is missing its target OID")
		}
		encoded = encode(extensions)
	}
	fields[extensionIndex] = asn1.RawValue{Class: fields[extensionIndex].Class, Tag: fields[extensionIndex].Tag, IsCompound: true, Bytes: encoded}
	return encode(fields)
}
