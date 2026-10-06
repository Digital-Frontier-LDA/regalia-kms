package policy

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
)

var x509ECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

// ParseX509TBS accepts complete unhashed certificate or CRL signing bytes.
// It owns a copy of all parsed state and consumes every supported DER field.
// Name, issuer, time and usage authorization belongs to the compiled profile.
func ParseX509TBS(data []byte) (*X509TBS, error) {
	if len(data) == 0 || len(data) > 32<<10 {
		return nil, ErrX509Malformed
	}
	copied := bytes.Clone(data)
	fields, err := x509DERSequence(copied, 12)
	if err != nil {
		return nil, ErrX509Malformed
	}
	encoded, err := asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: copied}, pkix.AlgorithmIdentifier{Algorithm: x509ECDSASHA256}, asn1.BitString{Bytes: []byte{0}, BitLength: 8}})
	if err != nil {
		return nil, ErrX509Malformed
	}
	digest := sha256.Sum256(copied)
	result := &X509TBS{digest: "sha256:" + hex.EncodeToString(digest[:])}
	if len(fields) == 8 && fields[0].Class == 2 && fields[0].Tag == 0 && fields[7].Class == 2 && fields[7].Tag == 3 {
		if !x509CertificateDER(fields) {
			return nil, ErrX509Malformed
		}
		cert, err := x509.ParseCertificate(encoded)
		if err != nil || !bytes.Equal(cert.RawTBSCertificate, copied) || cert.SignatureAlgorithm != x509.ECDSAWithSHA256 ||
			!x509ExtensionsDER(fields[7], cert.Extensions) {
			return nil, ErrX509Malformed
		}
		result.certificate = cert
		return result, nil
	}
	if (len(fields) == 6 || len(fields) == 7) && x509Primitive(fields[0], asn1.TagInteger) && bytes.Equal(fields[0].FullBytes, []byte{2, 1, 1}) &&
		fields[len(fields)-1].Class == 2 && fields[len(fields)-1].Tag == 0 {
		if !x509NameDER(fields[2].FullBytes) || !x509TimeDER(fields[3]) || !x509TimeDER(fields[4]) {
			return nil, ErrX509Malformed
		}
		crl, err := x509.ParseRevocationList(encoded)
		if err != nil || !bytes.Equal(crl.RawTBSRevocationList, copied) || crl.SignatureAlgorithm != x509.ECDSAWithSHA256 ||
			!x509CRLEntriesDER(fields, len(crl.RevokedCertificateEntries)) || !x509ExtensionsDER(fields[len(fields)-1], crl.Extensions) {
			return nil, ErrX509Malformed
		}
		result.crl = crl
		return result, nil
	}
	return nil, ErrX509Malformed
}

func x509DERSequence(data []byte, maxFields int) ([]asn1.RawValue, error) {
	if len(data) == 0 || len(data) > 32<<10 {
		return nil, ErrX509Malformed
	}
	var sequence asn1.RawValue
	if rest, err := asn1.Unmarshal(data, &sequence); err != nil || len(rest) != 0 || sequence.Class != 0 || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return nil, ErrX509Malformed
	}
	return x509DERContents(sequence.Bytes, maxFields)
}

func x509DERContents(data []byte, maxFields int) ([]asn1.RawValue, error) {
	var fields []asn1.RawValue
	for len(data) != 0 {
		var value asn1.RawValue
		rest, err := asn1.Unmarshal(data, &value)
		if err != nil || len(fields) >= maxFields {
			return nil, ErrX509Malformed
		}
		fields = append(fields, value)
		data = rest
	}
	return fields, nil
}

func x509Primitive(value asn1.RawValue, tag int) bool {
	return value.Class == 0 && value.Tag == tag && !value.IsCompound
}
func x509TimeDER(value asn1.RawValue) bool {
	return x509Primitive(value, asn1.TagUTCTime) || x509Primitive(value, asn1.TagGeneralizedTime)
}

func x509NameDER(data []byte) bool {
	names, err := x509DERSequence(data, 32)
	if err != nil {
		return false
	}
	for _, set := range names {
		if set.Class != 0 || set.Tag != asn1.TagSet || !set.IsCompound {
			return false
		}
		attributes, err := x509DERContents(set.Bytes, 16)
		if err != nil || len(attributes) == 0 {
			return false
		}
		for _, attribute := range attributes {
			values, err := x509DERSequence(attribute.FullBytes, 2)
			if err != nil || len(values) != 2 || !x509Primitive(values[0], asn1.TagOID) || values[1].Class != 0 || values[1].IsCompound {
				return false
			}
		}
	}
	return true
}

func x509CertificateDER(fields []asn1.RawValue) bool {
	if !fields[0].IsCompound || !bytes.Equal(fields[0].Bytes, []byte{2, 1, 2}) || !x509Primitive(fields[1], asn1.TagInteger) ||
		!x509NameDER(fields[3].FullBytes) || !x509NameDER(fields[5].FullBytes) {
		return false
	}
	validity, err := x509DERSequence(fields[4].FullBytes, 2)
	if err != nil || len(validity) != 2 || !x509TimeDER(validity[0]) || !x509TimeDER(validity[1]) {
		return false
	}
	spki, err := x509DERSequence(fields[6].FullBytes, 2)
	if err != nil || len(spki) != 2 || !x509Primitive(spki[1], asn1.TagBitString) {
		return false
	}
	algorithm, err := x509DERSequence(spki[0].FullBytes, 2)
	if err != nil || len(algorithm) == 0 || !x509Primitive(algorithm[0], asn1.TagOID) {
		return false
	}
	return len(algorithm) == 1 || x509Primitive(algorithm[1], asn1.TagOID) || x509Primitive(algorithm[1], asn1.TagNull)
}

func x509ExtensionsDER(wrapper asn1.RawValue, extensions []pkix.Extension) bool {
	if !wrapper.IsCompound {
		return false
	}
	values, err := x509DERSequence(wrapper.Bytes, 32)
	if err != nil || len(values) != len(extensions) {
		return false
	}
	seen := map[string]bool{}
	for i, value := range values {
		fields, err := x509DERSequence(value.FullBytes, 3)
		if err != nil || (len(fields) != 2 && len(fields) != 3) || !x509Primitive(fields[0], asn1.TagOID) || !x509Primitive(fields[len(fields)-1], asn1.TagOctetString) {
			return false
		}
		if len(fields) == 3 && (!x509Primitive(fields[1], asn1.TagBoolean) || !bytes.Equal(fields[1].Bytes, []byte{0xff})) {
			return false
		}
		oid := extensions[i].Id.String()
		if seen[oid] || !x509ExtensionValueDER(extensions[i]) {
			return false
		}
		seen[oid] = true
	}
	return true
}

func x509ExtensionValueDER(extension pkix.Extension) bool {
	oid := extension.Id.String()
	switch oid {
	case "2.5.29.14", "2.5.29.15", "2.5.29.17", "2.5.29.19", "2.5.29.35", "2.5.29.37", "2.5.29.20", "2.5.29.27":
	default:
		return true // Unknown semantics are refused by the issuing profile.
	}
	var value asn1.RawValue
	if rest, err := asn1.Unmarshal(extension.Value, &value); err != nil || len(rest) != 0 || value.Class != 0 {
		return false
	}
	switch oid {
	case "2.5.29.14":
		return !extension.Critical && x509Primitive(value, asn1.TagOctetString)
	case "2.5.29.15":
		var usage asn1.BitString
		rest, err := asn1.Unmarshal(extension.Value, &usage)
		return err == nil && len(rest) == 0 && usage.BitLength <= 9 && (usage.BitLength == 0 || usage.At(usage.BitLength-1) == 1)
	case "2.5.29.17":
		_, err := x509DERSequence(extension.Value, 32)
		return err == nil
	case "2.5.29.19":
		fields, err := x509DERSequence(extension.Value, 2)
		if err != nil {
			return false
		}
		if len(fields) == 0 {
			return true
		}
		index := 0
		if fields[0].Tag == asn1.TagBoolean {
			if !x509Primitive(fields[0], asn1.TagBoolean) || !bytes.Equal(fields[0].Bytes, []byte{0xff}) {
				return false
			}
			index = 1
		}
		return len(fields) == index || (len(fields) == index+1 && x509Primitive(fields[index], asn1.TagInteger))
	case "2.5.29.35":
		fields, err := x509DERSequence(extension.Value, 1)
		return !extension.Critical && err == nil && len(fields) == 1 && fields[0].Class == 2 && fields[0].Tag == 0 && !fields[0].IsCompound
	case "2.5.29.37":
		fields, err := x509DERSequence(extension.Value, 32)
		if err != nil {
			return false
		}
		for _, field := range fields {
			if !x509Primitive(field, asn1.TagOID) {
				return false
			}
		}
		return true
	case "2.5.29.20":
		return !extension.Critical && x509Primitive(value, asn1.TagInteger)
	case "2.5.29.27":
		return extension.Critical && x509Primitive(value, asn1.TagInteger)
	}
	return false
}

func x509CRLEntriesDER(fields []asn1.RawValue, parsedCount int) bool {
	if len(fields) == 6 {
		return parsedCount == 0
	}
	entries, err := x509DERSequence(fields[5].FullBytes, 1024)
	if err != nil || len(entries) != parsedCount {
		return false
	}
	for _, entry := range entries {
		values, err := x509DERSequence(entry.FullBytes, 2)
		if err != nil || len(values) != 2 || !x509Primitive(values[0], asn1.TagInteger) || !x509TimeDER(values[1]) {
			return false
		}
	}
	return true
}

func x509IssuerDNSConstraintsDER(issuer *x509.Certificate) bool {
	for _, extension := range issuer.Extensions {
		if extension.Id.String() != "2.5.29.30" {
			continue
		}
		fields, err := x509DERSequence(extension.Value, 1)
		if err != nil || len(fields) != 1 || fields[0].Class != 2 || fields[0].Tag != 0 || !fields[0].IsCompound {
			return false
		}
		subtrees, err := x509DERContents(fields[0].Bytes, 8)
		if err != nil || len(subtrees) == 0 || len(subtrees) != len(issuer.PermittedDNSDomains) {
			return false
		}
		for i, subtree := range subtrees {
			values, err := x509DERSequence(subtree.FullBytes, 1)
			if err != nil || len(values) != 1 || values[0].Class != 2 || values[0].Tag != 2 || values[0].IsCompound || string(values[0].Bytes) != issuer.PermittedDNSDomains[i] {
				return false
			}
		}
		return true
	}
	return false
}
