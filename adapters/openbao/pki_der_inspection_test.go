package openbaopoc

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// The standard x509 parser exposes useful semantics, but intentionally ignores
// some nested fields. This narrow fixture must account for every DER field
// before signing; the original bytes, rather than a reencoding, are signed.
func pocPrimitive(value asn1.RawValue, tag int) bool {
	return value.Class == 0 && value.Tag == tag && !value.IsCompound
}

func pocTimeDER(value asn1.RawValue) bool {
	return pocPrimitive(value, asn1.TagUTCTime) || pocPrimitive(value, asn1.TagGeneralizedTime)
}

func pocCertificateDERFields(fields []asn1.RawValue) bool {
	if !fields[0].IsCompound || !bytes.Equal(fields[0].Bytes, []byte{2, 1, 2}) {
		return false
	}
	validity, err := pocTBSFields(fields[4].FullBytes)
	if err != nil || len(validity) != 2 || !pocTimeDER(validity[0]) || !pocTimeDER(validity[1]) {
		return false
	}
	subject, err := pocTBSFields(fields[5].FullBytes)
	if err != nil || len(subject) != 1 || subject[0].Class != 0 || subject[0].Tag != asn1.TagSet || !subject[0].IsCompound {
		return false
	}
	var attribute asn1.RawValue
	if rest, err := asn1.Unmarshal(subject[0].Bytes, &attribute); err != nil || len(rest) != 0 {
		return false
	}
	values, err := pocTBSFields(attribute.FullBytes)
	if err != nil || len(values) != 2 || !pocPrimitive(values[0], asn1.TagOID) {
		return false
	}
	spki, err := pocTBSFields(fields[6].FullBytes)
	if err != nil || len(spki) != 2 || !pocPrimitive(spki[1], asn1.TagBitString) {
		return false
	}
	algorithm, err := pocTBSFields(spki[0].FullBytes)
	return err == nil && len(algorithm) == 2 && pocPrimitive(algorithm[0], asn1.TagOID) && pocPrimitive(algorithm[1], asn1.TagOID)
}

func pocExtensionDERFields(wrapper asn1.RawValue, extensions []pkix.Extension) bool {
	if !wrapper.IsCompound {
		return false
	}
	values, err := pocTBSFields(wrapper.Bytes)
	if err != nil || len(values) != len(extensions) {
		return false
	}
	for _, value := range values {
		fields, err := pocTBSFields(value.FullBytes)
		if err != nil || (len(fields) != 2 && len(fields) != 3) || !pocPrimitive(fields[0], asn1.TagOID) || !pocPrimitive(fields[len(fields)-1], asn1.TagOctetString) {
			return false
		}
		if len(fields) == 3 && (!pocPrimitive(fields[1], asn1.TagBoolean) || !bytes.Equal(fields[1].Bytes, []byte{0xff})) {
			return false // DER omits the default critical=false field.
		}
	}
	return true
}

func pocExtensionValueDER(extension pkix.Extension) bool {
	var value asn1.RawValue
	if rest, err := asn1.Unmarshal(extension.Value, &value); err != nil || len(rest) != 0 || value.Class != 0 {
		return false
	}
	switch extension.Id.String() {
	case "2.5.29.14": // subjectKeyIdentifier
		return !extension.Critical && pocPrimitive(value, asn1.TagOctetString)
	case "2.5.29.15": // Exactly digitalSignature, including unhandled higher bits.
		return bytes.Equal(extension.Value, []byte{3, 2, 7, 0x80})
	case "2.5.29.17": // Each SAN is checked separately by pocDNSOnlySAN.
		return value.Tag == asn1.TagSequence && value.IsCompound
	case "2.5.29.19": // A non-CA leaf has no path length or ignored fields.
		return bytes.Equal(extension.Value, []byte{0x30, 0})
	case "2.5.29.35": // Only the pinned authority key identifier is supported.
		fields, err := pocTBSFields(extension.Value)
		return !extension.Critical && err == nil && len(fields) == 1 && fields[0].Class == 2 && fields[0].Tag == 0 && !fields[0].IsCompound
	case "2.5.29.37": // Only the single parsed serverAuth OID is supported.
		fields, err := pocTBSFields(extension.Value)
		return err == nil && len(fields) == 1 && pocPrimitive(fields[0], asn1.TagOID)
	case "2.5.29.20": // cRLNumber
		return !extension.Critical && pocPrimitive(value, asn1.TagInteger)
	case "2.5.29.27": // deltaCRLIndicator; its base number is checked separately.
		return extension.Critical && pocPrimitive(value, asn1.TagInteger)
	default:
		return false
	}
}

func pocCRLEntryDER(fields []asn1.RawValue, parsedCount int) bool {
	if len(fields) == 6 {
		return parsedCount == 0
	}
	var entries []asn1.RawValue
	if rest, err := asn1.Unmarshal(fields[5].FullBytes, &entries); err != nil || len(rest) != 0 || len(entries) != parsedCount || len(entries) > 100 {
		return false
	}
	for _, entry := range entries {
		values, err := pocTBSFields(entry.FullBytes)
		if err != nil || len(values) != 2 || !pocPrimitive(values[0], asn1.TagInteger) || !pocTimeDER(values[1]) {
			return false // No entry extensions, empty extension wrapper or ignored fields.
		}
	}
	return true
}
