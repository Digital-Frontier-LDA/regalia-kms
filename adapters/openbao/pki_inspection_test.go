package openbaopoc

// This inspector exists only in software-token tests. It is not a server-owned
// production issuing profile, and is deliberately limited to one leaf shape.
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"strings"
	"time"
)

var errPOCProfile = errors.New("synthetic issuing profile refused")
var pocECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

func pocTBSFields(data []byte) ([]asn1.RawValue, error) {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(data, &sequence)
	if err != nil || len(rest) != 0 || sequence.Class != 0 || sequence.Tag != 16 || !sequence.IsCompound {
		return nil, errPOCProfile
	}
	var fields []asn1.RawValue
	for rest = sequence.Bytes; len(rest) != 0; {
		var value asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &value)
		if err != nil || len(fields) >= 12 {
			return nil, errPOCProfile
		}
		fields = append(fields, value)
	}
	return fields, nil
}

func pocSignedStructure(data []byte) ([]byte, error) {
	return asn1.Marshal(struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}{asn1.RawValue{FullBytes: data}, pkix.AlgorithmIdentifier{Algorithm: pocECDSASHA256}, asn1.BitString{Bytes: []byte{0}, BitLength: 8}})
}

func pocExtensions(extensions []pkix.Extension, allowed map[string]bool) bool {
	seen := map[string]bool{}
	for _, e := range extensions {
		oid := e.Id.String()
		if !allowed[oid] || seen[oid] {
			return false
		}
		seen[oid] = true
	}
	return true
}

func pocDNS(name string) bool {
	if name != strings.ToLower(name) || len(name) > 253 || (name != "svc.poc.invalid" && !strings.HasSuffix(name, ".svc.poc.invalid")) {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func pocDNSOnlySAN(cert *x509.Certificate) bool {
	for _, e := range cert.Extensions {
		if e.Id.String() != "2.5.29.17" {
			continue
		}
		values, err := pocTBSFields(e.Value)
		if err != nil || len(values) != len(cert.DNSNames) {
			return false
		}
		for i, value := range values {
			if value.Class != 2 || value.Tag != 2 || value.IsCompound || string(value.Bytes) != cert.DNSNames[i] {
				return false // No ignored otherName, email, IP or URI entries.
			}
		}
		return true
	}
	return false
}

func pocInspectCertificate(data []byte, issuer *x509.Certificate, now time.Time) (*x509.Certificate, error) {
	fields, err := pocTBSFields(data)
	if err != nil || len(fields) != 8 || fields[0].Class != 2 || fields[0].Tag != 0 || fields[7].Class != 2 || fields[7].Tag != 3 {
		return nil, errPOCProfile // v3 with extensions; no unique IDs/extra fields.
	}
	encoded, err := pocSignedStructure(data)
	if err != nil {
		return nil, errPOCProfile
	}
	cert, err := x509.ParseCertificate(encoded)
	if err != nil || !bytes.Equal(cert.RawTBSCertificate, data) || cert.Version != 3 || cert.SignatureAlgorithm != x509.ECDSAWithSHA256 ||
		!bytes.Equal(cert.RawIssuer, issuer.RawSubject) || !bytes.Equal(cert.AuthorityKeyId, issuer.SubjectKeyId) || cert.SerialNumber.Sign() <= 0 || cert.SerialNumber.BitLen() > 160 ||
		cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage != x509.KeyUsageDigitalSignature || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth ||
		len(cert.UnknownExtKeyUsage) != 0 || len(cert.UnhandledCriticalExtensions) != 0 || len(cert.DNSNames) == 0 || len(cert.DNSNames) > 8 || len(cert.IPAddresses)+len(cert.URIs)+len(cert.EmailAddresses) != 0 ||
		cert.NotBefore.Before(now.Add(-time.Minute)) || cert.NotBefore.After(now.Add(10*time.Second)) || !cert.NotAfter.After(now) || !cert.NotAfter.After(cert.NotBefore) || cert.NotBefore.Before(issuer.NotBefore) || cert.NotAfter.Sub(cert.NotBefore) > 10*time.Minute || cert.NotAfter.After(issuer.NotAfter) {
		return nil, errPOCProfile
	}
	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve.Params().BitSize != 256 || !pocExtensions(cert.Extensions, map[string]bool{"2.5.29.14": true, "2.5.29.15": true, "2.5.29.17": true, "2.5.29.19": true, "2.5.29.35": true, "2.5.29.37": true}) || !pocDNSOnlySAN(cert) {
		return nil, errPOCProfile
	}
	var subject pkix.RDNSequence
	if rest, err := asn1.Unmarshal(cert.RawSubject, &subject); err != nil || len(rest) != 0 || len(subject) != 1 || len(subject[0]) != 1 || subject[0][0].Type.String() != "2.5.4.3" {
		return nil, errPOCProfile
	}
	matched := false
	for _, name := range cert.DNSNames {
		if !pocDNS(name) {
			return nil, errPOCProfile
		}
		matched = matched || name == cert.Subject.CommonName
	}
	if !matched {
		return nil, errPOCProfile
	}
	return cert, nil
}
