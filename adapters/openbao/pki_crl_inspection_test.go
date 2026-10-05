package openbaopoc

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"time"
)

func pocInspectCRL(data []byte, issuer *x509.Certificate, now time.Time) (*x509.RevocationList, error) {
	fields, err := pocTBSFields(data)
	if err != nil || len(fields) < 6 || len(fields) > 7 || fields[0].Class != 0 || fields[0].Tag != 2 || !bytes.Equal(fields[0].FullBytes, []byte{2, 1, 1}) || fields[len(fields)-1].Class != 2 || fields[len(fields)-1].Tag != 0 {
		return nil, errPOCProfile
	}
	encoded, err := pocSignedStructure(data)
	if err != nil {
		return nil, errPOCProfile
	}
	crl, err := x509.ParseRevocationList(encoded)
	if err != nil || !bytes.Equal(crl.RawTBSRevocationList, data) || crl.SignatureAlgorithm != x509.ECDSAWithSHA256 ||
		!bytes.Equal(crl.RawIssuer, issuer.RawSubject) || !bytes.Equal(crl.AuthorityKeyId, issuer.SubjectKeyId) ||
		crl.Number == nil || crl.Number.Sign() < 0 || crl.Number.BitLen() > 64 || crl.ThisUpdate.Before(now.Add(-time.Minute)) || crl.ThisUpdate.After(now.Add(10*time.Second)) ||
		!crl.NextUpdate.After(now) || !crl.NextUpdate.After(crl.ThisUpdate) || crl.ThisUpdate.Before(issuer.NotBefore) || crl.NextUpdate.After(issuer.NotAfter) || crl.NextUpdate.Sub(crl.ThisUpdate) > time.Hour || len(crl.RevokedCertificateEntries) > 100 ||
		!pocCRLEntryDER(fields, len(crl.RevokedCertificateEntries)) || !pocExtensionDERFields(fields[len(fields)-1], crl.Extensions) ||
		!pocExtensions(crl.Extensions, map[string]bool{"2.5.29.35": true, "2.5.29.20": true, "2.5.29.27": true}) {
		return nil, errPOCProfile
	}
	for _, extension := range crl.Extensions {
		if extension.Id.String() == "2.5.29.27" {
			var base *big.Int
			rest, err := asn1.Unmarshal(extension.Value, &base)
			if err != nil || len(rest) != 0 || !extension.Critical || base == nil || base.Sign() < 0 || base.BitLen() > 64 || base.Cmp(crl.Number) >= 0 {
				return nil, errPOCProfile
			}
		}
	}
	seen := map[string]bool{}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber == nil || entry.SerialNumber.Sign() <= 0 || entry.SerialNumber.BitLen() > 160 || seen[entry.SerialNumber.String()] ||
			entry.RevocationTime.IsZero() || entry.RevocationTime.After(now.Add(10*time.Second)) || entry.ReasonCode != 0 || len(entry.Extensions) != 0 {
			return nil, errPOCProfile
		}
		seen[entry.SerialNumber.String()] = true
	}
	return crl, nil
}
