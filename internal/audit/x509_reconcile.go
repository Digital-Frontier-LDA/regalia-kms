package audit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"unicode"
)

const (
	MaxX509CollectorExportBytes = 64 << 20
	MaxX509ArtifactBytes        = 64 << 10
	MaxX509Artifacts            = 256
)

type X509ReconcileConfig struct {
	ExpectedSequence uint64
	ExpectedHash     string
	ProfileID        string
	ObjectID         string
	Purpose          string
	KeyFingerprint   string
	IssuerDER        []byte
}

type X509ReconcileReport struct {
	Status                string `json:"status"`
	Events                uint64 `json:"events"`
	Artifacts             uint64 `json:"artifacts"`
	AuthorizedRequests    uint64 `json:"authorized_requests"`
	SuccessfulRequests    uint64 `json:"successful_requests"`
	FailedRequests        uint64 `json:"failed_requests"`
	MatchedArtifacts      uint64 `json:"matched_artifacts"`
	UnattestedArtifacts   uint64 `json:"unattested_artifacts"`
	IndeterminateRequests uint64 `json:"indeterminate_requests"`
	Conflicts             uint64 `json:"conflicts"`
}

// ReconcileX509 binds a bounded export to an independently authenticated
// collector head and correlates verified issuer signatures with ordered signing
// evidence. Missing evidence remains indeterminate and never authorizes a
// re-sign. This does not reconstruct historical policy or revocation state.
func ReconcileX509(reader io.Reader, config X509ReconcileConfig, artifacts [][]byte) (X509ReconcileReport, error) {
	var report X509ReconcileReport
	if reader == nil || config.ExpectedSequence == 0 || !auditHashPattern.MatchString(config.ExpectedHash) ||
		!x509ProfileIDPattern.MatchString(config.ProfileID) || !safeReconcileLabel(config.ObjectID) || !safeReconcileLabel(config.Purpose) ||
		!auditHashPattern.MatchString(config.KeyFingerprint) || len(config.IssuerDER) == 0 || len(config.IssuerDER) > 32<<10 || len(artifacts) > MaxX509Artifacts {
		return report, errors.New("invalid or unanchored X.509 reconciliation input")
	}
	issuer, err := x509.ParseCertificate(bytes.Clone(config.IssuerDER))
	if err != nil || !bytes.Equal(issuer.Raw, config.IssuerDER) || !issuer.IsCA || !issuer.BasicConstraintsValid ||
		len(issuer.RawSubject) == 0 || len(issuer.Subject.Names) == 0 || len(issuer.SubjectKeyId) == 0 || len(issuer.SubjectKeyId) > 64 ||
		issuer.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		return report, errors.New("invalid X.509 reconciliation issuer")
	}
	key, ok := issuer.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || reconcileDigest(issuer.RawSubjectPublicKeyInfo) != config.KeyFingerprint {
		return report, errors.New("X.509 reconciliation issuer does not match the expected key")
	}
	bounded := &io.LimitedReader{R: reader, N: MaxX509CollectorExportBytes + 1}
	events, err := verifyEvents(bounded)
	if err != nil {
		return report, x509ReconcileReadError{cause: err}
	}
	if bounded.N == 0 || uint64(len(events)) != config.ExpectedSequence || events[len(events)-1].Hash != config.ExpectedHash {
		return report, errors.New("collector export does not verify against the expected head")
	}
	report.Events, report.Artifacts = uint64(len(events)), uint64(len(artifacts))
	// Select the configured scope first, then inspect every event bearing one
	// of its request IDs. A terminal cannot escape correlation by changing scope.
	groups := map[string]*x509Evidence{}
	for _, event := range events {
		if event.X509ProfileID == config.ProfileID && event.ObjectID == config.ObjectID && event.Purpose == config.Purpose && event.KeyFingerprint == config.KeyFingerprint {
			groups[event.RequestID] = &x509Evidence{}
		}
	}
	for i := range events {
		event := &events[i]
		group := groups[event.RequestID]
		if group == nil {
			continue
		}
		if validateReconcileEvent(*event) != nil {
			return report, errors.New("collector export contains invalid signing evidence")
		}
		if event.Operation != "sign" || event.X509ProfileID != config.ProfileID || event.ObjectID != config.ObjectID || event.Purpose != config.Purpose || event.KeyFingerprint != config.KeyFingerprint {
			group.conflict = true
			continue
		}
		if event.Decision == "allow" && event.Outcome == "authorized" {
			if group.authorization != nil || group.terminal != nil || group.denied {
				group.conflict = true
			}
			group.authorization = event
		} else if event.Decision == "allow" && (event.Outcome == "success" || event.Outcome == "backend-failed" || event.Outcome == "empty-output" || event.Outcome == "integrity-failed") || event.Decision == "deny" && event.Outcome == "not-admitted" {
			if group.terminal != nil || group.authorization == nil {
				group.conflict = true
			}
			group.terminal = event
		} else if event.Decision != "deny" || group.authorization != nil || group.denied {
			group.conflict = true
		} else {
			group.denied = true
		}
	}
	successes := map[string][]*x509Evidence{}
	authorized := map[string]bool{}
	for _, group := range groups {
		if group.authorization != nil {
			report.AuthorizedRequests++
		}
		if group.terminal != nil && group.terminal.Outcome == "success" {
			report.SuccessfulRequests++
		} else if group.terminal != nil {
			report.FailedRequests++
		}
		if group.authorization != nil && group.terminal != nil && !sameX509Evidence(*group.authorization, *group.terminal) {
			group.conflict = true
		}
		if group.conflict {
			report.Conflicts++
			continue
		}
		if group.authorization == nil {
			continue
		}
		identity := group.authorization.ArtifactKind + "\x00" + group.authorization.PayloadDigest
		authorized[identity] = true
		if group.terminal != nil && group.terminal.Outcome == "success" {
			successes[identity] = append(successes[identity], group)
		}
	}
	seenPayloads, seenIdentifiers := map[string]bool{}, map[string]bool{}
	for _, artifact := range artifacts {
		kind, digest, identifier, err := verifyReconcileArtifact(artifact, issuer)
		if err != nil {
			return report, err
		}
		identity := kind + "\x00" + digest
		if seenPayloads[identity] || seenIdentifiers[kind+"\x00"+identifier] {
			report.Conflicts++
			continue
		}
		seenPayloads[identity], seenIdentifiers[kind+"\x00"+identifier] = true, true
		candidates := successes[identity]
		if len(candidates) == 1 {
			candidates[0].matched = true
			report.MatchedArtifacts++
		} else if len(candidates) == 0 && !authorized[identity] {
			report.UnattestedArtifacts++
		}
	}
	for _, group := range groups {
		if !group.conflict && group.authorization != nil && !group.matched {
			report.IndeterminateRequests++
		}
	}
	report.Status = "consistent"
	if report.IndeterminateRequests > 0 || report.AuthorizedRequests == 0 && report.Artifacts == 0 {
		report.Status = "indeterminate"
	}
	if report.UnattestedArtifacts > 0 {
		report.Status = "unattested"
	}
	if report.Conflicts > 0 {
		report.Status = "conflict"
	}
	return report, nil
}

// Retain a reader failure for errors.Is while keeping diagnostics generic: a
// reader's error message can contain paths or other source metadata.
type x509ReconcileReadError struct{ cause error }

func (x509ReconcileReadError) Error() string {
	return "collector export does not verify against the expected head"
}
func (err x509ReconcileReadError) Unwrap() error { return err.cause }

type x509Evidence struct {
	authorization, terminal   *Event
	conflict, matched, denied bool
}

func safeReconcileLabel(value string) bool {
	if value == "" || len(value) > 512 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func reconcileDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validateReconcileEvent(e Event) error {
	return validateDraft(Draft{Timestamp: e.Timestamp, RequestID: e.RequestID, Principal: e.Principal, Decision: e.Decision, ObjectID: e.ObjectID, Purpose: e.Purpose,
		Operation: e.Operation, DeviceID: e.DeviceID, Outcome: e.Outcome, LatencyMilliseconds: e.LatencyMilliseconds, RegistryDigest: e.RegistryDigest,
		PolicyDigest: e.PolicyDigest, RBACDigest: e.RBACDigest, VerifiedApprovers: e.VerifiedApprovers, X509ProfileID: e.X509ProfileID,
		PayloadDigest: e.PayloadDigest, ArtifactKind: e.ArtifactKind, KeyFingerprint: e.KeyFingerprint})
}

func sameX509Evidence(a, b Event) bool {
	return a.Principal == b.Principal && a.ObjectID == b.ObjectID && a.Purpose == b.Purpose && a.Operation == b.Operation && a.DeviceID == b.DeviceID &&
		a.RegistryDigest == b.RegistryDigest && a.PolicyDigest == b.PolicyDigest && a.RBACDigest == b.RBACDigest && slices.Equal(a.VerifiedApprovers, b.VerifiedApprovers) &&
		a.X509ProfileID == b.X509ProfileID && a.PayloadDigest == b.PayloadDigest && a.ArtifactKind == b.ArtifactKind && a.KeyFingerprint == b.KeyFingerprint
}

func verifyReconcileArtifact(data []byte, issuer *x509.Certificate) (string, string, string, error) {
	errInvalid := errors.New("X.509 artifact is invalid or has no signature from the expected issuer")
	if len(data) == 0 || len(data) > MaxX509ArtifactBytes {
		return "", "", "", errInvalid
	}
	owned := bytes.Clone(data)
	if cert, err := x509.ParseCertificate(owned); err == nil {
		if !bytes.Equal(cert.Raw, owned) || !bytes.Equal(cert.RawIssuer, issuer.RawSubject) || !bytes.Equal(cert.AuthorityKeyId, issuer.SubjectKeyId) ||
			cert.SignatureAlgorithm != x509.ECDSAWithSHA256 || len(cert.RawTBSCertificate) > 32<<10 || cert.CheckSignatureFrom(issuer) != nil {
			return "", "", "", errInvalid
		}
		return "certificate", reconcileDigest(cert.RawTBSCertificate), cert.SerialNumber.String(), nil
	}
	if crl, err := x509.ParseRevocationList(owned); err == nil {
		if !bytes.Equal(crl.Raw, owned) || !bytes.Equal(crl.RawIssuer, issuer.RawSubject) || !bytes.Equal(crl.AuthorityKeyId, issuer.SubjectKeyId) || crl.Number == nil ||
			crl.SignatureAlgorithm != x509.ECDSAWithSHA256 || len(crl.RawTBSRevocationList) > 32<<10 || crl.CheckSignatureFrom(issuer) != nil {
			return "", "", "", errInvalid
		}
		// CRL numbers alone are not unique artifact identities: simultaneous
		// complete and delta CRLs can share one. This checks signing evidence,
		// without asserting historical revocation-state consistency.
		digest := reconcileDigest(crl.RawTBSRevocationList)
		return "crl", digest, digest, nil
	}
	return "", "", "", errInvalid
}
