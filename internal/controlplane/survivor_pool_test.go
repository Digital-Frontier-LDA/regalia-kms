package controlplane

import (
	"crypto/ecdh"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This file closes the reachable portion of the 2026-09-09 #237 controlplane
// survivor pool. The sweep was re-derived from all non-test Go in this package at
// 1cb2af1: 111 sites / 138 operands, of which 58 refusal-direction mutations
// survived. survivor_pool_ledger_test.go accounts for all 58; these are the 20
// that an ordinary fixture can reach and distinguish.

type refusingReader struct{}

func (refusingReader) Read([]byte) (int, error) { return 0, errors.New("injected entropy failure") }

type nonceRefusingReader struct{}

func (nonceRefusingReader) Read(p []byte) (int, error) {
	if len(p) == gcmNonceSize {
		return 0, errors.New("injected nonce entropy failure")
	}
	for index := range p {
		p[index] = byte(index + 1)
	}
	return len(p), nil
}

func TestSealNamesAWrongCurveBeforeECDH(t *testing.T) {
	wrong, err := ecdhP384PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = Seal([]byte("payload"), wrong.PublicKey())
	if err == nil || err.Error() != "controlplane: recipient key must be P-256" {
		t.Fatalf("wrong-curve recipient refusal = %v; want the boundary check, not a downstream ECDH failure", err)
	}
}

func TestSealSeparatesEphemeralAndNonceEntropyFailures(t *testing.T) {
	publicPEM, _ := testKeys(t)
	recipient, err := ParseRecipient(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	original := entropyReader
	originalGenerate := generateEphemeralKey
	t.Cleanup(func() {
		entropyReader = original
		generateEphemeralKey = originalGenerate
	})

	t.Run("ephemeral key", func(t *testing.T) {
		generateEphemeralKey = func(io.Reader) (*ecdh.PrivateKey, error) {
			return nil, errors.New("injected entropy failure")
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("Seal panicked after key generation failed instead of returning the failure: %v", recovered)
			}
		}()
		if _, err := Seal([]byte("payload"), recipient.PublicKey); err == nil || !strings.Contains(err.Error(), "generate ephemeral key: injected entropy failure") {
			t.Fatalf("ephemeral entropy failure was not named: %v", err)
		}
	})

	t.Run("nonce", func(t *testing.T) {
		generateEphemeralKey = originalGenerate
		entropyReader = nonceRefusingReader{}
		if _, err := Seal([]byte("payload"), recipient.PublicKey); err == nil || !strings.Contains(err.Error(), "nonce: injected nonce entropy failure") {
			t.Fatalf("nonce entropy failure was not named: %v", err)
		}
	})
}

func TestOpenRefusesPartialBase64Results(t *testing.T) {
	genuine, key := openEnvelope(t)
	for name, corrupt := range map[string]func(*Envelope){
		"ephemeral":  func(e *Envelope) { e.Ephemeral += "!" },
		"nonce":      func(e *Envelope) { e.Nonce += "!" },
		"ciphertext": func(e *Envelope) { e.Ciphertext += "!" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := genuine
			corrupt(&changed)
			var encodedField string
			switch name {
			case "ephemeral":
				encodedField = changed.Ephemeral
			case "nonce":
				encodedField = changed.Nonce
			default:
				encodedField = changed.Ciphertext
			}
			decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(encodedField)
			if decodeErr == nil || len(decoded) == 0 {
				t.Fatalf("fixture must yield useful decoded bytes and an error, got %d bytes / %v", len(decoded), decodeErr)
			}
			encoded, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			if opened, err := Open(encoded, key); !errors.Is(err, errOpen) {
				t.Fatalf("partially decoded %s opened (%d bytes, err=%v); decoder errors must not be ignored", name, len(opened), err)
			}
		})
	}
}

func TestMalformedDERIsRefusedByEitherParserLayer(t *testing.T) {
	for name, parse := range map[string]func([]byte) error{
		"recipient": func(der []byte) error {
			_, err := ParseRecipient(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
			return err
		},
		"authority": func(der []byte) error {
			_, err := ParseAuthorityKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("both parser layers failed open and dereferenced an invalid key: %v", recovered)
				}
			}()
			if err := parse([]byte("not DER")); err == nil {
				t.Fatal("malformed DER passed both the x509 parser and parsed-key type boundary")
			}
		})
	}
}

func TestEachConfiguredJournalPreventsTheNoSourcesDiagnosis(t *testing.T) {
	for name, sources := range map[string]Sources{
		"audit":   {AuditJournal: "/state/audit.jsonl"},
		"policy":  {PolicyState: "/state/policy.jsonl"},
		"fencing": {FencingState: "/state/epochs.jsonl"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Build(sources, "sitea", time.Unix(1, 0))
			if errors.Is(err, ErrNoSources) {
				t.Fatalf("%s is configured but Build diagnosed no sources", name)
			}
		})
	}
}

func TestBuildCanonicalisesAnOmittedSiteVersionPath(t *testing.T) {
	f := newFixture(t, true)
	f.sources.SiteVersion = ""
	exported, err := Build(f.sources, "sitea", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if exported.SiteVersion.Path != "/etc/regalia-kms/deployment-version" || !exported.SiteVersion.Absent {
		t.Fatalf("omitted site version = %#v; want an explicit absence marker at the canonical path", exported.SiteVersion)
	}
}

func TestAnOmittedConfiguredPathReachesStructuralValidation(t *testing.T) {
	f := newFixture(t, true)
	f.sources.PolicyState = ""
	_, err := Build(f.sources, "sitea", time.Unix(1, 0))
	if err == nil || !strings.Contains(err.Error(), "policy state journal is neither present nor absent") {
		t.Fatalf("omitted policy path was refused by the wrong boundary: %v", err)
	}
}

func TestBuildPropagatesAnUnarmedPayloadScan(t *testing.T) {
	f := newFixture(t, true)
	original := markerShapes
	markerShapes = nil
	t.Cleanup(func() { markerShapes = original })
	_, err := Build(f.sources, "sitea", time.Unix(1, 0))
	if !errors.Is(err, ErrScannerUnarmed) {
		t.Fatalf("Build returned %v; an unarmed payload scan must void the export", err)
	}
}

func absentExport() *Export {
	absent := func(path string) Entry { return Entry{Path: path, Absent: true} }
	return &Export{
		Version:        ExportFormatVersion,
		Site:           "sitea",
		CreatedAt:      time.Unix(1, 0).UTC(),
		AuditJournal:   absent("/state/audit.jsonl"),
		AuditHighWater: absent("/state/audit.jsonl.high-water"),
		AuditShipped:   absent("/state/audit.jsonl.shipped"),
		PolicyState:    absent("/state/policy.jsonl"),
		PolicyMark:     absent("/state/policy.jsonl.high-water"),
		FencingEpochs:  absent("/state/epochs.jsonl"),
		SiteVersion:    absent("/etc/regalia-kms/deployment-version"),
	}
}

func TestPresentEmptyEntryIsNotAnAbsenceMarker(t *testing.T) {
	exported := absentExport()
	digest := sha256.Sum256(nil)
	exported.FencingEpochs = Entry{Path: "/state/epochs.jsonl", SHA256: hex.EncodeToString(digest[:]), Data: []byte{}}
	if err := verifyExport(exported); err == nil || !strings.Contains(err.Error(), "present but empty") {
		t.Fatalf("present-empty fencing history was refused by the wrong rule: %v", err)
	}
}

func TestAbsentEntriesDoNotCollideByBasename(t *testing.T) {
	exported := absentExport()
	exported.AuditJournal.Path = "/audit/state.jsonl"
	exported.PolicyState.Path = "/policy/state.jsonl"
	if err := verifyExport(exported); err != nil {
		t.Fatalf("two absent markers with one basename collided: %v", err)
	}
}

func TestVerifyExportNamesTemporaryDirectoryCreationFailure(t *testing.T) {
	exported := absentExport()
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	if err := verifyExport(exported); err == nil || !strings.Contains(err.Error(), "controlplane: verify:") {
		t.Fatalf("temporary verification directory failure was not propagated: %v", err)
	}
}

func TestVerifyExportPropagatesJournalMaterialisationFailure(t *testing.T) {
	f := newFixture(t, true)
	exported, err := Build(f.sources, "sitea", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	exported.FencingEpochs.Path = "/"
	if err := verifyExport(exported); err == nil || !strings.Contains(err.Error(), "controlplane: verify:") || strings.Contains(err.Error(), "failed integrity verification") {
		t.Fatalf("journal write failure was not propagated at materialisation: %v", err)
	}
}

func TestMalformedSidecarsAreRefusedByAtLeastOneLayer(t *testing.T) {
	f := newFixture(t, true)
	base, err := Build(f.sources, "sitea", time.Unix(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	for name, selectEntry := range map[string]func(*Export) *Entry{
		"audit high-water": func(e *Export) *Entry { return &e.AuditHighWater },
		"audit shipped":    func(e *Export) *Entry { return &e.AuditShipped },
		"policy mark":      func(e *Export) *Entry { return &e.PolicyMark },
	} {
		t.Run(name, func(t *testing.T) {
			changed := *base
			entry := selectEntry(&changed)
			entry.Data = []byte("{")
			digest := sha256.Sum256(entry.Data)
			entry.SHA256 = hex.EncodeToString(digest[:])
			if err := verifyExport(&changed); err == nil {
				t.Fatal("malformed sidecar passed both the fail-fast JSON check and its journal verifier")
			}
		})
	}
}

func TestInspectPropagatesAnUnarmedPayloadScan(t *testing.T) {
	f := newFixture(t, true)
	envelope, _, privatePEM := sealedFixture(t, f)
	original := markerShapes
	markerShapes = nil
	t.Cleanup(func() { markerShapes = original })
	_, err := Inspect(envelope, authorityKey(t, privatePEM))
	if !errors.Is(err, ErrScannerUnarmed) {
		t.Fatalf("Inspect returned %v; an unarmed restored-state scan must void the verdict", err)
	}
}

func TestSummaryLinesDistinguishesAbsenceAndBoundsItsDigest(t *testing.T) {
	exported := absentExport()
	exported.SiteVersion = Entry{Path: "/version", SHA256: strings.Repeat("a", 64), Data: []byte("v")}
	lines := SummaryLines(exported)
	if !strings.Contains(lines[1], "absent") {
		t.Fatalf("absence marker rendered as present: %q", lines[1])
	}
	last := lines[len(lines)-1]
	if !strings.Contains(last, strings.Repeat("a", 12)+"…") || strings.Contains(last, strings.Repeat("a", 13)) {
		t.Fatalf("summary did not bound the digest to 12 characters: %q", last)
	}
}

func TestCanaryEntropyFailureCannotProduceAnArmedVerdict(t *testing.T) {
	original := entropyReader
	entropyReader = refusingReader{}
	t.Cleanup(func() { entropyReader = original })
	if probe := canary(); probe != "" {
		t.Fatalf("entropy failure produced a fixed or predictable canary: %q", probe)
	}
	if _, err := armedScan(map[string][]byte{"clean": []byte("ordinary")}); !errors.Is(err, ErrScannerUnarmed) {
		t.Fatalf("scan with no random canary returned a verdict: %v", err)
	}
}

// ecdhP384PrivateKey is kept out of the test body so the wrong-curve row reads as
// a contract assertion rather than key-generation mechanics.
func ecdhP384PrivateKey() (*ecdh.PrivateKey, error) {
	return ecdh.P384().GenerateKey(crand.Reader)
}
