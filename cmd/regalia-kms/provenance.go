package main

// THE COMMISSIONING RECORD (#220): the one fact that separates a fresh site from one whose
// history was lost. Four configured paths are designed to be absent on a first boot — the
// fencing epochs, the policy state, the audit journal, the revocations — and on a RESTORED
// or WIPED host the same absence means the record of what happened is gone. Nothing in the
// code could tell those apart, and preflight printed "ok ... will be created on first start"
// at exactly the moment an operator rebuilding under pressure needed the ambiguity named.
//
// The record cannot come from the daemon: a wiped host's daemon would simply write a new one,
// which is self-attestation. It comes from the PROVISIONING layer — the guest role writes it
// when it commissions the site, before the first start — so its absence on a configured host
// means one of two things, both refused:
//
//   - state exists with no record: history without provenance. Somebody has journals and no
//     story for how they got there; refuse and restore from the custody export instead.
//   - no record and no state: first boot OR wipe. A first boot is commissioned by the role,
//     which writes the record; if the role did not run, treat the host as uncommissioned.
//
// A rebuilt-with-export host is the third state and needs no special case: restoring the
// control-plane export brings the journals AND their marks back, the record is written by the
// rebuild, and #223's rules verify what returned. One mechanism: the record answers "was this
// site ever commissioned"; #223 answers "is this journal complete"; the collector's
// acknowledged position answers "what shipped". Three nets, three different questions, no
// overlaps pretending to be redundancy.
//
// Unconfigured (today's deployments and every test config): no check, and preflight names the
// ambiguity in Unchecked rather than printing an "ok" the words do not support.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
)

type commissioningRecord struct {
	Site              string    `json:"site"`
	CommissionedAt    time.Time `json:"commissioned_at"`
	DeploymentVersion string    `json:"deployment_version"`
	Nonce             string    `json:"nonce"`
	Signature         string    `json:"signature"`
}

// commissioningPayload is the signed portion: the record minus the signature itself, marshalled
// in struct order so the bytes the authority signed are the bytes verified here.
func commissioningPayload(record commissioningRecord) []byte {
	record.Signature = ""
	encoded, _ := json.Marshal(record)
	return encoded
}

// statePaths returns the paths whose absence is ambiguous without provenance. Revocations are
// included even though they are not a journal: an empty revocation list on a host that HAD
// revocations silently re-admits every revoked client, which is the same missing-provenance
// shape with a worse failure.
func statePaths(settings config.Config) []string {
	var paths []string
	for _, path := range []string{settings.FencingStatePath, settings.PolicyStatePath, settings.AuditJournalPath, settings.RevokedSerialsPath} {
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

// checkProvenance enforces the commissioning record when one is configured. It runs BEFORE any
// journal is opened for writing, because opening creates the file — and a created file
// destroys the very absence this check exists to interpret.
func checkProvenance(settings config.Config) (*commissioningRecord, error) {
	if settings.CommissioningRecordPath == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(settings.CommissioningRecordPath)
	if errors.Is(err, os.ErrNotExist) {
		var existing []string
		for _, path := range statePaths(settings) {
			switch _, statErr := os.Stat(path); {
			case statErr == nil:
				existing = append(existing, path)
			case errors.Is(statErr, os.ErrNotExist):
				// genuinely absent: the fresh-host reading below
			default:
				// A STAT ERROR IS NOT ABSENCE. The loop this replaces counted only
				// stat==nil as existing, so an unreadable state file read as absent and
				// an unaccountable host was reported as merely uncommissioned — the
				// milder refusal, in the wrong direction (third instance of the class
				// after the two mark probes; this one IS constructible and tested).
				return nil, fmt.Errorf("cannot tell whether %s exists: %v — an unreadable state path is not an absent one, and an unaccountable host must not read as a fresh one", path, statErr)
			}
		}
		if len(existing) > 0 {
			return nil, fmt.Errorf("commissioning record %s is absent but state exists (%s): history without provenance — restore from the custody export or re-commission deliberately; a host may not serve state it cannot account for",
				settings.CommissioningRecordPath, existing[0])
		}
		return nil, fmt.Errorf("commissioning record %s is absent and no state exists: a first start must be COMMISSIONED (the provisioning role writes the record) so that a wiped host cannot pass as a fresh one — refusing to start uncommissioned",
			settings.CommissioningRecordPath)
	}
	if err != nil {
		return nil, fmt.Errorf("read commissioning record: %w", err)
	}
	var record commissioningRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("commissioning record %s is malformed: %w", settings.CommissioningRecordPath, err)
	}
	// THE RECORD IS SIGNED BY THE COMMISSIONING AUTHORITY (fencing_public_key_path — the
	// same two-person custody that signs leases), because a record the host can write is a
	// record a compromised host can forge after wiping its history: rows 2 and 4 of the
	// #220 measurement table showed exactly that shape for the journal marks, and a
	// provenance file with the same authorship answers nothing. The host holds only the
	// public half; deleting the record is still possible and still refuses startup, which
	// is the fail-closed direction. The key is loaded only once a record exists to answer:
	// the missing-record refusals above are about the host's own state and must not be
	// masked by a key problem.
	if settings.FencingPublicKeyPath == "" {
		return nil, errors.New("a commissioning record is configured without fencing_public_key_path: provenance must be verifiable against a key the host does not hold")
	}
	publicKey, err := loadFencingKey(settings.FencingPublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("commissioning authority key: %w", err)
	}
	if record.Site == "" || record.CommissionedAt.IsZero() {
		return nil, errors.New("commissioning record names no site or no time — an unattributable record is not provenance")
	}
	signature, decodeErr := base64.StdEncoding.DecodeString(record.Signature)
	if decodeErr != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, commissioningPayload(record), signature) {
		return nil, errors.New("commissioning record signature does not verify under the configured authority key — an unsigned or forged record is not provenance")
	}
	if settings.Site != "" && record.Site != settings.Site {
		return nil, fmt.Errorf("commissioning record names site %q but this host is configured as %q — the record belongs to a different deployment",
			record.Site, settings.Site)
	}
	return &record, nil
}
