package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/approval"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/audit"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/auth"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/config"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// preflight performs every startup check that does not need the token, and reports what it could
// not check.
//
// The daemon accumulated a number of startup refusals — a registry routing to a backend no provider
// serves, a manifest whose declared policy_id is not the enforced one, an RBAC grant naming an
// object that does not exist, a production object with fewer than two hardware bindings, a policy
// state journal that has been truncated. Every one of them is correct, and every one of them was
// reachable only by STARTING THE DAEMON.
//
// On a KMS that is an expensive way to learn a configuration is wrong. A restart drops the fencing
// lease, interrupts in-flight signing, and on a passive site is exactly the event the lease exists
// to make deliberate. "Restart it and see" is the wrong instrument for a question that can be
// answered from the files.
//
// It is the SAME code, not a second validator. Two validators for one document is the defect this
// repository spent a day removing: a Python custody table that disagreed with the Go one, an
// OpenAPI document that disagreed with the router, a capability matrix that disagreed with the
// driver. A preflight that re-implemented these checks would be the next instance, and it would be
// worse because it would be the one people trust before deploying.
type preflightReport struct {
	Checked   []string
	Unchecked []string
}

func preflight(settings config.Config) (*registry.Registry, *auth.Policy, *policy.Engine, *approval.KeySet, *preflightReport, error) {
	report := &preflightReport{}
	note := func(what string) { report.Checked = append(report.Checked, what) }

	if err := settings.Validate(); err != nil {
		return nil, nil, nil, nil, report, fmt.Errorf("configuration: %w", err)
	}
	note("configuration is internally consistent")

	// PROVENANCE BEFORE EVERYTHING (#220): the commissioning record decides what the
	// absence of the four state paths MEANS, so it is checked before anything below opens,
	// creates or reads them. It must also precede the journal checks so its verdict is not
	// coloured by files this run had no hand in.
	switch record, provenanceErr := checkProvenance(settings); {
	case provenanceErr != nil:
		return nil, nil, nil, nil, report, provenanceErr
	case record != nil:
		note(fmt.Sprintf("site commissioned at %s (deployment %s)", record.CommissionedAt.UTC().Format(time.RFC3339), record.DeploymentVersion))
	default:
		// Unconfigured: today's posture. Named in Unchecked rather than passed silently —
		// see the notes below, which change meaning without provenance.
		report.Unchecked = append(report.Unchecked,
			"no commissioning record is configured, so a missing journal cannot be distinguished from a lost one: 'does not exist yet' and 'was deleted' look identical here (#220)")
	}

	if err := requireLoopbackUnlessMutualTLS(settings.ListenAddress, settings.TLSCertificatePath != ""); err != nil {
		return nil, nil, nil, nil, report, err
	}
	note("listener address is loopback or mutual TLS is configured")

	var keyRegistry *registry.Registry
	var err error
	if settings.RegistryPath != "" {
		keyRegistry, err = registry.LoadFile(settings.RegistryPath, settings.Site, nil)
		if err != nil {
			return nil, nil, nil, nil, report, fmt.Errorf("custody manifest: %w", err)
		}
		note(fmt.Sprintf("custody manifest loads for site %q, digest %s", settings.Site, keyRegistry.Digest()))
	}

	var rbacPolicy *auth.Policy
	if settings.RBACPolicyPath != "" {
		rbacPolicy, err = auth.LoadPolicyFile(settings.RBACPolicyPath)
		if err != nil {
			return nil, nil, nil, nil, report, fmt.Errorf("RBAC policy: %w", err)
		}
		note("RBAC policy loads, digest " + rbacPolicy.Digest())
	}

	var policyEngine *policy.Engine
	if settings.PolicyPath != "" {
		policies, digest, loadErr := policy.LoadFile(settings.PolicyPath)
		if loadErr != nil {
			return nil, nil, nil, nil, report, fmt.Errorf("purpose policy: %w", loadErr)
		}
		// A verification-only replay: no lock, nothing opened for writing, so this is safe to run
		// against the journal a live daemon is holding.
		// A JOURNAL THAT DOES NOT EXIST YET IS NOT A FAILURE HERE, and that is the opposite of what
		// -verify-policy-state does. The two commands ask different questions: the verify command
		// is an operator asserting a trail should exist, so a missing file is the answer they need;
		// preflight asks whether the daemon will start, and on a first deployment it legitimately
		// will, creating the journal as it goes. Reporting the absence keeps it visible rather than
		// silently passing.
		if settings.PolicyStatePath != "" {
			switch summary, stateErr := policy.VerifyState(settings.PolicyStatePath); {
			case stateErr == nil:
				note(fmt.Sprintf("policy state journal is intact: %d reservations, head sequence %d", summary.Reservations, summary.HeadSequence))
			case errors.Is(stateErr, os.ErrNotExist):
				if settings.CommissioningRecordPath != "" {
					note("policy state journal does not exist yet; the commissioning record makes that a commissioned site with no reservations, not a loss")
				} else {
					note("policy state journal does not exist yet; with no commissioning record this is indistinguishable from losing it (#220)")
				}
			default:
				return nil, nil, nil, nil, report, fmt.Errorf("policy state journal: %w", stateErr)
			}
		}
		policyEngine, err = policy.New(policies, discardingState{}, time.Now)
		if err != nil {
			return nil, nil, nil, nil, report, fmt.Errorf("purpose policy: %w", err)
		}
		note("purpose policy compiles, digest " + digest)
	}

	if keyRegistry != nil && policyEngine != nil {
		if err := requireDeclaredPoliciesAreEnforced(keyRegistry, policyEngine); err != nil {
			return nil, nil, nil, nil, report, err
		}
		note("every object's declared policy_id is the policy that governs it")
	}
	if keyRegistry != nil && rbacPolicy != nil {
		if err := requireGrantsReferenceRealObjects(keyRegistry, rbacPolicy); err != nil {
			return nil, nil, nil, nil, report, err
		}
		note("every RBAC grant names an object the registry has")
	}

	if settings.SecureChannelEvidence != "" {
		if _, err := nitrokey.LoadSecureChannelEvidence(settings.SecureChannelEvidence, time.Now); err != nil {
			return nil, nil, nil, nil, report, fmt.Errorf("secure-channel evidence: %w", err)
		}
		note("secure-channel evidence is well-formed and unexpired")
	}
	if settings.FencingLeasePath != "" {
		if _, err := loadFencingKey(settings.FencingPublicKeyPath); err != nil {
			return nil, nil, nil, nil, report, err
		}
		note("fencing public key is readable and well-formed")
		// THE EPOCH JOURNAL IS NOT READ HERE, and the omission is deliberate honesty rather
		// than an oversight: preflight must not take the gate's view of the lease, and the
		// epoch chain's integrity is verified when the gate opens it. What preflight CAN say
		// is what absence would mean — and without a commissioning record it cannot even
		// say that (#220).
		if settings.FencingStatePath != "" && settings.CommissioningRecordPath == "" {
			report.Unchecked = append(report.Unchecked,
				"the fencing epoch journal is not read, so a truncated or lost epoch history looks the same as none")
		}
	}
	if settings.RevokedSerialsPath != "" && settings.CommissioningRecordPath == "" {
		// An EMPTY revocation list is the only state that re-admits every revoked client by
		// doing nothing, and without provenance "empty" is indistinguishable from "wiped".
		report.Unchecked = append(report.Unchecked,
			"the revocation list is not read, so an emptied list looks the same as one with nothing revoked")
	}
	if settings.AuditJournalPath != "" {
		// Same distinction as the policy state journal above.
		if _, statErr := os.Stat(settings.AuditJournalPath); errors.Is(statErr, os.ErrNotExist) {
			if settings.CommissioningRecordPath != "" {
				note("audit journal does not exist yet; the commissioning record makes that a commissioned site with no events, not a loss")
			} else {
				note("audit journal does not exist yet; with no commissioning record this is indistinguishable from losing it (#220)")
			}
		} else {
			events, err := audit.VerifyIntegrity(settings.AuditJournalPath)
			if err != nil {
				return nil, nil, nil, nil, report, fmt.Errorf("audit journal: %w", err)
			}
			note(fmt.Sprintf("audit journal is intact: %d events", len(events)))
		}
	}
	if settings.AuditSinkURL != "" {
		if err := audit.ValidateSinkURL(settings.AuditSinkURL); err != nil {
			return nil, nil, nil, nil, report, fmt.Errorf("audit sink: %w", err)
		}
		note("audit sink URL is an https origin the sink accepts")
	}

	// TLS MATERIAL, INCLUDING EXPIRY. This was on the unchecked list, and it should not have been:
	// an expired server certificate is a scheduled outage that the files predict, and a certificate
	// whose key does not match is a deployment mistake that only shows up as a handshake failure
	// once traffic arrives. Both are answerable without starting anything.
	//
	// mutualTLSConfig is the daemon's own loader, so a keypair preflight accepts is one the listener
	// accepts — the point of preflight is that it cannot hold a second opinion.
	if settings.TLSCertificatePath != "" {
		tlsConfig, err := mutualTLSConfig(settings)
		if err != nil {
			return nil, nil, nil, nil, report, fmt.Errorf("mutual TLS material: %w", err)
		}
		note("server keypair loads and the private key matches the certificate")
		if len(tlsConfig.Certificates) > 0 && len(tlsConfig.Certificates[0].Certificate) > 0 {
			leaf, parseErr := x509.ParseCertificate(tlsConfig.Certificates[0].Certificate[0])
			if parseErr != nil {
				return nil, nil, nil, nil, report, fmt.Errorf("server certificate: %w", parseErr)
			}
			now := time.Now()
			switch {
			case now.After(leaf.NotAfter):
				return nil, nil, nil, nil, report, fmt.Errorf("server certificate expired on %s: the listener would refuse every connection",
					leaf.NotAfter.UTC().Format(time.RFC3339))
			case now.Before(leaf.NotBefore):
				return nil, nil, nil, nil, report, fmt.Errorf("server certificate is not valid until %s",
					leaf.NotBefore.UTC().Format(time.RFC3339))
			default:
				// Report the remaining life rather than only that it is valid. "Valid" on the day
				// before expiry and "valid" with a year left are the same word for very different
				// situations, and preflight is run precisely when someone is deciding whether to act.
				note(fmt.Sprintf("server certificate is valid until %s (%d days remaining)",
					leaf.NotAfter.UTC().Format(time.RFC3339), int(leaf.NotAfter.Sub(now).Hours()/24)))
			}
		}
	}

	// SAY WHAT WAS NOT CHECKED. A preflight that reports success without naming its limits invites
	// the reading that the daemon will start, which is a stronger claim than it can make.
	if settings.PKCS11ModulePath != "" {
		report.Unchecked = append(report.Unchecked,
			"the PKCS#11 module is not loaded and no token is contacted, so device presence, PIN validity and secure-messaging state are unverified",
			"the fencing lease itself is not read, so whether this site currently holds it is unknown")
	}
	if settings.TLSCertificatePath == "" {
		report.Unchecked = append(report.Unchecked,
			"no mutual TLS is configured, so no transport identity was checked")
	}
	// The approver key set is optional and loaded here so that -check-config rejects a
	// malformed one without starting the daemon. Left unconfigured it stays nil, nothing
	// is ever counted as an approver, and any policy with required_approvals > 0 denies --
	// the posture every deployment has today.
	var approverKeys *approval.KeySet
	if settings.ApproverKeysPath != "" {
		approverKeys, err = approval.LoadKeySet(settings.ApproverKeysPath)
		if err != nil {
			return nil, nil, nil, nil, report, fmt.Errorf("approver keys: %w", err)
		}
		note(fmt.Sprintf("approver key set loads, %d approvers, digest %s", approverKeys.Len(), approverKeys.Digest()))
	} else {
		report.Unchecked = append(report.Unchecked,
			"no approver key set is configured, so any policy requiring approvals will deny every request")
	}

	return keyRegistry, rbacPolicy, policyEngine, approverKeys, report, nil
}

// discardingState satisfies policy.State for a compile-only check of the policy document. Preflight
// must never write to the real journal, and must never take its lock.
type discardingState struct{}

func (discardingState) Reserve(ctx context.Context, reservation policy.Reservation) error { return nil }
func (discardingState) Ready(ctx context.Context) bool                                    { return true }

func writePreflight(report *preflightReport, out io.Writer) {
	for _, item := range report.Checked {
		fmt.Fprintln(out, "  ok      ", item)
	}
	for _, item := range report.Unchecked {
		fmt.Fprintln(out, "  UNCHECKED", item)
	}
}
