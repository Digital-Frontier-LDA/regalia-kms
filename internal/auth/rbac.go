package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
)

const maxPolicyBytes = 512 << 10

// AGENT PRINCIPALS GET OPERATIONS, NEVER THE SECRET (regalia-kms-sv3.2; CB4A draft-hartman-credential-broker-4-agents
// §3.3, "Model C"). An AI agent that can call release-secret holds the real long-lived credential (an API token, a
// password), which the draft calls NOT RECOMMENDED: everything it then does with that credential is outside this
// service's audit and revocation. An agent is identified by its URI SAN, under AgentIdentityPrefix, so the class comes
// from the workload CA that issued the certificate rather than from a policy field an author could leave out. Sign,
// wrap, unwrap and the other operations stay grantable to an agent: the key never leaves the token.
const (
	AgentIdentityPrefix = "spiffe://regalia/agent/"
	// AgentRefusedOperation is the one operation an agent may never be granted or served.
	AgentRefusedOperation = "release-secret"
	// AgentReleaseRefused is the audit outcome of a release-secret request by an agent principal: its own rule id,
	// so the trail tells "an agent asked for a secret" apart from an ordinary missing grant (rbac-denied).
	AgentReleaseRefused = "agent-release-refused"
)

// IsAgent reports whether principal is an agent identity (AgentIdentityPrefix and at least one more character).
func IsAgent(principal string) bool {
	return len(principal) > len(AgentIdentityPrefix) && principal[:len(AgentIdentityPrefix)] == AgentIdentityPrefix
}

// AgentRefuses reports whether the request is one an agent principal is never served, whatever the policy grants.
func AgentRefuses(principal, operation string) bool {
	return operation == AgentRefusedOperation && IsAgent(principal)
}

type policyDocument struct {
	SchemaVersion int                 `json:"schema_version"`
	Principals    []principalDocument `json:"principals"`
}

type principalDocument struct {
	URI    string          `json:"uri"`
	Grants []grantDocument `json:"grants"`
}

type grantDocument struct {
	Objects      []string `json:"objects"`
	Operations   []string `json:"operations"`
	Environments []string `json:"environments"`
}

type grant struct {
	objects      map[string]struct{}
	operations   map[string]struct{}
	environments map[string]struct{}
}

type Policy struct {
	digest string
	grants map[string][]grant
}

// GrantedObject is one (object, operation) pair some principal has been granted.
type GrantedObject struct {
	Principal string
	ObjectID  string
	Operation string
}

// GrantedObjects lists every (principal, object, operation) the policy grants.
//
// LoadPolicy never sees the key registry, so a grant naming an object that does not exist is
// accepted in silence. The daemon starts clean, the operator believes that principal is authorized,
// and every request denies at RBAC — fail-closed, but with the operator's mental model wrong and
// nothing to correct it. A grant that can never authorize anything is config that says something
// untrue.
//
// This exists so the daemon can check the grants against the registry at startup.
func (policy *Policy) GrantedObjects() []GrantedObject {
	if policy == nil {
		return nil
	}
	var granted []GrantedObject
	for principal, grants := range policy.grants {
		for _, item := range grants {
			for object := range item.objects {
				for operation := range item.operations {
					granted = append(granted, GrantedObject{Principal: principal, ObjectID: object, Operation: operation})
				}
			}
		}
	}
	sort.Slice(granted, func(i, j int) bool {
		if granted[i].ObjectID != granted[j].ObjectID {
			return granted[i].ObjectID < granted[j].ObjectID
		}
		if granted[i].Operation != granted[j].Operation {
			return granted[i].Operation < granted[j].Operation
		}
		return granted[i].Principal < granted[j].Principal
	})
	return granted
}

func LoadPolicyFile(path string) (*Policy, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open RBAC policy: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat RBAC policy: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("RBAC policy must be a non-writable regular file")
	}
	return LoadPolicy(file)
}

func LoadPolicy(reader io.Reader) (*Policy, error) {
	contents, err := io.ReadAll(io.LimitReader(reader, maxPolicyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read RBAC policy: %w", err)
	}
	if len(contents) > maxPolicyBytes {
		return nil, errors.New("RBAC policy exceeds 512 KiB")
	}
	var document policyDocument
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode RBAC policy: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("RBAC policy must contain exactly one JSON document")
	}
	if document.SchemaVersion != 1 || len(document.Principals) == 0 {
		return nil, errors.New("RBAC policy is empty or unsupported")
	}
	result := &Policy{grants: make(map[string][]grant, len(document.Principals))}
	identityPrefix, _ := url.Parse("spiffe://regalia/")
	sum := sha256.Sum256(contents)
	result.digest = "sha256:" + hex.EncodeToString(sum[:])
	for _, principal := range document.Principals {
		identity, parseErr := url.Parse(principal.URI)
		// One message for three operands told an operator with one bad entry among many only that
		// something was invalid, while the duplicate refusal and compileGrant's wrapper -- both
		// further down this same loop -- already named the principal (#333). Each arm now says
		// which operand fired, because "invalid URI" and "no grants" are different repairs.
		switch {
		case parseErr != nil:
			return nil, fmt.Errorf("RBAC principal %q: URI does not parse: %w", principal.URI, parseErr)
		case !canonicalURISAN(identity, identityPrefix):
			return nil, fmt.Errorf("RBAC principal %q: URI is not a canonical workload identity under %q",
				principal.URI, identityPrefix.String())
		case identity.String() != principal.URI:
			// The authenticator keys a request by the parsed URI's String() (auth.go), so a grant under any other
			// spelling of the same identity could never match one -- and every check below that reads principal.URI
			// (IsAgent above all) would judge the spelling, not the identity: "SPIFFE://regalia/agent/x" passed the
			// agent release-secret refusal while naming an agent (regalia-kms#668 review, B1). One spelling loads.
			return nil, fmt.Errorf("RBAC principal %q: URI is not in its canonical spelling (want %q)",
				principal.URI, identity.String())
		case len(principal.Grants) == 0:
			return nil, fmt.Errorf("RBAC principal %q: no grants", principal.URI)
		}
		if _, duplicate := result.grants[principal.URI]; duplicate {
			return nil, fmt.Errorf("duplicate RBAC principal %q", principal.URI)
		}
		for _, input := range principal.Grants {
			compiled, err := compileGrant(input)
			if err != nil {
				return nil, fmt.Errorf("principal %q: %w", principal.URI, err)
			}
			// A grant that can never be served is config that says something untrue (see GrantedObjects): refuse it
			// here, naming the principal, rather than load a policy whose author believes the agent can release.
			if _, releases := compiled.operations[AgentRefusedOperation]; releases && IsAgent(principal.URI) {
				return nil, fmt.Errorf("RBAC principal %q: an agent principal may not be granted %s (CB4A Model C: agents get operations, never the secret)",
					principal.URI, AgentRefusedOperation)
			}
			result.grants[principal.URI] = append(result.grants[principal.URI], compiled)
		}
	}
	return result, nil
}

func compileGrant(input grantDocument) (grant, error) {
	if len(input.Objects) == 0 || len(input.Operations) == 0 || len(input.Environments) == 0 {
		return grant{}, errors.New("grant dimensions must be non-empty")
	}
	result := grant{
		objects: stringSet(input.Objects), operations: stringSet(input.Operations),
		environments: stringSet(input.Environments),
	}
	if len(result.objects) != len(input.Objects) || len(result.operations) != len(input.Operations) || len(result.environments) != len(input.Environments) {
		return grant{}, errors.New("grant values must be unique")
	}
	for _, values := range [][]string{input.Objects, input.Operations, input.Environments} {
		for _, value := range values {
			if value == "" || value == "*" {
				return grant{}, errors.New("empty values and wildcards are forbidden")
			}
		}
	}
	return result, nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func (policy *Policy) Allowed(principal, object, operation, environment string) bool {
	for _, grant := range policy.grants[principal] {
		_, objectAllowed := grant.objects[object]
		_, operationAllowed := grant.operations[operation]
		_, environmentAllowed := grant.environments[environment]
		if objectAllowed && operationAllowed && environmentAllowed {
			return true
		}
	}
	return false
}

func (policy *Policy) Digest() string { return policy.digest }

func (policy *Policy) Ready(context.Context) bool { return policy != nil && len(policy.grants) > 0 }
