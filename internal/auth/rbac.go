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
