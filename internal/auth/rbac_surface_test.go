package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePolicyFile(t *testing.T, contents string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rbac.json")
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile is subject to umask, so the mode is set explicitly afterwards or the
	// permission cases below would be testing whatever umask the runner happens to have.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadPolicyFileRefusesAnythingAnyoneElseCouldRewrite.
//
// The RBAC policy decides who may use which key. A file another user can rewrite is a file that
// grants whatever they like, and the daemon reads it at startup with no further check — so the
// refusal has to happen here or not at all.
func TestLoadPolicyFileRefusesAnythingAnyoneElseCouldRewrite(t *testing.T) {
	// A slice, not a map: Go randomises map iteration, so subtest order would differ run to run and
	// two CI logs could not be diffed against each other. Same reason GrantedObjects sorts.
	for _, test := range []struct {
		name string
		mode os.FileMode
	}{
		{"group-writable", 0o620},
		{"world-writable", 0o602},
		{"writable by everyone", 0o666},
	} {
		name, mode := test.name, test.mode
		t.Run(name, func(t *testing.T) {
			path := writePolicyFile(t, validPolicy, mode)
			policy, err := LoadPolicyFile(path)
			if err == nil {
				t.Fatalf("a %s RBAC policy loaded with %d grants: anyone who can write it can grant themselves any key",
					name, len(policy.GrantedObjects()))
			}
			if !strings.Contains(err.Error(), "non-writable regular file") {
				t.Fatalf("%s: error = %q, want the writability refusal — a different failure leaves this one unproven", name, err)
			}
		})
	}
}

// The rule is about WRITABILITY, not secrecy: the policy is an authority, and everything below is
// readable by someone other than the owner and still accepted. Naming this "owner-only" described a
// stricter rule than the one the code has, which would send a reader looking for a mode check that
// is not there.
func TestLoadPolicyFileAcceptsAnyFileOthersCannotWrite(t *testing.T) {
	for _, test := range []struct {
		name string
		mode os.FileMode
	}{
		{"read-only to the owner", 0o400},
		{"owner read-write", 0o600},
		{"readable by the group", 0o640},
		{"readable by everyone", 0o644},
	} {
		name, mode := test.name, test.mode
		t.Run(name, func(t *testing.T) {
			// Readable-by-others is deliberately fine: the policy is not a secret, it is an
			// authority. What must not happen is someone else CHANGING it.
			if _, err := LoadPolicyFile(writePolicyFile(t, validPolicy, mode)); err != nil {
				t.Fatalf("a %s policy was refused: %v — the refusals above would then be about existence, not writability", name, err)
			}
		})
	}
}

func TestLoadPolicyFileRefusesWhatIsNotAFile(t *testing.T) {
	directory := t.TempDir()

	// THE MESSAGE, NOT JUST AN ERROR. Without the IsRegular check a directory still fails — os.Open
	// succeeds on one, the permission bits of a 0755 directory pass, and the failure arrives later
	// when LoadPolicy tries to read it. So "an error came back" cannot tell whether the
	// regular-file rule exists, and asserting only that leaves it unproven.
	_, err := LoadPolicyFile(directory)
	if err == nil {
		t.Fatal("a directory was accepted as an RBAC policy")
	}
	if !strings.Contains(err.Error(), "non-writable regular file") {
		t.Fatalf("a directory was refused with %q rather than by the regular-file rule: the refusal is coming from the read, so the rule itself is untested", err)
	}

	if _, err := LoadPolicyFile(filepath.Join(directory, "absent.json")); err == nil {
		t.Fatal("a missing RBAC policy loaded: the daemon would start with no grants rather than refusing")
	}
}

// TestTheDigestIdentifiesThePolicyInForce.
//
// Every audit record carries the RBAC digest, which is the only thing tying a recorded decision to
// the grants that produced it. A digest that did not move when the grants did would attribute
// yesterday's decisions to today's policy — and the whole point of recording it is to answer "under
// what authority was this allowed?" months later.
func TestTheDigestIdentifiesThePolicyInForce(t *testing.T) {
	base, err := LoadPolicy(strings.NewReader(validPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if base.Digest() == "" || !strings.HasPrefix(base.Digest(), "sha256:") {
		t.Fatalf("digest = %q, want a sha256: prefix", base.Digest())
	}

	same, err := LoadPolicy(strings.NewReader(validPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if same.Digest() != base.Digest() {
		t.Fatal("the same policy text produced two digests, so the audit record could not be matched to a policy at all")
	}

	for _, test := range []struct {
		name    string
		altered string
	}{
		{"another object", strings.Replace(validPolicy, `"production-sops"`, `"staging-sops"`, 1)},
		{"another operation", strings.Replace(validPolicy, `"unwrap"`, `"sign"`, 1)},
		{"another principal", strings.Replace(validPolicy, "sops-prod", "sops-staging", 1)},
		{"another environment", strings.Replace(validPolicy, `"production"]`, `"staging"]`, 1)},
	} {
		name, altered := test.name, test.altered
		t.Run(name, func(t *testing.T) {
			if altered == validPolicy {
				t.Fatal("the fixture did not change, so this case compares a policy with itself")
			}
			changed, err := LoadPolicy(strings.NewReader(altered))
			if err != nil {
				t.Fatal(err)
			}
			if changed.Digest() == base.Digest() {
				t.Fatalf("granting %s produced the same digest: an audit record could not tell the two policies apart", name)
			}
		})
	}
}

// TestGrantedObjectsReportsEveryTripleOnce. Preflight uses this to name grants for objects the
// manifest does not have, so a missed triple is a grant nobody reviews and a duplicated one is a
// warning an operator learns to ignore.
func TestGrantedObjectsReportsEveryTripleOnce(t *testing.T) {
	const twoGrants = `{
	  "schema_version": 1,
	  "principals": [{
	    "uri": "spiffe://regalia/workload/sops-prod",
	    "grants": [{
	      "objects": ["beta-object", "alpha-object"],
	      "operations": ["wrap", "unwrap"],
	      "environments": ["production"]
	    }]
	  }]
	}`
	policy, err := LoadPolicy(strings.NewReader(twoGrants))
	if err != nil {
		t.Fatal(err)
	}

	granted := policy.GrantedObjects()
	if len(granted) != 4 {
		t.Fatalf("two objects and two operations produced %d entries, want the 4 pairs: %+v", len(granted), granted)
	}
	seen := map[string]int{}
	for _, item := range granted {
		seen[item.Principal+"/"+item.ObjectID+"/"+item.Operation]++
	}
	if len(seen) != 4 {
		t.Fatalf("entries are not distinct: %v", seen)
	}
	// Sorted by object then operation. Preflight prints this list, and an order that changed run to
	// run would make its output undiffable.
	if granted[0].ObjectID != "alpha-object" || granted[len(granted)-1].ObjectID != "beta-object" {
		t.Fatalf("not ordered by object id: %+v", granted)
	}
	if granted[0].Operation != "unwrap" || granted[1].Operation != "wrap" {
		t.Fatalf("not ordered by operation within an object: %+v", granted)
	}
}

func TestGrantedObjectsOnANilPolicyIsEmptyRatherThanAPanic(t *testing.T) {
	var policy *Policy
	if got := policy.GrantedObjects(); got != nil {
		t.Fatalf("GrantedObjects() = %+v, want nil", got)
	}
}
