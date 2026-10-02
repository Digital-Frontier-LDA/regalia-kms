package config

import (
	"strings"
	"testing"
)

// RUNTIME ADMISSION HAS NO DEFAULT WHERE THERE IS A TOKEN (regalia-kms#74).
//
// "All three settings or none" would leave the fail-open case standing: a production host whose
// configuration simply lacks the block serves with no runtime lease, and nothing says so. So the
// decision is written down. With a token configured, runtime_admission must be "required" (and then
// its three settings must be there) or "disabled-for-lab" (and then none of them may be).
func TestRuntimeAdmissionMustBeStatedWhereThereIsAToken(t *testing.T) {
	withToken := func(cfg *Config) {
		cfg.PKCS11ModulePath = "/usr/lib/opensc-pkcs11.so"
		cfg.PINPaths = map[string]string{"hsm-sitea": "/run/credentials/regalia-kms.service/hsm-sitea.pin"}
		cfg.SecureChannelEvidence = "/etc/regalia/secure-channel.json"
		cfg.AuditJournalPath = "/var/lib/regalia/audit.jsonl"
		cfg.RegistryPath, cfg.Site = "/etc/regalia/registry.json", "sitea"
		cfg.PolicyPath, cfg.PolicyStatePath = "/etc/regalia/policy.json", "/var/lib/regalia/policy-state.jsonl"
		cfg.RBACPolicyPath = "/etc/regalia/rbac.json"
	}
	withYubiKey := func(cfg *Config) {
		cfg.YubiKeyDevices = map[string]string{"yubi-a": "25923905"}
		cfg.PINPaths = map[string]string{"yubi-a": "/run/credentials/regalia-kms.service/yubi-a.pin"}
		cfg.AuditJournalPath = "/var/lib/regalia/audit.jsonl"
		cfg.RegistryPath, cfg.Site = "/etc/regalia/registry.json", "sitea"
		cfg.PolicyPath, cfg.PolicyStatePath = "/etc/regalia/policy.json", "/var/lib/regalia/policy-state.jsonl"
		cfg.RBACPolicyPath = "/etc/regalia/rbac.json"
	}
	required := func(cfg *Config) {
		cfg.RuntimeAdmission = RuntimeAdmissionRequired
		cfg.RuntimeAdmissionPath, cfg.NodeID, cfg.BootSessionPath = "/run/regalia/admission.json", "site-a", "/run/regalia/boot-session"
	}
	cases := []struct {
		name   string
		build  []func(*Config)
		refuse string // empty: accepted
	}{
		{"a token and nothing stated", []func(*Config){withToken}, "must state runtime_admission"},
		{"a YubiKey and nothing stated", []func(*Config){withYubiKey}, "must state runtime_admission"},
		{"a token, required, complete", []func(*Config){withToken, required}, ""},
		{"a YubiKey, required, complete", []func(*Config){withYubiKey, required}, ""},
		{"a token, disabled for the lab", []func(*Config){withToken, func(c *Config) { c.RuntimeAdmission = RuntimeAdmissionDisabledForLab }}, ""},
		{"no token, nothing stated", nil, ""},
		{"no token, required, complete", []func(*Config){required}, ""},
		{"required without the admission path", []func(*Config){withToken, required, func(c *Config) { c.RuntimeAdmissionPath = "" }}, `"required" needs runtime_admission_path, node_id and boot_session_path`},
		{"required without the node ID", []func(*Config){withToken, required, func(c *Config) { c.NodeID = "" }}, `"required" needs runtime_admission_path, node_id and boot_session_path`},
		{"required without the boot session path", []func(*Config){withToken, required, func(c *Config) { c.BootSessionPath = "" }}, `"required" needs runtime_admission_path, node_id and boot_session_path`},
		{"required with nothing else", []func(*Config){withToken, func(c *Config) { c.RuntimeAdmission = RuntimeAdmissionRequired }}, `"required" needs runtime_admission_path, node_id and boot_session_path`},
		{"a relative admission path", []func(*Config){required, func(c *Config) { c.RuntimeAdmissionPath = "admission.json" }}, "must be absolute"},
		{"a relative boot session path", []func(*Config){required, func(c *Config) { c.BootSessionPath = "run/boot-session" }}, "must be absolute"},
		{"a node ID the manifest could not hold", []func(*Config){required, func(c *Config) { c.NodeID = "Site A" }}, "node_id must be this node's ID"},
		{"disabled for the lab, with a path left in", []func(*Config){withToken, required, func(c *Config) { c.RuntimeAdmission = RuntimeAdmissionDisabledForLab }}, `"disabled-for-lab" takes no`},
		{"disabled for the lab, with only a node ID", []func(*Config){func(c *Config) { c.RuntimeAdmission, c.NodeID = RuntimeAdmissionDisabledForLab, "site-a" }}, `"disabled-for-lab" takes no`},
		{"the settings without the word", []func(*Config){required, func(c *Config) { c.RuntimeAdmission = "" }}, `need runtime_admission "required"`},
		{"one setting without the word", []func(*Config){func(c *Config) { c.BootSessionPath = "/run/regalia/boot-session" }}, `need runtime_admission "required"`},
		{"another word", []func(*Config){withToken, required, func(c *Config) { c.RuntimeAdmission = "optional" }}, `must be "required" or "disabled-for-lab", not "optional"`},
		{"the word in another case", []func(*Config){withToken, required, func(c *Config) { c.RuntimeAdmission = "Required" }}, `must be "required" or "disabled-for-lab"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Default()
			for _, step := range c.build {
				step(&cfg)
			}
			err := cfg.Validate()
			if c.refuse == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.refuse) {
				t.Fatalf("Validate = %v, want a refusal containing %q", err, c.refuse)
			}
		})
	}
}

// The same through the document an operator writes, where "absent" is a key that is not there.
func TestADocumentWithATokenAndNoRuntimeAdmissionIsRefused(t *testing.T) {
	const token = `"pkcs11_module_path":"/usr/lib/opensc-pkcs11.so","pin_paths":{"hsm-sitea":"/run/credentials/regalia-kms.service/hsm-sitea.pin"},` +
		`"secure_channel_evidence_path":"/etc/regalia/secure-channel.json","audit_journal_path":"/var/lib/regalia/audit.jsonl",` +
		`"registry_path":"/etc/regalia/registry.json","site":"sitea","policy_path":"/etc/regalia/policy.json",` +
		`"policy_state_path":"/var/lib/regalia/policy-state.jsonl","rbac_policy_path":"/etc/regalia/rbac.json"`
	if _, err := Decode(strings.NewReader("{" + token + "}")); err == nil || !strings.Contains(err.Error(), "must state runtime_admission") {
		t.Fatalf("Decode = %v, want the runtime_admission refusal", err)
	}
	settings, err := Decode(strings.NewReader("{" + token + `,"runtime_admission":"required","runtime_admission_path":"/run/regalia/admission.json",` +
		`"node_id":"site-a","boot_session_path":"/run/regalia/boot-session"}`))
	if err != nil || settings.RuntimeAdmission != RuntimeAdmissionRequired {
		t.Fatalf("Decode = %+v, %v", settings.RuntimeAdmission, err)
	}
	if _, err := Decode(strings.NewReader("{" + token + `,"runtime_admission":"disabled-for-lab"}`)); err != nil {
		t.Fatalf("the lab value was refused: %v", err)
	}
}
