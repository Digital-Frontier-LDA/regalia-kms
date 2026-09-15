package config

// Validate() states four all-or-nothing rules, each with a comment saying which control the
// missing piece removes. Two of them — mutual TLS and certificate issuing — have tests. The
// other two did not: replacing either the hardware or the fencing guard with a constant passed
// the entire kms module. Same shape as the registry digest (#221) and the epoch hash (#222) —
// a control that runs, is documented, and whose wrong answer nothing catches.
//
// Every case below was built so the guard under test is the ONLY thing that can refuse it; the
// fixtures say where that constrained the case.

import (
	"strings"
	"testing"
)

// hardwareFieldNames are the four fields the hardware rule binds together, in the order the
// bitmask below walks them.
var hardwareFieldNames = []string{"pkcs11_module_path", "pin_paths", "secure_channel_evidence_path", "audit_journal_path"}

func applyHardwareSubset(cfg *Config, mask int) {
	if mask&1 != 0 {
		cfg.PKCS11ModulePath = "/usr/lib/opensc-pkcs11.so"
	}
	if mask&2 != 0 {
		cfg.PINPaths = map[string]string{"user": "/run/credentials/kms/user-pin"}
	}
	if mask&4 != 0 {
		cfg.SecureChannelEvidence = "/var/lib/regalia/secure-channel.json"
	}
	if mask&8 != 0 {
		cfg.AuditJournalPath = "/var/lib/regalia/audit.jsonl"
	}
}

func hardwareSubsetName(mask int) string {
	present := []string{}
	for i, name := range hardwareFieldNames {
		if mask&(1<<i) != 0 {
			present = append(present, name)
		}
	}
	return strings.Join(present, "+")
}

// A module without PIN material cannot log in; PIN material without secure-channel evidence uses
// the token over an unproven channel; either without an audit journal operates the token without a
// record. Each missing piece removes a control the others assume is present, so every proper
// non-empty subset must be refused — all fourteen of them, walked by mask so a row cannot be
// silently dropped.
func TestPartialHardwareConfigurationIsRefused(t *testing.T) {
	// The known-good row (§18), in the same test rather than beside it: without it a rule that
	// refused EVERY hardware configuration would pass all fourteen negative rows. It is an anchor
	// and not a gate — the shipped-example tests configure hardware in full and would also go red
	// on an over-refusal — but a reader of this table should not have to know that to trust it.
	t.Run("complete (known good)", func(t *testing.T) {
		cfg := baseConfig()
		applyHardwareSubset(&cfg, 15)
		cfg.RegistryPath, cfg.Site = "/etc/regalia/registry.json", "sitea"
		cfg.PolicyPath, cfg.PolicyStatePath = "/etc/regalia/policy.json", "/var/lib/regalia/policy-state.jsonl"
		cfg.RBACPolicyPath = "/etc/regalia/rbac.json"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("a complete hardware configuration was refused: %v", err)
		}
	})
	for mask := 1; mask < 15; mask++ {
		t.Run(hardwareSubsetName(mask), func(t *testing.T) {
			cfg := baseConfig()
			applyHardwareSubset(&cfg, mask)
			// Nothing else is set, so the pairing rules for registry/site and policy/state are
			// satisfied by both halves being absent: the hardware rule is the only refuser.
			if err := cfg.Validate(); err == nil {
				t.Fatalf("a hardware configuration missing %d of its four fields was accepted",
					4-len(strings.Split(hardwareSubsetName(mask), "+")))
			}
		})
	}
}

// A token must not be operated without routing, policy and authorization. Each row drops exactly
// one of the three while keeping the four hardware fields, so the hardware-completeness rule
// above cannot be what refuses it.
func TestHardwareRequiresRoutingPolicyAndAuthorization(t *testing.T) {
	cases := []struct {
		name    string
		missing func(*Config)
	}{
		// registry_path and site are paired by their own rule, so the row drops BOTH: dropping
		// registry_path alone would be refused by the pairing rule and prove nothing about this one.
		{"no registry", func(c *Config) { c.RegistryPath, c.Site = "", "" }},
		// Likewise policy_path is paired with policy_state_path.
		{"no policy", func(c *Config) { c.PolicyPath, c.PolicyStatePath = "", "" }},
		{"no rbac policy", func(c *Config) { c.RBACPolicyPath = "" }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := baseConfig()
			applyHardwareSubset(&cfg, 15)
			cfg.RegistryPath, cfg.Site = "/etc/regalia/registry.json", "sitea"
			cfg.PolicyPath, cfg.PolicyStatePath = "/etc/regalia/policy.json", "/var/lib/regalia/policy-state.jsonl"
			cfg.RBACPolicyPath = "/etc/regalia/rbac.json"
			testCase.missing(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("hardware was accepted without routing, policy and authorization")
			}
		})
	}
}

func TestYubiKeyHardwareConfigurationDoesNotRequirePKCS11ChannelEvidence(t *testing.T) {
	cfg := baseConfig()
	cfg.YubiKeyDevices = map[string]string{"yubi-a": "25923905", "yubi-b": "25923902"}
	cfg.PINPaths = map[string]string{"yubi-a": "/run/credentials/kms/yubi-a.pin", "yubi-b": "/run/credentials/kms/yubi-b.pin"}
	cfg.AuditJournalPath = "/var/lib/regalia/audit.jsonl"
	cfg.RegistryPath, cfg.Site = "/etc/regalia/registry.json", "sitea"
	cfg.PolicyPath, cfg.PolicyStatePath = "/etc/regalia/policy.json", "/var/lib/regalia/policy-state.jsonl"
	cfg.RBACPolicyPath = "/etc/regalia/rbac.json"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("complete YubiKey configuration was refused: %v", err)
	}
	cfg.PINPaths = map[string]string{"yubi-a": "/run/credentials/kms/yubi-a.pin"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("YubiKey configuration accepted without PIN material for every commissioned device")
	}
}

// A lease without its public key would be trusted unsigned; a lease without its epoch journal
// would let a revoked active site present an old lease and sign again. Half a fence is a gate.
func TestPartialFencingConfigurationIsRefused(t *testing.T) {
	fields := []struct {
		name  string
		apply func(*Config)
	}{
		{"fencing_lease_path", func(c *Config) { c.FencingLeasePath = "/var/lib/regalia/lease.json" }},
		{"fencing_state_path", func(c *Config) { c.FencingStatePath = "/var/lib/regalia/epochs.jsonl" }},
		{"fencing_public_key_path", func(c *Config) { c.FencingPublicKeyPath = "/etc/regalia/fencing.pub" }},
	}
	completeFence := func(cfg *Config) {
		for i := range fields {
			fields[i].apply(cfg)
		}
	}
	// The known-good row, for the same reason as the hardware table above.
	t.Run("complete (known good)", func(t *testing.T) {
		cfg := baseConfig()
		cfg.RegistryPath, cfg.Site = "/etc/regalia/registry.json", "sitea"
		completeFence(&cfg)
		if err := cfg.Validate(); err != nil {
			t.Fatalf("a complete fencing configuration was refused: %v", err)
		}
	})
	for mask := 1; mask < 7; mask++ {
		present := []string{}
		for i := range fields {
			if mask&(1<<i) != 0 {
				present = append(present, fields[i].name)
			}
		}
		t.Run(strings.Join(present, "+"), func(t *testing.T) {
			cfg := baseConfig()
			// site and registry_path are set, so the rule that fencing needs them cannot be the
			// refuser; only the completeness rule can.
			cfg.RegistryPath, cfg.Site = "/etc/regalia/registry.json", "sitea"
			for i := range fields {
				if mask&(1<<i) != 0 {
					fields[i].apply(&cfg)
				}
			}
			if err := cfg.Validate(); err == nil {
				t.Fatal("a partially configured fence was accepted")
			}
		})
	}
}

// A lease names the site it grants and is bound to the registry it was issued against, so fencing
// without either has nothing to check the lease's claims against.
//
// ONE ROW, DELIBERATELY. registry_path and site are paired by an earlier rule, so a fixture with
// exactly one of them present is refused by THAT rule and would go red without this one ever
// running — the fixture would certify a guard it never reached. Both absent is the only state
// that reaches this rule as the sole possible refuser.
func TestFencingRequiresSiteAndRegistry(t *testing.T) {
	cfg := baseConfig()
	cfg.FencingLeasePath = "/var/lib/regalia/lease.json"
	cfg.FencingStatePath = "/var/lib/regalia/epochs.jsonl"
	cfg.FencingPublicKeyPath = "/etc/regalia/fencing.pub"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("a complete fence with no site and no registry was accepted")
	}
	if !strings.Contains(err.Error(), "fencing requires site and registry_path") {
		t.Fatalf("refused by the wrong rule: %v", err)
	}
}

// An unparseable listen_address must be refused. The fixture configures mutual TLS in full,
// because that is what makes this guard the sole detector: with it removed, SplitHostPort's empty
// host is neither "localhost" nor a loopback IP, so the non-loopback rule refuses the address for
// an unrelated reason and the missing guard looks tested.
func TestAnUnparseableListenAddressIsRefused(t *testing.T) {
	withTLS := func() Config {
		cfg := baseConfig()
		cfg.TLSCertificatePath = "/etc/regalia/tls/server.crt"
		cfg.TLSPrivateKeyPath = "/etc/regalia/tls/server.key"
		cfg.TLSClientCAPath = "/etc/regalia/tls/clients.crt"
		return cfg
	}
	// Positive control: the same configuration with a parseable address is accepted, so a refusal
	// below is about the address and not about the transport.
	control := withTLS()
	control.ListenAddress = "10.0.0.4:8443"
	if err := control.Validate(); err != nil {
		t.Fatalf("control: a valid non-loopback address with full mTLS was refused: %v", err)
	}
	// Named rather than keyed by the address itself: one of the cases IS the empty string, which
	// would produce a subtest with no name and could not be selected with -run.
	unparseable := []struct {
		name    string
		address string
	}{
		{"no port separator", "no-colon-here"},
		{"too many colons", "host:port:extra"},
		{"empty", ""},
	}
	for _, bad := range unparseable {
		t.Run(bad.name, func(t *testing.T) {
			cfg := withTLS()
			cfg.ListenAddress = bad.address
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("an unparseable listen_address %q was accepted", bad.address)
			}
			if !strings.Contains(err.Error(), "invalid listen_address") {
				t.Fatalf("refused by the wrong rule: %v", err)
			}
		})
	}
}
