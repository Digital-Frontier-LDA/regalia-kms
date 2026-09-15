package config

// GUARD SWEEP (#237, second pass): 70 sites / 88 operands / 176 operand-directions,
// every operand neutralised in BOTH polarities against the whole kms module. 16 survived.
// The shape of the survivors is the finding, and it is the one this package was expected
// to hide:
//
// A FIXTURE THAT SETS EVERY FIELD CANNOT FIND A DROPPED-FIELD DEFECT. Decode() applies
// Default() and then overwrites each field only when the document carries it. The shipped
// example (daemon.example.json) sets 24 of the 27 document fields, and the three it does
// NOT set -- approver_keys_path, commissioning_record_path, revoked_serials_path -- are
// exactly the three whose `if input.X != nil` guard nothing detected. Replacing any of
// those three with a constant false passed the entire kms module: the operator's value is
// discarded, the default silently stands, and the daemon runs on a configuration nobody
// wrote. For revoked_serials_path that default is a NO-OP revocation list whose Check
// returns (false, nil) without touching the filesystem, so a revoked credential is
// accepted.
//
// The fix is not three rows. Every field is one added field away from the same defect, so
// the table below walks ALL 27 document fields, one at a time, and a reflection check makes
// a newly added field fail until it has a row.
//
// AND EVERY ROW'S VALUE MUST DIFFER FROM THE DEFAULT, or the row proves nothing: a fixture
// that sets a field to the value Default() already produces passes just as happily when the
// field is dropped. That is asserted per row rather than left to the author's care.
//
// ELEVEN OPERAND-DIRECTIONS ARE PINNED HERE. The other five are recorded as examined rather
// than left for the next sweep to rediscover, with what was measured about each:
//
//	config.go:131  err != nil (file.Stat)   UNREACHABLE. os.Open has already succeeded, so
//	                                        fstat holds a valid descriptor; no fixture built
//	                                        from the exported API can make it fail.
//	config.go:298  ip == nil                NEVER THE SOLE REFUSER. Measured over seven
//	                                        hosts: none makes `ip == nil` true while
//	                                        `!ip.IsLoopback()` is false, because a nil IP is
//	                                        not loopback. Neutralising BOTH together is
//	                                        caught by three tests, so the branch is exercised
//	                                        and the sibling is what catches it.
//	config.go:386  cfg.Site == ""           NEVER THE SOLE REFUSER. Isolating either operand
//	config.go:386  cfg.RegistryPath == ""   needs one of the pair set and the other empty,
//	                                        which :316 refuses first -- measured, the error
//	                                        reads "registry_path and site must be configured
//	                                        together". This is the same reason
//	                                        TestFencingRequiresSiteAndRegistry carries one
//	                                        row deliberately.
//	config.go:394  len(principal) == 0      NEVER THE SOLE REFUSER; see the §17 note already
//	                                        at that row in guard_coverage_test.go.
//
// A separate honest limit: the FORCE direction of every `input.X != nil` guard makes Decode
// dereference a nil pointer, so it is "detected" by a panic in the first test that decodes
// anything -- all 27 of the 27 such sites. Those verdicts say nothing about coverage, and a
// panic aborts the binary, so each of their failing sets is only a lower bound. NEUTRALISE
// is the informative direction for that family, and it is where the three survivors above
// were found.

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// documentFieldRow pins one json field of the configuration document: the minimal document
// in which that field is the only thing that varies, and the value it must reach in Config.
type documentFieldRow struct {
	field    string
	document string
	got      func(Config) string
	want     string
}

func documentFieldRows() []documentFieldRow {
	const (
		registryAndSite = `"registry_path":"/etc/regalia/registry.json","site":"sitea"`
		policyPair      = `"policy_path":"/etc/regalia/policy.json","policy_state_path":"/var/lib/regalia/policy-state.jsonl"`
		tlsTriple       = `"tls_certificate_path":"/tls/server.crt","tls_private_key_path":"/tls/server.key","tls_client_ca_path":"/tls/clients.pem"`
		issuerTriple    = `"issuer_certificate_path":"/pki/ca.crt","issuer_dns_suffixes":["staging.internal","svc.internal"],"issuer_validity":"2160h"`
		fencingTriple   = `"fencing_lease_path":"/run/regalia/lease.json","fencing_state_path":"/var/lib/regalia/epochs.jsonl","fencing_public_key_path":"/etc/regalia/fencing.pub"`
		hardwareQuad    = `"pkcs11_module_path":"/usr/lib/opensc-pkcs11.so","pin_paths":{"hsm-sitea":"/run/credentials/regalia-kms.service/hsm-sitea.pin"},"secure_channel_evidence_path":"/etc/regalia/secure-channel.json","audit_journal_path":"/var/lib/regalia/audit.jsonl"`
		yubikeyTriple   = `"yubikey_devices":{"yubi-a":"25923905"},"pin_paths":{"yubi-a":"/run/credentials/regalia-kms.service/yubi-a.pin"},"audit_journal_path":"/var/lib/regalia/audit.jsonl"`
	)
	// Hardware is all-or-nothing AND requires routing, policy and authorization, so the
	// hardware rows carry the minimum that lets the document validate at all.
	hardwareDocument := "{" + hardwareQuad + "," + registryAndSite + "," + policyPair +
		`,"rbac_policy_path":"/etc/regalia/rbac.json"}`
	yubikeyDocument := "{" + yubikeyTriple + "," + registryAndSite + "," + policyPair + `,"rbac_policy_path":"/etc/regalia/rbac.json"}`
	fencingDocument := "{" + fencingTriple + "," + registryAndSite + "}"

	return []documentFieldRow{
		// listen_address's default is a loopback address, so the row uses a DIFFERENT
		// loopback address: still valid without TLS, still distinguishable from the default.
		{"listen_address", `{"listen_address":"127.0.0.2:9443"}`,
			func(c Config) string { return c.ListenAddress }, "127.0.0.2:9443"},
		{"registry_path", "{" + registryAndSite + "}",
			func(c Config) string { return c.RegistryPath }, "/etc/regalia/registry.json"},
		{"site", "{" + registryAndSite + "}",
			func(c Config) string { return c.Site }, "sitea"},
		{"rbac_policy_path", `{"rbac_policy_path":"/etc/regalia/rbac.json"}`,
			func(c Config) string { return c.RBACPolicyPath }, "/etc/regalia/rbac.json"},
		{"policy_path", "{" + policyPair + "}",
			func(c Config) string { return c.PolicyPath }, "/etc/regalia/policy.json"},
		{"policy_state_path", "{" + policyPair + "}",
			func(c Config) string { return c.PolicyStatePath }, "/var/lib/regalia/policy-state.jsonl"},

		// A SURVIVOR. Dropped, dual control is silently off: no approver keys load, nothing
		// counts as an approver, and every policy with required_approvals > 0 denies.
		{"approver_keys_path", `{"approver_keys_path":"/etc/regalia/approvers.json"}`,
			func(c Config) string { return c.ApproverKeysPath }, "/etc/regalia/approvers.json"},

		{"operation_timeout", `{"operation_timeout":"30s"}`,
			func(c Config) string { return c.OperationTimeout.String() }, "30s"},
		{"shutdown_timeout", `{"shutdown_timeout":"20s"}`,
			func(c Config) string { return c.ShutdownTimeout.String() }, "20s"},
		{"max_concurrent_operations", `{"max_concurrent_operations":8}`,
			func(c Config) string { return strconv.Itoa(c.MaxConcurrentOperations) }, "8"},

		{"tls_certificate_path", "{" + tlsTriple + "}",
			func(c Config) string { return c.TLSCertificatePath }, "/tls/server.crt"},
		{"tls_private_key_path", "{" + tlsTriple + "}",
			func(c Config) string { return c.TLSPrivateKeyPath }, "/tls/server.key"},
		{"tls_client_ca_path", "{" + tlsTriple + "}",
			func(c Config) string { return c.TLSClientCAPath }, "/tls/clients.pem"},

		{"issuer_certificate_path", "{" + issuerTriple + "}",
			func(c Config) string { return c.IssuerCertificatePath }, "/pki/ca.crt"},
		{"issuer_dns_suffixes", "{" + issuerTriple + "}",
			func(c Config) string { return strings.Join(c.IssuerDNSSuffixes, ",") }, "staging.internal,svc.internal"},
		{"issuer_validity", "{" + issuerTriple + "}",
			func(c Config) string { return c.IssuerValidity.String() }, "2160h0m0s"},

		{"pkcs11_module_path", hardwareDocument,
			func(c Config) string { return c.PKCS11ModulePath }, "/usr/lib/opensc-pkcs11.so"},
		{"yubikey_devices", yubikeyDocument,
			func(c Config) string { return c.YubiKeyDevices["yubi-a"] }, "25923905"},
		{"pin_paths", hardwareDocument,
			func(c Config) string { return c.PINPaths["hsm-sitea"] }, "/run/credentials/regalia-kms.service/hsm-sitea.pin"},
		{"secure_channel_evidence_path", hardwareDocument,
			func(c Config) string { return c.SecureChannelEvidence }, "/etc/regalia/secure-channel.json"},
		{"audit_journal_path", hardwareDocument,
			func(c Config) string { return c.AuditJournalPath }, "/var/lib/regalia/audit.jsonl"},
		{"audit_sink_url", `{"audit_sink_url":"https://audit.internal"}`,
			func(c Config) string { return c.AuditSinkURL }, "https://audit.internal"},

		{"fencing_lease_path", fencingDocument,
			func(c Config) string { return c.FencingLeasePath }, "/run/regalia/lease.json"},
		{"fencing_state_path", fencingDocument,
			func(c Config) string { return c.FencingStatePath }, "/var/lib/regalia/epochs.jsonl"},
		{"fencing_public_key_path", fencingDocument,
			func(c Config) string { return c.FencingPublicKeyPath }, "/etc/regalia/fencing.pub"},

		// A SURVIVOR. Dropped, the provenance check at startup has no record to verify.
		{"commissioning_record_path", `{"commissioning_record_path":"/etc/regalia/commissioning.json"}`,
			func(c Config) string { return c.CommissioningRecordPath }, "/etc/regalia/commissioning.json"},

		// A SURVIVOR, and the one that fails open. Dropped, NewRevocationList gets "" and
		// returns a no-op list whose Check answers (false, nil) without reading anything:
		// every revoked serial is accepted, and the operator's file is never opened.
		{"revoked_serials_path", `{"revoked_serials_path":"/etc/regalia/revoked-serials.txt"}`,
			func(c Config) string { return c.RevokedSerialsPath }, "/etc/regalia/revoked-serials.txt"},

		{"metrics_reader_principals", `{"metrics_reader_principals":["spiffe://regalia/operator/monitoring"]}`,
			func(c Config) string { return strings.Join(c.MetricsReaderPrincipals, ",") }, "spiffe://regalia/operator/monitoring"},
	}
}

// EVERY FIELD AN OPERATOR CAN WRITE MUST REACH THE CONFIGURATION. One document per field,
// carrying the minimum that lets it validate, so a guard that discards that field is the
// only thing that can fail the row.
func TestEveryDocumentFieldReachesTheConfiguration(t *testing.T) {
	defaults := Default()
	for _, row := range documentFieldRows() {
		t.Run(row.field, func(t *testing.T) {
			// THE ROW MUST BE ABLE TO FAIL. If the wanted value is what Default() already
			// produces, the row passes whether or not the document was read at all -- which
			// is the exact defect this file exists to catch, reintroduced in the test.
			if row.got(defaults) == row.want {
				t.Fatalf("%s wants %q, which is already the default: this row cannot detect a dropped field",
					row.field, row.want)
			}
			settings, err := Decode(strings.NewReader(row.document))
			if err != nil {
				t.Fatalf("the minimal document for %s was refused: %v\ndocument: %s", row.field, err, row.document)
			}
			if got := row.got(settings); got != row.want {
				t.Fatalf("%s did not reach the configuration: got %q, want %q — the operator's value was discarded and the default silently stands",
					row.field, got, row.want)
			}
		})
	}
}

// A FIELD WITH NO ROW IS A FIELD NOTHING PINS. The table above is only a gate while it is
// complete, and completeness is a property of the document type rather than of this file,
// so it is derived from the type instead of counted by hand.
func TestEveryDocumentFieldHasARow(t *testing.T) {
	covered := map[string]bool{}
	for _, row := range documentFieldRows() {
		if covered[row.field] {
			t.Fatalf("two rows both claim to pin %q", row.field)
		}
		covered[row.field] = true
	}
	documentType := reflect.TypeOf(document{})
	for i := 0; i < documentType.NumField(); i++ {
		tag := strings.Split(documentType.Field(i).Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			t.Fatalf("document field %s has no json tag", documentType.Field(i).Name)
		}
		if !covered[tag] {
			t.Fatalf("document carries %q but no row pins it: a field with no row can be dropped by Decode and every test still passes", tag)
		}
		delete(covered, tag)
	}
	for stale := range covered {
		t.Fatalf("a row pins %q, which is not a field of the document", stale)
	}
}

// THE localhost EXEMPTION, IN THE DIRECTION A SWEEP IS WORST AT.
//
// Validate() skips the non-loopback rule entirely when the host is the literal string
// "localhost", because net.ParseIP("localhost") is nil and a nil IP is not loopback -- so
// without that exemption the hostname would be treated as routable. Neutralising the
// exemption (forcing the branch to run for every host) was NOT detected: every negative
// test stayed green, because making a guard stricter never breaks a test that asserts a
// refusal.
//
// Measured with the exemption removed: `localhost:8443` with no TLS is refused with
// "listen_address is non-loopback: mutual TLS must be configured" -- the daemon declines to
// start on a correct loopback configuration and the error blames the operator's address.
// The negative row keeps the exemption narrow: it must free the loopback NAME, not any name.
func TestALoopbackHostnameIsPermittedWithoutMutualTLS(t *testing.T) {
	permitted := baseConfig()
	permitted.ListenAddress = "localhost:8443"
	if err := permitted.Validate(); err != nil {
		t.Fatalf("localhost:8443 without TLS was refused: %v — localhost is loopback, so a daemon that refuses it will not start on a configuration the operator wrote correctly", err)
	}

	// The exemption must be exactly "localhost" and not "any name that fails to parse as an
	// IP": a routable hostname still has to authenticate its callers.
	routable := baseConfig()
	routable.ListenAddress = "kms.internal:8443"
	err := routable.Validate()
	if err == nil {
		t.Fatal("kms.internal:8443 was accepted without mutual TLS — a hostname that is not loopback is reachable by anything that can route to it")
	}
	if !strings.Contains(err.Error(), "mutual TLS") {
		t.Fatalf("refused by the wrong rule: %v", err)
	}
}

// A MALFORMED DURATION MUST NAME ITSELF. Each of these three fields parses with
// time.ParseDuration, which has no day unit -- "90d" is the mistake an operator actually
// makes -- and returns 0 alongside its error.
//
// That zero is why the message matters rather than merely the refusal. For the two timeouts
// the range check refuses 0 anyway, so dropping the parse-error guard still produces AN
// error, just one that reports the value as out of range instead of unparseable. For
// issuer_validity there is no such backstop: with the guard dropped the field counts as
// unset, the all-or-nothing issuer rule sees zero configured fields, and the document is
// ACCEPTED with the operator's issuer_validity silently discarded.
func TestAMalformedDurationIsRefusedByTheFieldThatFailedToParse(t *testing.T) {
	for _, row := range []struct{ field, document string }{
		{"issuer_validity", `{"issuer_validity":"90d"}`},
		{"operation_timeout", `{"operation_timeout":"90d"}`},
		{"shutdown_timeout", `{"shutdown_timeout":"90d"}`},
	} {
		t.Run(row.field, func(t *testing.T) {
			_, err := Decode(strings.NewReader(row.document))
			if err == nil {
				t.Fatalf("%s of \"90d\" was accepted: time.ParseDuration has no day unit, so the value was discarded and a default silently stands", row.field)
			}
			want := "invalid " + row.field
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("refused, but not as an unparseable %s: %v — want a message containing %q, so the operator is told the value could not be parsed rather than that it is out of range",
					row.field, err, want)
			}
		})
	}
}

// TRAILING DATA: THE DIAGNOSTIC MUST SAY WHICH KIND. requireEndOfJSON distinguishes a
// SECOND well-formed value from bytes that are not JSON at all, and the two get different
// messages. Neither direction of that branch was detected, because both produce an error
// and the existing test only asks whether one was returned.
//
// The second row is the more useful of the two: with the branch forced the other way, a
// document followed by junk reports "more than one JSON value", which sends the operator
// looking for a second document that does not exist.
func TestTrailingDataIsDiagnosedByWhatFollowsTheDocument(t *testing.T) {
	const valid = `{"listen_address":"127.0.0.1:8443"}`
	for _, row := range []struct{ name, document, want string }{
		{"a second JSON value", valid + " {}", "more than one JSON value"},
		{"bytes that are not JSON", valid + " @@@", "decode trailing configuration data"},
	} {
		t.Run(row.name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(row.document))
			if err == nil {
				t.Fatalf("a document followed by %s was accepted", row.name)
			}
			if !strings.Contains(err.Error(), row.want) {
				t.Fatalf("the message does not name what was found: %v — want %q", err, row.want)
			}
		})
	}
}

// truncatedReader yields one complete-looking document and then fails, the way a short read
// from a file or socket does.
type truncatedReader struct {
	payload []byte
	served  bool
}

func (r *truncatedReader) Read(p []byte) (int, error) {
	if r.served {
		return 0, errors.New("simulated I/O failure part-way through the configuration")
	}
	r.served = true
	return copy(p, r.payload), nil
}

// A READ THAT FAILED IS NOT A DOCUMENT. io.ReadAll returns whatever it managed to read
// ALONGSIDE the error, so ignoring that error hands the decoder a truncated document. The
// payload here is deliberately one that parses and validates cleanly on its own: if the read
// error is dropped, Decode succeeds and every field the operator wrote past the truncation
// point silently takes its default.
func TestAFailedReadIsNeverTreatedAsACompleteDocument(t *testing.T) {
	reader := &truncatedReader{payload: []byte(`{"audit_sink_url":"https://audit.internal"}`)}
	_, err := Decode(reader)
	if err == nil {
		t.Fatal("a configuration whose read failed was accepted: the bytes that did arrive parsed, so every later field silently took its default")
	}
	if !strings.Contains(err.Error(), "read configuration") {
		t.Fatalf("refused, but not as a failed read: %v", err)
	}

	// KNOWN-GOOD (§18): the same payload read completely IS accepted, so the row above is
	// about the read failing and not about the document being unacceptable.
	if _, err := Decode(strings.NewReader(`{"audit_sink_url":"https://audit.internal"}`)); err != nil {
		t.Fatalf("the same document read in full was refused: %v", err)
	}
}

// LOAD MUST NAME THE FILE IT COULD NOT OPEN. os.Open returns a nil *os.File with its error,
// and a nil file's Stat() answers ErrInvalid -- so dropping the open-error guard still
// produces an error, but it reports "stat configuration: invalid argument" for a file that
// simply is not there. A missing configuration is the most common startup failure there is,
// and that message sends the operator after a permissions or filesystem problem instead.
func TestLoadNamesTheFileItCouldNotOpen(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "there-is-no-such-file.json")
	_, err := Load(missing)
	if err == nil {
		t.Fatal("Load accepted a path that does not exist")
	}
	if !strings.Contains(err.Error(), "open configuration") {
		t.Fatalf("refused, but not as a failure to open: %v — want the message to name the open, so a missing file does not read as a stat failure", err)
	}
}

// A guard on the shape of the file itself: Load must still accept a well-formed one. Without
// this, every refusal above would be satisfied by a Load that refuses everything.
func TestLoadAcceptsAWellFormedConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	// 0600: Load refuses anything group- or world-writable, so a laxer mode here would be
	// refused by that rule instead and this row would never reach the parse at all.
	if err := os.WriteFile(path, []byte(`{"listen_address":"127.0.0.1:8443","operation_timeout":"30s"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, err := Load(path)
	if err != nil {
		t.Fatalf("a well-formed configuration was refused: %v", err)
	}
	if settings.OperationTimeout != 30*time.Second {
		t.Fatalf("OperationTimeout = %s, want 30s", settings.OperationTimeout)
	}
}
