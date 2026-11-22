package audit

import (
	"strings"
	"testing"
)

const (
	descriptorGeneration = "0123456789abcdef0123456789abcdef"
	fixturePublicRoot    = "/var/lib/regalia-etc/regalia/collector-v1/generations/" + descriptorGeneration + "/public"
	fixtureDaemonRoot    = "/var/lib/regalia-etc/regalia-kms/collector-v1/" + descriptorGeneration
	fixtureShipperRoot   = "/var/lib/regalia-etc/regalia/collector-v1/generations/" + descriptorGeneration + "/shipper"
	collectorFixture     = `{
		"schema":"regalia.collector-config/v1","node_id":"node-1","site":"Site.a","generation":"` + descriptorGeneration + `",
		"origin":"https://collector.invalid/","ca_path":"` + fixturePublicRoot + `/absent/ca.pem","receipt_keys_path":"` + fixturePublicRoot + `/receipts",
		"daemon":{"certificate_path":"` + fixtureDaemonRoot + `/daemon.crt","private_key_path":"` + fixtureDaemonRoot + `/daemon.key"},
		"node_shipper":{"certificate_path":"` + fixtureShipperRoot + `/ship.crt","private_key_path":"` + fixtureShipperRoot + `/ship.key"}
	}`
)

func replaceDescriptor(t *testing.T, from, to string) string {
	t.Helper()
	if strings.Count(collectorFixture, from) != 1 {
		t.Fatal("fixture change must have exactly one source occurrence")
	}
	return strings.Replace(collectorFixture, from, to, 1)
}

func loadDescriptor(t *testing.T, data string) CollectorDescriptor {
	t.Helper()
	got, err := DecodeCollectorDescriptor([]byte(data))
	if err != nil {
		t.Fatalf("valid descriptor rejected: %v", err)
	}
	return got
}

func refuseDescriptor(t *testing.T, data string, want CollectorDescriptorError) {
	t.Helper()
	got, err := DecodeCollectorDescriptor([]byte(data))
	if err != want || got != (CollectorDescriptor{}) {
		t.Fatalf("descriptor refusal = (%T, %v), want fixed error %q and zero descriptor", err, err, want)
	}
}

func TestCollectorDescriptorMapsBothRolesWithoutFiles(t *testing.T) {
	got := loadDescriptor(t, collectorFixture)
	if got.NodeID() != "node-1" || got.Site() != "Site.a" || got.Generation() != descriptorGeneration {
		t.Fatal("decoded descriptor lost node, site or generation")
	}
	for _, tc := range []struct {
		role      CollectorRole
		cert, key string
	}{
		{CollectorRoleDaemon, fixtureDaemonRoot + "/daemon.crt", fixtureDaemonRoot + "/daemon.key"},
		{CollectorRoleNodeShipper, fixtureShipperRoot + "/ship.crt", fixtureShipperRoot + "/ship.key"},
	} {
		t.Run(string(tc.role), func(t *testing.T) {
			want := CollectorEndpointOptions{
				Collector: "https://collector.invalid/", Site: "Site.a", CertificatePath: tc.cert, PrivateKeyPath: tc.key,
				CAPath: fixturePublicRoot + "/absent/ca.pem", ReceiptKeysPath: fixturePublicRoot + "/receipts",
			}
			opts, err := got.EndpointOptions(tc.role)
			if err != nil || opts != want {
				t.Fatalf("selected role did not receive its own pair and the common endpoint: %v", err)
			}
		})
	}

	opts, err := got.EndpointOptions(CollectorRole("unknown"))
	if err != ErrCollectorDescriptorRole || opts != (CollectorEndpointOptions{}) {
		t.Fatalf("unknown role mapped an endpoint: %v", err)
	}
	var zero CollectorDescriptor
	if _, err := zero.EndpointOptions(CollectorRoleDaemon); err != ErrCollectorDescriptorUninitialized {
		t.Fatalf("zero descriptor mapped an endpoint: %v", err)
	}
	if err := zero.ValidateStreams([]string{"sync"}); err != ErrCollectorDescriptorUninitialized {
		t.Fatalf("zero descriptor accepted a stream projection: %v", err)
	}
}

func TestCollectorDescriptorBoundsAndEncoding(t *testing.T) {
	const limit = 16 * 1024
	exact := collectorFixture + strings.Repeat(" ", limit-len(collectorFixture))
	loadDescriptor(t, exact)
	t.Run("oversize-whitespace", func(t *testing.T) {
		refuseDescriptor(t, exact+" ", ErrCollectorDescriptorFormat)
	})
	t.Run("invalid-utf8", func(t *testing.T) {
		data := replaceDescriptor(t, "/daemon.crt", "/daemon-\xff.crt")
		refuseDescriptor(t, data, ErrCollectorDescriptorFormat)
	})
	loadDescriptor(t, replaceDescriptor(t, "/daemon.crt", "/dæmon.crt"))
}

func TestCollectorDescriptorStrictJSON(t *testing.T) {
	loadDescriptor(t, collectorFixture)
	loadDescriptor(t, replaceDescriptor(t, `"node_id"`, `"node\u005fid"`))
	for _, tc := range []struct{ name, from, to string }{
		{"duplicate-root", `"node_id":"node-1"`, `"node_id":"node-1","node_id":"node-1"`},
		{"escaped-duplicate", `"node_id":"node-1"`, `"node_id":"node-1","node\u005fid":"node-1"`},
		{"duplicate-role-field", `"daemon":{"certificate_path":`, `"daemon":{"certificate\u005fpath":"old","certificate_path":`},
		{"duplicate-shipper-field", `"node_shipper":{"certificate_path":`, `"node_shipper":{"certificate_path":"old","certificate_path":`},
		{"unknown-root", `"node_id":`, `"secret":"marker","node_id":`},
		{"unknown-role", `"daemon":{"certificate_path":`, `"daemon":{"secret":"marker","certificate_path":`},
		{"wrong-case", `"node_id"`, `"Node_id"`},
		{"wrong-role-case", `"daemon":{"certificate_path":`, `"daemon":{"Certificate_path":`},
		{"missing-root", `"node_id":"node-1",`, ""},
		{"missing-role-field", `,"private_key_path":"` + fixtureDaemonRoot + `/daemon.key"`, ""},
		{"null-string", `"node_id":"node-1"`, `"node_id":null`},
		{"empty-string", `"node_id":"node-1"`, `"node_id":""`},
		{"numeric-string", `"node_id":"node-1"`, `"node_id":123`},
		{"boolean-string", `"node_id":"node-1"`, `"node_id":true`},
		{"array-string", `"node_id":"node-1"`, `"node_id":["node-1"]`},
		{"null-role", `{"certificate_path":"` + fixtureDaemonRoot + `/daemon.crt","private_key_path":"` + fixtureDaemonRoot + `/daemon.key"}`, "null"},
		{"array-role", `{"certificate_path":"` + fixtureDaemonRoot + `/daemon.crt","private_key_path":"` + fixtureDaemonRoot + `/daemon.key"}`, "[]"},
		{"trailing-object", "\n\t}", "\n\t} {}"},
		{"trailing-garbage", "\n\t}", "\n\t} x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refuseDescriptor(t, replaceDescriptor(t, tc.from, tc.to), ErrCollectorDescriptorFormat)
		})
	}
	for _, data := range []string{"null", "[]", "true", `"object"`, ""} {
		refuseDescriptor(t, data, ErrCollectorDescriptorFormat)
	}
}

func TestCollectorDescriptorIdentityAndSchema(t *testing.T) {
	loadDescriptor(t, replaceDescriptor(t, "node-1", "a"+strings.Repeat("b", 31)))
	for _, tc := range []struct {
		name, from, to string
		want           CollectorDescriptorError
	}{
		{"schema", "regalia.collector-config/v1", "regalia.collector-config/v2", ErrCollectorDescriptorSchema},
		{"uppercase-node", "node-1", "Node-1", ErrCollectorDescriptorIdentity},
		{"leading-hyphen", "node-1", "-node", ErrCollectorDescriptorIdentity},
		{"long-node", "node-1", strings.Repeat("n", 33), ErrCollectorDescriptorIdentity},
		{"site-grammar", "Site.a", "site/a", ErrCollectorDescriptorIdentity},
		{"site-c1-length", "Site.a", strings.Repeat("s", 63), ErrCollectorDescriptorIdentity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refuseDescriptor(t, replaceDescriptor(t, tc.from, tc.to), tc.want)
		})
	}
	for _, tc := range []struct{ name, generation string }{
		{"uppercase-generation", strings.ToUpper(descriptorGeneration)},
		{"short-generation", "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Keep every path under the candidate's generation to isolate the ID rule.
			refuseDescriptor(t, strings.ReplaceAll(collectorFixture, descriptorGeneration, tc.generation), ErrCollectorDescriptorIdentity)
		})
	}
}

func TestCollectorDescriptorOrigin(t *testing.T) {
	const original = "https://collector.invalid/"
	for _, origin := range []string{"https://collector.invalid", original, "https://[::1]:8443/"} {
		loadDescriptor(t, replaceDescriptor(t, original, origin))
	}
	for _, tc := range []struct{ name, origin string }{
		{"http", "http://collector.invalid"},
		{"empty-hostname", "https://:8443"},
		{"path", original + "path"},
		{"encoded-slash", original + "%2F"},
		{"encoded-single-slash", "https://collector.invalid%2f"},
		{"double-slash", original + "/"},
		{"empty-query", original + "?"},
		{"query", original + "?q=v"},
		{"empty-fragment", original + "#"},
		{"fragment", original + "#fragment"},
		{"userinfo", "https://person@collector.invalid"},
		{"parse-error", "https://[::1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refuseDescriptor(t, replaceDescriptor(t, original, tc.origin), ErrCollectorDescriptorOrigin)
		})
	}
	// Legacy C1 keeps accepting these URL spellings. The canonical checks are local to C2a.
	for _, origin := range []string{"https://:8443", original + "?", original + "#"} {
		if err := ValidateSinkURL(origin); err != nil {
			t.Fatal("canonical origin validation changed the legacy URL rule")
		}
	}
}

func TestCollectorDescriptorLexicalPaths(t *testing.T) {
	const ca = fixturePublicRoot + "/absent/ca.pem"
	const cert = fixtureDaemonRoot + "/daemon.crt"
	loadDescriptor(t, collectorFixture)
	for _, tc := range []struct{ name, from, to string }{
		{"prefix-collision", ca, fixturePublicRoot + "-other/ca.pem"},
		{"root-is-not-a-file", ca, fixturePublicRoot},
		{"relative", ca, strings.TrimPrefix(ca, "/")},
		{"traversal", ca, fixturePublicRoot + "/../else/ca.pem"},
		{"dot", ca, fixturePublicRoot + "/./ca.pem"},
		{"repeated-slash", ca, fixturePublicRoot + "//ca.pem"},
		{"trailing-slash", ca, ca + "/"},
		{"nul", ca, ca + `\u0000suffix`},
		{"wrong-generation", ca, strings.Replace(ca, descriptorGeneration, strings.Repeat("a", 32), 1)},
		{"wrong-role-root", cert, fixtureShipperRoot + "/daemon.crt"},
		{"shipper-outside-role-root", fixtureShipperRoot + "/ship.key", fixtureDaemonRoot + "/ship.key"},
		{"alias", cert, fixtureDaemonRoot + "/daemon.key"},
		{"shipper-alias", fixtureShipperRoot + "/ship.crt", fixtureShipperRoot + `/ship\u002ekey`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refuseDescriptor(t, replaceDescriptor(t, tc.from, tc.to), ErrCollectorDescriptorPath)
		})
	}
}

func TestCollectorDescriptorValidatesTrustedProjection(t *testing.T) {
	got := loadDescriptor(t, replaceDescriptor(t, "Site.a", strings.Repeat("s", 60)))
	if err := got.ValidateStreams([]string{"one", "two"}); err != nil {
		t.Fatalf("64-character streams rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		trails []string
	}{
		{"no-members", nil},
		{"empty-member", []string{"one", ""}},
		{"duplicate-member", []string{"one", "two", "one"}},
		{"invalid-stream-character", []string{"ok", "a/b"}},
		{"overlong-stream", []string{"ok", "four"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := got.ValidateStreams(tc.trails); err != ErrCollectorDescriptorStream {
				t.Fatalf("invalid stream projection accepted or wrong error: %v", err)
			}
		})
	}
}

func TestCollectorDescriptorErrorsDoNotEchoInput(t *testing.T) {
	const marker = "descriptor-private-input"
	for _, tc := range []struct {
		from, to string
		want     CollectorDescriptorError
	}{
		{`"node_id":`, `"` + marker + `":null,"node_id":`, ErrCollectorDescriptorFormat},
		{"https://collector.invalid/", "https://user:" + marker + "@collector.invalid", ErrCollectorDescriptorOrigin},
		{fixtureDaemonRoot + "/daemon.key", "/" + marker, ErrCollectorDescriptorPath},
		{"node-1", "!" + marker, ErrCollectorDescriptorIdentity},
	} {
		_, err := DecodeCollectorDescriptor([]byte(replaceDescriptor(t, tc.from, tc.to)))
		if err != tc.want || strings.Contains(err.Error(), marker) {
			t.Fatal("descriptor refusal did not return the fixed nonsecret error")
		}
	}
}
