package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/nitrokey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// mechanismToken answers OffersMechanism from a table and is otherwise a session nothing uses.
type mechanismToken struct {
	missing    map[string]bool // "operation/algorithm" the token does not offer
	unreadable bool
	asked      []string
	closed     int
}

func (token *mechanismToken) OffersMechanism(_ context.Context, operation, algorithm string) error {
	token.asked = append(token.asked, operation+"/"+algorithm)
	if token.unreadable {
		return errors.New("mechanism list unavailable")
	}
	if token.missing[operation+"/"+algorithm] {
		return nitrokey.ErrMechanismNotOffered
	}
	return nil
}
func (token *mechanismToken) Close() error { token.closed++; return nil }

var errNotUsed = errors.New("not used by the mechanism check")

func (*mechanismToken) Identity(context.Context) (string, string, error)  { return "", "", errNotUsed }
func (*mechanismToken) EstablishSecureChannel(context.Context) error      { return errNotUsed }
func (*mechanismToken) PINRetries(context.Context) (int, error)           { return 0, errNotUsed }
func (*mechanismToken) Login(context.Context, []byte) error               { return errNotUsed }
func (*mechanismToken) PublicKey(context.Context, string) ([]byte, error) { return nil, errNotUsed }
func (*mechanismToken) Sign(context.Context, string, string, []byte) ([]byte, error) {
	return nil, errNotUsed
}
func (*mechanismToken) Wrap(context.Context, string, string, []byte, []byte) ([]byte, error) {
	return nil, errNotUsed
}
func (*mechanismToken) Unwrap(context.Context, string, string, []byte, []byte) ([]byte, error) {
	return nil, errNotUsed
}
func (*mechanismToken) Derive(context.Context, string, string, []byte) ([]byte, error) {
	return nil, errNotUsed
}
func (*mechanismToken) AssertKEKGeneratedOnToken(context.Context, string) error { return errNotUsed }
func (*mechanismToken) AssertKEKNonExportable(context.Context, string) error    { return errNotUsed }

// mechanismTokens opens the one token, or reports it absent.
type mechanismTokens struct {
	token  *mechanismToken
	absent bool
	// sessionWithError makes Open return the session together with its error.
	sessionWithError bool
	opened           []registry.Binding
}

func (tokens *mechanismTokens) Open(_ context.Context, binding registry.Binding) (nitrokey.Session, error) {
	tokens.opened = append(tokens.opened, binding)
	if tokens.absent {
		if tokens.sessionWithError {
			return tokens.token, errors.New("commissioned PKCS#11 device is unavailable")
		}
		return nil, errors.New("commissioned PKCS#11 device is unavailable")
	}
	return tokens.token, nil
}

// hsmRegistry loads a manifest of objects routed to one SmartCard-HSM. Each object is
// "id algorithm kek-algorithm operations...", kek-algorithm "-" for none.
func hsmRegistry(t *testing.T, objects ...string) *registry.Registry {
	t.Helper()
	return hsmRegistryFor(t, "DENK0000001", objects...)
}

func hsmRegistryFor(t *testing.T, serial string, objects ...string) *registry.Registry {
	t.Helper()
	var encoded []string
	for index, object := range objects {
		fields := strings.Fields(object)
		kek := ""
		if fields[2] != "-" {
			kek = fmt.Sprintf(`"kek_algorithm":%q,"kek_version":"1",`, fields[2])
		}
		encoded = append(encoded, fmt.Sprintf(`{"id":%q,"name":"Mechanism check","kind":"asymmetric-key","classification":"restricted","environment":"staging",
		  "owner":"security","purpose":"mechanism-check","custody":"direct-hardware","algorithm":%q,"operations":["%s"],"policy_id":%q,
		  "bindings":[{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"hsm-sitea","device_serial":%q,"object_id":"%02x",%s
		    "devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		    "public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"active"}],
		  "recovery":{"mode":"none","authority_id":"none","minimum_replicas":1,"status":"planned"},
		  "rotation":{"maximum_age_days":365,"last_rotated":null},
		  "migration":{"status":"planned","source":"new"},
		  "verification":{"status":"planned","last_verified":null,"evidence":"issue:541"}}`,
			fields[0], fields[1], strings.Join(fields[3:], `","`), fields[0]+"-policy", serial, index+1, kek))
	}
	manifest := `{"schema_version":1,"manifest_id":"mechanisms","generated_at":"2026-10-02T00:00:00Z","objects":[` + strings.Join(encoded, ",") + `]}`
	loaded, err := registry.Load(strings.NewReader(manifest), "sitea", nil)
	if err != nil {
		t.Fatalf("the fixture manifest does not load, so this test would check nothing: %v", err)
	}
	if routed := loaded.RoutedTo("nitrokey-pkcs11"); len(routed) != len(objects) {
		t.Fatalf("the fixture routes %d objects, want %d", len(routed), len(objects))
	}
	return loaded
}

// A KEY BOUND TO A TOKEN THAT CANNOT DO IT IS NAMED AT STARTUP (regalia#541).
func TestObjectsATokenCannotServeAreRefusedAtStartupByName(t *testing.T) {
	ctx := context.Background()
	loaded := hsmRegistry(t,
		"release-ed25519 ed25519 - sign",
		"issuing-ca p384 - sign certificate-sign key-agreement",
		"deploy-token opaque aes-256 release-secret",
		"wallet secp256k1 - sign",
	)
	// What a SmartCard-HSM does not offer, as measured: EdDSA and AES.
	hsm := &mechanismTokens{token: &mechanismToken{missing: map[string]bool{"sign/ed25519": true, "unwrap/aes-256": true}}}
	unchecked, err := requireTokensOfferBoundMechanisms(ctx, hsm, loaded)
	if err == nil {
		t.Fatal("a registry binding ed25519 and an aes-256 KEK to a SmartCard-HSM was accepted")
	}
	if len(unchecked) != 0 {
		t.Fatalf("a token that answered every question is reported unchecked: %v", unchecked)
	}
	for _, want := range []string{"release-ed25519 declares sign on a ed25519 key", "deploy-token declares release-secret on a aes-256 key", "DENK0000001"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
	for _, innocent := range []string{"issuing-ca", "wallet"} {
		if strings.Contains(err.Error(), innocent) {
			t.Errorf("the refusal names %s, which the token can serve: %v", innocent, err)
		}
	}
	// Each declared operation was asked about as the provider would send it: a certificate is a
	// signature, and a release is an unwrap on the KEK the binding names.
	asked := strings.Join(hsm.token.asked, " ")
	for _, want := range []string{"sign/ed25519", "sign/p384", "key-agreement/p384", "unwrap/aes-256", "sign/secp256k1"} {
		if !strings.Contains(asked, want) {
			t.Errorf("the token was not asked about %s (asked: %s)", want, asked)
		}
	}
	if strings.Contains(asked, "certificate-sign") || strings.Contains(asked, "release-secret") {
		t.Errorf("the token was asked about an operation name it never receives: %s", asked)
	}
	// Four objects on one token are one session, closed once.
	if len(hsm.opened) != 1 || hsm.token.closed != 1 {
		t.Fatalf("opened %d sessions and closed %d, want 1 and 1", len(hsm.opened), hsm.token.closed)
	}

	// A certificate needs the CA key's signing mechanism, under the name the manifest uses.
	noECDSA := &mechanismTokens{token: &mechanismToken{missing: map[string]bool{"sign/p384": true}}}
	if _, err := requireTokensOfferBoundMechanisms(ctx, noECDSA, hsmRegistry(t, "issuing-ca p384 - certificate-sign")); err == nil || !strings.Contains(err.Error(), "issuing-ca declares certificate-sign on a p384 key") {
		t.Fatalf("a CA key the token cannot sign with: %v", err)
	}

	// The control: a token that offers everything refuses nothing.
	if unchecked, err := requireTokensOfferBoundMechanisms(ctx, &mechanismTokens{token: &mechanismToken{}}, loaded); err != nil || len(unchecked) != 0 {
		t.Fatalf("a token offering every mechanism: err=%v unchecked=%v", err, unchecked)
	}
}

// Only a definite "no" stops the daemon. An absent token, or a list that cannot be read, must not:
// that would turn a pulled token into an outage that outlives the token's return. But it is
// reported as unchecked, so that "checked and fine" and "not checked" do not look the same.
func TestAnAbsentOrUnreadableTokenDoesNotStopTheDaemonAndIsReportedUnchecked(t *testing.T) {
	loaded := hsmRegistry(t, "release-ed25519 ed25519 - sign", "wallet secp256k1 - sign")
	absent := &mechanismTokens{absent: true}
	unchecked, err := requireTokensOfferBoundMechanisms(context.Background(), absent, loaded)
	if err != nil || len(unchecked) != 1 || unchecked[0] != "DENK0000001" {
		t.Fatalf("an absent token: err=%v unchecked=%v, want no error and the token named once", err, unchecked)
	}
	if len(absent.opened) != 1 {
		t.Fatalf("the absent token was tried %d times, want 1", len(absent.opened))
	}
	unreadable := &mechanismTokens{token: &mechanismToken{unreadable: true}}
	unchecked, err = requireTokensOfferBoundMechanisms(context.Background(), unreadable, loaded)
	if err != nil || len(unchecked) != 1 || unchecked[0] != "DENK0000001" {
		t.Fatalf("an unreadable mechanism list: err=%v unchecked=%v, want no error and the token named once", err, unchecked)
	}
	if len(unreadable.token.asked) != 2 || unreadable.token.closed != 1 {
		t.Fatalf("asked %v, closed %d: the token was not asked, or its session was left open", unreadable.token.asked, unreadable.token.closed)
	}
	// A driver that hands back a session together with an error: the session is closed, and the
	// token is unchecked, not used.
	stray := &mechanismTokens{token: &mechanismToken{}, absent: true, sessionWithError: true}
	unchecked, err = requireTokensOfferBoundMechanisms(context.Background(), stray, loaded)
	if err != nil || len(unchecked) != 1 || stray.token.closed != 1 || len(stray.token.asked) != 0 {
		t.Fatalf("a session returned with an error: err=%v unchecked=%v closed=%d asked=%v", err, unchecked, stray.token.closed, stray.token.asked)
	}
	if unchecked, err := requireTokensOfferBoundMechanisms(context.Background(), absent, nil); err != nil || len(unchecked) != 0 {
		t.Fatalf("an empty registry: err=%v unchecked=%v", err, unchecked)
	}
}

func (*mechanismToken) Reader(context.Context) (string, bool, error) { return "", false, nil }
