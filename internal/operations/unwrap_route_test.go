package operations

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/api"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/secrets"
)

// sealingWrapper produces envelopes for these tests. Its wrap is reversible and obviously not
// hardware; nothing here is testing cryptography, only which KEK generation the coordinator asks
// to be routed to.
type sealingWrapper struct{ backend string }

func (w *sealingWrapper) Backend() string { return w.backend }
func (w *sealingWrapper) WrapKey(_ context.Context, _ envelope.KeyRef, dataKey, _ []byte) ([]byte, error) {
	return append([]byte("wrapped:"), dataKey...), nil
}
func (w *sealingWrapper) UnwrapKey(_ context.Context, _ envelope.KeyRef, wrapped, _ []byte) ([]byte, error) {
	if !bytes.HasPrefix(wrapped, []byte("wrapped:")) {
		return nil, errors.New("not wrapped by this backend")
	}
	return bytes.TrimPrefix(wrapped, []byte("wrapped:")), nil
}

// envelopeNaming builds an encoded envelope whose KEK reference carries `version`.
func envelopeNaming(t *testing.T, version string) []byte {
	t.Helper()
	return envelopeAt(t, version, time.Now())
}

// envelopeAt is envelopeNaming with an explicit seal time, for the lifetime tests.
func envelopeAt(t *testing.T, version string, createdAt time.Time) []byte {
	t.Helper()
	wrapper := &sealingWrapper{backend: "nitrokey-pkcs11"}
	sealed, err := envelope.Seal(context.Background(), wrapper,
		envelope.KeyRef{Backend: "nitrokey-pkcs11", ID: "production-sops", Version: version},
		"production-sops", envelope.ReleaseContext("production-sops", "sops-data-key", "production"),
		[]byte("the secret"), rand.Reader, createdAt)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	encoded, err := sealed.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return encoded
}

func releaseRequest(data []byte) api.Request {
	request := operationRequest()
	request.Operation = "release-secret"
	request.Data = data
	return request
}

func releaseCoordinator(t *testing.T, router *fakeRouter, hardware *fakeHardware) *Coordinator {
	t.Helper()
	coordinator, err := New(fakeAuthorizer{allowed: true}, router,
		&fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}},
		&fakeAudit{}, directRunner{}, hardware, "sha256:policy", nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	return coordinator
}

// TestReleaseRoutesToTheKEKGenerationTheEnvelopeNames is the coordinator half of #84: the route is
// chosen from the envelope's own kek_version, not from whichever binding is active.
//
// The version is read off a REAL sealed envelope rather than asserted against a constant, so a
// coordinator that sent a hardcoded string would have to hardcode the same one this envelope was
// built with, and the two versions below make that impossible to do for both.
func TestReleaseRoutesToTheKEKGenerationTheEnvelopeNames(t *testing.T) {
	for _, version := range []string{"1", "7"} {
		router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "opaque", PolicyID: "sops", KEKAlgorithm: "rsa4096", KEKVersion: version, Binding: registry.Binding{DeviceID: "hsm-1"}}}
		coordinator := releaseCoordinator(t, router, &fakeHardware{output: []byte("the secret")})

		if _, err := coordinator.Execute(context.Background(), releaseRequest(envelopeNaming(t, version))); err != nil {
			t.Fatalf("Execute() error = %v", err)
		}
		if router.askedKEKVersion != version {
			t.Fatalf("coordinator asked to route KEK version %q for an envelope naming %q: release resolves the wrong generation, so a rotated object opens on whatever is active",
				router.askedKEKVersion, version)
		}
	}
}

// TestSealDoesNotRouteByEnvelopeVersion. Seal has no envelope to read a version from, and must
// keep taking the active/standby/qualified route.
func TestSealDoesNotRouteByEnvelopeVersion(t *testing.T) {
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "opaque", PolicyID: "sops", KEKAlgorithm: "rsa4096", KEKVersion: "2", Binding: registry.Binding{DeviceID: "hsm-1"}}}
	coordinator := releaseCoordinator(t, router, &fakeHardware{output: []byte("sealed")})

	request := operationRequest()
	request.Operation = "seal-envelope"
	request.Data = nil
	request.SealNonce = bytes.Repeat([]byte{1}, 12)
	request.SealCiphertext = []byte("ciphertext")
	request.SealDataKey = bytes.Repeat([]byte{2}, 32)
	_, _ = coordinator.Execute(context.Background(), request)

	if router.askedKEKVersion != "" {
		t.Fatalf("seal asked RouteForUnwrap for version %q: seal must not resolve by an envelope it is about to create", router.askedKEKVersion)
	}
}

// TestAMalformedEnvelopeIsARejectionNotADenial. Routing now parses caller bytes, so the parse
// failure has to keep its own identity: reported as DENIED it would send a caller with a corrupt
// envelope to an operator to widen a policy that was never the problem.
func TestAMalformedEnvelopeIsARejectionNotADenial(t *testing.T) {
	router := &fakeRouter{route: registry.Route{ObjectID: "production-sops", Purpose: "sops-data-key", Environment: "production", Algorithm: "opaque", PolicyID: "sops", KEKAlgorithm: "rsa4096", KEKVersion: "1", Binding: registry.Binding{DeviceID: "hsm-1"}}}
	hardware := &fakeHardware{output: []byte("never reached")}
	coordinator := releaseCoordinator(t, router, hardware)

	_, err := coordinator.Execute(context.Background(), releaseRequest([]byte("{not an envelope")))
	var failed *api.Failure
	if !errors.As(err, &failed) {
		t.Fatalf("Execute() error = %v, want a Failure", err)
	}
	if failed.Code != "INVALID_ARGUMENT" || failed.Status != http.StatusBadRequest {
		t.Fatalf("malformed envelope reported as %s/%d, want INVALID_ARGUMENT/400: a corrupt envelope is the caller's fault and retrying or widening policy cannot fix it",
			failed.Code, failed.Status)
	}
	if failed.Retryable {
		t.Fatal("malformed envelope reported as retryable: the same bytes will fail forever")
	}
	if hardware.calls != 0 {
		t.Fatalf("hardware called %d times for an unparseable envelope", hardware.calls)
	}
	if router.askedKEKVersion != "" {
		t.Fatalf("routing was attempted with version %q from bytes that do not parse", router.askedKEKVersion)
	}
}

// TestAnUnroutableGenerationIsDenied — the registry's refusal has to survive the coordinator, or a
// v1 envelope whose binding was deleted would surface as something retryable.
func TestAnUnroutableGenerationIsDenied(t *testing.T) {
	router := &fakeRouter{unwrapErr: &registry.Error{Code: registry.CodeDenied}}
	hardware := &fakeHardware{}
	coordinator := releaseCoordinator(t, router, hardware)

	_, err := coordinator.Execute(context.Background(), releaseRequest(envelopeNaming(t, "9")))
	var failed *api.Failure
	if !errors.As(err, &failed) || failed.Code != "DENIED" {
		t.Fatalf("Execute() error = %v, want DENIED for a generation no binding holds", err)
	}
	if hardware.calls != 0 {
		t.Fatalf("hardware called %d times after routing was denied", hardware.calls)
	}
}

// slotCard is a card that reverses sealingWrapper's wrap and records which physical slot it was
// asked to use. The slot is the point: a route carrying the right version but the wrong device
// would send an old envelope to the new card.
type slotCard struct {
	slots []string
}

func (c *slotCard) Execute(ctx context.Context, route registry.Route, operation, _, _ string, data, aad []byte) ([]byte, string, error) {
	if operation != "unwrap" {
		return []byte("passed-through"), "application/octet-stream", nil
	}
	c.slots = append(c.slots, route.Binding.ObjectID)
	key, err := (&sealingWrapper{backend: "nitrokey-pkcs11"}).UnwrapKey(ctx, envelope.KeyRef{}, data, aad)
	if err != nil {
		return nil, "", err
	}
	return key, "application/vnd.regalia.data-key", nil
}

const rotatedManifest = `{"schema_version":1,"manifest_id":"rotation","generated_at":"2026-09-05T00:00:00Z","objects":[{"id":"production-sops","name":"rotating","kind":"opaque-secret","classification":"restricted","environment":"production","owner":"security","purpose":"sops-data-key","custody":"hardware-envelope","algorithm":"opaque","operations":["seal-envelope","release-secret"],"policy_id":"sops","bindings":[%s],"recovery":{"mode":"shamir-4-of-6","authority_id":"root","minimum_replicas":2,"status":"tested"},"rotation":{"maximum_age_days":365,"last_rotated":null},"migration":{"status":"migrated","source":"test"},"verification":{"status":"verified"}}]}`

const retiredSlot1 = `{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"dev-1","object_id":"slot-1","public_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"retired","kek_algorithm":"rsa4096","kek_version":"1"}`
const activeSlot2 = `{"site":"sitea","backend":"nitrokey-pkcs11","device_id":"dev-2","object_id":"slot-2","public_fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"active","device_serial":"test-serial","devaut_fingerprint":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","kek_algorithm":"rsa4096","kek_version":"2"}`

// A production object may not be single-homed, so both cases below carry a second site. It is at
// siteb and RouteForUnwrap filters by the registry's own site, so it never competes for the
// routing decision — it is here to satisfy the two-binding rule and to keep the two cases
// differing in exactly one thing: whether the retired v1 binding exists.
const standbySiteB = `{"site":"siteb","backend":"nitrokey-pkcs11","device_id":"dev-9","object_id":"slot-9","public_fingerprint":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","state":"standby","device_serial":"siteb-serial","devaut_fingerprint":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","kek_algorithm":"rsa4096","kek_version":"2"}`

type allHealthy struct{}

func (allHealthy) Healthy(context.Context, registry.Binding) bool { return true }

// TestARotatedObjectStillOpensItsOldEnvelopes runs the whole path against a REAL registry and a
// REAL releaser — only the authorizer, policy, audit sink and card are doubles, and none of them
// decides which KEK is used. This is the acceptance criterion of #84 and of #6's "backup and
// restore work without depending on the original token": a v1 envelope, restored from a backup
// taken before the rotation, opens after v1 has retired and v2 serves.
//
// THE SECOND HALF IS WHAT MAKES THE FIRST MEAN ANYTHING. Delete the retired binding and the same
// release must fail. Without that, a green here is equally consistent with v1 still being active
// under another name.
func TestARotatedObjectStillOpensItsOldEnvelopes(t *testing.T) {
	oldEnvelope := envelopeNaming(t, "1")

	release := func(t *testing.T, bindings string) ([]byte, []string, error) {
		t.Helper()
		reg, err := registry.Load(strings.NewReader(fmt.Sprintf(rotatedManifest, bindings)), "sitea", allHealthy{})
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		card := &slotCard{}
		releaser, err := secrets.NewReleaser(card)
		if err != nil {
			t.Fatal(err)
		}
		coordinator, err := New(fakeAuthorizer{allowed: true}, reg,
			&fakePolicy{decision: policy.Decision{Allowed: true, Code: policy.CodeAllowed, PolicyID: "sops", Rule: "allow"}},
			&fakeAudit{}, directRunner{}, releaser, "sha256:policy", nil, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		result, err := coordinator.Execute(context.Background(), releaseRequest(oldEnvelope))
		return result.Data, card.slots, err
	}

	t.Run("the retired KEK still opens what it sealed", func(t *testing.T) {
		data, slots, err := release(t, retiredSlot1+","+activeSlot2+","+standbySiteB)
		if err != nil {
			t.Fatalf("a v1 envelope failed to open after v1 retired: %v — this is the rotation destroying data", err)
		}
		if string(data) != "the secret" {
			t.Fatalf("released %q, want the sealed plaintext", data)
		}
		if len(slots) != 1 || slots[0] != "slot-1" {
			t.Fatalf("the card was asked for slots %v, want exactly [slot-1]: the v1 envelope must reach v1's slot, not whichever one is active", slots)
		}
	})

	t.Run("and nothing else does", func(t *testing.T) {
		_, slots, err := release(t, activeSlot2+","+standbySiteB)
		if err == nil {
			t.Fatalf("a v1 envelope opened with no v1 binding in the manifest (card slots %v): the release path is not resolving by generation at all", slots)
		}
		var failed *api.Failure
		if !errors.As(err, &failed) || failed.Code != "DENIED" {
			t.Fatalf("error = %v, want DENIED", err)
		}
		if len(slots) != 0 {
			t.Fatalf("the card was reached at slots %v for an unroutable generation", slots)
		}
	})
}
