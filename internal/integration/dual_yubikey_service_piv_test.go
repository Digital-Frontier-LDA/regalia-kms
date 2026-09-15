//go:build piv

package integration_test

// This is the service routing seam for the two physical-key qualification.  It
// deliberately uses the real PIV provider and registry rather than a fake
// driver: a route must select the commissioned serial, authenticate with the
// corresponding PIN, and fail over when that binding is revoked.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/yubikey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/pin"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

func TestTwoPhysicalYubiKeysServiceFailoverAndRevocation(t *testing.T) {
	serialA, serialB := os.Getenv("REGALIA_YK_SERIAL_A"), os.Getenv("REGALIA_YK_SERIAL_B")
	pinA, pinB := os.Getenv("REGALIA_YK_PIN_A"), os.Getenv("REGALIA_YK_PIN_B")
	if serialA == "" || serialB == "" || pinA == "" || pinB == "" {
		t.Skip("set both serials and separate PINs for physical service qualification")
	}
	if serialA == serialB {
		t.Fatal("physical service qualification requires distinct serials")
	}
	dir := t.TempDir()
	pathA, pathB := filepath.Join(dir, "a.pin"), filepath.Join(dir, "b.pin")
	if err := os.WriteFile(pathA, []byte(pinA), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathB, []byte(pinB), 0o600); err != nil {
		t.Fatal(err)
	}
	pins, err := pin.NewLockedFileSource(map[string]string{"site-a": pathA, "site-b": pathB})
	if err != nil {
		t.Fatal(err)
	}
	driver, err := yubikey.NewPIVDriver(map[string]string{"site-a": serialA, "site-b": serialB})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := yubikey.New(driver, pins)
	if err != nil {
		t.Fatal(err)
	}
	hardware, err := backend.New(map[string]backend.Provider{"yubikey-piv": provider})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	digest := sha256.Sum256([]byte("dual physical service failover"))
	// Route selection is tested independently from the readiness probe here. The
	// physical provider still verifies serial, slot policy and PIN at Execute;
	// the standalone qualification test covers the live probe path.
	first := loadPhysicalManifest(t, serialA, serialB, "active", "standby", alwaysHealthy{})
	route, err := first.Route(ctx, "dual-sign", "dual-purpose", "sign")
	if err != nil {
		t.Fatalf("active key route: %v", err)
	}
	if route.Binding.DeviceSerial != serialA {
		t.Fatalf("active route serial=%q want %q", route.Binding.DeviceSerial, serialA)
	}
	if signature, _, err := hardware.Execute(ctx, route, "sign", "", "application/octet-stream", digest[:], nil); err != nil || len(signature) == 0 {
		t.Fatalf("active key sign: len=%d err=%v", len(signature), err)
	}

	// Revoking A removes the only active route and must fail closed; it must not
	// silently use the standby key.  The rotated manifest then promotes B.
	revoked := loadPhysicalManifest(t, serialA, serialB, "revoked", "standby", alwaysHealthy{})
	if _, err := revoked.Route(ctx, "dual-sign", "dual-purpose", "sign"); !registry.IsCode(err, registry.CodeDependencyUnavailable) {
		t.Fatalf("revoked active binding route error=%v; expected dependency unavailable", err)
	}
	rotated := loadPhysicalManifest(t, serialA, serialB, "retired", "active", alwaysHealthy{})
	route, err = rotated.Route(ctx, "dual-sign", "dual-purpose", "sign")
	if err != nil {
		t.Fatalf("rotated standby route: %v", err)
	}
	if route.Binding.DeviceSerial != serialB {
		t.Fatalf("failover route serial=%q want %q", route.Binding.DeviceSerial, serialB)
	}
	if signature, _, err := hardware.Execute(ctx, route, "sign", "", "application/octet-stream", digest[:], nil); err != nil || len(signature) == 0 {
		t.Fatalf("failover key sign: len=%d err=%v", len(signature), err)
	}
}

type alwaysHealthy struct{}

func (alwaysHealthy) Healthy(context.Context, registry.Binding) bool { return true }

func loadPhysicalManifest(t *testing.T, serialA, serialB, stateA, stateB string, health registry.BackendHealth) *registry.Registry {
	t.Helper()
	fingerprint := func(serial string) string {
		h := sha256.Sum256([]byte(serial))
		return "sha256:" + hex.EncodeToString(h[:])
	}
	manifest := fmt.Sprintf(`{"schema_version":1,"manifest_id":"dual-physical","generated_at":"2026-09-04T12:00:00Z","objects":[{"id":"dual-sign","name":"dual sign","kind":"asymmetric-key","classification":"restricted","environment":"staging","owner":"security","purpose":"dual-purpose","custody":"direct-hardware","algorithm":"p256","operations":["sign"],"policy_id":"dual-policy","bindings":[{"site":"sitea","backend":"yubikey-piv","device_id":"site-a","device_serial":%q,"object_id":"9c","public_fingerprint":%q,"state":%q,"pin_policy":"once","touch_policy":"never"},{"site":"sitea","backend":"yubikey-piv","device_id":"site-b","device_serial":%q,"object_id":"9c","public_fingerprint":%q,"state":%q,"pin_policy":"once","touch_policy":"never"}],"recovery":{"mode":"shamir-2-of-2","status":"tested"},"rotation":{"maximum_age_days":365,"last_rotated":null},"migration":{"status":"migrated","source":"test"},"verification":{"status":"verified"}}]}`, serialA, fingerprint(serialA), stateA, serialB, fingerprint(serialB), stateB)
	r, err := registry.Load(bytes.NewBufferString(manifest), "sitea", health)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
