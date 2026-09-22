package nitrokey

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/miekg/pkcs11"
)

// qualNoSecureChannel is a no-op SecureChannel. The read-only qualification never establishes one:
// Fingerprint, PIN-retry and AssertKEKGeneratedOnToken (CKA_LOCAL on the public half, logged out)
// all read without secure messaging and without spending a PIN attempt.
type qualNoSecureChannel struct{}

func (qualNoSecureChannel) Establish(context.Context, string, string) error { return nil }

// TestNitrokeyHSM2Qualification measures, through the SAME probes and guards the daemon uses, the two
// open questions gating the production Nitrokey backend:
//
//   - #448: does the token expose its device-authentication certificate as a PKCS#11
//     CKO_CERTIFICATE? TokenProbes.Fingerprint hashes exactly one such object. On the staging Pico
//     through OpenSC it found none ("device certificate is not present"), so the daemon's identity
//     probe refuses the card before login. A genuine SmartCard-HSM (Nitrokey HSM 2) may expose it.
//   - #447: does a key GENERATED on the token report CKA_LOCAL true on its public half?
//     AssertKEKGeneratedOnToken reads that attribute logged out. On the Pico through OpenSC it was
//     false for every key, generated or imported, so the wrap guard refuses every KEK.
//
// It is READ-ONLY: no initialization, no key generation, no login, no PIN attempt spent. It is
// opt-in (skips without a module + serial), so ordinary CI never runs it.
//
// Env:
//
//	REGALIA_QUAL_MODULE   PKCS#11 module path (opensc-pkcs11.so for a real token; libsofthsm2.so for the control)
//	REGALIA_QUAL_SERIAL   the token serial to select
//	REGALIA_QUAL_GENERATED_ID  hex id of a key GENERATED on the token (optional; measured for #447)
//	REGALIA_QUAL_IMPORTED_ID   hex id of a key IMPORTED from a host (optional; must be refused)
//	REGALIA_QUAL_CONTROL=1     assert the SoftHSM-known outcomes instead of only recording them,
//	                          so this instrument is falsifiable on a token whose answers are known.
//
// The SoftHSM control (e2e/softhsm-pkcs11.sh shapes a matching token) proves the instrument
// reads what it claims: a SoftHSM-generated key reports local, an imported key does not, and there
// is no device certificate. Pointed at a Nitrokey, the same calls record the real answers.
func TestNitrokeyHSM2Qualification(t *testing.T) {
	modulePath := os.Getenv("REGALIA_QUAL_MODULE")
	serial := os.Getenv("REGALIA_QUAL_SERIAL")
	if modulePath == "" || serial == "" {
		t.Skip("set REGALIA_QUAL_MODULE and REGALIA_QUAL_SERIAL to qualify a token")
	}
	control := os.Getenv("REGALIA_QUAL_CONTROL") == "1"
	ctx := context.Background()

	module := pkcs11.New(modulePath)
	if module == nil {
		t.Fatal("PKCS#11 module could not be loaded")
	}
	if err := module.Initialize(); err != nil {
		t.Fatalf("PKCS#11 Initialize: %v", err)
	}
	t.Cleanup(func() { _ = module.Finalize(); module.Destroy() })

	probes, err := NewTokenProbes(module)
	if err != nil {
		t.Fatalf("NewTokenProbes: %v", err)
	}

	// #448 — device certificate as a PKCS#11 object.
	fingerprint, fpErr := probes.Fingerprint(ctx, "qual", serial)
	t.Logf("#448 device-certificate probe: fingerprint=%q err=%v", fingerprint, fpErr)
	certPresent := fpErr == nil && fingerprint != ""
	if control {
		// The SoftHSM control token carries no device certificate.
		if certPresent {
			t.Fatalf("control: SoftHSM reported a device certificate (%q); the control token has none", fingerprint)
		}
		// TYPED, not phrased. The caller that matters is the one deciding whether to fall back to
		// EF 2F02 — where an SC-HSM actually keeps its device certificate — and it cannot make
		// that decision on a substring. Pinning the wording also meant this assertion broke when
		// the error gained the explanation that tells an operator what to do about it.
		if !errors.Is(fpErr, ErrNoDeviceCertificate) {
			t.Fatalf("control: device-cert probe error = %v, want ErrNoDeviceCertificate", fpErr)
		}
	}

	// PIN retry health (read-only, from the token flags).
	if remaining, rErr := probes.Remaining(ctx, "qual", serial); rErr != nil {
		t.Logf("PIN retry probe: err=%v", rErr)
	} else {
		t.Logf("PIN retries remaining: %d", remaining)
	}

	// Build the driver from the SAME module (as NewPKCS11DriverWithProbes does), so the guard reads
	// the identical objects the daemon would.
	driver, err := newPKCS11Driver(module, probes, qualNoSecureChannel{}, probes)
	if err != nil {
		t.Fatalf("newPKCS11Driver: %v", err)
	}
	binding := registry.Binding{Backend: "nitrokey-pkcs11", DeviceID: "qual", DeviceSerial: serial}
	session, err := driver.Open(ctx, binding)
	if err != nil {
		t.Fatalf("open the token by serial %q: %v", serial, err)
	}
	t.Cleanup(func() { _ = session.Close() })

	classify := func(err error) string {
		switch {
		case err == nil:
			return "LOCAL (generated on token)"
		case errors.Is(err, ErrKEKNotTokenGenerated):
			return "NOT LOCAL (CKA_LOCAL present and false)"
		default:
			return "UNAVAILABLE (" + err.Error() + ")"
		}
	}

	// #447 — CKA_LOCAL on a key GENERATED on the token.
	if id := os.Getenv("REGALIA_QUAL_GENERATED_ID"); id != "" {
		gErr := session.AssertKEKGeneratedOnToken(ctx, id)
		t.Logf("#447 generated key %q: %s", id, classify(gErr))
		if control && gErr != nil {
			t.Fatalf("control: a SoftHSM-generated key was not reported LOCAL: %v", gErr)
		}
	} else if control {
		t.Fatal("control: set REGALIA_QUAL_GENERATED_ID to a SoftHSM-generated key id")
	}

	// A key IMPORTED from a host must be refused — the guard's whole purpose.
	if id := os.Getenv("REGALIA_QUAL_IMPORTED_ID"); id != "" {
		iErr := session.AssertKEKGeneratedOnToken(ctx, id)
		t.Logf("#447 imported key %q: %s", id, classify(iErr))
		if control && !errors.Is(iErr, ErrKEKNotTokenGenerated) {
			t.Fatalf("control: an IMPORTED key was not refused as non-local: %v", iErr)
		}
	} else if control {
		t.Fatal("control: set REGALIA_QUAL_IMPORTED_ID to a host-imported key id")
	}
}
