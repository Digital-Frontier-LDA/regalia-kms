//go:build piv

package integration_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/backend/yubikey"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/certs"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/policy"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
)

// PIV KEYS ANSWER THE SIGN OPERATION AS EVERY OTHER BACKEND DOES (regalia-kms#162).
//
// The PIV backend used to return ECDSA as ASN.1 DER and to accept a bare digest for RSA, where the
// contract is r||s and the PKCS #1 DigestInfo. regalia-sign and the certificate signer are written
// to the contract, so neither could use a PIV key. This runs both against real PIV keys:
//
//   - regalia-sign, the built executable, over mTLS, RBAC, purpose policy and audit, with GnuPG as
//     the judge, for each key type;
//   - certs.CardSigner, the signer certificate-sign uses, issuing a certificate that verifies.
//
// REGALIA_PIV_CONTRACT_SERIAL names the YubiKey and REGALIA_PIV_CONTRACT_PIN its PIV PIN.
// REGALIA_PIV_CONTRACT_SLOTS lists the slots to use as algorithm=slot pairs, for example
// "p256=9c,ed25519=84,rsa2048=85"; each key needs PIN policy once (or always) and touch never.
func TestPIVKeysServeRegaliaSignAndTheCertificateSigner(t *testing.T) {
	serial, pin, slots := os.Getenv("REGALIA_PIV_CONTRACT_SERIAL"), os.Getenv("REGALIA_PIV_CONTRACT_PIN"), os.Getenv("REGALIA_PIV_CONTRACT_SLOTS")
	if serial == "" || slots == "" {
		t.Skip("set REGALIA_PIV_CONTRACT_SERIAL, REGALIA_PIV_CONTRACT_PIN and REGALIA_PIV_CONTRACT_SLOTS (e.g. p256=9c,ed25519=84,rsa2048=85)")
	}
	if pin == "" {
		t.Fatal("REGALIA_PIV_CONTRACT_SERIAL is set but REGALIA_PIV_CONTRACT_PIN is not: the test cannot run")
	}
	gpg := requireGPG(t)
	binary := buildRegaliaSign(t)
	pki := newSidecarPKI(t)
	ctx := context.Background()

	driver, err := yubikey.NewPIVDriver(map[string]string{"yubikey-e2e": serial})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := yubikey.New(driver, pinSource{value: []byte(pin)})
	if err != nil {
		t.Fatal(err)
	}
	hardware, err := backend.New(map[string]backend.Provider{"yubikey-piv": provider})
	if err != nil {
		t.Fatal(err)
	}

	// The payload each key type is sent: a digest for ECDSA, a 32-byte digest as the message for
	// Ed25519, the DigestInfo of a SHA-256 digest for RSA.
	payloadBytes := map[string]int64{"p256": 32, "p384": 48, "ed25519": 32, "rsa2048": 51}
	type key struct{ algorithm, slot, objectID string }
	var keys []key
	var manifestObjects, granted []string
	var policies []policy.Policy
	for _, pair := range strings.Split(slots, ",") {
		algorithm, slot, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || payloadBytes[algorithm] == 0 {
			t.Fatalf("REGALIA_PIV_CONTRACT_SLOTS entry %q is not algorithm=slot for a key type this test knows", pair)
		}
		objectID := "release-piv-" + algorithm
		keys = append(keys, key{algorithm, slot, objectID})
		manifestObjects = append(manifestObjects, fmt.Sprintf(`{"id":%q,"name":"Release signing on PIV","kind":"asymmetric-key","classification":"restricted","environment":"development","owner":"security","purpose":"release-artifact","custody":"direct-hardware","algorithm":%q,"operations":["sign"],"policy_id":%q,"bindings":[{"site":"e2e-site","backend":"yubikey-piv","device_id":"yubikey-e2e","device_serial":%q,"object_id":%q,"public_fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"active","pin_policy":"once","touch_policy":"never"}],"recovery":{},"rotation":{},"migration":{},"verification":{"status":"verified"}}`,
			objectID, algorithm, objectID+"-policy", serial, slot))
		granted = append(granted, strconv.Quote(objectID))
		policies = append(policies, policy.Policy{
			ID: objectID + "-policy", ObjectID: objectID, Purpose: "release-artifact", Environment: "development",
			Operation: "sign", Algorithm: algorithm, ContentTypes: []string{"application/vnd.regalia.digest"},
			MaxPayloadBytes: payloadBytes[algorithm], MaxFuture: 2 * time.Minute,
		})
	}
	manifest := fmt.Sprintf(`{"schema_version":1,"manifest_id":"release-piv","generated_at":"2026-10-02T00:00:00Z","objects":[%s]}`, strings.Join(manifestObjects, ","))
	daemon := startYubiKeyReleaseDaemon(t, hardware, manifest, granted, policies, pki)

	for _, key := range keys {
		route := registry.Route{Algorithm: key.algorithm, Binding: registry.Binding{
			Backend: "yubikey-piv", DeviceID: "yubikey-e2e", DeviceSerial: serial, ObjectID: key.slot, State: "active", PINPolicy: "once", TouchPolicy: "never",
		}}
		publicDER, _, err := hardware.Execute(ctx, route, "public-key", "", "", nil, nil)
		if err != nil {
			t.Fatalf("%s: read the public key of PIV slot %s: %v", key.algorithm, key.slot, err)
		}
		public, err := x509.ParsePKIXPublicKey(publicDER)
		if err != nil {
			t.Fatal(err)
		}

		t.Run("regalia-sign/"+key.algorithm, func(t *testing.T) {
			deployment := t.TempDir()
			config := writeSignDeployment(t, deployment, signConfig{
				kmsURL: daemon.server.URL, serverName: "kms.e2e.internal", ca: pki.caPEM, certificate: pki.clientPEM, privateKey: pki.clientKeyPEM,
				objectID: key.objectID, purpose: "release-artifact", publicKey: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}),
			})
			fingerprint := strings.TrimSpace(regaliaSign(t, binary, config, "--fingerprint"))
			exported := regaliaSign(t, binary, config, "--export-key")
			home := importIntoThrowawayGnuPG(t, gpg, exported, fingerprint)
			sums := filepath.Join(deployment, "SHA256SUMS")
			if err := os.WriteFile(sums, []byte("9f2c…  regalia-kms_1.0.0_linux_amd64.tar.gz\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			regaliaSign(t, binary, config, "--detach", sums)
			// requireGPG found gpg on PATH, and that is the one this runs.
			output, err := exec.Command("gpg", "--homedir", home, "--batch", "--no-tty", "--status-fd", "1", "--verify", sums+".asc", sums).CombinedOutput()
			if err != nil || !strings.Contains(string(output), "[GNUPG:] VALIDSIG "+fingerprint) {
				t.Fatalf("GnuPG does not accept the signature made by the PIV %s key: %v\n%s", key.algorithm, err, output)
			}
		})

		if key.algorithm == "ed25519" || key.algorithm == "p384" {
			// certs.CardSigner signs certificates with SHA-256 and nothing else: an Ed25519 key is
			// not a CA key here, and a P-384 key would need SHA-384, which it refuses.
			continue
		}
		t.Run("certificate/"+key.algorithm, func(t *testing.T) {
			signer := &certs.CardSigner{PublicKey: public.(crypto.PublicKey), Sign_: func(payload []byte) ([]byte, error) {
				signature, _, err := hardware.Execute(ctx, route, "sign", "", "application/vnd.regalia.digest", payload, nil)
				return signature, err
			}}
			template := &x509.Certificate{
				SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "regalia-kms#162 PIV " + key.algorithm},
				NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
				IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
			}
			der, err := x509.CreateCertificate(rand.Reader, template, template, public, signer)
			if err != nil {
				t.Fatalf("a certificate could not be issued from the PIV %s key: %v", key.algorithm, err)
			}
			certificate, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if err := certificate.CheckSignatureFrom(certificate); err != nil {
				t.Fatalf("the certificate issued from the PIV %s key does not verify: %v", key.algorithm, err)
			}
		})
	}
}
