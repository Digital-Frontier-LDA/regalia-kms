package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeIdentity emits ONE self-signed certificate and writes it to both the certificate path and
// the CA path, plus its key. It is not a real chain — the leaf is its own issuer — and that is
// enough here because these tests are about file modes, missing files and mismatched keypairs, not
// about verification. Said plainly so nobody edits ca.crt expecting a different certificate.
//
// Modes are what an operator would deploy: the key owner-only, the certificate and CA readable.
func writeIdentity(t *testing.T, dir string) (certPath, keyPath, caPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "sops-adapter"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	caPath = filepath.Join(dir, "ca.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for path, blob := range map[string][]byte{
		certPath: certPEM,
		caPath:   certPEM,
		keyPath:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	} {
		if err := os.WriteFile(path, blob, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The certificate and CA are public; only the key needs to be unreadable by others. Set
	// explicitly so the asymmetry below is exercised rather than assumed from the umask.
	for _, path := range []string{certPath, caPath} {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, caPath
}

// TestASecretIsHeldToATighterModeThanAPublicFile is the whole point of readProtected's `secret`
// flag, and the existing test shows only the strict half. A private key readable by the group is
// refused; a certificate readable by everyone is fine, because it is public and refusing it would
// make the adapter unable to load an ordinary deployment.
//
// Both directions matter: the strict rule alone could be satisfied by refusing everything, and the
// permissive rule alone could be satisfied by checking nothing.
func TestASecretIsHeldToATighterModeThanAPublicFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "material.pem")
	if err := os.WriteFile(path, []byte("contents"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		mode        os.FileMode
		asSecret    bool
		asPublic    bool
		describedAs string
	}{
		{0o600, true, true, "owner-only"},
		{0o400, true, true, "owner read-only"},
		{0o640, false, true, "group-readable"},
		{0o644, false, true, "world-readable"},
		{0o620, false, false, "group-writable"},
		{0o602, false, false, "world-writable"},
	} {
		t.Run(test.describedAs, func(t *testing.T) {
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			_, secretErr := readProtected(path, 64, true)
			if (secretErr == nil) != test.asSecret {
				t.Fatalf("as a secret, %s gave err=%v; accepted should be %v", test.describedAs, secretErr, test.asSecret)
			}
			_, publicErr := readProtected(path, 64, false)
			if (publicErr == nil) != test.asPublic {
				t.Fatalf("as a public file, %s gave err=%v; accepted should be %v", test.describedAs, publicErr, test.asPublic)
			}
		})
	}
}

func TestAProtectedPathMustBeAbsoluteAndBounded(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "material.pem")
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A relative path that EXISTS, so that only the IsAbs check can be refusing it. The first
	// version used a path that does not exist, so unix.Open refused it and the case passed with
	// IsAbs deleted — the right verdict from the wrong rule. The second used "config.go", which is
	// only there because `go test` happens to run in the package directory: a binary built with
	// `go test -c` and run elsewhere would quietly restore the same problem.
	//
	// t.Chdir makes the working directory part of the test rather than part of the environment,
	// and Go restores it afterwards.
	relativeDirectory := t.TempDir()
	if err := os.WriteFile(filepath.Join(relativeDirectory, "material.pem"), []byte("contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(relativeDirectory)
	if contents, err := readProtected("material.pem", 1<<20, false); err == nil {
		t.Fatalf("a relative path was read (%d bytes): it resolves against whatever the working directory happens to be, which is not a property of the configuration", len(contents))
	}
	// ...and the same file by its absolute path is fine, so the refusal is about the spelling.
	if _, err := readProtected(filepath.Join(relativeDirectory, "material.pem"), 1<<20, false); err != nil {
		t.Fatalf("the same file was refused by its absolute path: %v", err)
	}
	if _, err := readProtected(path, 0, false); err == nil {
		t.Fatal("a maximum of zero was accepted")
	}
	if _, err := readProtected(path, 9, false); err == nil {
		t.Fatal("ten bytes were read under a nine-byte maximum")
	}
	if contents, err := readProtected(path, 10, false); err != nil || string(contents) != "0123456789" {
		t.Fatalf("exactly the maximum was refused: %q %v — the bound is one tighter than it says", contents, err)
	}
	nested := filepath.Join(directory, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readProtected(nested, 64, false); err == nil {
		t.Fatal("a directory was read as a protected file")
	}
}

func TestIdentityLoadsACompleteWorkloadIdentity(t *testing.T) {
	certPath, keyPath, caPath := writeIdentity(t, t.TempDir())
	cfg := config{CertificatePath: certPath, PrivateKeyPath: keyPath, CAPath: caPath}

	certificate, roots, err := cfg.identity()
	if err != nil {
		t.Fatalf("identity() error = %v: the refusals below prove nothing if the success path fails", err)
	}
	if len(certificate.Certificate) == 0 {
		t.Fatal("identity() returned no certificate")
	}
	if roots == nil || len(roots.Subjects()) == 0 { //nolint:staticcheck // Subjects is the available assertion here
		t.Fatal("identity() returned an empty trust pool: the client would trust nothing and fail every handshake")
	}
}

// TestIdentityNamesWhichHalfIsMissing. The two messages are the one piece of diagnosis an operator
// gets: "workload identity unavailable" points at this host's own certificate and key, and "KMS
// trust roots unavailable" points at what it uses to verify the server. Collapsing them would send
// someone to reissue a certificate that is fine.
func TestIdentityNamesWhichHalfIsMissing(t *testing.T) {
	for _, test := range []struct {
		name  string
		spoil func(t *testing.T, certPath, keyPath, caPath string) config
		wants string
	}{
		{"no certificate", func(t *testing.T, c, k, a string) config {
			return config{CertificatePath: filepath.Join(filepath.Dir(c), "absent.crt"), PrivateKeyPath: k, CAPath: a}
		}, "workload identity"},
		{"no private key", func(t *testing.T, c, k, a string) config {
			return config{CertificatePath: c, PrivateKeyPath: filepath.Join(filepath.Dir(k), "absent.key"), CAPath: a}
		}, "workload identity"},
		{"a key that is not the certificate's", func(t *testing.T, c, k, a string) config {
			_, otherKey, _ := writeIdentity(t, t.TempDir())
			return config{CertificatePath: c, PrivateKeyPath: otherKey, CAPath: a}
		}, "workload identity"},
		{"no trust roots", func(t *testing.T, c, k, a string) config {
			return config{CertificatePath: c, PrivateKeyPath: k, CAPath: filepath.Join(filepath.Dir(a), "absent.crt")}
		}, "KMS trust roots"},
		{"trust roots holding no certificate", func(t *testing.T, c, k, a string) config {
			empty := filepath.Join(filepath.Dir(a), "empty.crt")
			if err := os.WriteFile(empty, []byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return config{CertificatePath: c, PrivateKeyPath: k, CAPath: empty}
		}, "KMS trust roots"},
	} {
		t.Run(test.name, func(t *testing.T) {
			certPath, keyPath, caPath := writeIdentity(t, t.TempDir())
			_, _, err := test.spoil(t, certPath, keyPath, caPath).identity()
			if err == nil {
				t.Fatalf("identity() accepted %s", test.name)
			}
			if !strings.Contains(err.Error(), test.wants) {
				t.Fatalf("%s: error = %q, want it to name %q — the wrong half sends an operator to reissue material that is fine",
					test.name, err, test.wants)
			}
		})
	}
}

// TestAGroupReadablePrivateKeyStopsTheWholeIdentity, so the mode rule is shown to apply through
// identity() and not only when readProtected is called directly.
func TestAGroupReadablePrivateKeyStopsTheWholeIdentity(t *testing.T) {
	certPath, keyPath, caPath := writeIdentity(t, t.TempDir())
	cfg := config{CertificatePath: certPath, PrivateKeyPath: keyPath, CAPath: caPath}
	if _, _, err := cfg.identity(); err != nil {
		t.Fatalf("the well-formed identity was refused: %v", err)
	}

	if err := os.Chmod(keyPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cfg.identity(); err == nil {
		t.Fatal("a group-readable private key loaded: anyone in the group holds this workload's identity")
	}
}
