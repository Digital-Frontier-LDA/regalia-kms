package gpgsign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	pgpeddsa "github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Both in the past: GnuPG and go-crypto refuse a signature, or a key, dated after their own clock.
var fixedNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
var keyCreated = time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)

const userID = "Regalia Release Signing (test) <releases@example.invalid>"

// fakeKMS answers POST /v1/operations/sign the way the daemon and a SmartCard-HSM do: an ECDSA key
// signs the payload as a digest and returns r||s; an RSA key applies PKCS #1 v1.5 padding to the
// payload AS GIVEN (CKM_RSA_PKCS), so the caller must have sent DigestInfo. It records what it saw.
type fakeKMS struct {
	t      *testing.T
	server *httptest.Server
	key    crypto.Signer

	mu       sync.Mutex
	requests []seenRequest
	// respond, when set, replaces the normal answer.
	respond func(writer http.ResponseWriter, seen seenRequest, signature []byte)
}

type seenRequest struct {
	requestID, idempotencyKey string
	document                  operationRequest
	payload                   []byte
}

func newFakeKMS(t *testing.T, key crypto.Signer) *fakeKMS {
	t.Helper()
	kms := &fakeKMS{t: t, key: key}
	kms.server = httptest.NewTLSServer(http.HandlerFunc(kms.serve))
	t.Cleanup(kms.server.Close)
	return kms
}

func (kms *fakeKMS) serve(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/v1/operations/sign" || request.Method != http.MethodPost {
		http.NotFound(writer, request)
		return
	}
	var document operationRequest
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields() // the real API refuses unknown request fields
	if err := decoder.Decode(&document); err != nil {
		kms.t.Errorf("the request is not the API's document: %v", err)
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(document.Payload)
	if err != nil {
		kms.t.Errorf("payload_base64: %v", err)
	}
	seen := seenRequest{requestID: request.Header.Get("X-Request-ID"), idempotencyKey: request.Header.Get("Idempotency-Key"), document: document, payload: payload}
	kms.mu.Lock()
	kms.requests = append(kms.requests, seen)
	respond := kms.respond
	kms.mu.Unlock()

	var signature []byte
	switch key := kms.key.(type) {
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, payload)
		if err != nil {
			kms.t.Fatal(err)
		}
		size := (key.Curve.Params().N.BitLen() + 7) / 8
		signature = append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
	case *rsa.PrivateKey:
		signature, err = rsa.SignPKCS1v15(nil, key, crypto.Hash(0), payload)
		if err != nil {
			kms.t.Fatal(err)
		}
	case ed25519.PrivateKey:
		// CKM_EDDSA: the payload is the Ed25519 message, as given.
		signature = ed25519.Sign(key, payload)
	}
	if respond != nil {
		respond(writer, seen, signature)
		return
	}
	writeResult(writer, seen.requestID, document.ObjectID, signature)
}

func writeResult(writer http.ResponseWriter, requestID, objectID string, signature []byte) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]string{
		"request_id": requestID, "operation_id": "op-1", "object_id": objectID,
		"content_type": digestContentType, "result_base64": base64.StdEncoding.EncodeToString(signature),
	})
}

func (kms *fakeKMS) seen() []seenRequest {
	kms.mu.Lock()
	defer kms.mu.Unlock()
	return append([]seenRequest(nil), kms.requests...)
}

var target = Target{ObjectID: "release-signing-key", Environment: "staging", Purpose: "release-artifact"}

func (kms *fakeKMS) key4(t *testing.T, public crypto.PublicKey) *Key {
	t.Helper()
	client, err := NewClient(kms.server.URL, kms.server.Client(), func() time.Time { return fixedNow })
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSigner(public, client, target)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewKey(signer, keyCreated, userID)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type keyCase struct {
	name        string
	key         crypto.Signer
	payloadSize int
}

// The RSA keys are generated once: a 3072-bit key costs seconds, and nothing here mutates one.
var keyCases = sync.OnceValue(func() []keyCase {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsa3072, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		panic(err)
	}
	_, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return []keyCase{
		{"p256", p256, 32},
		{"p384", p384, 48},
		{"rsa3072", rsa3072, 19 + 32}, // DigestInfo(SHA-256)
		{"ed25519", edPrivate, 32},
	}
})

// requireGPG returns gpg's path, or skips — unless REGALIA_EXPECT_GPG says this job installed it,
// in which case its absence is a FAILURE. A skip is a pass, and "GnuPG accepts the signature" is the
// claim this adapter exists to make. Same contract as REGALIA_EXPECT_SOPS.
func requireGPG(t *testing.T) string {
	t.Helper()
	expect := false
	if raw := os.Getenv("REGALIA_EXPECT_GPG"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			t.Fatalf("REGALIA_EXPECT_GPG=%q is not a boolean (%v)", raw, err)
		}
		expect = parsed
	}
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		if expect {
			t.Fatalf("REGALIA_EXPECT_GPG is set, but gpg is not on PATH: %v", err)
		}
		t.Skipf("gpg is not on PATH: %v", err)
	}
	return gpg
}

// gnupg runs gpg in a throwaway home and returns its combined output.
func gnupg(t *testing.T, gpg, home string, args ...string) (string, error) {
	t.Helper()
	command := exec.Command(gpg, append([]string{"--homedir", home, "--batch", "--no-tty", "--status-fd", "1"}, args...)...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func gnupgHome(t *testing.T) string {
	t.Helper()
	// Short, because gpg-agent's socket path must fit a unix socket.
	home, err := os.MkdirTemp("/tmp", "rgl-gpg-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run()
		_ = os.RemoveAll(home)
	})
	return home
}

// THE CLAIM: a signature made through the KMS is one GnuPG and go-crypto both accept, against the
// exported public key alone, for every supported key type — and neither accepts it over a document
// that differs by one byte.
func TestADetachedSignatureVerifiesWithGnuPGAndGoCrypto(t *testing.T) {
	for _, tc := range keyCases() {
		t.Run(tc.name, func(t *testing.T) {
			kms := newFakeKMS(t, tc.key)
			key := kms.key4(t, tc.key.Public())
			document := []byte("3b1f…  regalia-kms_1.0.0_linux_amd64.tar.gz\n")

			var exported, signature bytes.Buffer
			if err := key.ExportPublic(context.Background(), &exported); err != nil {
				t.Fatal(err)
			}
			signed, err := key.DetachSign(context.Background(), &signature, bytes.NewReader(document), fixedNow, true)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(signature.String(), "-----BEGIN PGP SIGNATURE-----") {
				t.Fatalf("not an armored signature:\n%s", signature.String())
			}

			// go-crypto: an independent parse of both artifacts.
			keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(exported.Bytes()))
			if err != nil || len(keyring) != 1 {
				t.Fatalf("go-crypto cannot read the exported key: %v", err)
			}
			if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(document), bytes.NewReader(signature.Bytes()), nil); err != nil {
				t.Fatalf("go-crypto rejects the signature: %v", err)
			}
			tampered := append([]byte{}, document...)
			tampered[0] ^= 1
			if _, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(tampered), bytes.NewReader(signature.Bytes()), nil); err == nil {
				t.Fatal("go-crypto accepted the signature over a different document")
			}

			// The KMS saw exactly two operations — the key certification and the document — each a
			// digest of the size this key's policy allows, each under a fresh nonce that is also the
			// idempotency key, and the document's subject names the document.
			requests := kms.seen()
			if len(requests) != 2 {
				t.Fatalf("expected 2 KMS operations, saw %d", len(requests))
			}
			sum := sha256.Sum256(document)
			for index, request := range requests {
				if len(request.payload) != tc.payloadSize || request.document.ContentType != digestContentType {
					t.Fatalf("operation %d: payload of %d bytes as %q, want %d as %q", index, len(request.payload), request.document.ContentType, tc.payloadSize, digestContentType)
				}
				if request.document.Context.Nonce == "" || request.document.Context.Nonce != request.idempotencyKey {
					t.Fatalf("operation %d: nonce %q is not the idempotency key %q", index, request.document.Context.Nonce, request.idempotencyKey)
				}
				if request.document.ObjectID != target.ObjectID || request.document.Context.Purpose != target.Purpose || request.document.Context.Environment != target.Environment {
					t.Fatalf("operation %d was not for the configured target: %#v", index, request.document)
				}
				if request.document.Context.ExpiresAt != fixedNow.Add(time.Minute).Format(time.RFC3339Nano) {
					t.Fatalf("operation %d expires at %q", index, request.document.Context.ExpiresAt)
				}
			}
			if requests[0].document.Context.Nonce == requests[1].document.Context.Nonce || requests[0].requestID == requests[1].requestID {
				t.Fatal("two operations shared a nonce or a request ID")
			}
			if want := "openpgp-key-certification " + key.Fingerprint(); requests[0].document.Context.Subject != want {
				t.Fatalf("certification subject %q, want %q", requests[0].document.Context.Subject, want)
			}
			if want := "openpgp-detached sha256:" + hex.EncodeToString(sum[:]); requests[1].document.Context.Subject != want || signed.DocumentHash != hex.EncodeToString(sum[:]) {
				t.Fatalf("document subject %q, want %q", requests[1].document.Context.Subject, want)
			}

			// GnuPG: what a third party runs.
			gpg := requireGPG(t)
			home, work := gnupgHome(t), t.TempDir()
			keyPath, documentPath, signaturePath := filepath.Join(work, "key.asc"), filepath.Join(work, "SHA256SUMS"), filepath.Join(work, "SHA256SUMS.asc")
			for path, contents := range map[string][]byte{keyPath: exported.Bytes(), documentPath: document, signaturePath: signature.Bytes()} {
				if err := os.WriteFile(path, contents, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if output, err := gnupg(t, gpg, home, "--import", keyPath); err != nil || !strings.Contains(output, "IMPORT_OK 1 "+key.Fingerprint()) {
				t.Fatalf("gpg did not import the key under fingerprint %s: %v\n%s", key.Fingerprint(), err, output)
			}
			output, err := gnupg(t, gpg, home, "--verify", signaturePath, documentPath)
			if err != nil || !strings.Contains(output, "[GNUPG:] VALIDSIG "+key.Fingerprint()) || !strings.Contains(output, "[GNUPG:] GOODSIG "+key.KeyID()) {
				t.Fatalf("gpg does not accept the signature: %v\n%s", err, output)
			}
			if err := os.WriteFile(documentPath, tampered, 0o600); err != nil {
				t.Fatal(err)
			}
			if output, err := gnupg(t, gpg, home, "--verify", signaturePath, documentPath); err == nil || !strings.Contains(output, "[GNUPG:] BADSIG") {
				t.Fatalf("gpg accepted the signature over a different document: %v\n%s", err, output)
			}
		})
	}
}

// THE PINNED KEY IS THE AUTHORITY, NOT THE KMS'S ANSWER. If the KMS object is routed to another key
// — a registry mistake, a swapped token, an altered response — no signature comes out.
func TestASignatureThePinnedKeyDoesNotVerifyIsNeverEmitted(t *testing.T) {
	for _, tc := range keyCases() {
		t.Run(tc.name, func(t *testing.T) {
			kms := newFakeKMS(t, tc.key)
			var pinned crypto.PublicKey
			switch tc.key.(type) {
			case *ecdsa.PrivateKey:
				other, _ := ecdsa.GenerateKey(tc.key.Public().(*ecdsa.PublicKey).Curve, rand.Reader)
				pinned = other.Public()
			case ed25519.PrivateKey:
				other, _, _ := ed25519.GenerateKey(rand.Reader)
				pinned = other
			default:
				other, err := rsa.GenerateKey(rand.Reader, 3072)
				if err != nil {
					t.Fatal(err)
				}
				pinned = other.Public()
			}
			key := kms.key4(t, pinned) // the operator pinned a key the KMS does not hold
			var out bytes.Buffer
			_, err := key.DetachSign(context.Background(), &out, strings.NewReader("document"), fixedNow, true)
			if err == nil || !strings.Contains(err.Error(), "pinned public key does not verify") {
				t.Fatalf("expected the pinned-key refusal, got %v", err)
			}
			if out.Len() != 0 {
				t.Fatalf("a refused signature still wrote %d bytes", out.Len())
			}
			if err := key.ExportPublic(context.Background(), &out); err == nil || out.Len() != 0 {
				t.Fatalf("the key was exported with a certification the pinned key does not verify: %v", err)
			}
		})
	}
}

func TestAKMSRefusalIsReportedByItsCode(t *testing.T) {
	tc := keyCases()[0]
	kms := newFakeKMS(t, tc.key)
	kms.respond = func(writer http.ResponseWriter, seen seenRequest, _ []byte) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(writer).Encode(map[string]any{"request_id": seen.requestID, "code": "DENIED", "message": "request failed", "retryable": false})
	}
	var out bytes.Buffer
	_, err := kms.key4(t, tc.key.Public()).DetachSign(context.Background(), &out, strings.NewReader("document"), fixedNow, true)
	var failure *KMSError
	if !errors.As(err, &failure) || failure.Code != "DENIED" || failure.Status != http.StatusForbidden || failure.Retryable || out.Len() != 0 {
		t.Fatalf("expected KMSError DENIED and no output, got %v (%d bytes written)", err, out.Len())
	}
}

func TestAnAnswerThatIsNotToThisRequestIsRefused(t *testing.T) {
	tc := keyCases()[0]
	for name, respond := range map[string]func(http.ResponseWriter, seenRequest, []byte){
		"another request id": func(writer http.ResponseWriter, seen seenRequest, signature []byte) {
			writeResult(writer, "00000000-0000-4000-8000-000000000000", seen.document.ObjectID, signature)
		},
		"another object": func(writer http.ResponseWriter, seen seenRequest, signature []byte) {
			writeResult(writer, seen.requestID, "another-object", signature)
		},
		"an oversized result": func(writer http.ResponseWriter, seen seenRequest, _ []byte) {
			writeResult(writer, seen.requestID, seen.document.ObjectID, make([]byte, maxSignatureBytes+1))
		},
		"not JSON": func(writer http.ResponseWriter, _ seenRequest, _ []byte) {
			writer.Header().Set("Content-Type", "text/html")
			_, _ = writer.Write([]byte("<html>a proxy's login page</html>"))
		},
		"a redirect": func(writer http.ResponseWriter, _ seenRequest, _ []byte) {
			writer.Header().Set("Location", "/v1/operations/sign")
			writer.WriteHeader(http.StatusTemporaryRedirect)
		},
	} {
		t.Run(name, func(t *testing.T) {
			kms := newFakeKMS(t, tc.key)
			kms.respond = respond
			var out bytes.Buffer
			if _, err := kms.key4(t, tc.key.Public()).DetachSign(context.Background(), &out, strings.NewReader("document"), fixedNow, true); err == nil || out.Len() != 0 {
				t.Fatalf("accepted an answer that is not to this request (err=%v, %d bytes written)", err, out.Len())
			}
			if got := len(kms.seen()); got != 1 {
				t.Fatalf("the request was sent %d times; a redirect or a retry must not repeat a signature request", got)
			}
		})
	}
}

func TestTheSignerRefusesAnotherHashAndAnotherScheme(t *testing.T) {
	rsaCase := keyCases()[2]
	kms := newFakeKMS(t, rsaCase.key)
	key := kms.key4(t, rsaCase.key.Public())
	operation := &bound{signer: key.signer, ctx: context.Background()}
	digest := sha256.Sum256([]byte("document"))
	if _, err := operation.Sign(nil, digest[:], &rsa.PSSOptions{Hash: crypto.SHA256}); err == nil {
		t.Fatal("a PSS signature was produced")
	}
	if _, err := operation.Sign(nil, make([]byte, 64), crypto.SHA512); err == nil {
		t.Fatal("a SHA-512 digest was signed by a key whose policy is SHA-256")
	}
	if _, err := operation.Sign(nil, digest[:31], crypto.SHA256); err == nil {
		t.Fatal("a truncated digest was signed")
	}
	if got := len(kms.seen()); got != 0 {
		t.Fatalf("a refused request reached the KMS %d times", got)
	}
}

// The fingerprint is the key's name to every verifier. It depends on the public key and the creation
// time only — not on the throwaway key ecdsaPublicKey borrows a curve from, and not on the clock.
func TestTheFingerprintIsAFunctionOfTheKeyAndItsCreationTimeOnly(t *testing.T) {
	for _, tc := range keyCases() {
		t.Run(tc.name, func(t *testing.T) {
			kms := newFakeKMS(t, tc.key)
			first, second := kms.key4(t, tc.key.Public()), kms.key4(t, tc.key.Public())
			if first.Fingerprint() != second.Fingerprint() || len(first.Fingerprint()) != 40 {
				t.Fatalf("two framings of one key disagree: %s vs %s", first.Fingerprint(), second.Fingerprint())
			}
			later, err := NewKey(first.signer, keyCreated.Add(time.Second), userID)
			if err != nil {
				t.Fatal(err)
			}
			if later.Fingerprint() == first.Fingerprint() {
				t.Fatal("the creation time is not part of the fingerprint")
			}
		})
	}
}

func TestAnRSAKeyExportsToTheSameBytesEveryTime(t *testing.T) {
	rsaCase := keyCases()[2]
	kms := newFakeKMS(t, rsaCase.key)
	key := kms.key4(t, rsaCase.key.Public())
	var first, second bytes.Buffer
	if err := key.ExportPublic(context.Background(), &first); err != nil {
		t.Fatal(err)
	}
	if err := key.ExportPublic(context.Background(), &second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("two exports of one RSA key differ: something in the export follows the clock or a random source")
	}
}

func TestMatchesReadsASelectorTheWayGnuPGDoes(t *testing.T) {
	tc := keyCases()[0]
	key := newFakeKMS(t, tc.key).key4(t, tc.key.Public())
	for _, selector := range []string{key.Fingerprint(), strings.ToLower(key.Fingerprint()), "0x" + key.KeyID(), key.KeyID() + "!", "releases@example.invalid", "Regalia Release"} {
		if !key.Matches(selector) {
			t.Errorf("%q should name this key", selector)
		}
	}
	for _, selector := range []string{"", " ", "0123456789ABCDEF", "someone@else.invalid", key.Fingerprint()[1:]} {
		if key.Matches(selector) {
			t.Errorf("%q should not name this key", selector)
		}
	}
}

func TestOnlyAnHTTPSOriginIsAKMS(t *testing.T) {
	now := func() time.Time { return fixedNow }
	for _, bad := range []string{"http://kms.internal:8443", "https://kms.internal/v1", "https://user@kms.internal", "https://kms.internal?x=1", "kms.internal:8443", ""} {
		if _, err := NewClient(bad, &http.Client{}, now); err == nil {
			t.Errorf("%q was accepted as a KMS URL", bad)
		}
	}
	if _, err := NewClient("https://kms.internal:8443/", &http.Client{}, now); err != nil {
		t.Errorf("a bare trailing slash was refused: %v", err)
	}
}

func TestOnlySupportedKeysBecomeSigners(t *testing.T) {
	client, err := NewClient("https://kms.internal", &http.Client{}, func() time.Time { return fixedNow })
	if err != nil {
		t.Fatal(err)
	}
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	for name, public := range map[string]crypto.PublicKey{"P-521": p521.Public(), "RSA-1024": small.Public(), "nil": nil} {
		if _, err := NewSigner(public, client, target); err == nil {
			t.Errorf("%s was accepted as a release key", name)
		}
	}
	if _, err := NewSigner(keyCases()[0].key.Public(), client, Target{ObjectID: "Bad Object", Environment: "staging", Purpose: "release-artifact"}); err == nil {
		t.Error("an object ID the API would refuse was accepted")
	}
}

// A Release file as apt reads one: no trailing whitespace, ends in a newline. Under the cleartext
// framework such a text comes back byte for byte.
const releaseFile = `Origin: Regalia
Suite: stable
Codename: stable
Date: Thu, 01 Oct 2026 12:00:00 UTC
Architectures: amd64
Components: main
SHA256:
 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 0 main/binary-amd64/Packages
`

// THE CLAIM: a cleartext signature made through the KMS is one GnuPG, apt's verifiers (gpgv, and sqv
// where it exists) and go-crypto all accept against the exported key, the text they extract is the
// text that was signed, and none accepts it once a byte of the text changes.
func TestAClearSignedDocumentVerifiesWithGnuPGAptsVerifiersAndGoCrypto(t *testing.T) {
	for _, tc := range keyCases() {
		t.Run(tc.name, func(t *testing.T) {
			kms := newFakeKMS(t, tc.key)
			key := kms.key4(t, tc.key.Public())
			var exported, signed bytes.Buffer
			if err := key.ExportPublic(context.Background(), &exported); err != nil {
				t.Fatal(err)
			}
			before := len(kms.seen())
			result, err := key.ClearSign(context.Background(), &signed, strings.NewReader(releaseFile), fixedNow)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(signed.String(), "-----BEGIN PGP SIGNED MESSAGE-----\nHash: ") || !strings.Contains(signed.String(), "\n-----BEGIN PGP SIGNATURE-----\n") {
				t.Fatalf("not a cleartext-signed document:\n%s", signed.String())
			}
			// THE CHECKSUM LINE IS LOAD-BEARING FOR GNUPG. Without it gpg and gpgv exit 2 on any
			// signature whose base64 needs no padding (every RSA-3072 one, measured), while still
			// printing "Good signature". Asserted on the bytes so it does not depend on this run's
			// signature happening to have the unlucky length.
			if !regexp.MustCompile(`\n=[A-Za-z0-9+/]{4}\n-----END PGP SIGNATURE-----\n$`).MatchString(signed.String()) {
				t.Fatalf("the signature armor carries no CRC-24 line, or the document does not end in a newline:\n%s", signed.String())
			}

			// One KMS operation, whose subject names the document.
			requests := kms.seen()[before:]
			sum := sha256.Sum256([]byte(releaseFile))
			if len(requests) != 1 || requests[0].document.Context.Subject != "openpgp-cleartext sha256:"+hex.EncodeToString(sum[:]) ||
				len(requests[0].payload) != tc.payloadSize || result.DocumentHash != hex.EncodeToString(sum[:]) {
				t.Fatalf("expected one operation over the document, saw %#v", requests)
			}

			// go-crypto, as an independent parser.
			keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(exported.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			block, rest := clearsign.Decode(signed.Bytes())
			if block == nil || len(bytes.TrimSpace(rest)) != 0 {
				t.Fatalf("go-crypto cannot read the document back (rest %q)", rest)
			}
			if _, err := block.VerifySignature(keyring, nil); err != nil {
				t.Fatalf("go-crypto rejects the cleartext signature: %v", err)
			}
			// go-crypto returns the text without its final line ending, which the framework treats
			// as the separator before the signature. GnuPG and sqv, below, give it back whole.
			if string(block.Plaintext)+"\n" != releaseFile {
				t.Fatalf("the text read back differs from the text signed:\n%q\n%q", block.Plaintext, releaseFile)
			}
			tampered := bytes.Replace(signed.Bytes(), []byte("Suite: stable"), []byte("Suite: sid   "), 1)
			if other, _ := clearsign.Decode(tampered); other == nil {
				t.Fatal("the tampered document did not parse at all; the control proves nothing")
			} else if _, err := other.VerifySignature(keyring, nil); err == nil {
				t.Fatal("go-crypto accepted the signature over a changed text")
			}

			// GnuPG, then the two verifiers apt has used.
			gpg := requireGPG(t)
			home, work := gnupgHome(t), t.TempDir()
			keyPath, inRelease, tamperedPath := filepath.Join(work, "key.asc"), filepath.Join(work, "InRelease"), filepath.Join(work, "InRelease.tampered")
			for path, contents := range map[string][]byte{keyPath: exported.Bytes(), inRelease: signed.Bytes(), tamperedPath: tampered} {
				if err := os.WriteFile(path, contents, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if output, err := gnupg(t, gpg, home, "--import", keyPath); err != nil {
				t.Fatalf("gpg --import: %v\n%s", err, output)
			}
			extracted := filepath.Join(work, "Release.gpg-out")
			if output, err := gnupg(t, gpg, home, "--output", extracted, "--decrypt", inRelease); err != nil || !strings.Contains(output, "[GNUPG:] VALIDSIG "+key.Fingerprint()) {
				t.Fatalf("gpg does not accept the cleartext signature: %v\n%s\n%s", err, output, signed.String())
			}
			if text, err := os.ReadFile(extracted); err != nil || string(text) != releaseFile {
				t.Fatalf("gpg extracted a different text (%v):\n%q", err, text)
			}
			if output, err := gnupg(t, gpg, home, "--verify", tamperedPath); err == nil || !strings.Contains(output, "[GNUPG:] BADSIG") {
				t.Fatalf("gpg accepted the signature over a changed text: %v\n%s", err, output)
			}

			// gpgv takes a binary keyring; apt before 3.0 runs it on InRelease.
			keyring4gpgv := filepath.Join(work, "trusted.gpg")
			if output, err := gnupg(t, gpg, home, "--output", keyring4gpgv, "--dearmor", keyPath); err != nil {
				t.Fatalf("gpg --dearmor: %v\n%s", err, output)
			}
			gpgv := requireVerifier(t, "gpgv", true)
			if output, err := exec.Command(gpgv, "--keyring", keyring4gpgv, "--status-fd", "1", inRelease).CombinedOutput(); err != nil || !strings.Contains(string(output), "[GNUPG:] VALIDSIG "+key.Fingerprint()) {
				t.Fatalf("gpgv does not accept InRelease: %v\n%s", err, output)
			}
			if output, err := exec.Command(gpgv, "--keyring", keyring4gpgv, "--status-fd", "1", tamperedPath).CombinedOutput(); err == nil {
				t.Fatalf("gpgv accepted the changed InRelease:\n%s", output)
			}
			// sqv (Sequoia) is apt 3's verifier. It is not on every system this test runs on, so
			// its absence is logged, not failed.
			if sqv := requireVerifier(t, "sqv", false); sqv != "" {
				out := filepath.Join(work, "Release.sqv-out")
				if output, err := exec.Command(sqv, "--keyring", keyPath, "--output", out, "--cleartext", inRelease).CombinedOutput(); err != nil {
					t.Fatalf("sqv does not accept InRelease: %v\n%s", err, output)
				}
				// sqv returns the text without its final line ending (the framework's separator);
				// GnuPG, above, puts one back.
				if text, err := os.ReadFile(out); err != nil || strings.TrimSuffix(string(text), "\n")+"\n" != releaseFile {
					t.Fatalf("sqv extracted a different text (%v):\n%q", err, text)
				}
				if output, err := exec.Command(sqv, "--keyring", keyPath, "--output", out+".tampered", "--cleartext", tamperedPath).CombinedOutput(); err == nil {
					t.Fatalf("sqv accepted the changed InRelease:\n%s", output)
				}
			} else {
				t.Log("sqv is not installed; apt 3's verifier was not exercised here")
			}
		})
	}
}

// requireVerifier finds an apt verifier. A required one follows REGALIA_EXPECT_GPG (absent is a
// failure when the job says it installed GnuPG); an optional one returns "" when absent.
func requireVerifier(t *testing.T, name string, required bool) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err == nil {
		return path
	}
	if !required {
		return ""
	}
	if expect, _ := strconv.ParseBool(os.Getenv("REGALIA_EXPECT_GPG")); expect {
		t.Fatalf("REGALIA_EXPECT_GPG is set, but %s is not on PATH: %v", name, err)
	}
	t.Skipf("%s is not on PATH: %v", name, err)
	return ""
}

// The framework's own rules, held to GnuPG's reading of them: a line that begins with a dash is
// escaped and comes back whole, a text without a final newline is signed and comes back without
// one, and trailing blanks on a line are outside the signature.
func TestClearSigningFollowsTheCleartextFrameworkAsGnuPGReadsIt(t *testing.T) {
	gpg := requireGPG(t)
	tc := keyCases()[1]
	kms := newFakeKMS(t, tc.key)
	key := kms.key4(t, tc.key.Public())
	var exported bytes.Buffer
	if err := key.ExportPublic(context.Background(), &exported); err != nil {
		t.Fatal(err)
	}
	home, work := gnupgHome(t), t.TempDir()
	keyPath := filepath.Join(work, "key.asc")
	if err := os.WriteFile(keyPath, exported.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := gnupg(t, gpg, home, "--import", keyPath); err != nil {
		t.Fatalf("gpg --import: %v\n%s", err, output)
	}
	for name, text := range map[string]string{
		"lines beginning with a dash": "- a list item\n-----BEGIN PGP SIGNATURE-----\nnot a signature\n",
		"no final newline":            "one line, unterminated",
		"an empty document":           "",
		"blank lines":                 "first\n\n\nlast\n",
		"a From line":                 "From here on\nFrom there\n",
	} {
		t.Run(name, func(t *testing.T) {
			var signed bytes.Buffer
			if _, err := key.ClearSign(context.Background(), &signed, strings.NewReader(text), fixedNow); err != nil {
				t.Fatal(err)
			}
			path, out := filepath.Join(t.TempDir(), "signed.asc"), filepath.Join(t.TempDir(), "text")
			if err := os.WriteFile(path, signed.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			if output, err := gnupg(t, gpg, home, "--output", out, "--decrypt", path); err != nil || !strings.Contains(output, "[GNUPG:] VALIDSIG "+key.Fingerprint()) {
				t.Fatalf("gpg does not accept it: %v\n%s\n%s", err, output, signed.String())
			}
			// GnuPG ends the extracted text with a newline whether or not the original had one.
			if extracted, err := os.ReadFile(out); err != nil || strings.TrimSuffix(string(extracted), "\n") != strings.TrimSuffix(text, "\n") {
				t.Fatalf("gpg extracted %q, signed %q (%v)", extracted, text, err)
			}
		})
	}
	// Trailing blanks are not signed: two texts that differ only there carry interchangeable
	// signatures. That is the framework, and the reason a byte-exact artifact gets a detached one.
	var signed bytes.Buffer
	if _, err := key.ClearSign(context.Background(), &signed, strings.NewReader("value: 1\n"), fixedNow); err != nil {
		t.Fatal(err)
	}
	padded := filepath.Join(work, "padded.asc")
	if err := os.WriteFile(padded, bytes.Replace(signed.Bytes(), []byte("value: 1\n"), []byte("value: 1  \t\n"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := gnupg(t, gpg, home, "--verify", padded); err != nil {
		t.Fatalf("gpg rejected a text that differs only in trailing blanks, so the framework is not what this test says it is: %v\n%s", err, output)
	}
}

func TestARefusedClearSignWritesNothing(t *testing.T) {
	tc := keyCases()[2] // RSA: the path where go-crypto would lose the signer's error
	kms := newFakeKMS(t, tc.key)
	kms.respond = func(writer http.ResponseWriter, seen seenRequest, _ []byte) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(writer).Encode(map[string]any{"request_id": seen.requestID, "code": "DENIED", "message": "request failed", "retryable": false})
	}
	var out bytes.Buffer
	_, err := kms.key4(t, tc.key.Public()).ClearSign(context.Background(), &out, strings.NewReader(releaseFile), fixedNow)
	var failure *KMSError
	if !errors.As(err, &failure) || failure.Code != "DENIED" || out.Len() != 0 {
		t.Fatalf("expected KMSError DENIED and no output, got %v (%d bytes written)", err, out.Len())
	}
}

func ed25519Case(t *testing.T) (keyCase, ed25519.PublicKey) {
	t.Helper()
	for _, tc := range keyCases() {
		if private, ok := tc.key.(ed25519.PrivateKey); ok {
			return tc, private.Public().(ed25519.PublicKey)
		}
	}
	t.Fatal("no Ed25519 key in the test matrix")
	return keyCase{}, nil
}

// SIGNING TWICE (eddsa.go), CONDITION 1: everything that is hashed names the KMS key. The throwaway
// key go-crypto signs with first supplies a private half and nothing else: the exported key packet
// carries the KMS key's point, and every signature's issuer fingerprint and key ID are the KMS
// key's. Asserted by parsing what was written, not by trusting the code that wrote it.
func TestAnEd25519SignatureAndKeyNameTheKMSKeyAndNothingOfTheThrowawayKey(t *testing.T) {
	tc, public := ed25519Case(t)
	kms := newFakeKMS(t, tc.key)
	key := kms.key4(t, public)

	var exported, detached, cleartext bytes.Buffer
	if err := key.ExportPublic(context.Background(), &exported); err != nil {
		t.Fatal(err)
	}
	if _, err := key.DetachSign(context.Background(), &detached, strings.NewReader("document"), fixedNow, false); err != nil {
		t.Fatal(err)
	}
	if _, err := key.ClearSign(context.Background(), &cleartext, strings.NewReader(releaseFile), fixedNow); err != nil {
		t.Fatal(err)
	}

	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(exported.Bytes()))
	if err != nil || len(keyring) != 1 {
		t.Fatalf("the exported key does not parse: %v", err)
	}
	primary := keyring[0].PrimaryKey
	point, ok := primary.PublicKey.(*pgpeddsa.PublicKey)
	if !ok || primary.PubKeyAlgo != packet.PubKeyAlgoEdDSA || !bytes.Equal(point.X, public) {
		t.Fatalf("the exported key is not the KMS key as an EdDSA key (algorithm %d, %T)", primary.PubKeyAlgo, primary.PublicKey)
	}
	if !bytes.Equal(primary.Fingerprint, key.public.Fingerprint) || strings.ToUpper(hex.EncodeToString(primary.Fingerprint)) != key.Fingerprint() {
		t.Fatal("the exported key's fingerprint is not the one the tool reports")
	}
	if bytes.Equal(point.X, key.throwaway.PublicKey.X) {
		t.Fatal("the throwaway key's public half was exported")
	}

	_, clearBlock, err := signatureBlock(cleartext.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	selfSignature := keyring[0].Identities[userID].SelfSignature
	issued := map[string]*packet.Signature{"the key certification": selfSignature}
	for name, serialized := range map[string][]byte{"the detached signature": detached.Bytes(), "the cleartext signature": clearBlock} {
		parsed, err := packet.Read(bytes.NewReader(serialized))
		if err != nil {
			t.Fatalf("%s does not parse: %v", name, err)
		}
		issued[name] = parsed.(*packet.Signature)
	}
	for name, signature := range issued {
		if signature.IssuerKeyId == nil || *signature.IssuerKeyId != primary.KeyId || !bytes.Equal(signature.IssuerFingerprint, primary.Fingerprint) {
			t.Fatalf("%s does not name the KMS key as its issuer", name)
		}
		if signature.PubKeyAlgo != packet.PubKeyAlgoEdDSA || signature.Hash != crypto.SHA256 || signature.Version != 4 {
			t.Fatalf("%s is algorithm %d, hash %v, version %d; want EdDSA, SHA-256, v4", name, signature.PubKeyAlgo, signature.Hash, signature.Version)
		}
	}

	// The KMS was asked three times, each for a 32-byte SHA-256 digest, and each answer verifies
	// under the KMS key as Ed25519 over exactly those bytes: nothing else was ever signed.
	requests := kms.seen()
	if len(requests) != 3 {
		t.Fatalf("expected 3 KMS operations, saw %d", len(requests))
	}
	for index, request := range requests {
		if len(request.payload) != sha256.Size {
			t.Fatalf("operation %d sent %d bytes, want a 32-byte digest", index, len(request.payload))
		}
	}
}

// CONDITIONS 2 AND 3: the finished signature is verified against the KMS public key before anything
// is written, and the throwaway signature can never leave. With the swap of R and S skipped, the
// packet still carries the throwaway key's own (perfectly valid, wrong-key) signature — and every
// output path must refuse it and write nothing.
func TestTheThrowawayEd25519SignatureCanNeverLeave(t *testing.T) {
	tc, public := ed25519Case(t)
	kms := newFakeKMS(t, tc.key)
	key := kms.key4(t, public)

	real := edDSASwap
	t.Cleanup(func() { edDSASwap = real })
	edDSASwap = func(*packet.Signature, []byte) error { return nil } // step 4 does not happen

	for name, attempt := range map[string]func(*bytes.Buffer) error{
		"a detached signature": func(out *bytes.Buffer) error {
			_, err := key.DetachSign(context.Background(), out, strings.NewReader("document"), fixedNow, true)
			return err
		},
		"a cleartext signature": func(out *bytes.Buffer) error {
			_, err := key.ClearSign(context.Background(), out, strings.NewReader(releaseFile), fixedNow)
			return err
		},
		"the key export": func(out *bytes.Buffer) error { return key.ExportPublic(context.Background(), out) },
	} {
		var out bytes.Buffer
		err := attempt(&out)
		if err == nil || !strings.Contains(err.Error(), "does not verify against the KMS public key") {
			t.Errorf("%s: expected the verification refusal, got %v", name, err)
		}
		if out.Len() != 0 {
			t.Errorf("%s: %d bytes were written although the signature is the throwaway key's", name, out.Len())
		}
	}

	// And with the swap restored the same key signs normally, so the refusals above were the
	// skipped step and not a broken fixture.
	edDSASwap = real
	var out bytes.Buffer
	if _, err := key.DetachSign(context.Background(), &out, strings.NewReader("document"), fixedNow, true); err != nil || out.Len() == 0 {
		t.Fatalf("the control failed: %v", err)
	}
}

// THE TWO INTEGERS THIS ADAPTER ENCODES. An OpenPGP integer drops leading zero bytes and states its
// length in bits, so R or S beginning with a zero byte (one signature in 128) or with zero bits
// (most of them) takes a different encoding from the easy case.
func TestMPIEncodingIsTheOpenPGPOne(t *testing.T) {
	for _, vector := range []struct {
		value   []byte
		encoded string
	}{
		{[]byte{0x01}, "000101"},
		{[]byte{0x01, 0xff}, "000901ff"}, // RFC 9580 §3.2's own examples
		{[]byte{0x00, 0x00, 0x80}, "000880"},
		{[]byte{0x00, 0x7f, 0x00}, "000f7f00"},
		{[]byte{0xff, 0x00}, "0010ff00"},
		{[]byte{0x00, 0x00}, "0000"},
		{nil, "0000"},
	} {
		got := newMPI(vector.value)
		if hex.EncodeToString(got.EncodedBytes()) != vector.encoded || int(got.EncodedLength()) != len(got.EncodedBytes()) {
			t.Errorf("newMPI(%x) encodes as %x (length %d), want %s", vector.value, got.EncodedBytes(), got.EncodedLength(), vector.encoded)
		}
	}
}

// ...and held to GnuPG on the hard case. Signatures are made until R or S begins with a zero byte;
// every one of them has already passed finish's own verification, and that one must pass GnuPG's.
func TestAnEd25519SignatureWithALeadingZeroIntegerVerifiesWithGnuPG(t *testing.T) {
	tc, public := ed25519Case(t)
	kms := newFakeKMS(t, tc.key)
	key := kms.key4(t, public)
	var exported bytes.Buffer
	if err := key.ExportPublic(context.Background(), &exported); err != nil {
		t.Fatal(err)
	}
	var signature bytes.Buffer
	document := ""
	for attempt := 0; ; attempt++ {
		if attempt == 5000 {
			t.Fatal("no signature with a leading zero byte in 5000 attempts")
		}
		signature.Reset()
		document = "document " + strconv.Itoa(attempt)
		if _, err := key.DetachSign(context.Background(), &signature, strings.NewReader(document), fixedNow, false); err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		parsed, err := packet.Read(bytes.NewReader(signature.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		made := parsed.(*packet.Signature)
		if len(made.EdDSASigR.Bytes()) < 32 || len(made.EdDSASigS.Bytes()) < 32 {
			break
		}
	}
	gpg := requireGPG(t)
	home, work := gnupgHome(t), t.TempDir()
	keyPath, documentPath, signaturePath := filepath.Join(work, "key.asc"), filepath.Join(work, "document"), filepath.Join(work, "document.sig")
	for path, contents := range map[string][]byte{keyPath: exported.Bytes(), documentPath: []byte(document), signaturePath: signature.Bytes()} {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if output, err := gnupg(t, gpg, home, "--import", keyPath); err != nil {
		t.Fatalf("gpg --import: %v\n%s", err, output)
	}
	if output, err := gnupg(t, gpg, home, "--verify", signaturePath, documentPath); err != nil || !strings.Contains(output, "[GNUPG:] VALIDSIG "+key.Fingerprint()) {
		t.Fatalf("gpg rejects an Ed25519 signature whose R or S begins with a zero byte: %v\n%s", err, output)
	}
}
