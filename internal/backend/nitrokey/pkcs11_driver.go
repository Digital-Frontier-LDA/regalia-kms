package nitrokey

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/keywrap"
	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/miekg/pkcs11"
)

var (
	oidPublicKeyEC = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidEd25519     = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// CKM_EDDSA was assigned by PKCS#11 v3 after the headers bundled by
// github.com/miekg/pkcs11 v1.1.2. Keep the standard numeric identifier local
// until the binding publishes newer headers.
const ckmEdDSA = 0x00001057

// DevAuthProbe reads and validates C.DevAut independently of PKCS#11. A
// production driver cannot be constructed without this hardware identity
// boundary because token labels and PKCS#11 slot numbers are not identities.
type DevAuthProbe interface {
	Fingerprint(context.Context, string, string) (string, error)
}

// SecureChannel establishes the commissioned SmartCard-HSM secure-messaging
// session. It is deliberately mandatory rather than silently implemented as a
// no-op for middleware that cannot prove the channel state.
type SecureChannel interface {
	Establish(context.Context, string, string) error
}

// PINRetryProbe reads retry metadata without attempting authentication.
type PINRetryProbe interface {
	Remaining(context.Context, string, string) (int, error)
}

type cryptoki interface {
	GetSlotList(bool) ([]uint, error)
	GetTokenInfo(uint) (pkcs11.TokenInfo, error)
	OpenSession(uint, uint) (pkcs11.SessionHandle, error)
	CloseSession(pkcs11.SessionHandle) error
	Login(pkcs11.SessionHandle, uint, string) error
	Logout(pkcs11.SessionHandle) error
	FindObjectsInit(pkcs11.SessionHandle, []*pkcs11.Attribute) error
	FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error)
	FindObjectsFinal(pkcs11.SessionHandle) error
	SignInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	Sign(pkcs11.SessionHandle, []byte) ([]byte, error)
	DecryptInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error
	Decrypt(pkcs11.SessionHandle, []byte) ([]byte, error)
	GetAttributeValue(pkcs11.SessionHandle, pkcs11.ObjectHandle, []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	DeriveKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	UnwrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, []byte, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	WrapKey(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle, pkcs11.ObjectHandle) ([]byte, error)
	CreateObject(pkcs11.SessionHandle, []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	DestroyObject(pkcs11.SessionHandle, pkcs11.ObjectHandle) error
}

type PKCS11Driver struct {
	module  cryptoki
	devAuth DevAuthProbe
	secure  SecureChannel
	retries PINRetryProbe
	close   func() error
}

// NewPKCS11Driver loads one PKCS#11 module. Every Open receives a server-owned
// registry binding and re-enumerates slots by its commissioned serial, so USB
// or PKCS#11 enumeration order is never trusted.
func NewPKCS11Driver(modulePath string, devAuth DevAuthProbe, secure SecureChannel, retries PINRetryProbe) (*PKCS11Driver, error) {
	if strings.TrimSpace(modulePath) == "" {
		return nil, errors.New("PKCS#11 module path is required")
	}
	module := pkcs11.New(modulePath)
	if module == nil {
		return nil, errors.New("PKCS#11 module unavailable")
	}
	if err := module.Initialize(); err != nil {
		module.Destroy()
		return nil, errors.New("PKCS#11 initialization failed")
	}
	return newPKCS11Driver(module, devAuth, secure, retries, func() error {
		err := module.Finalize()
		module.Destroy()
		return err
	})
}

func newPKCS11Driver(module cryptoki, devAuth DevAuthProbe, secure SecureChannel, retries PINRetryProbe, cleanup ...func() error) (*PKCS11Driver, error) {
	if module == nil || devAuth == nil || secure == nil || retries == nil {
		return nil, errors.New("complete PKCS#11 driver configuration is required")
	}
	var closeFunc func() error
	if len(cleanup) > 0 {
		closeFunc = cleanup[0]
	}
	return &PKCS11Driver{module: module, devAuth: devAuth, secure: secure, retries: retries, close: closeFunc}, nil
}

func (driver *PKCS11Driver) Open(ctx context.Context, binding registry.Binding) (Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if binding.Backend != "nitrokey-pkcs11" || strings.TrimSpace(binding.DeviceID) == "" || strings.TrimSpace(binding.DeviceSerial) == "" {
		return nil, errors.New("PKCS#11 device is not configured")
	}
	deviceID, expectedSerial := binding.DeviceID, binding.DeviceSerial
	slots, err := driver.module.GetSlotList(true)
	if err != nil {
		return nil, errors.New("PKCS#11 enumeration failed")
	}
	var selected uint
	matches := 0
	for _, slot := range slots {
		info, infoErr := driver.module.GetTokenInfo(slot)
		if infoErr == nil && strings.TrimSpace(info.SerialNumber) == expectedSerial {
			selected, matches = slot, matches+1
		}
	}
	if matches != 1 {
		return nil, errors.New("commissioned PKCS#11 device is unavailable")
	}
	handle, err := driver.module.OpenSession(selected, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, errors.New("PKCS#11 session unavailable")
	}
	return &pkcs11Session{module: driver.module, handle: handle, deviceID: deviceID, serial: expectedSerial, devAuth: driver.devAuth, secure: driver.secure, retries: driver.retries}, nil
}

func (driver *PKCS11Driver) Ready(ctx context.Context) bool {
	if driver == nil || driver.module == nil || ctx.Err() != nil {
		return false
	}
	slots, err := driver.module.GetSlotList(true)
	return err == nil && len(slots) > 0
}

func (driver *PKCS11Driver) Close() error {
	if driver == nil || driver.close == nil {
		return nil
	}
	closeFunc := driver.close
	driver.close = nil
	return closeFunc()
}

type pkcs11Session struct {
	module   cryptoki
	handle   pkcs11.SessionHandle
	deviceID string
	serial   string
	devAuth  DevAuthProbe
	secure   SecureChannel
	retries  PINRetryProbe
	mu       sync.Mutex
	loggedIn bool
	closed   bool
}

func (session *pkcs11Session) Identity(ctx context.Context) (string, string, error) {
	if err := session.usable(ctx); err != nil {
		return "", "", err
	}
	fingerprint, err := session.devAuth.Fingerprint(ctx, session.deviceID, session.serial)
	if err != nil || fingerprint == "" {
		return "", "", errors.New("device authentication unavailable")
	}
	return session.serial, fingerprint, nil
}

func (session *pkcs11Session) EstablishSecureChannel(ctx context.Context) error {
	if err := session.usable(ctx); err != nil {
		return err
	}
	if err := session.secure.Establish(ctx, session.deviceID, session.serial); err != nil {
		return errors.New("secure messaging unavailable")
	}
	return nil
}

func (session *pkcs11Session) PINRetries(ctx context.Context) (int, error) {
	if err := session.usable(ctx); err != nil {
		return 0, err
	}
	remaining, err := session.retries.Remaining(ctx, session.deviceID, session.serial)
	if err != nil || remaining < 0 {
		return 0, errors.New("PIN retry metadata unavailable")
	}
	return remaining, nil
}

func (session *pkcs11Session) Login(ctx context.Context, pin []byte) error {
	if err := session.usable(ctx); err != nil || len(pin) < 6 || len(pin) > 64 || containsZero(pin) {
		return errors.New("PKCS#11 login unavailable")
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.loggedIn || session.closed {
		return errors.New("PKCS#11 login unavailable")
	}
	pinText := string(pin)
	err := session.module.Login(session.handle, pkcs11.CKU_USER, pinText)
	pinText = ""
	if err != nil {
		return errors.New("PKCS#11 login unavailable")
	}
	session.loggedIn = true
	return nil
}

func (session *pkcs11Session) Sign(ctx context.Context, objectID, algorithm string, data []byte) ([]byte, error) {
	if err := session.privateUsable(ctx); err != nil || len(data) == 0 {
		return nil, errors.New("PKCS#11 signing unavailable")
	}
	mechanism, err := signingMechanism(algorithm)
	if err != nil {
		return nil, err
	}
	key, err := session.findObject(objectID, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return nil, err
	}
	if err := session.module.SignInit(session.handle, []*pkcs11.Mechanism{mechanism}, key); err != nil {
		return nil, errors.New("PKCS#11 signing unavailable")
	}
	result, err := session.module.Sign(session.handle, data)
	if err != nil || len(result) == 0 {
		zero(result)
		return nil, errors.New("PKCS#11 signing unavailable")
	}
	// LOW-S, OR THE COSMOS CHAIN REJECTS IT. The token returns whichever of the two equivalent
	// signatures it computed; the Cosmos SDK accepts only s <= N/2. 11 of 24 signatures measured on
	// DENK0404144 were high-S, so without this the signer fails roughly half the time, on-chain,
	// with a signature every general-purpose verifier calls valid. See lows.go.
	normalized, rewritten := normalizeLowS(algorithm, result)
	if rewritten {
		zero(result)
	}
	return normalized, nil
}

func (session *pkcs11Session) Unwrap(ctx context.Context, objectID, algorithm string, ciphertext, aad []byte) ([]byte, error) {
	if err := session.privateUsable(ctx); err != nil || len(ciphertext) == 0 || len(aad) == 0 {
		return nil, errors.New("PKCS#11 unwrap unavailable")
	}
	if !wrappingAlgorithm(algorithm) {
		return nil, errors.New("PKCS#11 unwrap algorithm unavailable")
	}
	switch algorithm {
	case "aes-256":
		return session.unwrapAES(ctx, objectID, ciphertext)
	default:
		return session.unwrapRSA(ctx, objectID, ciphertext)
	}
}

// unwrapRSA is the original path: CKM_RSA_PKCS_OAEP against the private half of an asymmetric KEK.
// The result is the unwrapped frame directly, because RSA-OAEP returns plaintext bytes from
// Decrypt, not a key handle.
func (session *pkcs11Session) unwrapRSA(ctx context.Context, objectID string, ciphertext []byte) ([]byte, error) {
	if err := session.privateUsable(ctx); err != nil {
		return nil, errors.New("PKCS#11 unwrap unavailable")
	}
	key, err := session.findObject(objectID, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return nil, err
	}
	hashAlg, mgf, err := oaepParameters()
	if err != nil {
		return nil, err
	}
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_OAEP, pkcs11.NewOAEPParams(hashAlg, mgf, pkcs11.CKZ_DATA_SPECIFIED, nil))
	if err := session.module.DecryptInit(session.handle, []*pkcs11.Mechanism{mechanism}, key); err != nil {
		return nil, fmt.Errorf("PKCS#11 unwrap initialization: %w", err)
	}
	result, err := session.module.Decrypt(session.handle, ciphertext)
	if err != nil || len(result) == 0 {
		zero(result)
		if err != nil {
			return nil, fmt.Errorf("PKCS#11 unwrap execution: %w", err)
		}
		return nil, errors.New("PKCS#11 unwrap returned no data")
	}
	return result, nil
}

// unwrapAES unwraps an AES-KEY-WRAP-PAD envelope using a CKO_SECRET_KEY KEK on the token.
//
// C_UnwrapKey returns a HANDLE, not bytes — the new key lives on the token until the session ends.
// The plaintext is recovered by reading CKA_VALUE on that handle (with CKA_EXTRACTABLE set in the
// template), then the handle is destroyed so the unwrapped material only exists in memory for the
// duration of this call. This is the same shape as Derive() above: the token never releases the
// material to anyone outside a GetAttributeValue it can also deny.
func (session *pkcs11Session) unwrapAES(ctx context.Context, objectID string, ciphertext []byte) ([]byte, error) {
	if err := session.privateUsable(ctx); err != nil {
		return nil, errors.New("PKCS#11 unwrap unavailable")
	}
	kek, err := session.findKEKObject(objectID, pkcs11.CKO_SECRET_KEY)
	if err != nil {
		return nil, errors.New("PKCS#11 unwrap unavailable")
	}
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP_PAD, nil)
	unwrapped, err := session.module.UnwrapKey(session.handle, []*pkcs11.Mechanism{mechanism}, kek, ciphertext, sessionObjectTemplate())
	if err != nil {
		return nil, fmt.Errorf("PKCS#11 unwrap execution: %w", err)
	}
	defer func() { _ = session.module.DestroyObject(session.handle, unwrapped) }()
	values, err := session.module.GetAttributeValue(session.handle, unwrapped,
		[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
	if err != nil || len(values) == 0 || len(values[0].Value) == 0 {
		return nil, errors.New("PKCS#11 unwrap returned no data")
	}
	plaintext := values[0].Value
	// COPY OUT OF THE SLOT BEFORE THE DEFER RUNS DESTROYOBJECT.
	//
	// The C buffer backing values[0].Value is invalidated by the destroy on some modules. More
	// importantly, the copy creates a lifetime obligation that Derive (the function this was
	// modelled on) does not have: Derive returns the buffer the token filled, and callers zero
	// it on the way out via `defer zero(shared)` in provider.Execute. Returning a copy here
	// means the buffer the caller zeroes is NOT the buffer holding the data key — the original
	// plaintext slice lives in values[0].Value for as long as that attribute struct is reachable.
	// The data key is exactly the secret this whole path exists to return; leaving it in the
	// C-allocated attribute buffer after DestroyObject is the wrong place for it to stay, even
	// briefly. Zero the original before returning, the same way the wrap and derive paths do.
	defer zero(plaintext)
	out := make([]byte, len(plaintext))
	copy(out, plaintext)
	return out, nil
}

// sessionObjectTemplate is the shape of a session-local CKO_SECRET_KEY the driver stages on the
// token to receive material from a derivation or unwrap, then destroys before returning. It is
// deliberately generic: CKA_KEY_TYPE=CKK_GENERIC_SECRET is the closest fit for "32 bytes that is
// now a data key" and is what SoftHSM expects. CKA_EXTRACTABLE must be true because the driver
// reads the material back via C_GetAttributeValue(CKA_VALUE) before destroying the handle — the
// alternative is to leave it on the token, which would survive past the session.
func sessionObjectTemplate() []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}
}

// Wrap is the inverse of Unwrap — see the comment on the Session interface. It is on the driver so
// the test suite can construct a real AES-KEY-WRAP-PAD envelope on the token and then exercise the
// unwrap path against it: a wrapped frame produced by AEAD on the host against a value the token
// doesn't know has nothing to prove, because the assertion would reduce to "the value we typed in
// matches the value we typed in".
//
// The RSA branch duplicates the wrap path that lives in provider.Execute rather than calling it —
// the provider path is gated on an explicit KEK-provenance check, and a test that wants to wrap
// against a known-bad KEK would otherwise have to thread a latched device to do it. Going through
// the driver keeps the wrap surface uniform with the unwrap one.
//
// ALGORITHM-DEPENDENT LOGIN. The privateUsable check below is for aes-256 (CKO_SECRET_KEY is a
// private object and PKCS#11 hides private objects from a logged-out session). RSA-OAEP wrap only
// reads CKA_PUBLIC_KEY_INFO, which a logged-out session can see, so its privateUsable check is
// redundant; leaving it in is the conservative shape, and the per-algorithm split inside the
// switch below documents the asymmetry rather than hiding it.
//
// TRAP if this method is wired in as the production entry for aes-256 wrap (#194 item 2):
// provider.go:208-215 records the same shape of defect for key-agreement, where the operation
// case sat above the PIN block and could not have worked on a real module. The login order
// matters: a caller that routes to session.Wrap without first calling session.Login will fail at
// the privateUsable check above, not at C_WrapKey. Cross-reference provider.go:210 if a future
// change moves the call site.
func (session *pkcs11Session) Wrap(ctx context.Context, objectID, algorithm string, plaintext, aad []byte) ([]byte, error) {
	if err := session.privateUsable(ctx); err != nil || len(plaintext) == 0 {
		return nil, errors.New("PKCS#11 wrap unavailable")
	}
	if !wrappingAlgorithm(algorithm) {
		return nil, errors.New("PKCS#11 wrap algorithm unavailable")
	}
	switch algorithm {
	case "aes-256":
		// AES-KEY-WRAP-PAD itself is AAD-blind — the AAD binding for aes-256 lives in the
		// regalia frame layout (keywrap.OpenFrame re-verifies the SHA256(label) prefix on
		// unwrap) and is the caller's responsibility to construct. The legacy AAD precondition
		// on Wrap as a whole came from RSA-OAEP, which genuinely uses aad as the OAEP label;
		// applying it here would make a precondition that reads as meaningful enforce nothing,
		// because the aes-256 path passes aad to a code that ignores it.
		return session.wrapAES(ctx, objectID, plaintext)
	default:
		return session.wrapRSA(ctx, objectID, algorithm, plaintext, aad)
	}
}

func (session *pkcs11Session) wrapRSA(ctx context.Context, objectID, algorithm string, plaintext, aad []byte) ([]byte, error) {
	if err := session.privateUsable(ctx); err != nil {
		return nil, errors.New("PKCS#11 wrap unavailable")
	}
	if len(aad) == 0 {
		return nil, errors.New("PKCS#11 wrap unavailable: RSA-OAEP requires a non-empty AAD as the OAEP label")
	}
	publicKey, err := session.PublicKey(ctx, objectID)
	if err != nil {
		return nil, errors.New("PKCS#11 wrap unavailable")
	}
	defer zero(publicKey)
	wrapped, err := keywrap.RSAOAEP(publicKey, plaintext, aad, algorithm)
	if err != nil {
		return nil, errors.New("PKCS#11 wrap unavailable")
	}
	return wrapped, nil
}

// wrapAES stages the plaintext as a session CKO_SECRET_KEY on the token, runs C_WrapKey with
// CKM_AES_KEY_WRAP_PAD against the KEK, and destroys the staging object before returning.
//
// CKA_EXTRACTABLE is true on the staging key because PKCS#11 requires the key BEING WRAPPED to
// be extractable (CKR_KEY_UNEXTRACTABLE otherwise — measured on SoftHSM). The wrapping key (the
// KEK) is the one whose extractability matters for production safety, and the guard in
// AssertKEKNonExportable already refuses a KEK that is extractable. CKA_SENSITIVE=false is what
// lets CreateObject accept the plaintext value in the template; the staging key lives only for
// the duration of one C_WrapKey round trip and is destroyed by the defer.
func (session *pkcs11Session) wrapAES(ctx context.Context, objectID string, plaintext []byte) ([]byte, error) {
	if err := session.privateUsable(ctx); err != nil {
		return nil, errors.New("PKCS#11 wrap unavailable")
	}
	kek, err := session.findKEKObject(objectID, pkcs11.CKO_SECRET_KEY)
	if err != nil {
		return nil, errors.New("PKCS#11 wrap unavailable")
	}
	stageTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, plaintext),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}
	stage, err := session.module.CreateObject(session.handle, stageTemplate)
	if err != nil {
		return nil, fmt.Errorf("PKCS#11 wrap staging: %w", err)
	}
	defer func() { _ = session.module.DestroyObject(session.handle, stage) }()

	mechanism := pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_WRAP_PAD, nil)
	wrapped, err := session.module.WrapKey(session.handle, []*pkcs11.Mechanism{mechanism}, kek, stage)
	if err != nil || len(wrapped) == 0 {
		if err != nil {
			return nil, fmt.Errorf("PKCS#11 wrap execution: %w", err)
		}
		return nil, errors.New("PKCS#11 wrap returned no data")
	}
	return wrapped, nil
}

func (session *pkcs11Session) PublicKey(ctx context.Context, objectID string) ([]byte, error) {
	if err := session.usable(ctx); err != nil {
		return nil, errors.New("PKCS#11 public key unavailable")
	}
	key, err := session.findObject(objectID, pkcs11.CKO_PUBLIC_KEY)
	if err != nil {
		return nil, err
	}
	keyTypeAttributes, err := session.module.GetAttributeValue(session.handle, key, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
	})
	if err != nil {
		return nil, errors.New("PKCS#11 public key unavailable")
	}
	keyType := attributeUint(keyTypeAttributes, pkcs11.CKA_KEY_TYPE)
	requested := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil), pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
	}
	if keyType == pkcs11.CKK_RSA {
		requested = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, nil), pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, nil),
		}
	}
	attributes, err := session.module.GetAttributeValue(session.handle, key, requested)
	if err != nil {
		return nil, errors.New("PKCS#11 public key unavailable")
	}
	attributes = append(attributes, pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType))
	return marshalPublicKey(attributes)
}

func (session *pkcs11Session) Close() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return nil
	}
	var logoutErr error
	if session.loggedIn {
		logoutErr = session.module.Logout(session.handle)
	}
	closeErr := session.module.CloseSession(session.handle)
	session.closed = true
	session.loggedIn = false
	if logoutErr != nil || closeErr != nil {
		return errors.New("PKCS#11 session close failed")
	}
	return nil
}

func (session *pkcs11Session) usable(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return errors.New("PKCS#11 session is closed")
	}
	return nil
}

func (session *pkcs11Session) privateUsable(ctx context.Context) error {
	if err := session.usable(ctx); err != nil {
		return err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.loggedIn {
		return errors.New("PKCS#11 login required")
	}
	return nil
}

func (session *pkcs11Session) findObject(objectID string, class uint) (pkcs11.ObjectHandle, error) {
	id, err := hex.DecodeString(objectID)
	if err != nil || len(id) == 0 || len(id) > 64 {
		return 0, errors.New("invalid PKCS#11 object identifier")
	}
	if err := session.module.FindObjectsInit(session.handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class), pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}); err != nil {
		return 0, errors.New("PKCS#11 object lookup failed")
	}
	objects, more, findErr := session.module.FindObjects(session.handle, 2)
	finalErr := session.module.FindObjectsFinal(session.handle)
	if findErr != nil || finalErr != nil || more || len(objects) != 1 {
		return 0, errors.New("PKCS#11 object lookup failed")
	}
	return objects[0], nil
}

// findKEKObject locates the object holding a KEK's attributes, trying each class in turn and
// returning the first that answers.
//
// A KEK IS NOT ALWAYS A KEY PAIR. The guards below were written for RSA and asked for
// CKO_PUBLIC_KEY and CKO_PRIVATE_KEY by name. An AES KEK is a single CKO_SECRET_KEY object and has
// neither, so both guards returned "PKCS#11 object lookup failed" for it — measured against a real
// SoftHSM token — and the provider quarantined the device as kek-provenance-unreadable. Fail-closed,
// but blaming provenance for what was a guard looking in the wrong drawer, which would have cost
// whoever lands the symmetric driver branch an afternoon inside their own code.
//
// The classes are tried in the order that keeps existing behaviour identical: an asymmetric KEK
// still resolves to the same object it always did, and the secret-key attempt only happens when
// that finds nothing.
func (session *pkcs11Session) findKEKObject(objectID string, classes ...uint) (pkcs11.ObjectHandle, error) {
	// A CALL WITH NO CLASSES MUST NOT LOOK LIKE A FOUND OBJECT. The loop below would not run,
	// lastErr would stay nil, and the zero handle would go back as a success — turning a
	// programmer error into an object reference the guards would then read attributes from.
	// Handle 0 is not a valid object, and a guard that reads nothing must refuse rather than
	// conclude anything about the key.
	if len(classes) == 0 {
		return 0, errors.New("PKCS#11 object lookup requires an object class")
	}
	var lastErr error
	for _, class := range classes {
		handle, err := session.findObject(objectID, class)
		if err == nil {
			return handle, nil
		}
		lastErr = err
	}
	return 0, lastErr
}

// AssertKEKGeneratedOnToken refuses a KEK whose key pair was not generated on the token.
//
// #6 requires that "production KEKs are non-exportable hardware keys and no software fallback
// exists", and nothing checked it. Measured against SoftHSM before this existed: a 2048-bit RSA
// key generated with openssl on the host and imported with CKA_EXTRACTABLE set wrapped a data key
// exactly as readily as the on-token key — 256 bytes, no complaint. The daemon called that
// envelope hardware-rooted. It was a file in a token-shaped box.
//
// WHY CKA_LOCAL, AND WHY ON THE PUBLIC KEY. The honest question is about the private half, but the
// wrap path deliberately never logs in — it needs only the public key, and PKCS#11 hides private
// objects from a logged-out session, so asking about CKA_EXTRACTABLE here would mean spending PIN
// budget on every seal. CKA_LOCAL on the public key answers a narrower question that is readable
// without login and is exactly the one that matters at wrap time: was this pair generated on the
// token, or did the private half exist somewhere else first? Verified logged out against SoftHSM
// ONLY: the generated pair reports local, the imported one does not. That is a SoftHSM answer, not
// a hardware one.
//
// ON AN SC-HSM BEHIND OPENSC, NO KEY HAS PASSED THIS (#447). Measured 2026-09-14 on the staging Pico
// HSM through opensc-pkcs11: a pair generated on the card and a DKEK-imported pair were both refused
// with ErrKEKNotTokenGenerated. The attribute was present and false on both. The refusal direction
// held, but nothing passed. Under D1 (doc/REQUIREMENTS.md) a Pico measurement informs no production
// decision. The Nitrokey HSM 2 uses the same OpenSC driver, so the same answer is plausible there
// and still unmeasured. If it holds, this guard refuses every production KEK, not only restored ones,
// and on-token provenance has to come from somewhere other than a PKCS#11 attribute.
//
// A DKEK-RESTORED KEK WILL FAIL THIS, AND THAT IS UNRESOLVED. #6's other half wants backup and
// restore to work without the original token, which means importing KEK material into a
// replacement. Such a key is not local. ENVELOPE.md already records production restore as blocked
// pending that physical ceremony, and the Nitrokey measurement above has to come first. So this
// refusal breaks nothing that works today, and it names itself precisely so that whoever runs that
// ceremony finds this comment rather than a bare "unavailable".
func (session *pkcs11Session) AssertKEKGeneratedOnToken(ctx context.Context, objectID string) error {
	if err := session.usable(ctx); err != nil {
		return errors.New("PKCS#11 key attributes unavailable")
	}
	// CKA_LOCAL lives on the public half of a key pair and on a secret key itself.
	key, err := session.findKEKObject(objectID, pkcs11.CKO_PUBLIC_KEY, pkcs11.CKO_SECRET_KEY)
	if err != nil {
		return err
	}
	attributes, err := session.module.GetAttributeValue(session.handle, key,
		[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LOCAL, nil)})
	if err != nil {
		return errors.New("PKCS#11 key attributes unavailable")
	}
	local, present := attributeBool(attributes, pkcs11.CKA_LOCAL)
	if !present {
		// Refuse, but do not claim to know where the key came from.
		return errors.New("PKCS#11 key attributes unavailable")
	}
	if !local {
		return ErrKEKNotTokenGenerated
	}
	return nil
}

// AssertKEKNonExportable refuses a KEK whose private half the token will hand out.
//
// This is the question AssertKEKGeneratedOnToken cannot ask, and it is asked on the unwrap path
// because that path has already logged in — the private object is invisible to a logged-out
// session, measured against SoftHSM, so this costs nothing extra here and would cost a PIN
// spend anywhere else.
//
// The two are not redundant. CKA_LOCAL says the pair was born here; CKA_EXTRACTABLE says it can
// still be taken out. A key can be local and extractable, and a key can be non-extractable and
// imported. Refusing an envelope at release when its KEK is extractable is fail-closed in the
// direction that matters: the material has already been exposed, and continuing to serve from it
// would keep producing plaintext under a key an attacker may hold.
func (session *pkcs11Session) AssertKEKNonExportable(ctx context.Context, objectID string) error {
	if err := session.usable(ctx); err != nil {
		return errors.New("PKCS#11 key attributes unavailable")
	}
	// THE COMMENT ABOVE WAS A CLAIM ABOUT THE CALLER; THIS MAKES IT A PRECONDITION. Called before
	// Login, the private object is invisible, findObject fails, and the caller would read that as
	// "could not determine" for a key that is in fact fine. Saying so here means a future caller
	// that gets the order wrong is told what it did, rather than latching a healthy device.
	if !session.loggedIn {
		return ErrKEKLoginRequired
	}
	// Both attributes live on the private half of a key pair and on a secret key itself.
	key, err := session.findKEKObject(objectID, pkcs11.CKO_PRIVATE_KEY, pkcs11.CKO_SECRET_KEY)
	if err != nil {
		return err
	}
	attributes, err := session.module.GetAttributeValue(session.handle, key, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, nil),
	})
	if err != nil {
		return errors.New("PKCS#11 key attributes unavailable")
	}
	sensitive, sensitivePresent := attributeBool(attributes, pkcs11.CKA_SENSITIVE)
	extractable, extractablePresent := attributeBool(attributes, pkcs11.CKA_EXTRACTABLE)
	if !sensitivePresent || !extractablePresent {
		return errors.New("PKCS#11 key attributes unavailable")
	}
	if !sensitive || extractable {
		return ErrKEKExportable
	}
	return nil
}

// Derive performs ECDH on the token: CKM_ECDH1_DERIVE against the peer's public point.
//
// The peer key arrives as PKIX DER, which is what a caller can reasonably produce, but PKCS#11
// wants the raw EC point — so it is converted here rather than pushing that detail outward.
//
// The derived value is created as a session object with CKA_EXTRACTABLE set, read once, and
// destroyed. It is the raw shared secret: the provider immediately runs it through HKDF and never
// returns it, because an ECDH result is a curve coordinate rather than a uniform key.
func (session *pkcs11Session) Derive(ctx context.Context, objectID, algorithm string, peerPKIX []byte) ([]byte, error) {
	if err := session.privateUsable(ctx); err != nil || len(peerPKIX) == 0 {
		return nil, errors.New("PKCS#11 key agreement unavailable")
	}
	if !agreementAlgorithm(algorithm) {
		return nil, errors.New("PKCS#11 key agreement algorithm unavailable")
	}
	peerPoint, err := ecPointFromPKIX(peerPKIX, algorithm)
	if err != nil {
		return nil, err
	}
	private, err := session.findObject(objectID, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return nil, err
	}
	mechanism := pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE,
		pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peerPoint))
	derived, err := session.module.DeriveKey(session.handle, []*pkcs11.Mechanism{mechanism}, private, sessionObjectTemplate())
	if err != nil {
		return nil, errors.New("PKCS#11 key agreement unavailable")
	}
	// Destroy the session object whether or not the read succeeds.
	defer func() { _ = session.module.DestroyObject(session.handle, derived) }()

	values, err := session.module.GetAttributeValue(session.handle, derived,
		[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
	if err != nil || len(values) == 0 || len(values[0].Value) == 0 {
		return nil, errors.New("PKCS#11 key agreement unavailable")
	}
	return values[0].Value, nil
}

// wrappingAlgorithm is the single statement of which algorithms the envelope supports, so the
// Unwrap gate and the capability matrix cannot drift apart.
//
// AES-256 is unwrap-only because the wrap side is an open design question (#194): a symmetric KEK
// has no public half, so a wrap site has to hold the KEK the same way the unwrap site does, which
// conflicts with the multi-site model the rest of the custody manifest assumes. The driver
// implements both directions on the token (so an end-to-end round trip is testable), but the
// matrix — and provider.Execute — advertise unwrap only.
func wrappingAlgorithm(algorithm string) bool {
	switch algorithm {
	case "rsa2048", "rsa3072", "rsa4096", "aes-256":
		return true
	}
	return false
}

// agreementAlgorithm is the set the driver will derive with, and it must not be wider than what
// registry.Capabilities() advertises for key-agreement.
//
// THAT is the source of truth -- a compiled-in Go map. backend-capabilities.json is a published
// copy of it, and editing the JSON changes nothing the daemon does; I mutated it first while
// falsifying this and got a green that meant nothing.
//
// secp256k1 was in this set and is advertised for `sign` only. Nothing could reach it -- routing
// validates a binding against the matrix first -- so it was a widening rather than a defect, but it
// is the drift #75 warns about pointed the other way: when the driver accepts more than the matrix
// promises, the eventual reconciliation is somebody widening the MATRIX to match the driver, and
// that promises a mechanism no token has been shown to implement. The SmartCard-HSM's ECDH support
// for secp256k1 is unverified here, and advertising on an unverified mechanism is the defect that
// produced aes-256/unwrap.
//
// Held to the matrix by TestTheDriverRefusesEveryAlgorithmTheMatrixDoesNotAdvertise, in both
// directions.
func agreementAlgorithm(algorithm string) bool {
	switch algorithm {
	case "p256", "p384":
		return true
	}
	return false
}

// ecPointFromPKIX extracts the uncompressed EC point PKCS#11 expects from a PKIX public key.
func ecPointFromPKIX(der []byte, algorithm string) ([]byte, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("peer public key is malformed")
	}
	public, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("peer public key is not an EC key")
	}
	if !curveMatches(public, algorithm) {
		return nil, errors.New("peer public key is on a different curve than the token key")
	}
	if !public.Curve.IsOnCurve(public.X, public.Y) {
		// A point off the curve is the classic invalid-curve attack: it can leak the private
		// scalar one derivation at a time.
		return nil, errors.New("peer public key is not a point on the curve")
	}
	return elliptic.Marshal(public.Curve, public.X, public.Y), nil
}

func curveMatches(public *ecdsa.PublicKey, algorithm string) bool {
	switch algorithm {
	case "p256":
		return public.Curve == elliptic.P256()
	case "p384":
		return public.Curve == elliptic.P384()
	case "secp256k1":
		// secp256k1 is not in crypto/elliptic; the token key is on it and the peer key cannot be
		// validated here, so it is refused rather than passed through unchecked.
		return false
	}
	return false
}

func signingMechanism(algorithm string) (*pkcs11.Mechanism, error) {
	switch algorithm {
	case "secp256k1", "p256", "p384":
		return pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), nil
	case "ed25519":
		return pkcs11.NewMechanism(ckmEdDSA, nil), nil
	case "rsa2048", "rsa3072", "rsa4096":
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), nil
	default:
		return nil, errors.New("PKCS#11 signing algorithm unavailable")
	}
}

func marshalPublicKey(attributes []*pkcs11.Attribute) ([]byte, error) {
	values := make(map[uint][]byte, len(attributes))
	for _, attribute := range attributes {
		if attribute != nil {
			values[attribute.Type] = attribute.Value
		}
	}
	keyType := nativeUint(values[pkcs11.CKA_KEY_TYPE])
	if keyType == pkcs11.CKK_RSA {
		modulus := new(big.Int).SetBytes(values[pkcs11.CKA_MODULUS])
		exponent := int(new(big.Int).SetBytes(values[pkcs11.CKA_PUBLIC_EXPONENT]).Int64())
		if modulus.Sign() <= 0 || exponent < 3 {
			return nil, errors.New("invalid PKCS#11 RSA public key")
		}
		return x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: modulus, E: exponent})
	}
	params, point := values[pkcs11.CKA_EC_PARAMS], values[pkcs11.CKA_EC_POINT]
	var curveOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(params, &curveOID); err != nil {
		return nil, errors.New("invalid PKCS#11 EC parameters")
	}
	var rawPoint []byte
	if _, err := asn1.Unmarshal(point, &rawPoint); err != nil || len(rawPoint) == 0 {
		return nil, errors.New("invalid PKCS#11 EC point")
	}
	algorithm := publicKeyAlgorithm{Algorithm: oidPublicKeyEC, Parameters: asn1.RawValue{FullBytes: params}}
	if curveOID.Equal(oidEd25519) {
		algorithm = publicKeyAlgorithm{Algorithm: oidEd25519}
	}
	return asn1.Marshal(subjectPublicKeyInfo{Algorithm: algorithm, PublicKey: asn1.BitString{Bytes: rawPoint, BitLength: len(rawPoint) * 8}})
}

type publicKeyAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm publicKeyAlgorithm
	PublicKey asn1.BitString
}

func nativeUint(value []byte) uint {
	var result uint
	for index := len(value) - 1; index >= 0; index-- {
		result = result<<8 | uint(value[index])
	}
	return result
}

// ErrKEKNotTokenGenerated and ErrKEKExportable are the DEFINITIVE provenance answers: the token
// was asked and said no. Every other error out of these guards means the token was not asked
// successfully, which is a different thing an operator must not be told is the same — see the
// reason strings in provider.go.
var (
	ErrKEKNotTokenGenerated = errors.New("KEK was not generated on this token")
	ErrKEKExportable        = errors.New("KEK private key is exportable")
	// ErrKEKLoginRequired is separate so a caller that got the order wrong is told that, rather
	// than being handed the object-lookup failure it causes and reading it as a verdict.
	ErrKEKLoginRequired = errors.New("PKCS#11 private key attributes require a logged-in session")
)

// attributeBool reads a CK_BBOOL attribute and says whether the token actually supplied it.
//
// THE SECOND RETURN IS THE WHOLE POINT. An earlier version folded "absent" into a caller-supplied
// unsafe default, which fails closed correctly and then diagnoses wrongly: a token that simply
// does not publish CKA_LOCAL was reported as one that definitively generated the key elsewhere,
// and the operator was sent to re-provision. Refusing and misdiagnosing are separable, and only
// the refusal should be automatic.
func attributeBool(attributes []*pkcs11.Attribute, attributeType uint) (value, present bool) {
	for _, attribute := range attributes {
		if attribute != nil && attribute.Type == attributeType && len(attribute.Value) == 1 {
			return attribute.Value[0] != 0, true
		}
	}
	return false, false
}

func attributeUint(attributes []*pkcs11.Attribute, attributeType uint) uint {
	for _, attribute := range attributes {
		if attribute != nil && attribute.Type == attributeType {
			return nativeUint(attribute.Value)
		}
	}
	return ^uint(0)
}

func containsZero(value []byte) bool {
	for _, item := range value {
		if item == 0 {
			return true
		}
	}
	return false
}

// oaepParameters expresses keywrap.OAEPHash as PKCS#11 mechanism parameters.
//
// The card must unwrap with exactly the hash the KMS wrapped with. These used to be independent
// literals, so a change on one side produced envelopes the card silently could not open — and the
// first sign of it would have been a failed secret release in production. Deriving them here means
// an unsupported choice is a startup-visible error instead.
func oaepParameters() (hashAlg, mgf uint, err error) {
	switch keywrap.OAEPHash {
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, nil
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, nil
	default:
		return 0, 0, errors.New("PKCS#11 unwrap: no OAEP mechanism expresses the configured wrapping hash")
	}
}
