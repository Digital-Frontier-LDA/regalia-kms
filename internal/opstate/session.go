package opstate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SESSION KEY (ADR-0002 D32, #432; 48 and 95's design). The daemon makes an Ed25519 key pair at each start
// and keeps the private half in its memory only. It signs this server's operational-state entries (spends,
// high-water marks) with it: a TPM operation per spend would cost a TPM round trip on every approval-gated
// signature. The public half is published in SessionKeyFile; regalia-admission puts it in the lease request,
// the peer's re-attestation binds it, and the TPM-quoted lease names it. So:
//
//   - an entry signed by this key is this daemon instance's, as attested by the lease that named the key
//     (stored once per boot at sessions/<node>/<boot_id>);
//   - the Gate refuses a lease that names another key: a lease follows the daemon instance it was made for,
//     and a restarted daemon serves only once a fresh lease names its new key.
const SessionKeyFile = "session-key.json"

// SessionKey is this daemon instance's signing key.
type SessionKey struct {
	private ed25519.PrivateKey
	Public  ed25519.PublicKey
	BootID  string
	Started int64 // CLOCK_BOOTTIME in milliseconds when the daemon made it
}

// NewSessionKey makes a key pair from the kernel's random source.
func NewSessionKey(bootID string, startedMs int64) (*SessionKey, error) {
	if !bootIDPattern.MatchString(bootID) || startedMs < 0 {
		return nil, errors.New("opstate: a session key needs the kernel's boot ID and the daemon's start time")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("opstate: no session key could be made: %w", err)
	}
	return &SessionKey{private: private, Public: public, BootID: bootID, Started: startedMs}, nil
}

// Hex is the public key as the lease request and the entries name it: 64 lowercase hex.
func (k *SessionKey) Hex() string { return hex.EncodeToString(k.Public) }

// Sign signs domain ‖ message. The domain is required, so no signature made for one kind of entry can be
// presented as another's.
func (k *SessionKey) Sign(domain string, message []byte) ([]byte, error) {
	if len(domain) == 0 || domain[len(domain)-1] != 0 {
		return nil, errors.New("opstate: a signing domain ends with a NUL byte, as every regalia domain does")
	}
	return ed25519.Sign(k.private, append([]byte(domain), message...)), nil
}

// Publish writes SessionKeyFile in dir (the daemon's runtime directory): {"boot_id", "daemon_started",
// "session_key"}, by temp+rename, 0644. The private half is never written anywhere.
func (k *SessionKey) Publish(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("opstate: the session key's directory must be absolute and clean")
	}
	encoded, err := json.Marshal(struct {
		BootID        string `json:"boot_id"`
		DaemonStarted int64  `json:"daemon_started"`
		SessionKey    string `json:"session_key"`
	}{k.BootID, k.Started, k.Hex()})
	if err != nil {
		return err
	}
	return replaceFile(dir, SessionKeyFile, append(encoded, '\n'))
}

// replaceFile writes name in dir by temp+rename, 0644; a temporary that is not renamed is removed.
func replaceFile(dir, name string, contents []byte) error {
	temporary, err := os.CreateTemp(dir, "."+name+".")
	if err != nil {
		return fmt.Errorf("%s cannot be written: %w", name, err)
	}
	path := temporary.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("%s cannot be written: %w", name, err)
	}
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(path, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("%s cannot be replaced: %w", name, err)
	}
	ok = true
	return nil
}
