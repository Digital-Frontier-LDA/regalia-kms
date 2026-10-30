package openbaopoc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
)

func historicalVersions(current, text string) (map[string]bool, error) {
	if current == "" {
		if text != "" {
			return nil, errConfig
		}
		return nil, nil
	}
	if !generation.MatchString(current) {
		return nil, errConfig
	}
	allowed := map[string]bool{}
	if text == "" {
		return allowed, nil
	}
	items := strings.Split(text, ",")
	if len(items) > 16 {
		return nil, errConfig
	}
	for _, version := range items {
		if !generation.MatchString(version) || version == current || allowed[version] {
			return nil, errConfig
		}
		allowed[version] = true
	}
	return allowed, nil
}

func (w *Wrapper) decryptBinding(b binding, id string) (binding, error) {
	if id == keyID(b) {
		return b, nil
	}
	if b.KeyVersion == "" {
		return binding{}, errOperation
	}
	prefix := "regalia-poc-v2:" + b.ObjectID + ":"
	version, ok := strings.CutPrefix(id, prefix)
	w.mu.RLock()
	allowed := w.historical[version]
	w.mu.RUnlock()
	if !ok || !allowed {
		return binding{}, errOperation
	}
	b.KeyVersion = version
	return b, nil
}

func contextDigest(b binding) string {
	digest := sha256.Sum256(envelope.ReleaseContext(b.ObjectID, b.Purpose, b.Environment))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validInnerEnvelope(data []byte, b binding) bool {
	e, err := envelope.Parse(data)
	if err != nil {
		return false
	}
	canonical, err := e.Marshal()
	return err == nil && bytes.Equal(canonical, data) && e.ObjectID == b.ObjectID && e.KEK.ID == b.ObjectID &&
		e.KEK.Version == b.KeyVersion && e.ContextDigest == contextDigest(b) &&
		len(e.Ciphertext) == 32+16
}
