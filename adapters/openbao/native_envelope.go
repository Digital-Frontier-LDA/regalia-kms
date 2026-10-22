package openbaopoc

import (
	"bytes"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/envelope"
)

const nativeMaxPlaintext = 32 << 10
const nativeMaxEnvelope = 64 << 10

// Generation selection belongs to the KMS. This validates the object and
// authenticated context without a client-maintained historical allowlist.
func nativeEnvelope(data []byte, b binding) (*envelope.Envelope, error) {
	if len(data) == 0 || len(data) > nativeMaxEnvelope {
		return nil, errOperation
	}
	e, err := envelope.Parse(data)
	if err != nil {
		return nil, errOperation
	}
	canonical, err := e.Marshal()
	if err != nil || !bytes.Equal(data, canonical) || e.ObjectID != b.ObjectID || e.KEK.ID != b.ObjectID ||
		e.ContextDigest != contextDigest(b) || !generation.MatchString(e.KEK.Version) ||
		len(e.Ciphertext) <= 16 || len(e.Ciphertext) > nativeMaxPlaintext+16 {
		return nil, errOperation
	}
	return &e, nil
}
