package openbaopoc

import (
	"context"
	"crypto"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/internal/registry"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

func TestExternalRefusesSignatureFromReplacedMaterial(t *testing.T) {
	f := newSigningFixture(t, "p256", "sha256", testSigner(t, "p256"))
	_, key := configuredExternal(t, f)
	k := key.(*externalKey)
	replacement := softwareSigning{testSigner(t, "p256")}
	k.client.http.Transport = responseTransport(func(r *http.Request) (*http.Response, error) {
		var doc versionedRequest
		if json.NewDecoder(r.Body).Decode(&doc) != nil {
			t.Fatal("invalid request")
		}
		sig, _, err := replacement.Execute(r.Context(), registry.Route{Algorithm: "p256"}, "sign", "", doc.ContentType, doc.Payload, nil)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]any{"request_id": r.Header.Get("X-Request-ID"), "operation_id": "synthetic-op", "object_id": doc.ObjectID, "content_type": "application/octet-stream", "result_base64": sig})
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}}, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})
	if sig, err := k.Sign(context.Background(), &kms.SignOptions{Data: []byte{1}, SignerOpts: crypto.SHA256}); len(sig) != 0 || err == nil {
		t.Fatal("replaced key bypassed the immutable public-key pin")
	}
}
