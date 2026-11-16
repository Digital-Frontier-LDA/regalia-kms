package openbaopoc

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"github.com/openbao/go-kms-wrapping/v2/kms"
	"net/http"
	"testing"
	"time"
)

func TestExternalSigningRetryLimitAndCloseCancellation(t *testing.T) {
	f := newSigningFixture(t, "p256", "sha256", testSigner(t, "p256"))
	p, key := configuredExternal(t, f)
	k := key.(*externalKey)
	calls := 0
	seen := map[string]bool{}
	k.client.http.Transport = responseTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		var doc versionedRequest
		if json.NewDecoder(r.Body).Decode(&doc) != nil || doc.Format != "" || doc.ContentType != "application/vnd.regalia.digest" || seen[doc.Context.Nonce] {
			t.Fatal("bad signing request or replay")
		}
		seen[doc.Context.Nonce] = true
		return transportResponse(r, 503, "BACKEND_UNAVAILABLE", true), nil
	})
	_, err := k.Sign(context.Background(), &kms.SignOptions{Data: []byte{1}, SignerOpts: crypto.SHA256})
	var apiErr *APIError
	if calls != 2 || !errors.As(err, &apiErr) || apiErr.Code != "BACKEND_UNAVAILABLE" {
		t.Fatal("signing exceeded one retry", calls, err)
	}
	started := make(chan struct{})
	k.client.http.Transport = responseTransport(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	done := make(chan error, 1)
	go func() {
		_, err := k.Sign(context.Background(), &kms.SignOptions{Data: []byte{1}, SignerOpts: crypto.SHA256})
		done <- err
	}()
	<-started
	p.Close(context.Background())
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("close did not cancel request", err)
		}
	case <-time.After(time.Second):
		t.Fatal("provider close left signing in flight")
	}
}
