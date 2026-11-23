package openbaopoc

import (
	"bytes"
	"context"
	"testing"
)

func TestNativeClientSealsPayloadDirectly(t *testing.T) {
	f := newKMSFixtureMode(t, true)
	w := configuredWrapper(t, f.pki.config)
	c := w.client.(*versionedClient)
	for _, size := range []int{1, 32, 4096, nativeMaxPlaintext} {
		plain := bytes.Repeat([]byte{42}, size)
		req, err := request(c.binding, "seal-envelope", plain, nil)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := c.seal(context.Background(), req, nativeMaxEnvelope)
		if err != nil {
			t.Fatal("seal failed", size, err)
		}
		e, err := nativeEnvelope(doc, c.binding)
		if err != nil || len(e.Ciphertext) != size+16 || e.KEK.Version != "g1" {
			t.Fatal("native envelope does not protect the actual payload", size, err)
		}
		req, err = request(c.binding, "release-secret", doc, nil)
		if err != nil {
			t.Fatal(err)
		}
		out, err := c.callBounded(context.Background(), req, "release-secret", versionedRequest{Payload: doc}, "application/vnd.regalia.secret", nativeMaxPlaintext)
		if err != nil || !bytes.Equal(out, plain) {
			t.Fatal("native release failed", size, err)
		}
		clear(out)
	}
}
