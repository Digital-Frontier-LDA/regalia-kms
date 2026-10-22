package openbaopoc

import (
	"bytes"
	"context"
	"errors"
	"testing"

	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"google.golang.org/protobuf/proto"
)

func nativeFixtureConfig(c map[string]string) map[string]string {
	return map[string]string{"address": c["kms_url"], "server_name": c["server_name"], "ca_path": c["ca_path"],
		"cert_path": c["certificate_path"], "key_path": c["private_key_path"], "object_id": c["object_id"],
		"kms_purpose": c["kms_purpose"], "environment": c["environment"], "timeout": c["timeout"]}
}

func configuredNative(t *testing.T, c map[string]string) *NativeWrapper {
	t.Helper()
	w := NewNative()
	if _, err := w.SetConfig(context.Background(), wrappingConfig(c)); err != nil {
		t.Fatal(err)
	}
	return w
}

func TestNativeWrapperGenerationDiscoveryAndRecovery(t *testing.T) {
	f := newKMSFixtureMode(t, true)
	ctx := context.Background()
	w := configuredNative(t, nativeFixtureConfig(f.pki.config))
	if id, err := w.KeyId(ctx); err != nil || id != "" || f.audit.successful("seal-envelope") != 0 {
		t.Fatal("configuration must not discover a generation through a KMS call")
	}
	plain := []byte("synthetic-native-seal")
	old, err := w.Encrypt(ctx, plain)
	if err != nil || len(old.Iv) != 0 || old.KeyInfo.KeyId != "poc-seal-key@g1" {
		t.Fatal("native seal failed", err)
	}
	e, err := nativeEnvelope(old.Ciphertext, w.binding)
	if err != nil || len(e.Ciphertext) != len(plain)+16 {
		t.Fatal("blob is not the native payload envelope", err)
	}
	f.generations("retired", "active")
	current, err := w.Encrypt(ctx, plain)
	if err != nil || current.KeyInfo.KeyId != "poc-seal-key@g2" {
		t.Fatal("promotion was not discovered without configuration changes", err)
	}
	// SDK KeyInfo is informational, including when missing or mislabeled.
	for _, info := range []*wrapping.KeyInfo{nil, {KeyId: "other-object@unknown"}} {
		blob := proto.Clone(old).(*wrapping.BlobInfo)
		blob.KeyInfo = info
		out, err := w.Decrypt(ctx, blob, wrapping.WithKeyId("poc-seal-key@g1"))
		if err != nil || !bytes.Equal(out, plain) {
			t.Fatal("native envelope did not route its historical generation", err)
		}
		clear(out)
	}
	if id, _ := w.KeyId(ctx); id != current.KeyInfo.KeyId {
		t.Fatal("historical decrypt moved the sealing KeyId backwards")
	}
	f.generations("revoked", "active")
	denials := f.audit.outcomes("release-secret", "denied-kek-revoked")
	if out, err := w.Decrypt(ctx, old); !errors.Is(err, errOperation) || len(out) != 0 {
		t.Fatal("revoked generation released plaintext")
	}
	if f.audit.outcomes("release-secret", "denied-kek-revoked") <= denials {
		t.Fatal("revocation did not reach the KMS registry")
	}
	out, err := w.Decrypt(ctx, current)
	if err != nil || !bytes.Equal(out, plain) {
		t.Fatal("predecessor revocation broke the current generation", err)
	}
	clear(out)
}

func TestNativeWrapperRefusesCallerOptionsAndTampering(t *testing.T) {
	f := newKMSFixtureMode(t, true)
	ctx := context.Background()
	w := configuredNative(t, nativeFixtureConfig(f.pki.config))
	blob, err := w.Encrypt(ctx, []byte("synthetic-native-boundary"))
	if err != nil {
		t.Fatal(err)
	}
	for _, options := range [][]wrapping.Option{{wrapping.WithAad([]byte{1})}, {wrapping.WithKeyId("another-object@g1")}, {wrapping.WithKeyId("poc-seal-key@")}, {wrapping.WithConfigMap(map[string]string{"key_version": "g1"})}} {
		before := f.audit.successful("seal-envelope") + f.audit.successful("release-secret")
		if got, err := w.Encrypt(ctx, []byte{1}, options...); got != nil || !errors.Is(err, errOperation) {
			t.Fatal("invalid encrypt options accepted")
		}
		if got, err := w.Decrypt(ctx, blob, options...); len(got) != 0 || !errors.Is(err, errOperation) {
			t.Fatal("invalid decrypt options accepted")
		}
		if f.audit.successful("seal-envelope")+f.audit.successful("release-secret") != before {
			t.Fatal("invalid options reached a successful KMS operation")
		}
	}
	for _, part := range []string{"nil", "iv", "object", "context", "ciphertext", "generation", "duplicate", "oversize"} {
		t.Run(part, func(t *testing.T) {
			bad := proto.Clone(blob).(*wrapping.BlobInfo)
			e, err := nativeEnvelope(bad.Ciphertext, w.binding)
			if err != nil {
				t.Fatal(err)
			}
			switch part {
			case "nil":
				bad = nil
			case "iv":
				bad.Iv = []byte{1}
			case "object":
				e.ObjectID = "another-object"
			case "context":
				e.ContextDigest = "sha256:" + string(bytes.Repeat([]byte{'a'}, 64))
			case "ciphertext":
				e.Ciphertext[0] ^= 1
			case "generation":
				e.KEK.Version = "g404"
			}
			if bad != nil && part != "iv" {
				bad.Ciphertext, _ = e.Marshal()
			}
			if part == "duplicate" {
				bad.Ciphertext = append([]byte(`{"version":2,`), bad.Ciphertext[1:]...)
			}
			if part == "oversize" {
				bad.Ciphertext = bytes.Repeat([]byte{'x'}, nativeMaxEnvelope+1)
			}
			if out, err := w.Decrypt(ctx, bad); len(out) != 0 || !errors.Is(err, errOperation) {
				t.Fatal("tampered native blob released plaintext")
			}
		})
	}
	for _, plain := range [][]byte{nil, {}, bytes.Repeat([]byte{1}, nativeMaxPlaintext+1)} {
		if blob, err := w.Encrypt(ctx, plain); blob != nil || !errors.Is(err, errOperation) {
			t.Fatal("empty or oversized payload accepted")
		}
	}
}
