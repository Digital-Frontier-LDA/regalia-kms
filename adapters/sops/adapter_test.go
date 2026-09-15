package sopsadapter

import (
	"context"
	"errors"
	"testing"

	"github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops/sopsrpc"
)

type mockKMS struct {
	wrapResult   []byte
	unwrapResult []byte
	err          error
	requests     []Request
}

func (client *mockKMS) Wrap(_ context.Context, request Request) ([]byte, error) {
	client.requests = append(client.requests, request)
	return append([]byte(nil), client.wrapResult...), client.err
}

func (client *mockKMS) Unwrap(_ context.Context, request Request) ([]byte, error) {
	client.requests = append(client.requests, request)
	return append([]byte(nil), client.unwrapResult...), client.err
}

func sopsKey() *sopsrpc.Key {
	return &sopsrpc.Key{KmsKey: &sopsrpc.KmsKey{
		Arn: "arn:aws:kms:regalia:000000000000:key/production-sops",
		Context: map[string]string{
			"repository": "regalia-kms/infrastructure", "path": "clusters/prod/secrets.enc.yaml",
			"environment": "production", "purpose": "sops-data-key",
		},
	}}
}

func TestEncryptAndDecryptMapOnlyToKMS(t *testing.T) {
	client := &mockKMS{wrapResult: []byte("wrapped-envelope"), unwrapResult: []byte("01234567890123456789012345678901")}
	server := New(client)
	encrypted, err := server.Encrypt(context.Background(), &sopsrpc.EncryptRequest{Key: sopsKey(), Plaintext: []byte("01234567890123456789012345678901")})
	if err != nil || string(encrypted.Ciphertext) != "wrapped-envelope" {
		t.Fatalf("Encrypt() = %#v, %v", encrypted, err)
	}
	decrypted, err := server.Decrypt(context.Background(), &sopsrpc.DecryptRequest{Key: sopsKey(), Ciphertext: []byte("wrapped-envelope")})
	if err != nil || string(decrypted.Plaintext) != "01234567890123456789012345678901" {
		t.Fatalf("Decrypt() = %#v, %v", decrypted, err)
	}
	if len(client.requests) != 2 || client.requests[0].Operation != "wrap" || client.requests[1].Operation != "unwrap" ||
		client.requests[0].ObjectID != "production-sops" || client.requests[0].Path != "clusters/prod/secrets.enc.yaml" {
		t.Fatalf("KMS requests = %#v", client.requests)
	}
}

func TestRejectsOtherSOPSKeyTypesAndMalformedCarrierBeforeKMS(t *testing.T) {
	client := &mockKMS{}
	server := New(client)
	badContext := sopsKey()
	badContext.GetKmsKey().Context["path"] = "../escape.yaml"
	tests := []*sopsrpc.EncryptRequest{
		{Key: &sopsrpc.Key{}, Plaintext: []byte("data-key")},
		{Key: badContext, Plaintext: []byte("data-key")},
		{Key: sopsKey(), Plaintext: nil},
	}
	for _, request := range tests {
		if _, err := server.Encrypt(context.Background(), request); err == nil {
			t.Fatal("Encrypt() accepted malformed request")
		}
	}
	if len(client.requests) != 0 {
		t.Fatalf("KMS called: %#v", client.requests)
	}
}

func TestRejectsWrongEnvironmentAndWrongKeyBeforeKMS(t *testing.T) {
	client := &mockKMS{}
	server := New(client)
	wrongEnvironment := sopsKey()
	wrongEnvironment.GetKmsKey().Context["environment"] = "qa"
	wrongKey := sopsKey()
	wrongKey.GetKmsKey().Arn = "arn:aws:kms:us-east-1:123456789012:key/cloud-key"
	for _, key := range []*sopsrpc.Key{wrongEnvironment, wrongKey} {
		if _, err := server.Decrypt(context.Background(), &sopsrpc.DecryptRequest{Key: key, Ciphertext: []byte("wrapped")}); err == nil {
			t.Fatal("out-of-policy SOPS request accepted")
		}
	}
	if len(client.requests) != 0 {
		t.Fatalf("KMS called: %#v", client.requests)
	}
}

func TestKMSErrorsNeverReturnPlaintext(t *testing.T) {
	client := &mockKMS{unwrapResult: []byte("must-not-escape"), err: errors.New("denied with backend detail")}
	response, err := New(client).Decrypt(context.Background(), &sopsrpc.DecryptRequest{Key: sopsKey(), Ciphertext: []byte("wrapped")})
	if err == nil || response != nil || err.Error() != "KMS operation failed" {
		t.Fatalf("Decrypt() = %#v, %q", response, err)
	}
}
