package sopsrpc

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
)

// These vectors were constructed from getsops/sops v3.13.3
// (26e2f4784ca61353082c32dbd987c25eda086dc9), keyservice/keyservice.proto
// and the context map key/value tags in the generated keyservice.pb.go.
// The context entries in the literal request prefix are in deterministic key order.
// All field numbers come from upstream, independently of this package's tags.
const sops3133RequestKey = "0ac0010abd010a3461726e3a6177733a6b6d733a726567616c69613a3030303030303030303030303a6b65792f70726f64756374696f6e2d736f7073" +
	"1a190a0b656e7669726f6e6d656e74120a70726f64756374696f6e" +
	"1a260a0470617468121e636c7573746572732f70726f642f736563726574732e656e632e79616d6c" +
	"1a180a07707572706f7365120d736f70732d646174612d6b6579" +
	"1a280a0a7265706f7369746f7279121a726567616c69612d6b6d732f696e667261737472756374757265"

func TestSOPS3133WireNumbers(t *testing.T) {
	key := &Key{KmsKey: &KmsKey{
		Arn: "arn:aws:kms:regalia:000000000000:key/production-sops",
		Context: map[string]string{
			"repository":  "regalia-kms/infrastructure",
			"path":        "clusters/prod/secrets.enc.yaml",
			"environment": "production",
			"purpose":     "sops-data-key",
		},
	}}
	for _, tc := range []struct {
		name    string
		wire    string
		value   proto.Message
		decoded proto.Message
	}{
		{"EncryptRequest", sops3133RequestKey + "1205636c656172", &EncryptRequest{Key: key, Plaintext: []byte("clear")}, &EncryptRequest{}},
		{"EncryptResponse", "0a067365616c6564", &EncryptResponse{Ciphertext: []byte("sealed")}, &EncryptResponse{}},
		{"DecryptRequest", sops3133RequestKey + "12067365616c6564", &DecryptRequest{Key: key, Ciphertext: []byte("sealed")}, &DecryptRequest{}},
		{"DecryptResponse", "0a05636c656172", &DecryptResponse{Plaintext: []byte("clear")}, &DecryptResponse{}},
		// Wire-only control: these two nonempty fields are refused by the adapter's carrier rules.
		{"RoleAndProfileTags", "0a0361726e1204726f6c651a060a016b120176220770726f66696c65",
			&KmsKey{Arn: "arn", Role: "role", Context: map[string]string{"k": "v"}, AwsProfile: "profile"}, &KmsKey{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatalf("invalid literal vector: %v", err)
			}
			buffer := proto.NewBuffer(nil)
			buffer.SetDeterministic(true)
			if err := buffer.Marshal(tc.value); err != nil {
				t.Fatalf("local deterministic marshal: %v", err)
			}
			if !bytes.Equal(buffer.Bytes(), want) {
				t.Errorf("serialized wire differs from v3.13.3 vector: got %x, want %x", buffer.Bytes(), want)
			}
			if err := proto.Unmarshal(want, tc.decoded); err != nil {
				t.Fatalf("decoding upstream literal: %v", err)
			}
			if !proto.Equal(tc.decoded, tc.value) {
				t.Errorf("decoded upstream literal differs: got %v, want %v", tc.decoded, tc.value)
			}
		})
	}
}

func TestSOPS3133FullMethods(t *testing.T) {
	upstream := map[string]string{"Encrypt": "/KeyService/Encrypt", "Decrypt": "/KeyService/Decrypt"}
	server := grpc.NewServer()
	RegisterKeyServiceServer(server, &recordingServer{})
	registered := map[string]bool{}
	for service, info := range server.GetServiceInfo() {
		for _, method := range info.Methods {
			if !method.IsClientStream && !method.IsServerStream {
				registered["/"+service+"/"+method.Name] = true
			}
		}
	}
	for _, method := range []string{"Encrypt", "Decrypt"} {
		t.Run(method, func(t *testing.T) {
			want := upstream[method]
			if !registered[want] {
				t.Fatalf("upstream unary method %q is not registered", want)
			}
			req := &recordingServer{}
			called := false
			out, err := handlerFor(t, method)(req, context.Background(), func(any) error { return nil },
				func(ctx context.Context, message any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
					called = true
					if info.FullMethod != want {
						t.Errorf("interceptor reports %q, want upstream method %q", info.FullMethod, want)
					}
					return next(ctx, message)
				})
			if err != nil || !called || out == nil {
				t.Fatalf("unary dispatch did not complete: called=%t, result=%T, err=%v", called, out, err)
			}
			if (req.encrypted != nil) != (method == "Encrypt") || (req.decrypted != nil) != (method == "Decrypt") {
				t.Fatal("unary dispatch reached the wrong method")
			}
		})
	}
}
