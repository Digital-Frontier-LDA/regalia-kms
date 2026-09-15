// Package sopsrpc is the minimal wire-compatible subset of the upstream SOPS
// keyservice.proto. Field/method numbers are pinned to getsops/sops v3.13.3.
package sopsrpc

import (
	"context"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Key struct {
	KmsKey *KmsKey `protobuf:"bytes,1,opt,name=kms_key,json=kmsKey,proto3" json:"kms_key,omitempty"`
}

func (m *Key) Reset()         { *m = Key{} }
func (m *Key) String() string { return proto.CompactTextString(m) }
func (*Key) ProtoMessage()    {}
func (m *Key) GetKmsKey() *KmsKey {
	if m != nil {
		return m.KmsKey
	}
	return nil
}

type KmsKey struct {
	Arn        string            `protobuf:"bytes,1,opt,name=arn,proto3" json:"arn,omitempty"`
	Role       string            `protobuf:"bytes,2,opt,name=role,proto3" json:"role,omitempty"`
	Context    map[string]string `protobuf:"bytes,3,rep,name=context,proto3" json:"context,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	AwsProfile string            `protobuf:"bytes,4,opt,name=aws_profile,json=awsProfile,proto3" json:"aws_profile,omitempty"`
}

func (m *KmsKey) Reset()         { *m = KmsKey{} }
func (m *KmsKey) String() string { return proto.CompactTextString(m) }
func (*KmsKey) ProtoMessage()    {}
func (m *KmsKey) GetArn() string {
	if m != nil {
		return m.Arn
	}
	return ""
}
func (m *KmsKey) GetRole() string {
	if m != nil {
		return m.Role
	}
	return ""
}
func (m *KmsKey) GetContext() map[string]string {
	if m != nil {
		return m.Context
	}
	return nil
}
func (m *KmsKey) GetAwsProfile() string {
	if m != nil {
		return m.AwsProfile
	}
	return ""
}

type EncryptRequest struct {
	Key       *Key   `protobuf:"bytes,1,opt,name=key,proto3"`
	Plaintext []byte `protobuf:"bytes,2,opt,name=plaintext,proto3"`
}

func (m *EncryptRequest) Reset()         { *m = EncryptRequest{} }
func (m *EncryptRequest) String() string { return proto.CompactTextString(m) }
func (*EncryptRequest) ProtoMessage()    {}
func (m *EncryptRequest) GetKey() *Key {
	if m != nil {
		return m.Key
	}
	return nil
}
func (m *EncryptRequest) GetPlaintext() []byte {
	if m != nil {
		return m.Plaintext
	}
	return nil
}

type EncryptResponse struct {
	Ciphertext []byte `protobuf:"bytes,1,opt,name=ciphertext,proto3"`
}

func (m *EncryptResponse) Reset()         { *m = EncryptResponse{} }
func (m *EncryptResponse) String() string { return proto.CompactTextString(m) }
func (*EncryptResponse) ProtoMessage()    {}

type DecryptRequest struct {
	Key        *Key   `protobuf:"bytes,1,opt,name=key,proto3"`
	Ciphertext []byte `protobuf:"bytes,2,opt,name=ciphertext,proto3"`
}

func (m *DecryptRequest) Reset()         { *m = DecryptRequest{} }
func (m *DecryptRequest) String() string { return proto.CompactTextString(m) }
func (*DecryptRequest) ProtoMessage()    {}
func (m *DecryptRequest) GetKey() *Key {
	if m != nil {
		return m.Key
	}
	return nil
}
func (m *DecryptRequest) GetCiphertext() []byte {
	if m != nil {
		return m.Ciphertext
	}
	return nil
}

type DecryptResponse struct {
	Plaintext []byte `protobuf:"bytes,1,opt,name=plaintext,proto3"`
}

func (m *DecryptResponse) Reset()         { *m = DecryptResponse{} }
func (m *DecryptResponse) String() string { return proto.CompactTextString(m) }
func (*DecryptResponse) ProtoMessage()    {}

type KeyServiceServer interface {
	Encrypt(context.Context, *EncryptRequest) (*EncryptResponse, error)
	Decrypt(context.Context, *DecryptRequest) (*DecryptResponse, error)
}
type UnimplementedKeyServiceServer struct{}

func (UnimplementedKeyServiceServer) Encrypt(context.Context, *EncryptRequest) (*EncryptResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method Encrypt not implemented")
}
func (UnimplementedKeyServiceServer) Decrypt(context.Context, *DecryptRequest) (*DecryptResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method Decrypt not implemented")
}
func RegisterKeyServiceServer(r grpc.ServiceRegistrar, s KeyServiceServer) {
	r.RegisterService(&KeyService_ServiceDesc, s)
}

// THE UNCHECKED TYPE ASSERTIONS IN THESE TWO HANDLERS ARE SAFE TODAY, AND ONE OF THEM STOPS
// BEING SAFE IF SOMEBODY ADDS AN INTERCEPTOR. Swept 2026-09-07: these are the only unchecked
// assertions in non-test code in the repository, so the next person to run that sweep lands
// here, and this is the answer rather than a re-derivation.
//
//	s.(KeyServiceServer)        cannot fail. RegisterKeyServiceServer takes a TYPED
//	                            KeyServiceServer, so the value reaching `s any` was checked by
//	                            the compiler at the single call site in server.go.
//	request.(*EncryptRequest)   unreachable. It is inside the `interceptor != nil` branch, and
//	                            no UnaryInterceptor or ChainUnaryInterceptor is installed
//	                            anywhere in this repository.
//
// The second is the one to watch: install an interceptor and that branch becomes live, at which
// point the assertion is only as safe as the interceptor's contract to pass the handler the
// request it was given. Comma-ok alone is not the fix if that day comes: its second return is a
// BOOL, and ignoring it leaves the FIRST return at its zero value -- a nil *EncryptRequest
// travelling into Encrypt instead of a loud panic at the assertion. Comma-ok is only an
// improvement if the bool is acted on, so the decision to make then is what a misbehaving
// interceptor should produce, and to say so here.
func encryptHandler(s any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(EncryptRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return s.(KeyServiceServer).Encrypt(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: s, FullMethod: "/KeyService/Encrypt"}
	return interceptor(ctx, in, info, func(ctx context.Context, request any) (any, error) {
		return s.(KeyServiceServer).Encrypt(ctx, request.(*EncryptRequest))
	})
}

// decryptHandler carries the SAME two unchecked assertions as encryptHandler, for the same
// reasons and with the same tripwire: see the comment above encryptHandler. Noted here
// rather than left to inference, because the sweep that produced that comment covered all
// six assertions in this file and an explanation attached to only one of the two handlers
// documents half of it.
func decryptHandler(s any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(DecryptRequest)
	if err := decode(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return s.(KeyServiceServer).Decrypt(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: s, FullMethod: "/KeyService/Decrypt"}
	return interceptor(ctx, in, info, func(ctx context.Context, request any) (any, error) {
		return s.(KeyServiceServer).Decrypt(ctx, request.(*DecryptRequest))
	})
}

var KeyService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "KeyService", HandlerType: (*KeyServiceServer)(nil),
	Methods:  []grpc.MethodDesc{{MethodName: "Encrypt", Handler: encryptHandler}, {MethodName: "Decrypt", Handler: decryptHandler}},
	Metadata: "keyservice/keyservice.proto",
}
