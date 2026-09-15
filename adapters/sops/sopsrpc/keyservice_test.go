package sopsrpc

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// This package is a HAND-WRITTEN wire-compatible subset of upstream SOPS's keyservice.proto, not
// generated code, and its docstring says the names and numbers are pinned to getsops/sops v3.13.3.
// Nothing checked that. A drifted service name or method name does not fail to compile and does not
// fail a round trip against ourselves — it fails when the real `sops` binary dials the socket and
// cannot find the service, which is the one place this repository's tests do not reach.
//
// The interop test exercises a real round trip and covers the getters and the registration. What it
// cannot cover is the contract with a party that is not us.

func TestTheWireNamesArePinnedToUpstreamSOPS(t *testing.T) {
	if KeyService_ServiceDesc.ServiceName != "KeyService" {
		t.Fatalf("ServiceName = %q, want \"KeyService\": sops dials by this name and would not find the service",
			KeyService_ServiceDesc.ServiceName)
	}
	if KeyService_ServiceDesc.Metadata != "keyservice/keyservice.proto" {
		t.Fatalf("Metadata = %v, want the upstream proto path", KeyService_ServiceDesc.Metadata)
	}
	methods := map[string]bool{}
	for _, method := range KeyService_ServiceDesc.Methods {
		if method.Handler == nil {
			t.Fatalf("method %q has no handler", method.MethodName)
		}
		methods[method.MethodName] = true
	}
	for _, want := range []string{"Encrypt", "Decrypt"} {
		if !methods[want] {
			t.Fatalf("no %q method: sops calls /KeyService/%s and would get Unimplemented", want, want)
		}
	}
	if len(methods) != 2 {
		t.Fatalf("the descriptor exposes %d methods, want exactly Encrypt and Decrypt: %v", len(methods), methods)
	}
	if KeyService_ServiceDesc.HandlerType == nil {
		t.Fatal("HandlerType is nil, so grpc cannot type-check registrations")
	}
}

type recordingServer struct {
	encrypted *EncryptRequest
	decrypted *DecryptRequest
	err       error
}

func (s *recordingServer) Encrypt(_ context.Context, in *EncryptRequest) (*EncryptResponse, error) {
	s.encrypted = in
	if s.err != nil {
		return nil, s.err
	}
	return &EncryptResponse{Ciphertext: []byte("sealed")}, nil
}

func (s *recordingServer) Decrypt(_ context.Context, in *DecryptRequest) (*DecryptResponse, error) {
	s.decrypted = in
	if s.err != nil {
		return nil, s.err
	}
	return &DecryptResponse{Plaintext: []byte("opened")}, nil
}

func handlerFor(t *testing.T, method string) grpc.MethodHandler {
	t.Helper()
	for _, candidate := range KeyService_ServiceDesc.Methods {
		if candidate.MethodName == method {
			return candidate.Handler
		}
	}
	t.Fatalf("no handler for %q", method)
	return nil
}

// TestADecodeFailureIsReturnedRatherThanServed. The decode callback is grpc's, fed by bytes off the
// socket. A malformed frame must stop at the handler: passing a half-decoded request to the server
// would act on a message nobody sent.
func TestADecodeFailureIsReturnedRatherThanServed(t *testing.T) {
	broken := errors.New("truncated frame")
	for _, method := range []string{"Encrypt", "Decrypt"} {
		t.Run(method, func(t *testing.T) {
			server := &recordingServer{}
			out, err := handlerFor(t, method)(server, context.Background(),
				func(any) error { return broken }, nil)
			if !errors.Is(err, broken) {
				t.Fatalf("error = %v, want the decode error", err)
			}
			if out != nil {
				t.Fatalf("a response was produced from a request that did not decode: %#v", out)
			}
			if server.encrypted != nil || server.decrypted != nil {
				t.Fatal("the server was called with a request that did not decode")
			}
		})
	}
}

func TestTheHandlerPassesTheDecodedRequestThrough(t *testing.T) {
	server := &recordingServer{}
	out, err := handlerFor(t, "Encrypt")(server, context.Background(), func(target any) error {
		request, ok := target.(*EncryptRequest)
		if !ok {
			t.Fatalf("the handler asked to decode into %T, want *EncryptRequest", target)
		}
		request.Plaintext = []byte("secret")
		return nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if server.encrypted == nil || string(server.encrypted.GetPlaintext()) != "secret" {
		t.Fatalf("the server received %#v, want the decoded plaintext", server.encrypted)
	}
	if response, ok := out.(*EncryptResponse); !ok || string(response.Ciphertext) != "sealed" {
		t.Fatalf("the handler returned %#v", out)
	}
}

// TestAnInterceptorSeesTheRequestAndItsMethodName. grpc middleware — logging, metrics, auth — hangs
// off this path, and the FullMethod string is how it identifies the call. Nothing in this repository
// installs one today, so the branch is dead code until someone adds middleware and finds it broken.
func TestAnInterceptorSeesTheRequestAndItsMethodName(t *testing.T) {
	for _, test := range []struct {
		method     string
		fullMethod string
	}{
		{"Encrypt", "/KeyService/Encrypt"},
		{"Decrypt", "/KeyService/Decrypt"},
	} {
		t.Run(test.method, func(t *testing.T) {
			server := &recordingServer{}
			var sawMethod string
			var sawRequest any
			called := false

			out, err := handlerFor(t, test.method)(server, context.Background(),
				func(any) error { return nil },
				func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
					called = true
					sawMethod, sawRequest = info.FullMethod, request
					if info.Server != server {
						t.Fatal("the interceptor was not shown the server it wraps")
					}
					return handler(ctx, request)
				})
			if err != nil {
				t.Fatal(err)
			}
			if !called {
				t.Fatal("the interceptor was never called: middleware would be silently bypassed")
			}
			if sawMethod != test.fullMethod {
				t.Fatalf("FullMethod = %q, want %q — middleware keyed on the method name would attribute this call to the wrong one", sawMethod, test.fullMethod)
			}
			if sawRequest == nil {
				t.Fatal("the interceptor was shown a nil request")
			}
			if out == nil {
				t.Fatal("the interceptor path returned no response")
			}
			if server.encrypted == nil && server.decrypted == nil {
				t.Fatal("the interceptor path never reached the server")
			}
		})
	}
}

// TestTheUnimplementedServerRefusesCleanly. It exists so a future method added to the descriptor,
// or an embedder that forgets one, answers Unimplemented rather than panicking on a nil method set.
func TestTheUnimplementedServerRefusesCleanly(t *testing.T) {
	var server UnimplementedKeyServiceServer

	for name, call := range map[string]func() (any, error){
		"Encrypt": func() (any, error) { return server.Encrypt(context.Background(), &EncryptRequest{}) },
		"Decrypt": func() (any, error) { return server.Decrypt(context.Background(), &DecryptRequest{}) },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := call()
			if status.Code(err) != codes.Unimplemented {
				t.Fatalf("%s returned code %v, want Unimplemented: sops distinguishes an unimplemented method from a failing one and retries differently", name, status.Code(err))
			}
		})
	}
}
