module github.com/Digital-Frontier-LDA/regalia-kms

go 1.26.6

require (
	github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops v0.0.0
	github.com/go-piv/piv-go/v2 v2.6.0
	github.com/google/go-tpm v0.9.8
	github.com/miekg/pkcs11 v1.1.2
	go.etcd.io/etcd/api/v3 v3.6.15
	go.etcd.io/etcd/client/v3 v3.6.15
	go.uber.org/zap v1.27.0
	golang.org/x/sys v0.48.0
)

require (
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.26.3 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.6.15 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops => ./adapters/sops
