module github.com/Digital-Frontier-LDA/regalia-kms

go 1.26.11

require (
	github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops v0.0.0
	github.com/go-piv/piv-go/v2 v2.6.0
	github.com/google/go-tpm v0.9.8
	github.com/miekg/pkcs11 v1.1.2
	go.etcd.io/etcd/api/v3 v3.7.3
	go.etcd.io/etcd/client/v3 v3.6.15
	go.uber.org/zap v1.28.0
	golang.org/x/sys v0.49.0
)

require (
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.6.15 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260803160001-6ac0973c030d // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260803160001-6ac0973c030d // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops => ./adapters/sops
