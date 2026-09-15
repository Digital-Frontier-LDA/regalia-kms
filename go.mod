module github.com/Digital-Frontier-LDA/regalia-kms

go 1.26.6

require (
	github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops v0.0.0
	github.com/go-piv/piv-go/v2 v2.6.0
	github.com/miekg/pkcs11 v1.1.2
	golang.org/x/sys v0.48.0
)

require (
	github.com/golang/protobuf v1.5.4 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops => ./adapters/sops
