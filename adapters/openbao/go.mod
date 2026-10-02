module github.com/Digital-Frontier-LDA/regalia-kms/adapters/openbao

go 1.26.6

require (
	github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops v0.0.0
	github.com/openbao/go-kms-wrapping/v2 v2.9.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/fatih/color v1.18.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.2.0 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.7 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.2 // indirect
)

replace github.com/Digital-Frontier-LDA/regalia-kms => ../..

replace github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops => ../sops
