package main

import (
	"os"

	poc "github.com/Digital-Frontier-LDA/regalia-kms/adapters/openbao"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/go-kms-wrapping/plugin/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper { return poc.New() },
		Logger:             hclog.New(&hclog.LoggerOptions{Level: hclog.Warn, Output: os.Stderr, JSONFormat: true}),
	})
}
