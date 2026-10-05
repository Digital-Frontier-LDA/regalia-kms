// This separate executable is an experiment, never a production PKI provider.
package main

import (
	"os"

	poc "github.com/Digital-Frontier-LDA/regalia-kms/adapters/openbao"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/go-kms-wrapping/plugin/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper { return poc.NewNative() },
		KMSFactoryFunc:     func() kms.KMS { return poc.NewExternalPKIPoC() },
		Logger:             hclog.New(&hclog.LoggerOptions{Level: hclog.Info, Output: os.Stderr, JSONFormat: true}),
	})
}
