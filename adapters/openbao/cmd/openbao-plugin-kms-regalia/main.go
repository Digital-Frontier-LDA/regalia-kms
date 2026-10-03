package main

import (
	"os"

	poc "github.com/Digital-Frontier-LDA/regalia-kms/adapters/openbao"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/go-kms-wrapping/plugin/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
)

// This unreleased entrypoint is development-only. The production contract's
// typed error/retry behavior and hardware qualification remain open.
func main() {
	plugin.Serve(&plugin.ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper { return poc.NewNative() },
		Logger:             hclog.New(&hclog.LoggerOptions{Level: hclog.Warn, Output: os.Stderr, JSONFormat: true}),
	})
}
