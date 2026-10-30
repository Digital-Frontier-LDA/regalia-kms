package main

import (
	"fmt"
	"os"

	poc "github.com/Digital-Frontier-LDA/regalia-kms/adapters/openbao"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/go-kms-wrapping/plugin/v2"
	wrapping "github.com/openbao/go-kms-wrapping/v2"
	"github.com/openbao/go-kms-wrapping/v2/kms"
)

// This unreleased entrypoint is development-only. The production contract's
// hardware qualification remains open.
func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("regalia %s commit=%s OpenBao=2.7.1 development-only\n", poc.BuildVersion, poc.BuildCommit)
		return
	}
	plugin.Serve(&plugin.ServeOpts{
		WrapperFactoryFunc: func() wrapping.Wrapper { return poc.NewNative() },
		KMSFactoryFunc:     func() kms.KMS { return poc.NewExternal() },
		Logger:             hclog.New(&hclog.LoggerOptions{Level: hclog.Info, Output: os.Stderr, JSONFormat: true}),
	})
}
