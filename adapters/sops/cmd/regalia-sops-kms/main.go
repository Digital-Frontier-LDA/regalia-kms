package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	sopsadapter "github.com/Digital-Frontier-LDA/regalia-kms/adapters/sops"
)

var version = "development"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "regalia SOPS sidecar unavailable")
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "absolute path to strict JSON configuration")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return nil
	}
	if *configPath == "" {
		return errors.New("configuration is required")
	}
	settings, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	timeout, _ := settings.validate()
	certificate, roots, err := settings.identity()
	if err != nil {
		return err
	}
	httpClient, err := sopsadapter.NewMTLSHTTPClient(certificate, roots, settings.ServerName, timeout)
	if err != nil {
		return err
	}
	client := sopsadapter.NewHTTPClient(settings.KMSURL, httpClient, time.Now)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return sopsadapter.ServeUnix(ctx, settings.SocketPath, sopsadapter.New(client))
}
