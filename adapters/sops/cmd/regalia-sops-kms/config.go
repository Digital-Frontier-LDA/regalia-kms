package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const maxConfigBytes = 16 << 10

type config struct {
	SocketPath      string `json:"socket_path"`
	KMSURL          string `json:"kms_url"`
	ServerName      string `json:"server_name"`
	CAPath          string `json:"ca_path"`
	CertificatePath string `json:"certificate_path"`
	PrivateKeyPath  string `json:"private_key_path"`
	Timeout         string `json:"timeout"`
}

func loadConfig(path string) (config, error) {
	contents, err := readProtected(path, maxConfigBytes, false)
	if err != nil {
		return config{}, fmt.Errorf("read sidecar configuration: %w", err)
	}
	var result config
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return config{}, errors.New("invalid sidecar configuration")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return config{}, errors.New("sidecar configuration must contain one JSON document")
	}
	if _, err := result.validate(); err != nil {
		return config{}, err
	}
	return result, nil
}

func (cfg config) validate() (time.Duration, error) {
	for _, value := range []string{cfg.SocketPath, cfg.CAPath, cfg.CertificatePath, cfg.PrivateKeyPath} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return 0, errors.New("sidecar paths must be absolute and clean")
		}
	}
	parsed, err := url.Parse(cfg.KMSURL)
	// "AN HTTPS ORIGIN" IS DEFINED TWICE IN THIS REPOSITORY AND THE DEFINITIONS DISAGREED.
	//
	// audit.ValidateSinkURL in the kms module accepts a bare trailing slash and normalises it away;
	// this rejected it. Same rule, two answers, so "https://kms.internal:8443/" configured the audit
	// sink fine and refused to start the sidecar. An operator hitting that has no way to know which
	// of the two is the rule.
	//
	// They cannot share code: this is a separate module and the other lives under internal/. So the
	// agreement is prose plus a test on each side, and this comment names the other implementation
	// so a reader knows there is one. If you change this rule, change ValidateSinkURL with it.
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return 0, errors.New("kms_url must be an HTTPS origin")
	}
	if strings.TrimSpace(cfg.ServerName) == "" || strings.ContainsAny(cfg.ServerName, "/:@") {
		return 0, errors.New("invalid KMS server name")
	}
	timeout, err := time.ParseDuration(cfg.Timeout)
	if err != nil || timeout < time.Second || timeout > time.Minute {
		return 0, errors.New("timeout must be between 1s and 1m")
	}
	return timeout, nil
}

func (cfg config) identity() (tls.Certificate, *x509.CertPool, error) {
	certificatePEM, err := readProtected(cfg.CertificatePath, 256<<10, false)
	if err != nil {
		return tls.Certificate{}, nil, errors.New("workload identity unavailable")
	}
	privatePEM, err := readProtected(cfg.PrivateKeyPath, 256<<10, true)
	if err != nil {
		return tls.Certificate{}, nil, errors.New("workload identity unavailable")
	}
	defer zero(privatePEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privatePEM)
	if err != nil {
		return tls.Certificate{}, nil, errors.New("workload identity unavailable")
	}
	caPEM, err := readProtected(cfg.CAPath, 256<<10, false)
	if err != nil {
		return tls.Certificate{}, nil, errors.New("KMS trust roots unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return tls.Certificate{}, nil, errors.New("KMS trust roots unavailable")
	}
	return certificate, roots, nil
}

func readProtected(path string, maximum int64, secret bool) ([]byte, error) {
	if !filepath.IsAbs(path) || maximum < 1 {
		return nil, errors.New("invalid protected file")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open protected file")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open protected file")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return nil, errors.New("unsafe protected file owner")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || (secret && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("unsafe protected file")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) > maximum {
		zero(contents)
		return nil, errors.New("read protected file")
	}
	return contents, nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
