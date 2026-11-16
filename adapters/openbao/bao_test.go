package openbaopoc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const syntheticValue = "synthetic-openbao-poc-only"

type baoProcess struct {
	cmd     *exec.Cmd
	done    chan struct{}
	log     *os.File
	stopped bool
}

func isolatedEnv(tmp string) []string {
	var env []string
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		lower := strings.ToLower(name)
		if strings.HasPrefix(name, "BAO_") || strings.HasPrefix(name, "VAULT_") || strings.HasPrefix(name, "OPENBAO_") || name == "TMPDIR" || strings.Contains(lower, "proxy") {
			continue
		}
		env = append(env, entry)
	}
	return append(env, "TMPDIR="+tmp, "GOWORK=off")
}

func startBao(t *testing.T, binary, config, dir string) *baoProcess {
	t.Helper()
	file, err := os.CreateTemp(dir, "bao-log-")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "server", "-config="+config)
	cmd.Env = isolatedEnv(dir)
	cmd.Stdout = file
	cmd.Stderr = file
	if err := cmd.Start(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	p := &baoProcess{cmd: cmd, done: make(chan struct{}), log: file}
	go func() { _ = cmd.Wait(); close(p.done) }()
	t.Cleanup(func() { p.stop(t) })
	return p
}

func (p *baoProcess) stop(t *testing.T) {
	t.Helper()
	if p.stopped {
		return
	}
	p.stopped = true
	select {
	case <-p.done:
	default:
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.done:
		case <-time.After(10 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.done
			t.Error("OpenBao did not stop within deadline")
		}
	}
	_ = p.log.Close()
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func baoConfig(t *testing.T, dir, address, cluster, pluginDigest string, c map[string]string) string {
	t.Helper()
	return baoConfigVersion(t, dir, address, cluster, pluginDigest, "v0.0.1", c)
}

func baoConfigVersion(t *testing.T, dir, address, cluster, pluginDigest, pluginVersion string, c map[string]string) string {
	t.Helper()
	var text strings.Builder
	fmt.Fprintf(&text, "api_addr = %q\ncluster_addr = %q\nplugin_directory = %q\nlog_level = \"warn\"\n", "http://"+address, "https://"+cluster, dir)
	fmt.Fprintf(&text, "storage \"raft\" {\n path = %q\n node_id = %q\n}\nlistener \"tcp\" {\n address = %q\n cluster_address = %q\n tls_disable = true\n}\n", filepath.Join(dir, "storage"), filepath.Base(dir), address, cluster)
	pluginType := "regalia-poc"
	keys := []string{"kms_url", "server_name", "ca_path", "certificate_path", "private_key_path", "object_id", "repository", "path", "environment", "kms_purpose", "timeout", "key_version", "historical_key_versions"}
	if _, native := c["address"]; native {
		pluginType = "regalia"
		keys = []string{"address", "server_name", "ca_path", "cert_path", "key_path", "object_id", "environment", "kms_purpose", "timeout"}
	}
	// Both entrypoints are built/copied under this fixture-only executable name.
	fmt.Fprintf(&text, "plugin \"kms\" %q {\n command = \"openbao-plugin-kms-regalia-poc\"\n version = %q\n sha256sum = %q\n}\nseal %q {\n", pluginType, pluginVersion, pluginDigest, pluginType)
	for _, key := range keys {
		if c[key] == "" {
			continue
		}
		fmt.Fprintf(&text, " %s = %q\n", key, c[key])
	}
	text.WriteString(" health_check_interval = \"1s\"\n health_check_timeout = \"2s\"\n health_check_interval_unhealthy = \"1s\"\n}\n")
	file, err := os.CreateTemp(dir, "bao-config-*.hcl")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(text.String()); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return file.Name()
}

type baoAPI struct {
	base      string
	namespace string
	token     string
	client    *http.Client
}

func (b baoAPI) call(method, path string, input any) (int, []byte, error) {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return 0, nil, err
		}
		defer clear(encoded)
		body = bytes.NewReader(encoded)
	}
	return b.callBody(method, path, body, "application/json")
}

func (b baoAPI) callBody(method, path string, body io.Reader, contentType string) (int, []byte, error) {
	req, err := http.NewRequest(method, b.base+path, body)
	if err != nil {
		return 0, nil, err
	}
	if b.token != "" {
		req.Header.Set("X-Vault-Token", b.token)
	}
	if b.namespace != "" {
		req.Header.Set("X-Vault-Namespace", b.namespace)
	}
	req.Header.Set("Content-Type", contentType)
	response, err := b.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if len(data) > 2<<20 {
		return response.StatusCode, nil, fmt.Errorf("synthetic response exceeds test limit")
	}
	return response.StatusCode, data, err
}

func (b baoAPI) must(t *testing.T, method, path string, input any) []byte {
	t.Helper()
	status, data, err := b.call(method, path, input)
	if err != nil || status < 200 || status >= 300 {
		if os.Getenv("OPENBAO_POC_KEEP_FAILURE") == "1" {
			var failure struct {
				Errors []string `json:"errors"`
			}
			if json.Unmarshal(data, &failure) == nil {
				for _, message := range failure.Errors {
					if b.token != "" {
						message = strings.ReplaceAll(message, b.token, "[redacted]")
					}
					message = strings.ReplaceAll(message, syntheticValue, "[redacted]")
					t.Logf("synthetic API diagnostic: %.300s", message)
				}
			}
		}
		t.Fatalf("OpenBao %s %s failed (status %d); response omitted", method, path, status)
	}
	return data
}

func (b baoAPI) wait(t *testing.T, initialized, sealed bool, processes ...*baoProcess) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if len(processes) != 0 {
			select {
			case <-processes[0].done:
				t.Fatal("OpenBao exited before the requested health state")
			default:
			}
		}
		status, data, err := b.call(http.MethodGet, "/v1/sys/health", nil)
		var health struct {
			Initialized bool `json:"initialized"`
			Sealed      bool `json:"sealed"`
		}
		if err == nil && json.Unmarshal(data, &health) == nil && health.Initialized == initialized && health.Sealed == sealed &&
			(!initialized || sealed || status == http.StatusOK) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("OpenBao did not reach initialized=%t sealed=%t within deadline; raw logs omitted", initialized, sealed)
}

func (b baoAPI) assertValue(t *testing.T) {
	t.Helper()
	data := b.must(t, http.MethodGet, "/v1/poc/data/secret", nil)
	var result struct {
		Data struct {
			Data struct {
				Value string `json:"value"`
			} `json:"data"`
		} `json:"data"`
	}
	if json.Unmarshal(data, &result) != nil || result.Data.Data.Value != syntheticValue {
		t.Fatal("persisted synthetic value did not survive")
	}
}

func (b *baoAPI) initialize(t *testing.T) string {
	t.Helper()
	init := b.must(t, http.MethodPost, "/v1/sys/init", map[string]int{"recovery_shares": 1, "recovery_threshold": 1})
	defer clear(init)
	var initialized struct {
		RootToken    string   `json:"root_token"`
		RecoveryKeys []string `json:"recovery_keys"`
	}
	if json.Unmarshal(init, &initialized) != nil || initialized.RootToken == "" || len(initialized.RecoveryKeys) != 1 {
		t.Fatal("initialization returned no token")
	}
	b.token = initialized.RootToken
	b.wait(t, true, false)
	return initialized.RecoveryKeys[0]
}

func (b baoAPI) assertBlocked(t *testing.T, p *baoProcess) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status, _, err := b.call(http.MethodGet, "/v1/poc/data/secret", nil)
		if err == nil && status >= 200 && status < 300 {
			t.Fatal("protected value available despite refused seal dependency")
		}
		time.Sleep(100 * time.Millisecond)
	}
	p.stop(t)
}

func baoTestEnvironment(t *testing.T) (string, string, []byte, [32]byte) {
	return baoTestEnvironmentFor(t, "openbao-plugin-kms-regalia-poc")
}

func baoTestEnvironmentFor(t *testing.T, entrypoint string) (string, string, []byte, [32]byte) {
	t.Helper()
	binary := os.Getenv("OPENBAO_POC_BAO")
	if binary == "" {
		if os.Getenv("OPENBAO_POC_REQUIRE_E2E") == "1" {
			t.Fatal("OPENBAO_POC_BAO is required")
		}
		t.Skip("set OPENBAO_POC_BAO to a checksum-verified OpenBao 2.7.1 executable")
	}
	versionCmd := exec.Command(binary, "version")
	versionCmd.Env = isolatedEnv(os.TempDir())
	version, err := versionCmd.Output()
	if err != nil || !strings.HasPrefix(string(version), "OpenBao v2.7.1 ") {
		t.Fatal("PoC requires OpenBao 2.7.1")
	}
	// A short private directory also avoids macOS's Unix plugin-socket path limit.
	dir, err := os.MkdirTemp("/tmp", "bao-poc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() && os.Getenv("OPENBAO_POC_KEEP_FAILURE") == "1" {
			t.Logf("private synthetic debug artifacts preserved at %s", dir)
			return
		}
		_ = os.RemoveAll(dir)
	})
	pluginPath := filepath.Join(dir, "openbao-plugin-kms-regalia-poc")
	build := exec.Command("go", "build", "-o", pluginPath, "./cmd/"+entrypoint)
	build.Env = isolatedEnv(dir)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build plugin: %v\n%s", err, output)
	}
	pluginBytes, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatal(err)
	}
	return binary, dir, pluginBytes, sha256.Sum256(pluginBytes)
}

func TestOpenBao271InitializeRestartOutageAndIdentity(t *testing.T) {
	binary, dir, pluginBytes, digest := baoTestEnvironment(t)
	pluginPath := filepath.Join(dir, "openbao-plugin-kms-regalia-poc")
	f := newKMSFixture(t)
	address, cluster := freeAddress(t), freeAddress(t)
	config := baoConfig(t, dir, address, cluster, hex.EncodeToString(digest[:]), f.pki.config)
	b := baoAPI{base: "http://" + address, client: &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}}
	p := startBao(t, binary, config, dir)
	b.wait(t, false, true, p)
	b.initialize(t)
	b.seedSyntheticKV(t)
	// A successful periodic health check must perform an additional real wrap/unwrap pair.
	beforeWrap, beforeUnwrap := f.audit.successful("wrap"), f.audit.successful("unwrap")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && (f.audit.successful("wrap") <= beforeWrap || f.audit.successful("unwrap") <= beforeUnwrap) {
		time.Sleep(100 * time.Millisecond)
	}
	if f.audit.successful("wrap") <= beforeWrap || f.audit.successful("unwrap") <= beforeUnwrap {
		t.Fatal("periodic seal health check did not reach Regalia")
	}
	b.must(t, http.MethodPost, "/v1/sys/seal", map[string]any{})
	b.wait(t, true, true)
	p.stop(t)
	p = startBao(t, binary, config, dir)
	b.wait(t, true, false)
	b.assertValue(t)
	// Existing unsealed reads remain available, but a fresh process cannot unseal offline.
	f.server.Close()
	b.assertValue(t)
	p.stop(t)
	p = startBao(t, binary, config, dir)
	b.assertBlocked(t, p)
	f.start()
	p = startBao(t, binary, config, dir)
	b.wait(t, true, false)
	b.assertValue(t)
	p.stop(t)
	// A chain-valid but unauthorized SPIFFE principal cannot unseal existing state.
	unauthorized := baoConfig(t, dir, address, cluster, hex.EncodeToString(digest[:]), f.pki.strangerConfig)
	beforeUnwrap = f.audit.successful("unwrap")
	beforeDenial := f.audit.deniedUnwraps()
	p = startBao(t, binary, unauthorized, dir)
	b.assertBlocked(t, p)
	if f.audit.successful("unwrap") != beforeUnwrap {
		t.Fatal("unauthorized identity obtained a successful unwrap")
	}
	if f.audit.deniedUnwraps() <= beforeDenial {
		t.Fatal("wrong-identity drill did not reach Regalia's actual authorization boundary")
	}
	p = startBao(t, binary, config, dir)
	b.wait(t, true, false)
	b.assertValue(t)
	snapshot := b.must(t, http.MethodGet, "/v1/sys/storage/raft/snapshot", nil)
	defer clear(snapshot)
	p.stop(t)
	bootstrapToken := b.restoreToFreshNode(t, binary, dir, pluginBytes, hex.EncodeToString(digest[:]), snapshot, f)
	wrongKeyToken := b.rejectWrongKeyRestore(t, binary, dir, pluginBytes, hex.EncodeToString(digest[:]), snapshot)
	assertBaoArtifactsClean(t, dir, pluginPath, b.token, bootstrapToken, wrongKeyToken)
	t.Logf("OpenBao 2.7.1 + separate SDK plugin + real Regalia HTTP policy stack + software RSA: lifecycle, outage/identity denials, fresh-node snapshot restore/restart and wrong-key restore rejection passed; successful source-KMS wrap=%d unwrap=%d", f.audit.successful("wrap"), f.audit.successful("unwrap"))
}

func (b baoAPI) seedSyntheticKV(t *testing.T) {
	t.Helper()
	b.must(t, http.MethodPost, "/v1/sys/mounts/poc", map[string]any{"type": "kv", "options": map[string]string{"version": "2"}})
	// KV mounts start as v1 and upgrade asynchronously; poll a read-only endpoint
	// before writing once, rather than retrying an ambiguous write.
	kvDeadline := time.Now().Add(10 * time.Second)
	for {
		status, _, err := b.call(http.MethodGet, "/v1/poc/config", nil)
		if err == nil && status == http.StatusOK {
			break
		}
		if time.Now().After(kvDeadline) {
			t.Fatal("synthetic KV mount did not finish initialization")
		}
		time.Sleep(100 * time.Millisecond)
	}
	b.must(t, http.MethodPost, "/v1/poc/data/secret", map[string]any{"data": map[string]string{"value": syntheticValue}})
	b.assertValue(t)
}

func assertBaoArtifactsClean(t *testing.T, dir, pluginPath string, tokens ...string) {
	t.Helper()
	for _, sensitive := range append(tokens, syntheticValue) {
		err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || entry.Type()&os.ModeSocket != 0 || path == pluginPath || strings.HasPrefix(entry.Name(), "bao-config-") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if bytes.Contains(data, []byte(sensitive)) {
				t.Error("plaintext or token persisted in OpenBao storage/logs")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
