package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

type conditionNV struct {
	membership.NV // Public/Read must never be needed to establish index presence.
	defined       map[uint32]bool
	err           error
	calls         int
}

func (n *conditionNV) Defined() (map[uint32]bool, error) {
	n.calls++
	return n.defined, n.err
}

type conditionFixture struct {
	env                      renderEnv
	stub, esp                string
	nv                       *conditionNV
	mounts, unmounts, closed int
	mounted                  bool
	removed                  []string
}

func newConditionFixture(t *testing.T) *conditionFixture {
	t.Helper()
	dir := t.TempDir()
	f := &conditionFixture{stub: filepath.Join(dir, "stub"), esp: filepath.Join(dir, "esp"),
		nv: &conditionNV{defined: map[uint32]bool{}}}
	if err := os.Mkdir(f.esp, 0o700); err != nil {
		t.Fatal(err)
	}
	f.env = realRenderEnv("unused")
	mapPath := func(path string) string {
		if path == stubCredentials || strings.HasPrefix(path, stubCredentials+"/") {
			return f.stub + strings.TrimPrefix(path, stubCredentials)
		}
		return path
	}
	present := f.env.present
	f.env.present = func(path string) (bool, error) { return present(mapPath(path)) }
	f.env.readDir = func(path string) ([]os.DirEntry, error) { return os.ReadDir(mapPath(path)) }
	f.env.readFile = func(path string) ([]byte, error) {
		if path == loaderDevicePartUUID {
			return efivar(testUUID), nil
		}
		t.Fatal("the condition must not read credential contents")
		return nil, os.ErrPermission
	}
	f.env.exists = func(string) bool { return true }
	f.env.mkdtemp = func() (string, error) { return f.esp, nil }
	f.env.mount = func(string, string) error { f.mounts++; f.mounted = true; return nil }
	f.env.unmount = func(string) error { f.unmounts++; f.mounted = false; return nil }
	f.env.remove = func(path string) error { f.removed = append(f.removed, path); return nil }
	f.env.nv = func() (membership.NV, func(), error) {
		return f.nv, func() { f.closed++ }, nil
	}
	f.env.write = func(string, []byte) error { t.Fatal("the condition must not publish output"); return nil }
	f.env.sleep = func(time.Duration) {}
	return f
}

func conditionFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func useTestMarker(t *testing.T) {
	t.Helper()
	previous := preGenesisMarker
	preGenesisMarker = filepath.Join(t.TempDir(), "regalia-pre-genesis")
	t.Cleanup(func() { preGenesisMarker = previous })
}

func callRenderCheck(t *testing.T, env renderEnv, diagnostics io.Writer) int {
	t.Helper()
	factory := renderEnvForCheck
	renderEnvForCheck = func(string) renderEnv { return env }
	defer func() { renderEnvForCheck = factory }()
	defer func() {
		if recover() != nil {
			t.Fatal("condition panic escaped instead of hard failure 255")
		}
	}()
	return run([]string{"-render-check"}, diagnostics)
}

func TestRenderCondition(t *testing.T) {
	cases := []struct {
		name   string
		change func(*testing.T, *conditionFixture)
		code   int
		line   string
	}{
		{"pre_genesis", func(*testing.T, *conditionFixture) {}, 1, "no site credential: expected pre-genesis skip"},
		{"pre_genesis_empty_directories", func(t *testing.T, f *conditionFixture) {
			for _, dir := range []string{f.stub, filepath.Join(f.esp, espCredentials)} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
		}, 1, "no site credential: expected pre-genesis skip"},
		{"enrolled_chain_site_deleted", func(t *testing.T, f *conditionFixture) {
			conditionFile(t, filepath.Join(f.esp, chainOnESP))
		}, 255, "missing site credential on an enrolled node: ESP membership state is present"},
		{"enrolled_loader_site_deleted", func(t *testing.T, f *conditionFixture) {
			conditionFile(t, filepath.Join(f.esp, espCredentials, "regalia.unlock-local.cred"))
		}, 255, "missing site credential on an enrolled node: ESP loader credentials are present"},
		{"enrolled_stub_site_deleted", func(t *testing.T, f *conditionFixture) {
			conditionFile(t, filepath.Join(f.stub, "regalia.unlock-local.cred"))
		}, 255, "missing site credential on an enrolled node: stub enrolment state is present"},
		{"nv_counter_without_esp", func(t *testing.T, f *conditionFixture) { f.nv.defined[membership.HighWaterIndex] = true }, 255, "missing site credential on an enrolled node: TPM anchor state is present"},
		{"nv_base_without_esp", func(t *testing.T, f *conditionFixture) { f.nv.defined[membership.HighWaterIndex+1] = true }, 255, "missing site credential on an enrolled node: TPM anchor state is present"},
		{"nv_slot_0_without_esp", func(t *testing.T, f *conditionFixture) { f.nv.defined[membership.HighWaterIndex+4] = true }, 255, "missing site credential on an enrolled node: TPM anchor state is present"},
		{"nv_slot_1_without_esp", func(t *testing.T, f *conditionFixture) { f.nv.defined[membership.HighWaterIndex+5] = true }, 255, "missing site credential on an enrolled node: TPM anchor state is present"},
		{"tpm_open_error", func(t *testing.T, f *conditionFixture) {
			f.env.nv = func() (membership.NV, func(), error) { return nil, nil, os.ErrPermission }
		}, 255, "TPM cannot be opened; pre-genesis is unproven"},
		{"tpm_inventory_error", func(t *testing.T, f *conditionFixture) { f.nv.err = os.ErrPermission }, 255, "TPM NV inventory cannot be read; pre-genesis is unproven"},
		{"tpm_nil_inventory", func(t *testing.T, f *conditionFixture) { f.nv.defined = nil }, 255, "TPM NV inventory cannot be read; pre-genesis is unproven"},
		{"check_panic", func(t *testing.T, f *conditionFixture) {
			f.env.nv = func() (membership.NV, func(), error) { panic("synthetic check failure") }
		}, 255, "pre-genesis check aborted; boot render refused"},
		{"site_stat_error", func(t *testing.T, f *conditionFixture) {
			f.env.present = func(string) (bool, error) { return false, os.ErrPermission }
		}, 255, "site credential presence cannot be checked"},
		{"stub_read_error", func(t *testing.T, f *conditionFixture) {
			conditionFile(t, filepath.Join(f.stub, "regalia.unlock-local.cred"))
			f.env.readDir = func(string) ([]os.DirEntry, error) { return nil, os.ErrPermission }
		}, 255, "stub enrolment state cannot be checked"},
		{"esp_chain_stat_error", func(t *testing.T, f *conditionFixture) {
			present := f.env.present
			f.env.present = func(path string) (bool, error) {
				if path == filepath.Join(f.esp, chainOnESP) {
					return false, os.ErrPermission
				}
				return present(path)
			}
		}, 255, "ESP membership presence cannot be checked"},
		{"esp_credentials_read_error", func(t *testing.T, f *conditionFixture) {
			conditionFile(t, filepath.Join(f.esp, espCredentials, "regalia.unlock-local.cred"))
			f.env.readDir = func(string) ([]os.DirEntry, error) { return nil, os.ErrPermission }
		}, 255, "ESP loader credentials cannot be checked"},
		{"esp_mount_error", func(t *testing.T, f *conditionFixture) {
			f.env.mount = func(string, string) error { return os.ErrPermission }
		}, 255, "cannot be mounted read-only"},
		{"esp_unmount_error", func(t *testing.T, f *conditionFixture) {
			f.env.unmount = func(string) error { f.unmounts++; return errors.New("device busy") }
		}, 255, "cannot be unmounted"},
		{"esp_firmware_error", func(t *testing.T, f *conditionFixture) {
			f.env.readFile = func(string) ([]byte, error) { return nil, os.ErrNotExist }
		}, 255, "the ESP cannot be located; pre-genesis is unproven"},
		{"esp_device_absent", func(t *testing.T, f *conditionFixture) { f.env.exists = func(string) bool { return false } }, 255, "the ESP cannot be located; pre-genesis is unproven"},
		{"present_bad_site", func(t *testing.T, f *conditionFixture) {
			conditionFile(t, filepath.Join(f.stub, "regalia.site.cred"))
		}, 0, ""}, // The existing render tests check that ExecStart rejects these bytes.
		{"present_dangling_site", func(t *testing.T, f *conditionFixture) {
			if err := os.Mkdir(f.stub, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("absent-target", filepath.Join(f.stub, "regalia.site.cred")); err != nil {
				t.Fatal(err)
			}
		}, 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			useTestMarker(t)
			f := newConditionFixture(t)
			c.change(t, f)
			var diagnostics strings.Builder
			if got := callRenderCheck(t, f.env, &diagnostics); got != c.code {
				t.Fatalf("condition exit = %d, want %d: %s", got, c.code, diagnostics.String())
			}
			wantConsumer := 0
			if c.code == 1 {
				wantConsumer = 1
			}
			for _, name := range []string{"wg-boot", "unlock"} {
				if got := run([]string{"-consumer-check", name}, io.Discard); got != wantConsumer {
					t.Fatalf("%s consumer exit = %d, want %d after render exit %d", name, got, wantConsumer, c.code)
				}
			}
			if c.code == 0 {
				if diagnostics.Len() != 0 || f.mounts != 0 || f.nv.calls != 0 {
					t.Fatal("present credential must reach ExecStart without a skip decision")
				}
				return
			}
			if !strings.Contains(diagnostics.String(), c.line) || strings.Count(diagnostics.String(), "\n") != 1 {
				t.Fatalf("condition must log exactly one reason containing %q: %q", c.line, diagnostics.String())
			}
			if f.mounts != f.unmounts || (f.nv.calls > 0 && f.closed != 1) {
				t.Fatal("condition leaked a mount or TPM handle")
			}
			if c.code == 1 && (f.nv.calls != 1 || f.mounts != 1) {
				t.Fatal("skip requires successful ESP inspection and TPM inventory")
			}
		})
	}
}

func TestRenderCheckBadArgumentsFailHard(t *testing.T) {
	for _, args := range [][]string{{"-render-check", "unexpected"}, {"-render-check", "-tpm", ""}} {
		var diagnostics strings.Builder
		if got := runRenderCheck(args, &diagnostics); got != 255 {
			t.Fatalf("bad arguments exit = %d, want hard failure 255", got)
		}
	}
}

// Dispatch must precede normal flag parsing, whose error exit 1 is a non-failing unit skip.
func TestRenderCheckDispatchExitCode(t *testing.T) {
	var diagnostics strings.Builder
	if status := run([]string{"-render-check", "unexpected"}, &diagnostics); status != 255 {
		t.Fatalf("run must return 255, not a non-failing skip: %d: %s", status, diagnostics.String())
	}
	if diagnostics.String() != "regalia-unlock: usage: -render-check [-tpm DEVICE]\n" {
		t.Fatalf("run must log exactly one usage line: %q", diagnostics.String())
	}
}

func TestRenderCheckRunCleanup(t *testing.T) {
	for _, name := range []string{"normal", "panic"} {
		t.Run(name, func(t *testing.T) {
			useTestMarker(t)
			f := newConditionFixture(t)
			want := 1
			if name == "panic" {
				want = 255
				present := f.env.present
				f.env.present = func(path string) (bool, error) {
					if path == filepath.Join(f.esp, chainOnESP) {
						panic("synthetic inspect panic")
					}
					return present(path)
				}
			}
			var diagnostics strings.Builder
			if status := callRenderCheck(t, f.env, &diagnostics); status != want {
				t.Fatalf("run exit = %d, want %d: %s", status, want, diagnostics.String())
			}
			if f.mounts != 1 || f.unmounts != 1 || f.mounted || len(f.removed) != 1 || f.removed[0] != f.esp {
				t.Fatal("run returned before ESP unmount and private mountpoint removal")
			}
		})
	}
}

func TestRenderCheckFactoryPanicFailsHard(t *testing.T) {
	useTestMarker(t)
	factory := renderEnvForCheck
	t.Cleanup(func() { renderEnvForCheck = factory })
	renderEnvForCheck = func(string) renderEnv { panic("synthetic environment factory panic") }
	var diagnostics strings.Builder
	if status := run([]string{"-render-check"}, &diagnostics); status != 255 {
		t.Fatalf("condition factory panic must return 255: %d", status)
	}
	if diagnostics.String() != "regalia-unlock: pre-genesis check aborted; boot render refused\n" {
		t.Fatalf("condition factory panic must log one refusal: %q", diagnostics.String())
	}
}

func TestRenderConditionClearsPriorDecision(t *testing.T) {
	useTestMarker(t)
	f := newConditionFixture(t)
	check := func(want int) {
		t.Helper()
		var diagnostics strings.Builder
		if got := callRenderCheck(t, f.env, &diagnostics); got != want {
			t.Fatalf("condition exit = %d, want %d: %s", got, want, diagnostics.String())
		}
	}
	check(1)
	conditionFile(t, filepath.Join(f.stub, "regalia.site.cred"))
	check(0)
	if got := run([]string{"-consumer-check", "unlock"}, io.Discard); got != 0 {
		t.Fatalf("consumer exit = %d, want 0 after enrolled retry", got)
	}
}

func TestRenderConditionMarkerErrors(t *testing.T) {
	for _, phase := range []string{"reset", "publish"} {
		t.Run(phase, func(t *testing.T) {
			useTestMarker(t)
			f := newConditionFixture(t)
			if phase == "reset" {
				conditionFile(t, filepath.Join(preGenesisMarker, "unexpected"))
			} else {
				preGenesisMarker = filepath.Join(preGenesisMarker, "missing-parent")
			}
			var diagnostics strings.Builder
			if got := callRenderCheck(t, f.env, &diagnostics); got != 255 ||
				!strings.Contains(diagnostics.String(), "cannot "+phase+" pre-genesis decision") {
				t.Fatalf("condition exit = %d, want hard failure during %s: %s", got, phase, diagnostics.String())
			}
		})
	}
}

func TestConsumerConditionErrors(t *testing.T) {
	useTestMarker(t)
	conditionFile(t, preGenesisMarker)
	for _, tc := range []struct {
		args []string
		line string
	}{
		{[]string{"-consumer-check", "wg-boot"}, "invalid pre-genesis decision marker"},
		{[]string{"-consumer-check", "invalid-unit"}, "usage: -consumer-check"},
	} {
		var diagnostics strings.Builder
		if got := run(tc.args, &diagnostics); got != 255 || !strings.Contains(diagnostics.String(), tc.line) {
			t.Fatalf("%v exit = %d, want hard failure: %s", tc.args, got, diagnostics.String())
		}
	}
	preGenesisMarker = filepath.Join(preGenesisMarker, "unexpected")
	var diagnostics strings.Builder
	if got := run([]string{"-consumer-check", "unlock"}, &diagnostics); got != 255 ||
		!strings.Contains(diagnostics.String(), "cannot read pre-genesis decision") {
		t.Fatalf("consumer exit = %d, want hard failure on stat error: %s", got, diagnostics.String())
	}
}
