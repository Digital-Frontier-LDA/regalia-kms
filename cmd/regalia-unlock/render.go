package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/bootcfg"
	"github.com/Digital-Frontier-LDA/regalia-kms/cmd/regalia-unlock/membership"
)

// -render DIR (#66, B3): the boot credentials derived from membership, rendered in the initrd rather than
// read from the ESP. The signed chain is read from the ESP, verified from the root the image pins
// (root-key.json) and against this TPM's high-water anchor (a stale or forked chain is refused, however
// well signed), and the unlock configuration, the boot WireGuard configuration, its ruleset and boot.env
// are rendered from it and the measured site document (bootcfg, held to deploy/baremetal/bootcreds.py) into
// DIR, for regalia-wg-boot and this program. Any refusal ends the start with one line: the units that
// Require= this one do not start, the relay gives no key, and the console asks for the recovery key.

const (
	// systemd-stub's (and systemd-boot's) vendor GUID: the partition the image was loaded from
	loaderDevicePartUUID = "/sys/firmware/efi/efivars/LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
	chainOnESP           = "EFI/regalia/membership.json"
	maxChainBytes        = 64 << 20 // membership.MAX_CHAIN_BYTES
	siteCredential       = "regalia.site"
	espWait              = 30 * time.Second // the ESP's block device may still be appearing (udev)
)

// renderEnv is everything the render touches outside this process, so that each way it can fail is
// tested without a firmware, a disk or a TPM.
type renderEnv struct {
	readFile func(path string) ([]byte, error)
	exists   func(path string) bool
	mount    func(device, dir string) error
	unmount  func(dir string) error
	mkdtemp  func() (string, error)
	nv       func() (membership.NV, func(), error)
	sleep    func(time.Duration)
	write    func(path string, data []byte) error // a new file: it must not exist
	rename   func(from, to string) error
	remove   func(path string) error
	creds    string // $CREDENTIALS_DIRECTORY
	rootKey  string
}

func realRenderEnv(tpmPath string) renderEnv {
	return renderEnv{
		readFile: os.ReadFile,
		exists:   func(path string) bool { _, err := os.Stat(path); return err == nil },
		mount: func(device, dir string) error {
			return syscall.Mount(device, dir, "vfat", syscall.MS_RDONLY|syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, "")
		},
		unmount: func(dir string) error { return syscall.Unmount(dir, 0) },
		mkdtemp: func() (string, error) { return os.MkdirTemp("", "regalia-esp-") },
		nv: func() (membership.NV, func(), error) {
			device, err := openTPM(tpmPath)
			if err != nil {
				return nil, nil, err
			}
			return tpmNV{device}, func() { device.Close() }, nil
		},
		sleep: time.Sleep,
		write: func(path string, data []byte) error {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			if _, err := f.Write(data); err != nil {
				f.Close()
				return err
			}
			return f.Close()
		},
		rename:  os.Rename,
		remove:  os.Remove,
		creds:   os.Getenv("CREDENTIALS_DIRECTORY"),
		rootKey: membership.RootKeyPath,
	}
}

func runRender(arguments []string, out, diagnostics io.Writer) error {
	if len(arguments) != 2 && !(len(arguments) == 4 && arguments[2] == "-tpm") {
		return errors.New("usage: regalia-unlock -render DIR [-tpm DEVICE]")
	}
	tpmPath := "/dev/tpmrm0"
	if len(arguments) == 4 {
		tpmPath = arguments[3]
	}
	summary, err := render(arguments[1], realRenderEnv(tpmPath))
	if err != nil {
		fmt.Fprintf(diagnostics, "regalia-unlock: the boot configuration cannot be rendered: %v; nothing is asked of a peer, and the console asks for the recovery key\n", err)
		return err
	}
	fmt.Fprintf(out, "regalia-unlock: %s\n", summary)
	return nil
}

// espDevice is the ESP the image was loaded from, by the LoaderDevicePartUUID EFI variable: four bytes of
// attributes, then the partition's UUID in UTF-16LE, ending with a NUL.
func espDevice(env renderEnv) (string, error) {
	raw, err := env.readFile(loaderDevicePartUUID)
	if err != nil {
		return "", fmt.Errorf("the firmware does not say which partition the image came from (LoaderDevicePartUUID: %v)", err)
	}
	if len(raw) < 6 || len(raw)%2 != 0 {
		return "", errors.New("LoaderDevicePartUUID is not a UTF-16 string")
	}
	units := make([]uint16, 0, (len(raw)-4)/2)
	for i := 4; i+1 < len(raw); i += 2 {
		u := uint16(raw[i]) | uint16(raw[i+1])<<8
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	uuid := strings.ToLower(string(utf16.Decode(units)))
	if len(uuid) != 36 || strings.Trim(uuid, "0123456789abcdef-") != "" || strings.Count(uuid, "-") != 4 {
		return "", fmt.Errorf("LoaderDevicePartUUID is not a partition UUID (%q)", uuid)
	}
	device := "/dev/disk/by-partuuid/" + uuid
	for waited := time.Duration(0); !env.exists(device); waited += 200 * time.Millisecond {
		if waited >= espWait {
			return "", fmt.Errorf("the ESP %s did not appear in %s", device, espWait)
		}
		env.sleep(200 * time.Millisecond)
	}
	return device, nil
}

// readChain mounts the ESP read-only (nosuid, nodev, noexec) on a directory of its own, reads the chain, and
// unmounts it before anything else is done: nothing of the ESP stays mounted. (regalia-boot-render.service
// also runs with PrivateMounts=yes: a mount that could not be undone dies with the unit's namespace.)
func readChain(env renderEnv, device string) (raw []byte, err error) {
	dir, err := env.mkdtemp()
	if err != nil {
		return nil, err
	}
	defer env.remove(dir)
	if err := env.mount(device, dir); err != nil {
		return nil, fmt.Errorf("the ESP %s cannot be mounted read-only: %v", device, err)
	}
	defer func() {
		// an unmount that fails is reported, and never hides why the read failed
		if unmountErr := env.unmount(dir); unmountErr != nil {
			if err != nil {
				raw, err = nil, fmt.Errorf("%v; and the ESP %s cannot be unmounted: %v", err, device, unmountErr)
			} else {
				raw, err = nil, fmt.Errorf("the ESP %s cannot be unmounted: %v", device, unmountErr)
			}
		}
	}()
	raw, readErr := env.readFile(filepath.Join(dir, chainOnESP))
	if readErr != nil {
		return nil, fmt.Errorf("the ESP holds no membership chain (%s: %v)", chainOnESP, readErr)
	}
	if len(raw) > maxChainBytes {
		return nil, fmt.Errorf("the membership chain on the ESP is over %d bytes", maxChainBytes)
	}
	return raw, nil
}

// render does the work of -render: on success the four files are in dir, and the summary names the chain's
// epoch and the TPM's high-water.
func render(dir string, env renderEnv) (string, error) {
	rootValue, _, err := membership.LoadRoot(env.readFile, env.rootKey)
	if err != nil {
		return "", err
	}
	if env.creds == "" {
		return "", errors.New("no credentials directory: run by regalia-boot-render.service")
	}
	siteRaw, err := env.readFile(filepath.Join(env.creds, siteCredential))
	if err != nil {
		return "", fmt.Errorf("the site document %s is missing: %v", siteCredential, err)
	}
	site, err := bootcfg.ReadSite(siteRaw)
	if err != nil {
		return "", err
	}
	device, err := espDevice(env)
	if err != nil {
		return "", err
	}
	raw, err := readChain(env, device)
	if err != nil {
		return "", err
	}
	document, err := membership.Load(raw, maxChainBytes)
	if err != nil {
		return "", fmt.Errorf("the membership chain is not valid JSON: %v", err)
	}
	envelopes, ok := document.([]any)
	if !ok {
		return "", errors.New("the membership chain is not a list of envelopes")
	}
	manifests, err := membership.ReadChain(envelopes, rootValue)
	if err != nil {
		return "", err
	}
	nv, closeNV, err := env.nv()
	if err != nil {
		return "", fmt.Errorf("the TPM does not answer: %v", err)
	}
	high, err := membership.Anchored(nv, manifests)
	closeNV()
	if err != nil {
		return "", err
	}
	current := manifests[len(manifests)-1]
	files, err := bootcfg.Render(current, site)
	if err != nil {
		return "", err
	}
	if err := publish(env, dir, files); err != nil {
		return "", err
	}
	return fmt.Sprintf("rendered the boot configuration of %s under manifest epoch %v (TPM high-water %d)", site.NodeID, current["epoch"], high), nil
}

// publish puts the four files into dir all together or not at all: each is written under a temporary name
// first, and only when all four are written are they renamed onto their names. A failure removes what it
// wrote, so dir never holds a mixed set (d9's read of #299).
func publish(env renderEnv, dir string, files map[string][]byte) error {
	names := []string{"regalia.unlock-config", "regalia.wg-boot-conf", "regalia.boot-nft", "regalia.boot-env"}
	temporary := func(name string) string { return filepath.Join(dir, "."+name+".render-new") }
	var written, placed []string
	undo := func() {
		for _, path := range append(written, placed...) {
			env.remove(path)
		}
	}
	for _, name := range names {
		if err := env.write(temporary(name), files[name]); err != nil {
			env.remove(temporary(name)) // what the failed write itself left, cut short
			undo()
			return fmt.Errorf("cannot write %s: %v", name, err)
		}
		written = append(written, temporary(name))
	}
	for _, name := range names {
		if err := env.rename(temporary(name), filepath.Join(dir, name)); err != nil {
			undo()
			return fmt.Errorf("cannot put %s in place: %v", name, err)
		}
		written, placed = written[1:], append(placed, filepath.Join(dir, name))
	}
	return nil
}
