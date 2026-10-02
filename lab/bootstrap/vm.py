"""Build a public initramfs and boot only this node's disposable disk in QEMU."""

import argparse
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path


def copy_file(root, source, destination=None):
    target = root / str(destination or source).lstrip("/")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def build(fixture, modified=False):
    root = Path("/tmp/node/initramfs")
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir()
    for name, destination in [("bin", "usr/bin"), ("sbin", "usr/sbin"), ("lib", "usr/lib")]:
        (root / destination).mkdir(parents=True, exist_ok=True)
        (root / name).symlink_to(destination)
    if Path("/lib64").exists():
        (root / "usr/lib64").mkdir(parents=True)
        (root / "lib64").symlink_to("usr/lib64")
    for name in ["busybox", "python3", "ip", "wg", "cryptsetup", "modprobe", "mkfs.ext4",
                 "tpm2_quote", "tpm2_unseal", "tpm2_startup", "tpm2_pcrread", "tpm2_pcrextend"]:
        copy_file(root, shutil.which(name))
    for path in [Path("/usr/lib/python3/dist-packages"), *Path("/usr/lib").glob("python3.*")]:
        if path.exists() and not (root / str(path).lstrip("/")).exists():
            shutil.copytree(path, root / str(path).lstrip("/"), symlinks=False)
    for path in Path("/usr/lib").glob("*/libtss2*.so*"):
        copy_file(root, path)
    # OpenSSL providers are loaded dynamically and are absent from ldd output.
    for path in Path("/usr/lib").glob("*/ossl-modules/*.so*"):
        copy_file(root, path)
    copy_file(root, Path("/etc/ssl/openssl.cnf"))
    # Copy linked dependencies for executable tools and Python extension modules.
    files = list((root / "usr/bin").iterdir()) + list((root / "usr/sbin").iterdir())
    files += list((root / "usr/lib").rglob("*.so*"))
    for file in files:
        # Inspect the immutable source: the staging tmpfs deliberately has noexec,
        # so the dynamic loader cannot map staged ELF files to discover dependencies.
        source = Path("/") / file.relative_to(root)
        result = subprocess.run(["ldd", str(source)], capture_output=True, timeout=10)
        if result.returncode and source.name != "busybox":
            raise RuntimeError("guest dependency inspection failed")
        for linked in re.findall(rb"(/[\w./+:-]+)", result.stdout):
            path = Path(os.fsdecode(linked))
            if path.is_file():
                copy_file(root, path)
    kernel = sorted(Path("/boot").glob("vmlinuz-*"))[-1]
    version = kernel.name.removeprefix("vmlinuz-")
    modules = ["virtio_pci", "virtio_blk", "virtio_net", "tpm_tis", "wireguard", "dm_crypt", "ext4", "xts"]
    for module in modules + ["aes_generic", "aes_ce_blk", "aes_neon_bs"]:
        result = subprocess.run(["modprobe", "--show-depends", "-S", version, module], capture_output=True, timeout=10)
        if result.returncode and module in modules:
            raise RuntimeError(f"required guest module {module} unavailable")
        for line in result.stdout.decode().splitlines():
            if line.startswith("insmod "):
                copy_file(root, Path(line.split()[1]))
    for file in (Path("/lib/modules") / version).glob("modules.*"):
        copy_file(root, file)
    for name in ["lab.py", "peer.py", "network.py", "guest.py"]:
        copy_file(root, Path("/opt") / name, Path("/bootstrap") / name)
    copy_file(root, Path("/opt/guest-init.sh"), "/init")
    if modified:
        original = (root / "init").read_text()
        (root / "init").write_text(original.replace("#!/bin/busybox sh\n", "#!/bin/busybox sh\necho\necho REGALIA_MODIFIED_INITRAMFS_EXECUTED\n", 1))
    copy_file(root, Path("/opt/root-init.sh"), "/root-init")
    (root / "init").chmod(0o755)
    (root / "bootstrap/fixture.json").write_text(json.dumps(fixture))
    files = b"\0".join(os.fsencode(str(file.relative_to(root))) for file in root.rglob("*")) + b"\0"
    archive = subprocess.run(["cpio", "--null", "-o", "-H", "newc"], cwd=root,
                             input=files, capture_output=True, timeout=60, check=True).stdout
    initrd = Path("/tmp/node/guest-initrd.gz")
    initrd.write_bytes(gzip.compress(archive))
    return kernel, initrd


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", action="store_true")
    parser.add_argument("--survey", action="store_true")
    parser.add_argument("--modified-initramfs", action="store_true")
    parser.add_argument("--tamper-pcr", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    fixture = json.loads(input())
    if args.survey:
        fixture["survey"] = True
    if args.tamper_pcr:
        fixture["tamper_pcr"] = True
    kernel, initrd = build(fixture, modified=args.modified_initramfs)
    arm = platform.machine() == "aarch64"
    emulator = "qemu-system-aarch64" if arm else "qemu-system-x86_64"
    machine = ["-machine", "virt", "-cpu", "cortex-a57"] if arm else ["-machine", "q35"]
    arguments = [emulator, *machine, "-accel", "tcg", "-m", "512", "-smp", "2", "-nographic", "-no-reboot",
                 "-kernel", str(kernel), "-initrd", str(initrd), "-append",
                 f"console={'ttyAMA0' if arm else 'ttyS0'} quiet panic=1 net.ifnames=0 lab.format={int(args.format)}",
                 "-drive", "file=/tmp/node/disk.luks,if=virtio,format=raw,cache=writeback",
                 "-netdev", "user,id=net", "-device", "virtio-net-pci,netdev=net",
                 "-chardev", "socket,id=chrtpm,path=/tmp/node/A/tpm.sock.ctrl",
                 "-tpmdev", "emulator,id=tpm,chardev=chrtpm"]
    arguments += ["-device", f"{'tpm-tis-device' if arm else 'tpm-tis'},tpmdev=tpm"]
    result = subprocess.run(arguments, capture_output=True, timeout=180)
    markers = [line for line in (result.stdout + result.stderr).decode(errors="replace").splitlines()
               if line.startswith("REGALIA_")]
    diagnostics = [line for line in result.stderr.decode(errors="replace").splitlines()
                   if line.startswith(emulator + ":")]
    diagnostics += [line for line in result.stdout.decode(errors="replace").splitlines()
                    if "error while loading shared libraries" in line or line.startswith("ModuleNotFoundError:")]
    print(json.dumps({"exit_code": result.returncode, "markers": markers, "kernel": kernel.name,
                      "diagnostics": diagnostics,
                      "initramfs_sha256": hashlib.sha256(initrd.read_bytes()).hexdigest(),
                      "pcr7": next((line.removeprefix("REGALIA_PCR7_") for line in reversed(markers)
                                    if line.startswith("REGALIA_PCR7_")), None)}), flush=True)


if __name__ == "__main__":
    main()
