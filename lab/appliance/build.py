"""Build and boot a credential-free Debian prototype using authenticated media."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time

from deploy.images.verify import VerificationError, hash_regular, require, verify_gpg
from .probe import normal_boot
from deploy.images.snapshot import validate as validate_snapshot, check_installed, render_preseed, POLICY as SNAPSHOT_POLICY


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def command(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def install_guest(args: list[str], log: Path, timeout: float):
    """Stop an unattended installer promptly after the fixed failure marker."""
    with log.with_suffix(".stderr").open("wb") as errors:
        process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=errors)
        try:
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if log.exists() and "REGALIA_BUILD_FAILED" in log.read_text(errors="replace"):
                    raise VerificationError("guest setup failed; see installer diagnostic log")
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(args, timeout)
                time.sleep(0.2)
            require(process.returncode == 0, "installer process failed")
            require(not log.exists() or "REGALIA_BUILD_FAILED" not in log.read_text(errors="replace"),
                    "guest setup failed; see installer diagnostic log")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def build(media: Path, output: Path, firmware: Path, variables: Path, timeout: int, acceleration: str = "tcg", packages: Path | None = None) -> dict:
    packages = packages or ROOT / "deploy/images/.artifacts/package-snapshot"
    package_report, package_inventory = validate_snapshot(packages)
    snapshot_policy = json.loads(SNAPSHOT_POLICY.read_text())
    policy = json.loads((ROOT / "deploy/images/debian-policy.json").read_text())
    media_report = verify_gpg(media / policy["image"], media / policy["checksum"],
                              media / policy["signature"], media / "debian-cd.pub",
                              policy["primary_fingerprint"])
    require(not output.exists(), "build output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".appliance-build-", dir=output.parent))
    report = {"schema": "regalia.appliance-build/v1", "status": "building",
              "evidence_class": "emulated", "production_approved": False, "acceleration": acceleration,
              "installer": media_report, "package_snapshot": package_report, "sources": {}}
    try:
        frozen = staging / "inputs"
        frozen.mkdir()
        for source, target in (("preseed.cfg", "preseed.cfg"), ("finish.sh", "regalia-finish.sh"),
                               ("acceptance.sh", "regalia-acceptance.sh")):
            data = (HERE / source).read_bytes()
            if source == "preseed.cfg":
                data = render_preseed(data.decode(), snapshot_policy).encode()
            (frozen / target).write_bytes(data)
            report["sources"][source] = hashlib.sha256(data).hexdigest()
        commit = command(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        report["source_commit"] = commit
        source_tar = frozen / "regalia-source.tar"
        command(["git", "archive", "--format=tar", "--output", str(source_tar), commit], cwd=ROOT)
        metadata = frozen / "BUILD_COMMIT"
        metadata.write_text(commit + "\n")
        with tarfile.open(source_tar, "a") as archive:
            archive.add(metadata, arcname="BUILD_COMMIT")
        metadata.unlink()
        report["source_archive_sha256"] = hashlib.sha256(source_tar.read_bytes()).hexdigest()
        for source, destination in (("/install.amd/vmlinuz", "vmlinuz"), ("/install.amd/initrd.gz", "installer.gz")):
            command(["xorriso", "-osirrox", "on", "-indev", str(media / policy["image"]),
                     "-extract", source, str(staging / destination)], capture_output=True)
        files = "\n".join(sorted(path.name for path in frozen.iterdir())) + "\n"
        extra = command(["cpio", "-o", "-H", "newc"], cwd=frozen, input=files.encode(), capture_output=True).stdout
        initrd = staging / "installer-initrd.gz"
        initrd.write_bytes((staging / "installer.gz").read_bytes() + gzip.compress(extra, mtime=0))
        disk = staging / "regalia-debian13-amd64.qcow2"
        command(["qemu-img", "create", "-f", "qcow2", str(disk), "8G"], capture_output=True)
        shutil.copyfile(variables, staging / "uefi-vars.fd")
        report["firmware_sha256"] = hashlib.sha256(firmware.read_bytes()).hexdigest()
        report["qemu_version"] = command(["qemu-system-x86_64", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
        common = ["qemu-system-x86_64", "-machine", "q35,accel=" + acceleration, "-cpu", "host" if acceleration == "kvm" else "max",
                  "-m", "3072", "-smp", "4", "-display", "none", "-monitor", "none", "-no-reboot",
                  "-drive", f"if=pflash,format=raw,readonly=on,file={firmware}",
                  "-drive", f"if=pflash,format=raw,file={staging / 'uefi-vars.fd'}",
                  "-drive", f"if=virtio,format=qcow2,file={disk}",
                  "-device", "virtio-rng-pci"]
        install = common + ["-kernel", str(staging / "vmlinuz"), "-initrd", str(initrd),
                            "-append", "auto=true priority=critical console=ttyS0,115200 DEBIAN_FRONTEND=text",
                            "-cdrom", str(media / policy["image"]),
                            "-nic", "user,model=virtio-net-pci", "-serial", f"file:{staging / 'install.log'}"]
        print("Installing verified Debian media in a disposable UEFI QEMU guest...", flush=True)
        started = time.monotonic()
        install_guest(install, staging / "install.log", timeout)
        require("REGALIA_BUILD_COMPLETE" in (staging / "install.log").read_text(errors="replace"),
                "installer did not complete the appliance build")
        export = staging / "export"
        export.mkdir()
        acceptance = common + ["-nic", "user,restrict=on,model=virtio-net-pci",
                               "-fsdev", f"local,id=export,path={export},security_model=none",
                               "-device", "virtio-9p-pci,fsdev=export,mount_tag=regalia_export",
                               "-serial", f"file:{staging / 'acceptance.log'}"]
        print("Booting the installed disk and checking appliance restrictions...", flush=True)
        with (staging / "acceptance.stderr").open("wb") as errors:
            command(acceptance, timeout=600, stdout=subprocess.DEVNULL, stderr=errors)
        log = (staging / "acceptance.log").read_text(errors="replace")
        require("REGALIA_ENFORCED_DAEMON_PASS" in log and
                "REGALIA_ACCEPTANCE_PASS" in log and "REGALIA_FAIL:" not in log,
                "appliance acceptance failed")
        print("Checking normal UEFI boot without the verification flag...", flush=True)
        report["normal_boot"] = normal_boot(disk, firmware, staging / "uefi-vars.fd",
                                           staging / "normal-boot.log", acceleration)
        command(["qemu-img", "check", str(disk)], capture_output=True)
        with disk.open("rb") as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        report.update({"status": "passed", "elapsed_seconds": round(time.monotonic() - started),
                       "disk_sha256": digest, "acceleration": acceleration})
        report["installed_package_binding"] = check_installed(export / "packages.tsv", package_inventory)
        report["export"] = {path.name: hash_regular(path, "sha256")[0] for path in export.iterdir()}
        # Preserve useful final artifacts and evidence, not the compiler source
        # snapshot or installer initramfs. Failed builds retain diagnostics.
        shutil.rmtree(frozen)
        for name in ("vmlinuz", "installer.gz", "installer-initrd.gz"):
            (staging / name).unlink()
        (staging / "build-report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        staging.rename(output)
        return report
    except BaseException:
        report["status"] = "failed"
        (staging / "build-report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print(f"Failed build diagnostics: {staging}", flush=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--media", type=Path, required=True)
    parser.add_argument("--packages", type=Path, default=ROOT / "deploy/images/.artifacts/package-snapshot")
    parser.add_argument("--output", type=Path, default=HERE / ".artifacts/debian13-prototype")
    linux = Path("/usr/share/OVMF/OVMF_CODE_4M.fd").is_file()
    parser.add_argument("--firmware", type=Path, default=Path("/usr/share/OVMF/OVMF_CODE_4M.fd" if linux else "/opt/homebrew/share/qemu/edk2-x86_64-code.fd"))
    parser.add_argument("--variables", type=Path, default=Path("/usr/share/OVMF/OVMF_VARS_4M.fd" if linux else "/opt/homebrew/share/qemu/edk2-i386-vars.fd"))
    parser.add_argument("--acceleration", choices=("tcg", "kvm"), default="kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg")
    parser.add_argument("--timeout", type=int, default=3600)
    args = parser.parse_args()
    try:
        print(json.dumps(build(args.media.resolve(), args.output.resolve(), args.firmware.resolve(),
                               args.variables.resolve(), args.timeout, args.acceleration, args.packages.resolve()), sort_keys=True, indent=2))
    except (VerificationError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"REFUSED: {error}\n")


if __name__ == "__main__":
    main()
