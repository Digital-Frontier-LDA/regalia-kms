"""Boot a disposable disk overlay through UEFI after image verification ends."""

import argparse
import hashlib
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time

from deploy.images.verify import require


def normal_boot(disk: Path, firmware: Path, variables: Path, log: Path, acceleration: str = "tcg") -> dict:
    # Unix socket paths are limited to roughly 100 bytes; worktree paths on
    # macOS and hosted CI can already exceed that before the socket basename.
    with tempfile.TemporaryDirectory(prefix="regalia-probe-", dir="/tmp") as temporary:
        staging = Path(temporary)
        overlay = staging / "overlay.qcow2"
        subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(disk), str(overlay)],
                       check=True, capture_output=True)
        shutil.copyfile(variables, staging / "vars.fd")
        monitor = staging / "monitor.sock"
        command = ["qemu-system-x86_64", "-machine", "q35,accel=" + acceleration,
                   "-cpu", "host" if acceleration == "kvm" else "max", "-m", "3072", "-smp", "4",
                   "-display", "none", "-no-reboot", "-device", "virtio-rng-pci",
                   "-drive", f"if=pflash,format=raw,readonly=on,file={firmware}",
                   "-drive", f"if=pflash,format=raw,file={staging / 'vars.fd'}",
                   "-drive", f"if=virtio,format=qcow2,file={overlay}",
                   "-nic", "user,restrict=on,model=virtio-net-pci", "-serial", "file:" + str(log),
                   "-monitor", f"unix:{monitor},server=on,wait=off"]
        started = time.monotonic()
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            deadline = started + 180
            while time.monotonic() < deadline and process.poll() is None:
                text = log.read_text(errors="replace") if log.exists() else ""
                text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
                if re.search(r"Reached target .*multi-user.target", text):
                    break
                time.sleep(0.2)
            else:
                raise ValueError("normal UEFI boot did not reach multi-user.target")
            require("REGALIA_ACCEPTANCE_BEGIN" not in text, "verification reran during normal boot")
            lines = [line for line in text.splitlines() if "Kernel command line:" in line]
            require(bool(lines) and all("regalia.image_verify=1" not in line for line in lines),
                    "normal boot still has verification flag")
            boot_seconds = round(time.monotonic() - started, 2)
            with socket.socket(socket.AF_UNIX) as connection:
                connection.settimeout(10)
                connection.connect(str(monitor))
                connection.sendall(b"system_powerdown\n")
            require(process.wait(timeout=120) == 0, "normal guest did not shut down cleanly")
            return {"status": "passed", "mode": "UEFI disk boot in disposable overlay",
                    "multi_user_seconds": boot_seconds, "verification_reran": False,
                    "log_sha256": hashlib.sha256(log.read_bytes()).hexdigest()}
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            process.stderr.close()


if __name__ == "__main__":
    import json
    from deploy.images.verify import hash_regular
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--firmware", type=Path, default=Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
                        if Path("/usr/share/OVMF/OVMF_CODE_4M.fd").exists()
                        else Path("/opt/homebrew/share/qemu/edk2-x86_64-code.fd"))
    args = parser.parse_args()
    directory = args.build.resolve()
    report = json.loads((directory / "build-report.json").read_text())
    disk = directory / "regalia-debian13-amd64.qcow2"
    require(report.get("status") == "passed" and hash_regular(disk, "sha256")[0] == report["disk_sha256"], "build image differs")
    result = normal_boot(disk, args.firmware,
                         directory / "uefi-vars.fd", directory / "normal-boot.log")
    require(hash_regular(disk, "sha256")[0] == report["disk_sha256"], "probe changed base image")
    report["normal_boot"] = result
    (directory / "build-report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(result, indent=2))
