"""Exercise installed candidate utilities on private files without hardware.

This is a native userspace check, not a measured-boot or mount-security test.
All encryption keys and filesystem fixtures are temporary test data.
"""
import ctypes
import json
from pathlib import Path
import secrets
import subprocess
import tempfile
import uuid

from deploy.images.util_package import VERSION
from deploy.images.verify import require

PACKAGES = ("bsdutils", "mount", "util-linux", "util-linux-extra", "libmount1", "libblkid1",
            "libuuid1", "libsmartcols1", "liblastlog2-2")


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=60,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    require(result.returncode == 0, args[0] + " failed: " + result.stderr[-2000:])
    return result.stdout


def smoke():
    controls = {}
    for name in PACKAGES:
        version = command(["dpkg-query", "-W", "-f=${Version}", name])
        require(version == ("1:" if name == "bsdutils" else "") + VERSION,
                "installed utility version differs: " + name)
        controls[name] = version
    library_names = ("libmount.so.1", "libblkid.so.1", "libuuid.so.1", "libsmartcols.so.1", "liblastlog2.so.2")
    libraries = {name: ctypes.CDLL(name) for name in library_names}
    identifier = (ctypes.c_ubyte * 16)()
    generator = libraries["libuuid.so.1"].uuid_generate_random
    generator.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
    generator.restype = None
    generator(identifier)
    generated_uuid = uuid.UUID(bytes=bytes(identifier))
    require(generated_uuid.version == 4, "candidate UUID API returned an invalid identifier")
    with tempfile.TemporaryDirectory(prefix="regalia-util-smoke-") as temp:
        root = Path(temp)
        disk = root / "disk.img"
        with disk.open("wb") as stream:
            stream.truncate(64 * 1024 * 1024)
        key, wrong = root / "key", root / "wrong"
        key.write_bytes(secrets.token_bytes(32))
        wrong.write_bytes(secrets.token_bytes(32))
        # A small test-only KDF cost keeps this compatibility test bounded. It
        # never changes an appliance LUKS policy or contains a real credential.
        command(["cryptsetup", "luksFormat", "--type", "luks2", "--batch-mode", "--pbkdf", "pbkdf2",
                 "--pbkdf-force-iterations", "1000", "--key-file", str(key), str(disk)])
        disk_uuid = command(["cryptsetup", "luksUUID", str(disk)]).strip()
        uuid.UUID(disk_uuid)
        command(["cryptsetup", "open", "--test-passphrase", "--key-file", str(key), str(disk)])
        refused = subprocess.run(["cryptsetup", "open", "--test-passphrase", "--key-file", str(wrong), str(disk)],
                                 capture_output=True, text=True, timeout=60)
        require(refused.returncode == 2 and "No key available" in refused.stderr,
                "wrong LUKS test key was not refused specifically")
        probe = command(["blkid", "-p", "-o", "export", str(disk)])
        require("TYPE=crypto_LUKS" in probe.splitlines() and "UUID=" + disk_uuid in probe.splitlines(),
                "candidate blkid and cryptsetup disagree on LUKS identity")
        table = root / "fstab"
        table.write_text("UUID=" + disk_uuid + " /regalia-test ext4 defaults 0 2\n")
        mounts = json.loads(command(["findmnt", "--json", "--fstab", "--tab-file", str(table)]))
        require(len(mounts["filesystems"]) == 1 and mounts["filesystems"][0]["target"] == "/regalia-test",
                "candidate mount-table parser returned the wrong record")
    for tool in ("mount", "umount", "findmnt", "lsblk", "su", "sulogin"):
        command([tool, "--help"])
    return {"schema": "regalia.util-linux-native-smoke/v1", "status": "passed",
            "production_approved": False, "packages": controls, "loaded_libraries": list(libraries),
            "checks": ["UUID API", "LUKS2 header creation", "valid LUKS key", "wrong LUKS key rejected",
                       "blkid LUKS type/UUID", "findmnt fstab parser", "six CLI load checks"],
            "limits": ["No dm-crypt mapping, actual mount, measured boot, PAM login or hardware operations."]}


def main():
    print(json.dumps(smoke(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
