"""The node-units runner's disposable ESP, kept mounted across both parts."""

from contextlib import contextmanager


def require_vfat(esp, sh):
    fstype = sh("findmnt", "--kernel", "--nocanonicalize", "--noheadings",
                "--output", "FSTYPE", "--mountpoint", str(esp)).stdout.strip()
    if fstype != "vfat":
        raise SystemExit(f"node-units-systemd: {esp} must be mounted as vfat, found {fstype!r}")


@contextmanager
def mounted(work, esp, sh):
    """Format only a new regular image in work. Leave pre-existing mounts alone."""
    if esp.is_symlink():
        raise SystemExit(f"node-units-systemd: refusing a symlink at {esp}")
    made = not esp.exists()
    if made:
        esp.mkdir(mode=0o700)
    image = work / "node-units-esp.img"
    image_created = mounted_here = False
    try:
        # mountpoint returns 32 for a path that is not a mountpoint. Existing
        # mounts (including VFAT) and unexpected probe errors both stop setup.
        probe = sh("mountpoint", "--quiet", str(esp), check=False)
        if probe.returncode != 32:
            raise SystemExit(f"node-units-systemd: refusing to prepare {esp}: "
                             f"mountpoint exited {probe.returncode} (0 means already mounted)")
        with image.open("xb") as disk:
            image_created = True
            disk.truncate(64 * 1024 * 1024)
        sh("mkfs.vfat", "-F", "32", str(image))
        # mount owns allocation and autoclear of the loop device.
        sh("mount", "-t", "vfat", "-o", "loop,nosuid,nodev,noexec,fmask=0077,dmask=0077", str(image), str(esp))
        mounted_here = True
        require_vfat(esp, sh)
        yield
    finally:
        if mounted_here:
            # If this fails, retain the backing image and mountpoint.
            sh("umount", str(esp))
        if image_created:
            image.unlink()
        if made:
            esp.rmdir()
