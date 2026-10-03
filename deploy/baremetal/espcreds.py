#!/usr/bin/env python3
"""What systemd-stub measures into PCR 12 for the credentials on a host's ESP (#66, stage 2).

A KMS host's image is the same for every host; what differs per host reaches its initrd as system
credentials, files named <name>.cred in the ESP's loader/credentials directory. systemd-stub packs every
such file into one cpio archive (unpacked by the kernel at /.extra/global_credentials) and extends PCR 12
ONCE with the SHA-256 of that archive (systemd 257, src/boot/cpio.c pack_cpio and src/boot/stub.c,
"Global credentials initrd"). The archive is deterministic: the names sorted, mtimes zero, fixed modes.

So the PCR 12 a node shows in its initrd follows from its credential files alone, and a peer can be
given the value to expect: any other file there, a changed one, or one more (a unit drop-in, a tmpfiles
line, which systemd in the initrd would act on) gives another PCR 12, and the peers refuse the quote.

    pcr12(files)       64 lowercase hex: PCR 12 (SHA-256 bank) after the stub, from {file name: bytes}
    record(files)      {"pcr12", "credentials": [{"file", "name", "sha256", "size"}, ...]}, in the stub's order

What the stub skips, it does not measure either, and this module skips the same: a name that is not ASCII,
is longer than 255 characters, starts with a dot, or does not end in ".cred" (any case).

NOT covered here, and each would change PCR 12, so the peers refuse (the intent): the per-image credentials
(<image>.extra.d/*.cred, measured as an archive of their own BEFORE the global one), configuration extensions,
PE addons (loader/addons, <image>.extra.d/*.addon.efi), a kernel command line from a boot loader or from the
SMBIOS string io.systemd.stub.kernel-cmdline-extra, and a UKI profile other than the first. A KMS host has
none of them.

NOT MEASURED AT ALL, by anything the peers attest: credentials systemd in the initrd imports from other
sources, SMBIOS type 11 strings and QEMU's fw_cfg (systemd 257 src/core/import-creds.c). SMBIOS reaches
PCR 1 at most, through the firmware. What systemd does with credentials by name must therefore be
restricted in the image itself (#66, B2).
"""
import hashlib

PREFIX = ".extra/global_credentials"
DIRECTORY = "loader/credentials"
SUFFIX = ".cred"
ZERO = "00" * 32


def _word(value):
    return b"%08x" % value


def _header(inode, mode, size, name):
    # newc ("070701"): inode, mode, uid, gid, nlink, mtime, size, dev major/minor, rdev major/minor,
    # name size (with its NUL), check
    return (b"070701" + _word(inode) + _word(mode) + _word(0) + _word(0) + _word(1) + _word(0) + _word(size)
            + _word(0) * 4 + _word(len(name) + 1) + _word(0) + name + b"\0")


def _pad(data):
    return data + b"\0" * (-len(data) % 4)


def measured(name):
    """Whether the stub picks this file up (and measures it)."""
    return (isinstance(name, str) and name.isascii() and 0 < len(name) <= 255 and not name.startswith(".")
            and name.lower().endswith(SUFFIX))


def archive(files):
    """The cpio archive the stub makes of `files` ({file name: bytes}), or None when it makes none."""
    names = sorted(n for n in files if measured(n))
    if not names:
        return None
    out, inode = b"", 1
    parts = PREFIX.split("/")
    for depth in range(1, len(parts) + 1):
        path = "/".join(parts[:depth]).encode()
        mode = 0o040000 | (0o500 if depth == len(parts) else 0o555)
        out += _pad(_header(inode, mode, 0, path))
        inode += 1
    for name in names:
        content = files[name]
        out += _pad(_header(inode, 0o100000 | 0o400, len(content), (PREFIX + "/" + name).encode()))
        out += _pad(content)
        inode += 1
    trailer = b"070701" + b"00000000" * 4 + b"00000001" + b"00000000" * 6 + b"0000000B" + b"00000000" + b"TRAILER!!!\0\0\0\0"
    return out + trailer


def pcr12(files):
    """PCR 12 (SHA-256) as the stub leaves it, from the ESP's credential files and nothing else."""
    packed = archive(files)
    if packed is None:
        return ZERO
    return hashlib.sha256(bytes(32) + hashlib.sha256(packed).digest()).hexdigest()


def record(files):
    """PCR 12 and what it was computed from, in the stub's order: what a measurement set is made from."""
    names = sorted(n for n in files if measured(n))
    return {"pcr12": pcr12(files),
            # the stub takes the suffix in any case, systemd imports only ".cred" exactly: a file it measures but
            # never makes a credential of has no name
            "credentials": [{"file": n, "name": n[:-len(SUFFIX)] if n.endswith(SUFFIX) else None,
                             "sha256": hashlib.sha256(files[n]).hexdigest(), "size": len(files[n])} for n in names]}
