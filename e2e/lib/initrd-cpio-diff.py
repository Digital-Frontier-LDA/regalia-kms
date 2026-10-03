#!/usr/bin/env python3
"""initrd-cpio-diff.py A.img B.img: why two initrds with the same files are different bytes (#248).

Each image is split into its segments as the kernel reads them (cpio archives, NUL padding, compressed
streams, decompressed here with gzip/xz in Python or zstd/lz4 through the tool). It says whether the
decompressed cpio streams are identical (then only the COMPRESSION differs, and the compressor is the
unpinned input) or, if not, the first entry whose header or data differs, with every newc header field
(inode, mode, uid, gid, nlink, mtime, size, device numbers), so the varying field is named.
"""
import gzip
import lzma
import subprocess
import sys

FIELDS = ("ino", "mode", "uid", "gid", "nlink", "mtime", "filesize", "devmajor", "devminor", "rdevmajor", "rdevminor", "namesize", "check")


def segments(data):
    """[(kind, raw bytes)]: each cpio archive as stored, each compressed stream decompressed."""
    out, pos = [], 0
    while pos < len(data):
        if data[pos] == 0:
            pos += 1
            continue
        if data[pos:pos + 6] in (b"070701", b"070702"):
            start = pos
            while True:
                head = data[pos:pos + 110]
                f = [int(head[i:i + 8], 16) for i in range(6, 110, 8)]
                name_end = pos + 110 + f[11]
                body = (name_end + 3) & ~3
                name = data[pos + 110:name_end - 1]
                pos = (body + f[6] + 3) & ~3
                if name == b"TRAILER!!!":
                    break
            out.append(("cpio", data[start:pos]))
            continue
        rest = data[pos:]
        if rest[:2] == b"\x1f\x8b":
            out.append(("gzip", gzip.decompress(rest)))
        elif rest[:6] == b"\xfd7zXZ\x00":
            out.append(("xz", lzma.decompress(rest)))
        elif rest[:4] == b"\x28\xb5\x2f\xfd":
            out.append(("zstd", subprocess.run(["zstd", "-dc"], input=rest, capture_output=True, check=True).stdout))
        elif rest[:4] == b"\x02\x21\x4c\x18":
            out.append(("lz4", subprocess.run(["lz4", "-dc"], input=rest, capture_output=True, check=True).stdout))
        else:
            out.append(("unknown", rest))
        break
    return out


def entries(stream):
    """[(name, header fields, data)] of one decompressed cpio stream (possibly several archives)."""
    out, pos = [], 0
    while pos < len(stream):
        if stream[pos] == 0:
            pos += 1
            continue
        head = stream[pos:pos + 110]
        f = dict(zip(FIELDS, (int(head[i:i + 8], 16) for i in range(6, 110, 8))))
        name_end = pos + 110 + f["namesize"]
        body = (name_end + 3) & ~3
        name = stream[pos + 110:name_end - 1].decode("utf-8", "backslashreplace")
        out.append((name, f, stream[body:body + f["filesize"]]))
        pos = (body + f["filesize"] + 3) & ~3
    return out


def main(a_path, b_path):
    a, b = (segments(open(p, "rb").read()) for p in (a_path, b_path))
    print("segments: %s | %s" % ([(k, len(r)) for k, r in a], [(k, len(r)) for k, r in b]))
    for n, ((ka, ra), (kb, rb)) in enumerate(zip(a, b)):
        if ra == rb:
            print("segment %d (%s): the same bytes once decompressed%s" % (
                n, ka, "; only its COMPRESSED form differs: the compressor is the varying input" if ka not in ("cpio",) else ""))
            continue
        print("segment %d (%s / %s): the decompressed cpio streams differ" % (n, ka, kb))
        ea, eb = entries(ra), entries(rb)
        print("entries: %d / %d" % (len(ea), len(eb)))
        shown = 0
        for i, (x, y) in enumerate(zip(ea, eb)):
            if x == y:
                continue
            fields = [k for k in FIELDS if x[1][k] != y[1][k]]
            print("entry %d: %s | %s; header fields that differ: %s; data %s" % (
                i, x[0], y[0], ", ".join("%s %d/%d" % (k, x[1][k], y[1][k]) for k in fields) or "none",
                "same" if x[2] == y[2] else "DIFFERS"))
            shown += 1
            if shown >= 20:
                break
    if len(a) != len(b):
        print("the images have %d and %d segments" % (len(a), len(b)))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
