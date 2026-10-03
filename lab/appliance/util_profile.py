"""Prepare only the reviewed util-linux 2.42.4 / Debian packaging combination.

Source authentication remains a separate host gate. This transformation retains
the downstream patches and test policy; it grants no binary package admission.
"""
import argparse
import hashlib
from pathlib import Path

from deploy.images.verify import hash_regular, read_regular, require

VERSION = "2.42.4-0+regalia1"
FILES = {
    "debian/control": "3f9ff1015a263906b45094949abb28bd8e8c0b5c2fd1176762de1553696fb305",
    "debian/changelog": "a9174d55cd1d7be7eae33675dd24c3c3662766f9ad53ee914d6c7607e44e79aa",
    "debian/patches/series": "5b1df14f3d86dedc98174065a1ea5a5e05fa6e64ac85a3023f49b26bb3e41c88",
    "debian/patches/debian/lsfd-usrbin.patch": "3855ccf229151d6df6646d82a27dc78fa0303dbc4f9272bce9607fb311cb025c",
    "debian/patches/upstream/loopdev-use-openat2-RESOLVE_NO_SYMLINKS-for-backing-file.patch": "9276c07a00380c76512cecdf1521489b403201ec0f15d63a831795365c46acf6",
    "debian/patches/upstream/libmount-restrict-source-path-canonicalization-for-non-ro.patch": "543fe497aaa63410af1053e52724cb8bfae9d7e0660fd86c490b4ec43fde8133",
    # These exact authenticated upstream files contain both backing-file open
    # checks and the restricted /dev/ canonicalization already patched in Debian.
    "lib/loopdev.c": "0c5d58080d03202f483ba6c41d3af30b656cd8be86862f6b847dfffa7167a25e",
    "libmount/src/context.c": "e8a67883eb37f459f255047ca325ffffc12427708487d3baab9d33ec9cb298e8",
}
UPSTREAMED = (
    "upstream/loopdev-use-openat2-RESOLVE_NO_SYMLINKS-for-backing-file.patch",
    "upstream/libmount-restrict-source-path-canonicalization-for-non-ro.patch",
)


def prepare(root):
    # Check the whole reviewed edit set before making any change. Fresh source
    # directories are required; applying this profile twice must refuse.
    for name, digest in FILES.items():
        require(hash_regular(root / name, "sha256")[0] == digest,
                "util-linux profile input differs: " + name)
    edits = {}
    series = read_regular(root / "debian/patches/series").decode()
    for name in UPSTREAMED:
        require(series.count(name + "\n") == 1, "upstreamed patch is missing or ambiguous")
        series = series.replace(name + "\n", "")
    edits["debian/patches/series"] = series
    control = read_regular(root / "debian/control").decode()
    maintainer = "Maintainer: Chris Hofstaedtler <zeha@debian.org>"
    require(control.count(maintainer) == 1, "Debian maintainer field differs")
    edits["debian/control"] = control.replace(maintainer, "Maintainer: Regalia laboratory <noreply@example.invalid>")
    changelog = read_regular(root / "debian/changelog").decode()
    edits["debian/changelog"] = (
        f"util-linux ({VERSION}) experimental; urgency=medium\n\n"
        "  * Laboratory build from authenticated upstream 2.42.4 with reviewed Debian packaging.\n"
        "  * Upstreamed security patches are not applied twice; downstream Debian changes retained.\n\n"
        " -- Regalia laboratory <noreply@example.invalid>  Sat, 03 Oct 2026 00:00:00 +0000\n\n" + changelog)
    name = "debian/patches/debian/lsfd-usrbin.patch"
    patch = read_regular(root / name).decode()
    require(patch.count("lsfd-cmd/file.c: errnos.h") == 1, "lsfd patch context differs")
    # Only a make dependency's source filename changed upstream; retain Debian's
    # actual installation-path edit. dpkg-source must still apply without fuzz.
    edits[name] = patch.replace("lsfd-cmd/file.c: errnos.h", "lsfd-cmd/error.c: errnos.h")
    for name, text in edits.items():
        (root / name).write_text(text)
    return {name: hashlib.sha256(text.encode()).hexdigest() for name, text in edits.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    args = parser.parse_args()
    prepare(args.source)


if __name__ == "__main__":
    main()
