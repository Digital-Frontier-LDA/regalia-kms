#!/usr/bin/env python3
"""Every dynamic ELF file of an unpacked initrd, with its loader and every library it needs, in that initrd.

    python3 -BEs -m deploy.baremetal.elfclosure --root UNPACKED

#620's unlock-boot-qemu run 40636249776 (attempt 1) built an initrd without ld-linux-x86-64.so.2, libc.so.6 and every
other library dracut finds through ldd, while the libraries its modules install by name (libbpf, libcryptsetup, libffi,
libgcc_s, libjson-c) were there; attempt 2 of the same run, on the same inputs, built it whole. dracut 106 resolves
those libraries in one pass at the end (`find | xargs dracut-install -R`), and dracut-install takes an ldd that exits
below 126 ("not a dynamic executable" is 1) as a file with nothing to install: an ldd that misanswers for every file
makes dracut succeed with that very image. That the pass misanswered is inferred, not seen (dracut's log was not kept;
it is now). The inventory comparison refused that image, as a difference of 51 lines; this says what it was.

Each regular file that is an ELF64 little-endian executable or shared object (ET_EXEC, ET_DYN) is read: its PT_INTERP
must be a file in the initrd, and each DT_NEEDED must be found, as the loader searches, in its DT_RUNPATH (or DT_RPATH)
with $ORIGIN expanded, then the default directories. Symbolic links are followed inside UNPACKED, never out of it.
A static file needs nothing. A library loaded only by dlopen() is not anyone's DT_NEEDED and is not checked here.

Another machine's ELF (ELF32, big-endian, not x86-64: a device's firmware) is not this loader's and is skipped. The
directories etc/ld.so.conf names are searched after the run path, as the loader's cache holds them.

Exit 0 when every file has what it needs; 1, naming the missing loader and libraries, how many files lack them and the
first of those files, when one does not; 2 when the tree cannot be read or holds no dynamic ELF file at all.
"""
import argparse
import os
import struct
import sys

DEFAULT_DIRS = ("lib/x86_64-linux-gnu", "usr/lib/x86_64-linux-gnu", "lib64", "usr/lib64", "lib", "usr/lib")
PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_NEEDED, DT_STRTAB, DT_RPATH, DT_RUNPATH = 1, 5, 15, 29
ET_EXEC, ET_DYN = 2, 3
EM_X86_64 = 62
MAX_LINKS = 40
SHOWN = 20


class Unreadable(Exception):
    pass


class Foreign(str):
    """Why an ELF file is another machine's (its class, its byte order or its e_machine): skipped, and said so."""


def resolve(root, path):
    """`path` (absolute, as the initrd names it) to the file it is inside `root`, following symbolic links inside root
    only: an absolute target restarts at root. None when it is absent, or a link leads nowhere or loops."""
    parts = [p for p in path.split("/") if p not in ("", ".")]
    done, hops = [], 0
    while parts:
        part = parts.pop(0)
        if part == "..":
            if done:
                done.pop()
            continue
        here = os.path.join(root, *done, part)
        if os.path.islink(here):
            hops += 1
            if hops > MAX_LINKS:
                return None
            target = os.readlink(here)
            if target.startswith("/"):
                done = []
            parts = [p for p in target.split("/") if p not in ("", ".")] + parts
            continue
        if not os.path.lexists(here):
            return None
        done.append(part)
    full = os.path.join(root, *done)
    return full if os.path.isfile(full) else None


def elf_needs(data):
    """(interpreter or None, [DT_NEEDED], [run path directories as written]) of an ELF64 LE executable or shared
    object; None for any other file. A malformed ELF is Unreadable: a file the loader would refuse is not passed."""
    if data[:4] != b"\x7fELF":
        return None
    # another machine's ELF (a device's firmware, ELF32 or big-endian) is not loaded by this initrd's loader: skipped,
    # and every skip is printed with its reason, so the skip cannot hide a program of this machine
    if len(data) < 20:
        raise Unreadable("an ELF header cut short")
    if data[4] != 2:
        return Foreign("ELF class %d, not ELF64" % data[4])
    if data[5] != 1:
        return Foreign("byte order %d, not little-endian" % data[5])
    machine, = struct.unpack_from("<H", data, 18)
    if machine != EM_X86_64:
        return Foreign("e_machine %d, not x86-64" % machine)
    try:
        e_type, = struct.unpack_from("<H", data, 16)
        if e_type not in (ET_EXEC, ET_DYN):
            return None
        e_phoff, = struct.unpack_from("<Q", data, 32)
        e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
        loads, dynamic, interp = [], None, None
        for i in range(e_phnum):
            p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from("<IIQQQQQQ", data, e_phoff + i * e_phentsize)
            if p_type == PT_LOAD:
                loads.append((p_vaddr, p_offset, p_filesz))
            elif p_type == PT_DYNAMIC:
                dynamic = (p_offset, p_filesz)
            elif p_type == PT_INTERP:
                interp = data[p_offset:p_offset + p_filesz].split(b"\0", 1)[0].decode()
        if dynamic is None:
            return (interp, [], [])
        entries, strtab = [], None
        offset, end = dynamic[0], dynamic[0] + dynamic[1]
        while offset + 16 <= end:
            tag, value = struct.unpack_from("<qQ", data, offset)
            offset += 16
            if tag == 0:
                break
            if tag == DT_STRTAB:
                strtab = value
            entries.append((tag, value))
        if strtab is None:
            raise Unreadable("a dynamic section with no DT_STRTAB")
        base = next((off + strtab - vaddr for vaddr, off, size in loads if vaddr <= strtab < vaddr + size), None)
        if base is None:
            raise Unreadable("DT_STRTAB is in no loaded segment")

        def string(at):
            stop = data.index(b"\0", base + at)
            return data[base + at:stop].decode()
        needed = [string(v) for t, v in entries if t == DT_NEEDED]
        runpath = [d for t, v in entries if t == DT_RUNPATH for d in string(v).split(":") if d]
        if not runpath:
            runpath = [d for t, v in entries if t == DT_RPATH for d in string(v).split(":") if d]
        return (interp, needed, runpath)
    except (struct.error, ValueError, UnicodeDecodeError) as e:
        raise Unreadable(str(e))


def configured_dirs(root):
    """The directories etc/ld.so.conf names (with its include globs), inside root: the loader's cache holds them."""
    import glob
    found, seen = [], set()

    def read(path):
        real = resolve(root, path)
        if real is None or real in seen:
            return
        seen.add(real)
        with open(real) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line.startswith("include "):
                    for pattern in line.split()[1:]:
                        pattern = pattern if pattern.startswith("/") else os.path.join(os.path.dirname(path), pattern)
                        for hit in sorted(glob.glob(os.path.join(root, pattern.lstrip("/")))):
                            read("/" + os.path.relpath(hit, root))
                elif line.startswith("/"):
                    found.append(line)
    read("/etc/ld.so.conf")
    return found


def missing_of(root):
    """{what is missing: [the files that lack it]}, how many dynamic ELF files were judged, and [(file, why)] skipped as
    another machine's."""
    missing, judged, skipped = {}, 0, []
    configured = configured_dirs(root)
    for directory, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(directory, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            with open(path, "rb") as f:
                data = f.read()
            relative = "/" + os.path.relpath(path, root)
            try:
                needs = elf_needs(data)
            except Unreadable as e:
                raise Unreadable("%s: %s" % (relative, e))
            if needs is None:
                continue
            if isinstance(needs, Foreign):
                skipped.append((relative, needs))
                continue
            interp, needed, runpath = needs
            if interp is None and not needed:
                continue
            judged += 1
            if interp is not None and resolve(root, interp) is None:
                missing.setdefault("the loader " + interp, []).append(relative)
            origin = os.path.dirname(relative)
            search = [d.replace("$ORIGIN", origin).replace("${ORIGIN}", origin) for d in runpath] + configured + ["/" + d for d in DEFAULT_DIRS]
            for soname in needed:
                if "/" in soname:
                    found = resolve(root, soname if soname.startswith("/") else os.path.join(origin, soname))
                else:
                    found = next((hit for d in search for hit in [resolve(root, os.path.join(d, soname))] if hit), None)
                if found is None:
                    missing.setdefault(soname, []).append(relative)
    return missing, judged, skipped


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", required=True, help="the unpacked initrd")
    args = ap.parse_args(argv)
    if not os.path.isdir(args.root):
        print("elfclosure: %s is not a directory" % args.root, file=sys.stderr)
        return 2
    try:
        missing, judged, skipped = missing_of(args.root)
    except (OSError, Unreadable) as e:
        print("elfclosure: the initrd cannot be read: %s" % e, file=sys.stderr)
        return 2
    for path, why in skipped:
        print("elfclosure: skipped %s: another machine's ELF (%s)" % (path, why))
    if judged == 0:
        # a tree with no dynamic ELF file is no initrd this builder makes: a wrong --root, or an unpack that failed
        print("elfclosure: %s holds no dynamic ELF file: nothing was checked" % args.root, file=sys.stderr)
        return 2
    if not missing:
        print("elfclosure: %d dynamic ELF file(s), each with its loader and every library it needs; %d skipped as another"
              " machine's" % (judged, len(skipped)))
        return 0
    lacking = sorted({f for files in missing.values() for f in files})
    print("elfclosure: %d of %d dynamic ELF file(s) lack what they need: %d missing (a loader or a library); %d skipped as"
          " another machine's" % (len(lacking), judged, len(missing), len(skipped)))
    for what in sorted(missing, key=lambda w: (-len(missing[w]), w))[:SHOWN]:
        print("  %s, needed by %d file(s), e.g. %s" % (what, len(missing[what]), missing[what][0]))
    if len(missing) > SHOWN:
        print("  ... and %d more" % (len(missing) - SHOWN))
    return 1


if __name__ == "__main__":
    sys.exit(main())
