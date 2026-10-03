#!/usr/bin/env python3
"""The boot image of a KMS host: one unified kernel image (UKI), built the same on any machine, with a
record of what it will measure, and signed in a separate step by keys that are on no host (#57).

    python3 -Es -m deploy.baremetal.uki build   INPUTS --name NAME --out DIR
    python3 -Es -m deploy.baremetal.uki sign    INPUTS --record DIR/NAME.record.json --second-record OTHER/NAME.record.json --out DIR
                                            --initrd-key K --initrd-cert C --system-key K --system-cert C
                                            --secure-boot-key K --secure-boot-cert C [--key-source file|engine:pkcs11]
    python3 -Es -m deploy.baremetal.uki verify  --image IMAGE --record RECORD --initrd-pub P --system-pub P --secure-boot-cert C
    python3 -Es -m deploy.baremetal.uki set     --record RECORD --label LABEL --tpm-firmware-version HEX --pcrs FILE
                                            --esp ROOT [--credentials-record OUT]

    INPUTS: --linux VMLINUZ --initrd INITRD [--microcode FILE] --cmdline FILE --os-release FILE
            --uname VERSION --stub LINUX-STUB --pcrpkey SYSTEM-KEY.pub

WHAT IS MEASURED. systemd-stub extends PCR 11 with every section of the image it boots, in a fixed order,
and systemd then extends it with the name of each boot phase. So one image has one PCR 11 value in the
initrd (phase path `enter-initrd`), where a host asks a peer for its disk, and another once booted
(`enter-initrd:leave-initrd:sysinit:ready`), where it asks for a lease. `build` writes both into the
RECORD; they are what the measurement document's per-phase set holds (`set` prints that set;
attest.py, "PCR VALUES PER BOOT PHASE"). The values are computed here from the bytes of the built
image and must equal what this machine's systemd-measure says, or nothing is written: a systemd that
measures differently from this code is found at build time, not by a host that does not come back.

build   runs `ukify build` with no key, reads the image back, and requires every measured section to be
        the input it was given, byte for byte. ukify is deterministic (measured on 257: the same inputs
        give the same file), so the record's `unsigned_sha256` is what a second builder must also get.
        The image may hold only the sections this tool knows how to measure; any other is refused.
sign    refuses a record whose initrd review did not pass (#198). It
        takes TWO records of the same image built on two machines, which must be identical: one builder
        alone decides nothing. It copies every input into its private work directory ONCE and builds only
        from those copies, so no input can change between the builds it makes. It then builds the image
        again from the same inputs, which must hash to the record's values; signs the
        initrd-phase PCR 11 with one key and the booted-phase PCR 11 with another (two keys, so a secret
        sealed for the booted system does not open in the initrd); checks both signatures itself with
        OpenSSL against the policy it computed; attaches them (.pcrsig); requires EVERY section (the
        stub's code as well as the measured ones) to be unchanged apart from the added .pcrsig; then signs
        the file for Secure Boot, checks that, and requires every section unchanged by it.
        The key options take files, or with --key-source engine:pkcs11 the PKCS#11 URIs of keys in a
        token (the certificates are always files). A URI must name the card and the key: serial=, token=,
        object= or id=, and type=private, and nothing else (no query, no module path). No option takes
        a PIN, and a PIN in a URI is refused. WHO ASKS FOR THE PIN: systemd-measure asks through systemd's
        own password prompt (and keeps it in the user keyring as "measure-private-key-pin", which this
        tool purges after each signature; an inherited $CREDENTIALS_DIRECTORY is removed so the PIN cannot
        come in as a credential); sbsign asks through OpenSSL's engine. Three prompts in all.
        ONE CARD ATTACHED: the engine loads its PKCS#11 module, which enumerates EVERY slot before any
        login, and this tool cannot list them itself (it does not know the module). serial= in the URI is
        what selects the card, but a session with other cards attached exposes them to every load: the
        signing session attaches the signing HSM alone (a ceremony step, regalia#554).
verify  what a host's operator runs before installing an image: its measured sections AND the stub's
        sections are the record's, its two PCR signatures verify under the keys the record names, for the
        PCR 11 the record predicts, and its Secure Boot signature verifies under the certificate the
        record names (required: the stub is not in PCR 11, and only that signature covers it).

THE KEYS. Three RSA-2048 keys: the two PCR keys and the Secure Boot key, each different from the others
(refused otherwise). RSA because systemd seals only to an RSA key (systemd-measure itself would sign
with an EC key, and nothing could use the result); 2048 because the host's TPM has to load the public
key, and that is the size every TPM 2.0 has. The public half of the SYSTEM key is a section of the image
(.pcrpkey) and so is itself measured: it is an input of `build`. The initrd-phase key's public half is
given where the initrd's secret is sealed (unlock.seal_local).

THE INITRD'S REVIEW (#198, KERNEL-UPDATE.md step 2.2a). `build` unpacks the initrd it measures and
records whether it opens the root disk only through the unlock client (the rules are above
review_initrd); `sign` refuses a record whose review did not pass, and runs the review again on its own
copy; `verify` runs it again on the image's .initrd section.

WHAT THIS DOES NOT DO. It does not fetch or pin the inputs, build the initrd, or install anything. The command-line check is a short refusal list
(disk-unlock words, debug shells), not a review. Whether a real machine measures what the record says is
shown on a software TPM by e2e/uki-build.sh (the same sections replayed) and has not been shown by a
boot. Nothing here has run with a hardware token.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

from deploy.baremetal import attest, espcreds, membership

Refused, require = membership.Refused, membership.require

SCHEMA = "regalia.uki-build/v1"
# systemd-stub measures these sections into PCR 11, in this order, each as its name (".linux\0") then its
# content (systemd 257: src/fundamental/uki.h; .pcrsig is the one section left out). OURS are the ones a
# KMS host's image may hold; an image with any of the others is refused rather than measured by guess.
ORDER = ("linux", "osrel", "cmdline", "initrd", "ucode", "splash", "dtb", "uname", "sbat", "pcrpkey", "profile", "dtbauto", "hwids")
OURS = ("linux", "osrel", "cmdline", "initrd", "ucode", "uname", "sbat", "pcrpkey")
STUB_SECTIONS = (".text", ".rodata", ".data", ".reloc", ".sdmagic")
PHASE_PATHS = {"initrd": "enter-initrd", "system": "enter-initrd:leave-initrd:sysinit:ready"}
assert tuple(PHASE_PATHS) == attest.PHASES
KEY_BITS = 2048
KEY_SOURCES = ("file", "engine:pkcs11")
MAX_IMAGE = 512 * 1024 * 1024
# Words that have no place on a KMS host's command line. NOT a review: it catches the obvious.
#   rd.luks*, luks*   every form, rd.luks=0 included: the root volume is opened from the image's crypttab
#                     through the unlock client's socket, and no command-line word may change how
#   rd.break, rd.shell, systemd.debug_shell, init=, systemd.unit=, emergency, rescue, single
#                     a shell or another target before the disk is judged
#   root=UUID=…, root=PARTUUID=…   names ONE host's disk, so the image would be per host (the root is the
#                     mapping, root=/dev/mapper/root, and the partition is found by its label)
CMDLINE_REFUSED = (r"(rd\.)?luks(\.[a-z0-9_.-]+)?(=.*)?", r"rd\.break(=.*)?", r"rd\.shell(=.*)?", r"(rd\.)?systemd\.debug[-_]shell(=.*)?",
                   r"(rd)?init=.*", r"(rd\.)?systemd\.unit=.*", r"emergency", r"rescue", r"single", r"[sS1]", r"-b",
                   r"root=(UUID|PARTUUID|LABEL|PARTLABEL)=.*")
# ... except the forms that turn a shell OFF, which a KMS host's image should carry (rd.shell=0).
CMDLINE_HARDENING = r"(rd\.shell|(rd\.)?systemd\.debug[-_]shell)=(0|no|false|off)"
# Words the command line MUST carry. systemd.import_credentials=no: systemd in the initrd would otherwise
# import every credential on the ESP by name, and a credential named after a unit drop-in, a tmpfiles line
# or another unit changes what the initrd does (#66). The unlock units load the node's credentials by
# absolute path instead. A later image that dropped the word would quietly give that back.
# The words are compared as systemd compares a key: "-" and "_" are the same (proc_cmdline_key_streq), and
# an "rd." form applies in the initrd; any other spelling of the key beside the required word is refused,
# since the LAST value wins. WHAT ELSE CAN ADD WORDS on a host: signed addons (*.addon.efi) and, per
# systemd-stub's documentation, an SMBIOS type 11 io.systemd.stub.kernel-cmdline-extra. Both are measured
# into PCR 12, which the peers attest (#218), so an appended systemd.import_credentials=yes changes PCR 12
# and the peers refuse the unlock; and `set --esp` refuses an ESP that holds addons at all. The SMBIOS
# case is stated from the documentation, not yet shown by a boot.
# init_on_free=1 and init_on_alloc=1: the kernel zeroes every page when it is freed and when it is handed
# out (#221). The pre-root unlock client holds the local half, the boot session's RSA key and the volume's
# key through the initrd phase; Go cannot erase crypto/rsa's internal copy of the key, and the Go runtime
# does not clear memory it frees. With these words nothing the client held survives the process in RAM
# the booted system can reuse. The boot test checks the kernel actually enabled them (its boot log), since
# a kernel built without the options ignores the words.
CMDLINE_REQUIRED = ("systemd.import_credentials=no", "init_on_free=1", "init_on_alloc=1")


def _cmdline_key(word):
    """A command-line word's key as systemd compares it: "-" and "_" alike, without an "rd." prefix,
    case-folded (systemd's keys are case-sensitive; folding here only refuses more)."""
    key = word.split("=", 1)[0].casefold().replace("-", "_")
    return key[3:] if key.startswith("rd.") else key
TOOLS = {"ukify": "ukify", "measure": "/usr/lib/systemd/systemd-measure", "sbsign": "sbsign", "sbverify": "sbverify", "openssl": "openssl"}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read(path, limit=MAX_IMAGE):
    with open(path, "rb") as f:
        data = f.read(limit + 1)
    require(len(data) <= limit, "%s is larger than %d bytes" % (path, limit))
    return data


def sections(data):
    """The sections of a PE image as [(name, content)], content cut to its virtual size (what the stub
    measures). Refuses anything it would have to guess about."""
    require(len(data) >= 0x40 and data[:2] == b"MZ", "not a PE image (no MZ header)")
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    require(pe + 24 <= len(data) and data[pe:pe + 4] == b"PE\0\0", "not a PE image (no PE signature)")
    count, optional = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    table = pe + 24 + optional
    require(1 <= count <= 96 and table + 40 * count <= len(data), "the PE section table is not inside the file")
    # SizeOfImage, at offset 56 of the optional header (PE32 and PE32+ alike): every section must lie in it
    require(optional >= 60, "the PE optional header is too short to say how large the image is")
    size_of_image = struct.unpack_from("<I", data, pe + 24 + 56)[0]
    out, seen, spans = [], set(), []
    for i in range(count):
        entry = table + 40 * i
        raw_name = data[entry:entry + 8].rstrip(b"\0")
        require(re.fullmatch(rb"\.[a-z]{1,7}", raw_name) is not None, "section %d has the name %r" % (i, raw_name))
        name = raw_name.decode("ascii")
        virtual_size, address, raw_size, pointer = struct.unpack_from("<IIII", data, entry + 8)
        require(name not in seen, "the image has two %s sections" % name)
        seen.add(name)
        # where the loader puts it: inside the image, overlapping no other section
        require(address + virtual_size <= size_of_image, "section %s lies beyond the image's size" % name)
        require(all(address + virtual_size <= a or b <= address for a, b in spans), "section %s overlaps another in memory" % name)
        spans.append((address, address + max(virtual_size, 1)))
        # a virtual size above the raw size would be padded with zeros in memory; ukify never writes one
        require(virtual_size <= raw_size and pointer + raw_size <= len(data), "section %s is not inside the file" % name)
        out.append((name, data[pointer:pointer + virtual_size]))
    return out


def measured(data):
    """{section name without the dot: content} for the measured sections, refusing an image that holds a
    section this tool does not measure or does not know."""
    found = dict(sections(data))
    unknown = sorted(n for n in found if n[1:] not in OURS and n not in STUB_SECTIONS and n != ".pcrsig")
    require(not unknown, "the image has sections a KMS host's image does not hold: %s" % ", ".join(unknown))
    for needed in ("linux", "initrd", "cmdline", "osrel", "uname", "sbat"):
        require("." + needed in found, "the image has no .%s section" % needed)
    return {name: found["." + name] for name in ORDER if "." + name in found}


def pcr11(parts, phase_path):
    """PCR 11 (SHA-256) after systemd-stub measured `parts` and systemd passed the phases of `phase_path`."""
    value = bytes(32)
    for name in ORDER:
        if name in parts:
            value = hashlib.sha256(value + hashlib.sha256(b"." + name.encode() + b"\0").digest()).digest()
            value = hashlib.sha256(value + hashlib.sha256(parts[name]).digest()).digest()
    for phase in phase_path.split(":"):
        value = hashlib.sha256(value + hashlib.sha256(phase.encode()).digest()).digest()
    return value.hex()


def policy_digest(pcr11_hex):
    """The TPM2 policy digest of PolicyPCR(SHA-256 bank, PCR 11 = value): what the PCR key signs ("pol")."""
    select = struct.pack(">IHB", 1, 0x000b, 3) + bytes([0x00, 0x08, 0x00])           # one bank, PCR 11
    return hashlib.sha256(bytes(32) + struct.pack(">I", 0x0000017f) + select + hashlib.sha256(bytes.fromhex(pcr11_hex)).digest()).hexdigest()


def _clean_env():
    """The environment systemd-measure runs in: no inherited $CREDENTIALS_DIRECTORY, through which its
    password prompt would take a PIN nobody typed."""
    return {k: v for k, v in os.environ.items() if k not in ("CREDENTIALS_DIRECTORY", "ENCRYPTED_CREDENTIALS_DIRECTORY")}


def _purge_pin(run):
    """systemd-measure keeps the PIN it asked for in the user keyring, and asks with ACCEPT_CACHED: a PIN
    cached by anything else under this user would be used with no prompt. Purged BEFORE each signature
    and after it; a purge that fails is a refusal, so nobody believes a PIN gone that is not."""
    try:
        done = run(["keyctl", "purge", "user", "measure-private-key-pin"], capture_output=True)
    except OSError:
        return                                  # no keyctl: nothing could have been cached through it either
    require(done.returncode == 0, "keyctl could not purge the cached token PIN (measure-private-key-pin): %s"
            % (done.stderr or b"").decode("utf-8", "replace").strip()[-200:])


def _run(run, argv, what, **kw):
    try:
        done = run(argv, capture_output=True, **kw)
    except OSError as error:
        raise Refused("%s: cannot run %s (%s)" % (what, argv[0], error))
    require(done.returncode == 0, "%s failed: %s" % (what, (done.stderr or b"").decode("utf-8", "replace").strip()[-600:] or "no message"))
    return done.stdout


def public_key(pem, what, run=subprocess.run, tools=TOOLS):
    """(fingerprint, PKCS#1 DER) of an RSA public key or certificate in PEM. The fingerprint is systemd's
    `pkfp`: the SHA-256 of the PKCS#1 DER public key."""
    if b"BEGIN CERTIFICATE" in pem:
        pem = _run(run, [tools["openssl"], "x509", "-pubkey", "-noout"], "reading %s" % what, input=pem)
    text = _run(run, [tools["openssl"], "pkey", "-pubin", "-noout", "-text"], "reading %s" % what, input=pem).decode("ascii", "replace")
    bits = re.match(r"(RSA )?Public-Key: \((\d+) bit\)", text)
    require(bits is not None and "Modulus" in text, "%s is not an RSA public key: systemd seals only to RSA" % what)
    require(int(bits.group(2)) == KEY_BITS, "%s is RSA-%s; the keys are RSA-%d, the size every TPM 2.0 loads" % (what, bits.group(2), KEY_BITS))
    der = _run(run, [tools["openssl"], "rsa", "-pubin", "-RSAPublicKey_out", "-outform", "der"], "reading %s" % what, input=pem)
    return sha256(der), pem


def cmdline_text(raw):
    """The kernel command line as the image will hold it: one line of printable ASCII, no word of the
    refusal list. A trailing newline would become part of the measured section, so it is cut here and the
    section is compared with the result."""
    try:
        text = raw.decode("ascii").rstrip("\n")
    except UnicodeDecodeError:
        raise Refused("the command line is not ASCII")
    require(text and re.fullmatch(r"[\x20-\x7e]+", text) is not None, "the command line must be one line of printable ASCII")
    words = text.split()
    for needed in CMDLINE_REQUIRED:
        require(needed in words, "the command line does not carry %s, which every KMS host's image must" % needed)
        # ... and nothing that says otherwise: the kernel and systemd take the LAST value of a repeated word,
        # so a second systemd.import_credentials= (any value, the same one included) is refused
        key = _cmdline_key(needed)
        given = [w for w in words if _cmdline_key(w) == key]
        require(given == [needed], "the command line gives %s more than once or with another value or spelling (%s): it must say %s, once"
                % (needed.split("=", 1)[0], " ".join(given), needed))
    for word in words:
        if re.fullmatch(CMDLINE_HARDENING, word):
            continue
        for pattern in CMDLINE_REFUSED:
            require(re.fullmatch(pattern, word) is None, "the command line holds %r, which a KMS host's image does not carry" % word)
    return text


# ---- the initrd's review (#198): what the measured initrd does to open the root disk ----
#
# The image's initrd carries its own crypttab, command-line fragments and units, and once a host has
# booted nothing on it shows what they were (#135). So they are read HERE, from the exact bytes that are
# measured, and the result goes into the record; `sign` refuses an image whose initrd did not pass.
# The rules (KERNEL-UPDATE.md step 2.2a), each a refusal with its reason:
#   crypttab   etc/crypttab holds exactly the one generic line of the dracut module (the unlock client's
#              socket, the partition by its label), and nothing else
#   cmdline.d  no fragment (etc/cmdline.d/*.conf, etc/cmdline) holds a word of the command line's refusal
#              list: rd.luks* in any form, a debug shell, another target
#   the units  the unlock client's units and the boot mesh script are THIS repository's, byte for byte, as
#              systemd will take them (an /etc copy, a mask, wins over /usr/lib and is what is compared);
#              the client binary is there; the relay and the core socket are enabled
#   the image  the unlock path (those units, every drop-in that applies to them or to systemd-cryptsetup,
#              and every script they run) names no path outside the image: what it sources, executes or
#              reads is in the initrd, a runtime or kernel directory (/run, /proc, /sys, /dev, /tmp), or a
#              credential the stub unpacked from the ESP by its fixed name (/.extra/global_credentials/
#              NAME.cred, measured into PCR 12). Nothing from the root disk, nothing from the build machine.
# What it does NOT judge: the rest of dracut's own initrd (its hooks and systemd's units), which no rule
# here names. A review catches what it names (#198, "not covered").
INITRD_REVIEW = "regalia.initrd-review/v1"
INITRD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "initrd")
UNLOCK_UNITS = ("regalia-unlock-relay.service", "regalia-unlock-core.socket", "regalia-unlock.service", "regalia-wg-boot.service")
UNLOCK_SCRIPTS = {"usr/lib/regalia/wg-boot": "wg-boot"}
UNLOCK_BINARIES = ("usr/bin/regalia-unlock",)
UNLOCK_ENABLED = ("etc/systemd/system/sockets.target.wants/regalia-unlock-core.socket",
                  "etc/systemd/system/cryptsetup.target.wants/regalia-unlock-relay.service")
UNIT_DIRS = ("etc/systemd/system", "run/systemd/system", "usr/lib/systemd/system")      # systemd's precedence
RUNTIME_PREFIXES = ("/run", "/proc", "/sys", "/dev", "/tmp")
STUB_CREDENTIAL = r"/\.extra/global_credentials/[A-Za-z0-9._-]+\.cred"
# a path in a unit's value or a script's line: after a start, a separator or a unit's exec prefix (-@:+!)
PATH_TOKEN = re.compile(r"""(?:^|(?<=[\s=:"'(<>|;@+!-]))(/[A-Za-z.][A-Za-z0-9._@+-]*(?:/[A-Za-z0-9._@+-]+)*/?)""")
MAX_INITRD_FILES, MAX_UNPACKED = 200000, 2 * 1024 * 1024 * 1024
TOOLS.update({"zstd": "zstd", "lz4": "lz4"})


def _cpio(data, files):
    """Reads ONE newc archive at the start of `data` into `files` ({path: (mode, bytes)}, a link's bytes its
    target); returns how many bytes it used. Hard links carry their data on the last name (newc)."""
    pos, links = 0, {}
    while True:
        head = data[pos:pos + 110]
        require(len(head) == 110 and head[:6] in (b"070701", b"070702"), "the initrd's cpio archive is cut short or not newc")
        try:
            ino, mode, _, _, nlink, _, size, major, minor, _, _, namesize, _ = (int(head[i:i + 8], 16) for i in range(6, 110, 8))
        except ValueError:
            raise Refused("the initrd's cpio archive has a header that is not hexadecimal")
        name_end = pos + 110 + namesize
        name = data[pos + 110:name_end - 1].decode("utf-8", "replace")
        start = (name_end + 3) & ~3
        body = data[start:start + size]
        require(len(body) == size and namesize >= 1, "the initrd's cpio archive is cut short")
        pos = (start + size + 3) & ~3
        if name == "TRAILER!!!":
            return pos
        path = os.path.normpath("/" + name).lstrip("/")
        if not path or path == ".":
            continue
        if stat_regular(mode) and nlink > 1:
            group = links.setdefault((ino, major, minor), [])
            group.append(path)
            if size:
                for other in group:
                    files[other] = (mode, body)
                continue
        files[path] = (mode, body)
        require(len(files) <= MAX_INITRD_FILES, "the initrd holds more than %d files" % MAX_INITRD_FILES)


def stat_regular(mode):
    return mode & 0o170000 == 0o100000


def stat_link(mode):
    return mode & 0o170000 == 0o120000


def _decompress(data, run, tools):
    import gzip
    import lzma
    if data[:2] == b"\x1f\x8b":
        out = gzip.decompress(data)
    elif data[:6] == b"\xfd7zXZ\x00":
        out = lzma.decompress(data)
    elif data[:4] in (b"\x28\xb5\x2f\xfd", b"\x02\x21\x4c\x18"):
        tool = "zstd" if data[:4] == b"\x28\xb5\x2f\xfd" else "lz4"
        out = _run(run, [tools[tool], "-dc"], "decompressing the initrd (%s)" % tool, input=data, env=_clean_env())
    else:
        raise Refused("the initrd is neither a cpio archive nor compressed in a way this tool reads (gzip, xz, zstd, lz4)")
    require(len(out) <= MAX_UNPACKED, "the initrd unpacks to more than %d bytes" % MAX_UNPACKED)
    return out


def initrd_files(data, run=subprocess.run, tools=TOOLS, depth=0):
    """Every file of an initrd as the kernel unpacks it: one or more cpio archives one after the other (an
    uncompressed early one, microcode, then the main one, usually compressed), NUL padding between them, a
    later archive's file replacing an earlier one's. Read in memory only, nothing is written: a name is
    taken under the image's root ("/" + name, normalised, so ".." cannot leave it), and a link is followed
    only inside the image (_resolve)."""
    files, pos = {}, 0
    while pos < len(data):
        if data[pos] == 0:
            pos += 1
            continue
        if data[pos:pos + 6] in (b"070701", b"070702"):
            pos += _cpio(data[pos:], files)
            continue
        # the rest is one compressed stream holding the main archive(s); nothing follows it
        require(depth == 0, "the initrd nests one compressed stream in another")
        files.update(initrd_files(_decompress(data[pos:], run, tools), run, tools, depth + 1))
        break
    return files


def _resolve(files, path, depth=0):
    """`path` (relative to the image's root) with every link in it followed inside the image; None when it is
    not in the image."""
    require(depth < 40, "a link loop in the initrd")
    parts, done = [p for p in path.strip("/").split("/") if p not in ("", ".")], ""
    for i, part in enumerate(parts):
        here = os.path.normpath(os.path.join(done, part)) if part != ".." else os.path.dirname(done)
        entry = files.get(here)
        if entry is not None and stat_link(entry[0]):
            target = entry[1].decode("utf-8", "replace")
            base = "" if target.startswith("/") else os.path.dirname(here)
            rest = "/".join([os.path.join(base, target).lstrip("/")] + parts[i + 1:])
            return _resolve(files, os.path.normpath("/" + rest).lstrip("/"), depth + 1)
        if entry is None and not any(k.startswith(here + "/") for k in files):
            return None
        done = here
    return done


def _regular(files, path):
    where = _resolve(files, path)
    entry = files.get(where) if where else None
    return entry[1] if entry is not None and stat_regular(entry[0]) else None


def _effective_unit(files, name):
    """The unit file systemd will load for `name`: the first directory in its precedence that has it."""
    for directory in UNIT_DIRS:
        if os.path.join(directory, name) in files:
            return os.path.join(directory, name)
    return None


def _allowed(files, path, credential=False):
    if any(path == p or path.startswith(p + "/") for p in RUNTIME_PREFIXES):
        return True
    if credential and re.fullmatch(STUB_CREDENTIAL, path):
        return True
    return _resolve(files, path) is not None


def _scan_unit(files, where, text, findings, scripts):
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "[")) or "=" not in line:
            continue
        key, value = (s.strip() for s in line.split("=", 1))
        credential = key in ("LoadCredential", "LoadCredentialEncrypted")
        for path in PATH_TOKEN.findall(value):
            if not _allowed(files, path.rstrip("/") or "/", credential):
                findings.append("%s: %s names %s, which is not in the image" % (where, key, path))
        if key.startswith("Exec") and key != "ExecSearchPath" and value:
            program = value.split()[0].lstrip("@-:+!|")
            if program.startswith("/"):
                scripts.add(program)


def _scan_script(files, path, findings, seen):
    if path in seen:
        return
    seen.add(path)
    body = _regular(files, path)
    if body is None or not body.startswith(b"#!"):
        return
    text = body.decode("utf-8", "replace")
    interpreter = text.splitlines()[0][2:].strip().split()
    if interpreter and not _allowed(files, interpreter[0]):
        findings.append("%s: its interpreter %s is not in the image" % (path, interpreter[0]))
    for number, raw in enumerate(text.splitlines()[1:], 2):
        line = re.sub(r"(^|\s)#.*$", "", raw)
        for sourced in re.findall(r"(?:^|[;&|]\s*|\s)(?:\.|source)\s+(\S+)", line):
            if not sourced.startswith("/") or not _allowed(files, sourced):
                findings.append("%s:%d sources %s, which is not a file of the image" % (path, number, sourced))
        for token in PATH_TOKEN.findall(line):
            if not _allowed(files, token.rstrip("/") or "/"):
                findings.append("%s:%d names %s, which is not in the image" % (path, number, token))


def review_initrd(path, run=subprocess.run, tools=TOOLS):
    """The review of the initrd at `path` (see above): {"schema", "passed", "findings", "crypttab", "units"}."""
    return review_initrd_data(read(path), run, tools)


def review_initrd_data(data, run=subprocess.run, tools=TOOLS):
    """The same review, of an initrd's bytes (an image's .initrd section)."""
    findings = []
    try:
        files = initrd_files(data, run, tools)
    except Refused as refused:
        return {"schema": INITRD_REVIEW, "passed": False, "findings": ["the initrd cannot be read: %s" % refused], "crypttab": None, "units": {}}
    def lines(text):
        return [l.strip() for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")]
    with open(os.path.join(INITRD_DIR, "dracut", "90regalia-unlock", "crypttab")) as f:
        want = lines(f.read())
    crypttab = _regular(files, "etc/crypttab")
    got = lines(crypttab.decode("utf-8", "replace")) if crypttab is not None else None
    if got != want:
        findings.append("etc/crypttab must hold exactly the unlock client's line (%s); it holds %s"
                        % (want[0] if want else "?", "nothing" if got is None else (" | ".join(got) or "no line")))
    fragments = sorted(p for p in files if (p.startswith("etc/cmdline.d/") and p.endswith(".conf")) or p == "etc/cmdline")
    for fragment in fragments:
        body = _regular(files, fragment) or b""
        for word in " ".join(lines(body.decode("utf-8", "replace"))).split():
            if re.fullmatch(CMDLINE_HARDENING, word):
                continue
            if any(re.fullmatch(p, word) for p in CMDLINE_REFUSED):
                findings.append("%s holds %r: the initrd's command line must not say how the disk is opened" % (fragment, word))
    units, scripts = {}, set()
    for name in UNLOCK_UNITS:
        where = _effective_unit(files, name)
        with open(os.path.join(INITRD_DIR, name), "rb") as f:
            ours = f.read()
        body = _regular(files, where) if where else None
        if body != ours:
            findings.append("%s is %s" % (name, "not in the image" if where is None else
                            "not this repository's (%s, as systemd takes it: %s)" % ("masked or a link" if body is None else "other bytes", where)))
        else:
            units[name] = sha256(body)
            _scan_unit(files, where, body.decode("utf-8", "replace"), findings, scripts)
    for path, name in UNLOCK_SCRIPTS.items():
        with open(os.path.join(INITRD_DIR, name), "rb") as f:
            ours = f.read()
        if _regular(files, path) != ours:
            findings.append("%s is not this repository's %s" % (path, name))
    for path in UNLOCK_BINARIES:
        if _regular(files, path) is None:
            findings.append("%s, the unlock client, is not in the image" % path)
    for link in UNLOCK_ENABLED:
        if link not in files:
            findings.append("%s is not enabled (no %s)" % (os.path.basename(link), link))
    # every drop-in that applies to the unlock path: per unit, the type-wide service.d/socket.d, and
    # systemd-cryptsetup's (the template and the root volume's instance)
    targets = UNLOCK_UNITS + ("systemd-cryptsetup@.service", "systemd-cryptsetup@root.service", "service", "socket")
    for directory in UNIT_DIRS:
        for target in targets:
            prefix = "%s/%s.d/" % (directory, target)
            for dropin in sorted(p for p in files if p.startswith(prefix) and p.endswith(".conf")):
                body = _regular(files, dropin)
                if body is not None:
                    _scan_unit(files, dropin, body.decode("utf-8", "replace"), findings, scripts)
    seen = set()
    for script in sorted(scripts):
        _scan_script(files, script, findings, seen)
    return {"schema": INITRD_REVIEW, "passed": not findings, "findings": sorted(set(findings))[:64],
            "crypttab": got[0] if got and len(got) == 1 else None, "units": units}


def check_review(review):
    """A record's initrd review, checked for shape: the fields, and passed only with no finding."""
    membership.exact(review, ("schema", "passed", "findings", "crypttab", "units"), "record.initrd_review")
    require(review["schema"] == INITRD_REVIEW, "record.initrd_review is not a %s" % INITRD_REVIEW)
    require(isinstance(review["passed"], bool) and isinstance(review["findings"], list)
            and all(isinstance(f, str) for f in review["findings"]) and review["passed"] == (not review["findings"]),
            "record.initrd_review says passed only with no finding")
    require(review["crypttab"] is None or isinstance(review["crypttab"], str), "record.initrd_review.crypttab is not text")
    require(isinstance(review["units"], dict) and set(review["units"]) <= set(UNLOCK_UNITS)
            and all(attest.is_hex(v, 64) for v in review["units"].values()), "record.initrd_review.units is not a map of the unlock units")


INPUTS = ("linux", "initrd", "microcode", "cmdline", "os_release", "stub", "pcrpkey")


def _stage(inputs, work):
    """Every input copied once into the private work directory: every build after this reads the copies,
    so a file changed on disk between two builds changes nothing here."""
    staged = os.path.join(work, "inputs")
    os.mkdir(staged, 0o700)
    out = {}
    for key in INPUTS:
        if inputs.get(key):
            out[key] = os.path.join(staged, key)
            with open(out[key], "wb") as f:
                f.write(read(inputs[key]))
    return out


def stub_sections(data):
    """The sections that are not measured into PCR 11 (the stub's code and data): pinned by their hashes,
    since only the Secure Boot signature covers them on the host."""
    return {n: sha256(c) for n, c in sections(data) if n[1:] not in OURS and n != ".pcrsig"}


def _ukify(inputs, uname, output, run, tools, pcrsig=None):
    argv = [tools["ukify"], "build", "--config", "/dev/null", "--linux", inputs["linux"], "--initrd", inputs["initrd"],
            "--cmdline", cmdline_text(read(inputs["cmdline"], 4096)), "--os-release", "@" + inputs["os_release"], "--uname", uname,
            "--stub", inputs["stub"], "--pcrpkey", inputs["pcrpkey"], "--output", output]
    if inputs.get("microcode"):
        argv += ["--microcode", inputs["microcode"]]
    if pcrsig:
        argv += ["--section", ".pcrsig:@" + pcrsig]
    _run(run, argv, "ukify build")
    return read(output)


def _check_sections(parts, inputs, uname):
    """Every measured section is the input it was built from. ukify decides what goes where; this is the
    check that it did what the record will say."""
    want = {"linux": read(inputs["linux"]), "initrd": read(inputs["initrd"]), "osrel": read(inputs["os_release"], 65536),
            "cmdline": cmdline_text(read(inputs["cmdline"], 4096)).encode("ascii"), "uname": uname.encode("ascii"),
            "pcrpkey": read(inputs["pcrpkey"], 65536)}
    if inputs.get("microcode"):
        want["ucode"] = read(inputs["microcode"])
    for name, content in want.items():
        require(parts.get(name) == content, "the image's .%s section is not the input it was built from" % name)
    extra = sorted(set(parts) - set(want) - {"sbat"})
    require(not extra, "the image measures sections no input accounts for: %s" % ", ".join("." + n for n in extra))


def _tool_version(run, argv):
    return _run(run, argv, "reading a tool's version").decode("utf-8", "replace").strip().split("\n")[0][:120]


def _predict(parts, run, tools, work):
    """PCR 11 per phase, computed here and required to equal systemd-measure's on this machine."""
    mine = {phase: pcr11(parts, path) for phase, path in PHASE_PATHS.items()}
    argv = [tools["measure"], "calculate", "--bank=sha256", "--json=short"] + ["--phase=" + p for p in PHASE_PATHS.values()]
    flags = {"linux": "--linux", "osrel": "--osrel", "cmdline": "--cmdline", "initrd": "--initrd", "ucode": "--ucode", "uname": "--uname",
             "sbat": "--sbat", "pcrpkey": "--pcrpkey"}
    for name, content in parts.items():
        path = os.path.join(work, "section." + name)
        with open(path, "wb") as f:
            f.write(content)
        argv.append("%s=%s" % (flags[name], path))
    try:
        said = json.loads(_run(run, argv, "systemd-measure calculate"))["sha256"]
        theirs = {entry["phase"]: entry["hash"] for entry in said if entry["pcr"] == 11}
    except (ValueError, KeyError, TypeError):
        raise Refused("systemd-measure calculate did not answer as expected")
    for phase, path in PHASE_PATHS.items():
        require(theirs.get(path) == mine[phase], "this machine's systemd-measure predicts PCR 11 %s for the phase %s and this tool %s: "
                "they measure differently, and nothing is written" % (theirs.get(path), path, mine[phase]))
    return mine, flags


def _name(name):
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,47}", name) is not None, "the name must be a short plain name")
    return name


def _uname(uname):
    require(isinstance(uname, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}", uname) is not None, "--uname must be a kernel version")
    return uname


def build(inputs, uname, name, out_dir, run=subprocess.run, tools=TOOLS):
    """Builds NAME.unsigned.efi and NAME.record.json in `out_dir`; returns the record."""
    _name(name), _uname(uname)
    fingerprint, _ = public_key(read(inputs["pcrpkey"], 65536), "--pcrpkey", run, tools)
    os.makedirs(out_dir, exist_ok=True)
    for path in (os.path.join(out_dir, name + ".unsigned.efi"), os.path.join(out_dir, name + ".record.json")):
        require(not os.path.lexists(path), "%s already exists: nothing is overwritten" % path)
    with tempfile.TemporaryDirectory(dir=out_dir) as work:
        inputs = _stage(inputs, work)
        image = os.path.join(work, "image.efi")
        data = _ukify(inputs, uname, image, run, tools)
        parts = measured(data)
        require(".pcrsig" not in dict(sections(data)), "an unsigned image must have no .pcrsig section")
        _check_sections(parts, inputs, uname)
        values, _ = _predict(parts, run, tools, work)
        review = review_initrd(inputs["initrd"], run, tools)          # the staged copy: the bytes just measured
        record = {
            "schema": SCHEMA, "name": name, "uname": uname,
            "inputs": {k: {"sha256": sha256(read(inputs[k])), "size": os.path.getsize(inputs[k])} for k in INPUTS if inputs.get(k)},
            "sections": {"." + n: sha256(c) for n, c in parts.items()},
            "unsigned_sha256": sha256(data), "stub_sections": stub_sections(data), "cmdline": parts["cmdline"].decode("ascii"), "phase_paths": dict(PHASE_PATHS), "pcr11": values, "pcrpkey_pkfp": fingerprint,
            "initrd_review": review,
            "tools": {"ukify": _tool_version(run, [tools["ukify"], "--version"]),
                      "systemd_measure": _tool_version(run, [tools["measure"], "--version"])}}
        _place(image, os.path.join(out_dir, name + ".unsigned.efi"))
    _write(os.path.join(out_dir, name + ".record.json"), record)
    return record


def _write(path, record):
    # never through a link, never over an existing file
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(json.dumps(record, indent=2, sort_keys=True).encode("ascii") + b"\n")


def _place(source, destination):
    """Moves `source` to `destination`, which must not exist (os.link refuses an existing name)."""
    os.link(source, destination)
    os.unlink(source)


RECORD_KEYS = ("schema", "name", "uname", "inputs", "sections", "unsigned_sha256", "stub_sections", "cmdline", "phase_paths", "pcr11", "pcrpkey_pkfp",
               "initrd_review", "tools")


def load_record(raw, signed=None):
    """A build record, checked. `signed`: True requires the signing part, False refuses it, None takes either."""
    try:
        record = membership.load(raw, limit=64 * 1024)
    except RecursionError:
        raise Refused("not a build record: nested too deeply")
    require(isinstance(record, dict), "a build record is one JSON object")
    has = "signed" in record
    require(signed is None or has == signed, "the record %s" % ("is already signed" if has else "is of an unsigned image"))
    membership.exact(record, RECORD_KEYS + (("signed",) if has else ()), "record")
    require(record["schema"] == SCHEMA, "record schema must be %s" % SCHEMA)
    _name(record["name"]), _uname(record["uname"])
    require(record["phase_paths"] == PHASE_PATHS, "the record's phase paths are not this tool's")
    require(isinstance(record["cmdline"], str), "record.cmdline is not text")
    cmdline_text(record["cmdline"].encode("ascii", "replace"))      # the same rules, read back
    require(sha256(record["cmdline"].encode("ascii")) == record["sections"].get(".cmdline"), "record.cmdline is not the image's .cmdline section")
    membership.exact(record["pcr11"], attest.PHASES, "record.pcr11")
    check_review(record["initrd_review"])
    for field in [record["unsigned_sha256"], record["pcrpkey_pkfp"]] + list(record["pcr11"].values()):
        require(attest.is_hex(field, 64), "the record holds a value that is not a SHA-256 in lowercase hex")
    require(isinstance(record["sections"], dict) and set(record["sections"]) <= {"." + n for n in OURS}
            and all(attest.is_hex(v, 64) for v in record["sections"].values()), "record.sections is not a map of this tool's sections")
    require(isinstance(record["stub_sections"], dict) and record["stub_sections"] and set(record["stub_sections"]) <= set(STUB_SECTIONS)
            and all(attest.is_hex(v, 64) for v in record["stub_sections"].values()), "record.stub_sections is not a map of the stub's sections")
    require(isinstance(record["inputs"], dict) and set(record["inputs"]) <= set(INPUTS), "record.inputs names an input this tool does not take")
    for key, entry in record["inputs"].items():
        membership.exact(entry, ("sha256", "size"), "record.inputs.%s" % key)
        require(attest.is_hex(entry["sha256"], 64) and type(entry["size"]) is int, "record.inputs.%s is malformed" % key)
    if has:
        membership.exact(record["signed"], ("image_sha256", "pcr_signatures", "secure_boot_cert_sha256"), "record.signed")
        membership.exact(record["signed"]["pcr_signatures"], attest.PHASES, "record.signed.pcr_signatures")
        for phase, entry in record["signed"]["pcr_signatures"].items():
            membership.exact(entry, ("pkfp", "pol"), "record.signed.pcr_signatures.%s" % phase)
            require(attest.is_hex(entry["pkfp"], 64) and attest.is_hex(entry["pol"], 64), "record.signed.pcr_signatures.%s is malformed" % phase)
        require(attest.is_hex(record["signed"]["image_sha256"], 64) and attest.is_hex(record["signed"]["secure_boot_cert_sha256"], 64),
                "record.signed is malformed")
    return record


def check_pcrsig(raw, record, keys, run=subprocess.run, tools=TOOLS):
    """The image's .pcrsig, checked without systemd: exactly one signature per phase, each by that phase's
    key (`keys`: {phase: (pkfp, public key PEM)}), over the policy of the PCR 11 the record predicts, and
    each verifies. Returns {phase: {"pkfp", "pol"}}."""
    try:
        document = membership.load(raw.rstrip(b"\0"), limit=65536)      # duplicate keys refused, as everywhere here
    except Refused:
        raise Refused("the image's .pcrsig is not a PCR signature document")
    require(isinstance(document, dict) and set(document) == {"sha256"} and isinstance(document["sha256"], list),
            "the PCR signatures cover a bank other than SHA-256, or the document is not one")
    entries = document["sha256"]
    for entry in entries:
        membership.exact(entry, ("pcrs", "pkfp", "pol", "sig"), "a PCR signature")
    require(len(entries) == len(attest.PHASES), "the image carries %d PCR signatures, not one per phase" % len(entries))
    out = {}
    for phase in attest.PHASES:
        fingerprint, pem = keys[phase]
        want = policy_digest(record["pcr11"][phase])
        mine = [e for e in entries if isinstance(e, dict) and e.get("pkfp") == fingerprint]
        require(len(mine) == 1, "the image carries %d signatures by the %s-phase key, not one" % (len(mine), phase))
        entry = mine[0]
        require(entry.get("pcrs") == [11] and entry.get("pol") == want and isinstance(entry.get("sig"), str),
                "the %s-phase key signed something other than the PCR 11 the record predicts for that phase" % phase)
        try:
            signature = base64.b64decode(entry["sig"], validate=True)
        except ValueError:
            raise Refused("the %s-phase signature is not base64" % phase)
        with tempfile.TemporaryDirectory() as work:
            paths = {n: os.path.join(work, n) for n in ("key", "sig", "pol")}
            for n, content in (("key", pem), ("sig", signature), ("pol", bytes.fromhex(want))):
                with open(paths[n], "wb") as f:
                    f.write(content)
            done = run([tools["openssl"], "dgst", "-sha256", "-verify", paths["key"], "-signature", paths["sig"], paths["pol"]], capture_output=True)
        require(done.returncode == 0, "the %s-phase PCR signature does not verify under its key" % phase)
        out[phase] = {"pkfp": fingerprint, "pol": want}
    return out


URI_ATTRIBUTES = ("token", "serial", "object", "id", "type", "manufacturer", "model")


def _key_argument(value, source, what):
    """A key option: a file, or with engine:pkcs11 a PKCS#11 URI that names the card by serial and token
    label and the key by label or id, and carries nothing else: parsed, every attribute name on an
    allow-list (so no PIN, PIN file or module path in any spelling), no query part."""
    if source == "file":
        require(os.path.isfile(value), "%s: %s is not a file (with a token, pass --key-source engine:pkcs11 and a PKCS#11 URI)" % (what, value))
        return value
    require(isinstance(value, str) and value.startswith("pkcs11:") and len(value) <= 400, "%s must be a PKCS#11 URI" % what)
    require("?" not in value, "%s has a query part: a PKCS#11 URI here names a card and a key, nothing else (no PIN, no module)" % what)
    attributes = {}
    for part in value[len("pkcs11:"):].split(";"):
        name, sep, val = part.partition("=")
        require(sep and name in URI_ATTRIBUTES, "%s names %r, which is not one of %s (no PIN, no PIN file, no module path)"
                % (what, name, ", ".join(URI_ATTRIBUTES)))
        require(name not in attributes, "%s gives %s twice" % (what, name))
        # percent-encoding only in id (bytes); everywhere else plain printable text, so nothing hides behind an escape
        allowed = r"(%[0-9a-fA-F]{2})+" if name == "id" else r"[A-Za-z0-9 ._()-]+"
        require(re.fullmatch(allowed, val) is not None, "%s: %s=%r is not allowed" % (what, name, val))
        attributes[name] = val
    require("serial" in attributes and "token" in attributes, "%s must name the card by serial= and token=: the engine would "
            "otherwise take the first token that holds a matching key" % what)
    require("object" in attributes or "id" in attributes, "%s must name the key by object= or id=" % what)
    require(attributes.get("type") == "private", "%s must say type=private" % what)
    return value


def sign(inputs, record, keys, source, out_dir, run=subprocess.run, tools=TOOLS, second_record=None, report=None):
    """Signs the image `record` describes, rebuilt from `inputs`. `second_record` is the same image's record
    from another builder, and must be identical. `keys`: {"initrd" | "system" | "secure_boot": (key file
    or PKCS#11 URI, certificate file)}. Writes NAME.efi and NAME.signed.json."""
    require(source in KEY_SOURCES, "--key-source is one of %s" % ", ".join(KEY_SOURCES))
    load_record(membership.canonical(record), signed=False)
    require(second_record is not None, "a second builder's record is required: one builder alone does not decide what is signed")
    load_record(membership.canonical(second_record), signed=False)
    require(membership.canonical(second_record) == membership.canonical(record), "the two builders' records differ: nothing is signed")
    # #198: no image is signed whose initrd was not reviewed and found to open the disk only as it must
    require(record["initrd_review"]["passed"], "the record's initrd review did not pass, so nothing is signed: %s"
            % "; ".join(record["initrd_review"]["findings"]))
    for role in ("initrd", "system", "secure_boot"):
        _key_argument(keys[role][0], source, "the %s key" % role.replace("_", " "))
    public = {role: public_key(read(keys[role][1], 65536), "the %s certificate" % role.replace("_", " "), run, tools) for role in keys}
    fingerprints = [public[role][0] for role in ("initrd", "system", "secure_boot")]
    require(len(set(fingerprints)) == 3, "the two PCR keys and the Secure Boot key must be three different keys")
    require(public["system"][0] == record["pcrpkey_pkfp"], "the system-phase certificate is not for the key the image carries (.pcrpkey)")
    for key, entry in record["inputs"].items():
        require(inputs.get(key) and sha256(read(inputs[key])) == entry["sha256"], "the input --%s is not the one the record was built from"
                % key.replace("_", "-"))
    require(set(k for k in INPUTS if inputs.get(k)) == set(record["inputs"]), "the inputs given are not the record's set of inputs")
    name, uname = record["name"], record["uname"]
    os.makedirs(out_dir, exist_ok=True)
    for path in (os.path.join(out_dir, name + ".efi"), os.path.join(out_dir, name + ".signed.json")):
        require(not os.path.lexists(path), "%s already exists: nothing is overwritten" % path)
    # what is about to be signed, shown before any key is touched
    (report or (lambda line: print(line, file=sys.stderr)))(
        "signing %s: unsigned image %s; inputs %s" % (name, record["unsigned_sha256"],
                                                       ", ".join("%s %s" % (k, e["sha256"][:16]) for k, e in sorted(record["inputs"].items()))))
    with tempfile.TemporaryDirectory(dir=out_dir) as work:
        inputs = _stage(inputs, work)
        for key, entry in record["inputs"].items():               # the copies, not the originals, are what is built
            require(sha256(read(inputs[key])) == entry["sha256"], "the input --%s changed while it was copied" % key.replace("_", "-"))
        # the review again, here, on the copy that is about to be built and signed: not taken on the record's word
        require(review_initrd(inputs["initrd"], run, tools) == record["initrd_review"],
                "this machine's review of the initrd is not the record's: nothing is signed")
        # the third build: this machine must get the bytes the record names before it signs anything
        data = _ukify(inputs, uname, os.path.join(work, "unsigned.efi"), run, tools)
        require(sha256(data) == record["unsigned_sha256"], "this machine built another image than the record's (%s, not %s): "
                "nothing is signed" % (sha256(data), record["unsigned_sha256"]))
        parts = measured(data)
        values, flags = _predict(parts, run, tools, work)
        require(values == record["pcr11"], "the image does not measure what its record says")
        require(stub_sections(data) == record["stub_sections"], "the image's stub is not the record's")
        pcrsig = None
        for phase in attest.PHASES:
            argv = [tools["measure"], "sign", "--bank=sha256", "--phase=" + PHASE_PATHS[phase], "--private-key=" + keys[phase][0],
                    "--certificate=" + keys[phase][1]] + ["%s=%s" % (flags[n], os.path.join(work, "section." + n)) for n in parts]
            if source != "file":
                argv.append("--private-key-source=" + source)
            if pcrsig:
                argv.append("--append=" + pcrsig)
            _purge_pin(run)
            try:
                out = _run(run, argv, "signing the %s-phase PCR 11" % phase, env=_clean_env())
            finally:
                _purge_pin(run)
            pcrsig = os.path.join(work, "pcrsig-%s.json" % phase)
            with open(pcrsig, "wb") as f:
                f.write(out)
        signatures = check_pcrsig(read(pcrsig, 65536), record, public, run, tools)
        carrying = _ukify(inputs, uname, os.path.join(work, "pcrsigned.efi"), run, tools, pcrsig=pcrsig)
        # EVERY section, the stub's code included, must be the third build's, apart from the added .pcrsig
        require([s for s in sections(carrying) if s[0] != ".pcrsig"] == sections(data),
                "attaching the PCR signatures changed a section of the image (the stub's or a measured one)")
        check_pcrsig(dict(sections(carrying))[".pcrsig"], record, public, run, tools)
        final = os.path.join(work, "signed.efi")
        argv = [tools["sbsign"], "--key", keys["secure_boot"][0], "--cert", keys["secure_boot"][1], "--output", final, os.path.join(work, "pcrsigned.efi")]
        if source != "file":
            argv[1:1] = ["--engine", source.split(":", 1)[1]]
        _run(run, argv, "the Secure Boot signature")
        _run(run, [tools["sbverify"], "--cert", keys["secure_boot"][1], final], "checking the Secure Boot signature")
        signed = read(final)
        require(sections(signed) == sections(carrying), "the Secure Boot signature changed a section of the image")
        certificate = _run(run, [tools["openssl"], "x509", "-outform", "der"], "reading the Secure Boot certificate", input=read(keys["secure_boot"][1], 65536))
        _place(final, os.path.join(out_dir, name + ".efi"))
    result = dict(record, signed={"image_sha256": sha256(signed), "pcr_signatures": signatures, "secure_boot_cert_sha256": sha256(certificate)})
    _write(os.path.join(out_dir, name + ".signed.json"), result)
    return result


def verify(image, record, public_keys, secure_boot_cert, run=subprocess.run, tools=TOOLS):
    """`image` is the signed image `record` (a signed record) describes. `public_keys`: {phase: PEM} of the
    two PCR keys; their fingerprints must be the record's. `secure_boot_cert` is required: the stub's code
    is not in PCR 11, and the Secure Boot signature is what covers it. Returns the record's PCR 11 values."""
    load_record(membership.canonical(record), signed=True)
    require(secure_boot_cert, "the Secure Boot certificate is required: without it nothing vouches for the stub")
    data = read(image)
    require(sha256(data) == record["signed"]["image_sha256"], "the image is not the file the record names")
    parts = measured(data)
    require({"." + n: sha256(c) for n, c in parts.items()} == record["sections"], "the image's measured sections are not the record's")
    require(stub_sections(data) == record["stub_sections"], "the image's stub is not the record's")
    require({phase: pcr11(parts, path) for phase, path in PHASE_PATHS.items()} == record["pcr11"], "the image does not measure what its record says")
    keys = {phase: public_key(public_keys[phase], "the %s-phase public key" % phase, run, tools) for phase in attest.PHASES}
    for phase in attest.PHASES:
        require(keys[phase][0] == record["signed"]["pcr_signatures"][phase]["pkfp"], "the %s-phase key given is not the one the record names" % phase)
    require(keys["system"][0] == record["pcrpkey_pkfp"] and public_key(parts["pcrpkey"], "the image's .pcrpkey", run, tools)[0] == keys["system"][0],
            "the image's .pcrpkey is not the system-phase key")
    found = dict(sections(data)).get(".pcrsig")
    require(found is not None, "the image carries no PCR signatures")
    check_pcrsig(found, record, keys, run, tools)
    certificate = _run(run, [tools["openssl"], "x509", "-outform", "der"], "reading the Secure Boot certificate", input=read(secure_boot_cert, 65536))
    require(sha256(certificate) == record["signed"]["secure_boot_cert_sha256"], "the Secure Boot certificate given is not the one the record names")
    _run(run, [tools["sbverify"], "--cert", secure_boot_cert, image], "checking the Secure Boot signature")
    # and the initrd it carries reviewed again, here, on the operator's machine (#198): the signatures say
    # the reviewed record was signed, this says the bytes still pass the same rules
    require(record["initrd_review"]["passed"] and review_initrd_data(parts["initrd"], run, tools) == record["initrd_review"],
            "the image's initrd does not pass the review its record states")
    return dict(record["pcr11"])


MAX_CREDENTIALS = 32
MAX_CREDENTIAL_BYTES = 1024 * 1024


def credential_files(esp):
    """{file name: bytes} of a node's ESP credentials (<ESP>/loader/credentials), as the stub reads them:
    regular files only, no link (the stub would read the target; a reviewer reading the directory would
    not), bounded in number and size. Stricter than the stub on purpose: a subdirectory, which the stub
    would skip, is refused, so the directory holds exactly what is measured.
    The stub also measures PER-IMAGE credentials and addons (<ESP>/EFI/**/<image>.efi.extra.d/) and GLOBAL
    addons (<ESP>/loader/addons/) into PCR 12. A KMS host has none; any found is refused, because the PCR 12
    computed here would not be the one the host shows. No path component may be a link. Names are
    compared case-insensitively, as FAT and the stub compare them."""
    # The ESP is FAT: names are compared case-insensitively there, and by the stub. So is every check here.
    # The whole tree is walked once: no link anywhere (a link would measure files the installed ESP does
    # not hold), no per-image credentials or addons (*.efi.extra.d, wherever an image may sit), no global
    # addons (loader/addons), and no two names in one directory that FAT would take for one.
    require(not os.path.islink(esp), "%s is a link: give the ESP itself" % esp)
    credentials, extra, addons = None, [], []
    for top, dirs, files_here in os.walk(esp):
        for name in dirs + files_here:
            require(not os.path.islink(os.path.join(top, name)), "%s is a link: the ESP is read as it will be installed, with no link"
                    % os.path.join(top, name))
        folded = [n.casefold() for n in dirs + files_here]
        twins = sorted({n for n in folded if folded.count(n) > 1})
        require(not twins, "%s holds names FAT would take for one (%s)" % (top, ", ".join(twins)))
        where = os.path.relpath(top, esp).casefold().replace(os.sep, "/")
        extra += [os.path.relpath(os.path.join(top, d), esp) for d in dirs if d.casefold().endswith(".extra.d")]
        if where == "loader/addons":
            addons += files_here + dirs
        if where == "loader":
            credentials = next((os.path.join(top, d) for d in dirs if d.casefold() == "credentials"), None)
    require(not extra, "the ESP holds per-image credentials or addons (%s): systemd-stub measures them into PCR 12 too, and a KMS host has none"
            % ", ".join(sorted(extra)))
    require(not addons, "the ESP holds global addons (%s): systemd-stub measures them into PCR 12 too, and a KMS host has none" % ", ".join(sorted(addons)))
    require(credentials is not None, "%s has no loader/credentials directory: a KMS host's ESP holds its credentials there" % esp)
    directory = credentials
    names = sorted(os.listdir(directory))
    require(len(names) <= MAX_CREDENTIALS, "%s holds %d files; a KMS host has a handful of credentials" % (directory, len(names)))
    files = {}
    for name in names:
        path = os.path.join(directory, name)
        require(not os.path.islink(path) and os.path.isfile(path), "%s is not a regular file: a credential directory holds files only" % path)
        files[name] = read(path, MAX_CREDENTIAL_BYTES)
    return files


def measurement_set(record, label, firmware, pcrs, credentials):
    """The measurement set of this image on one host (KERNEL-UPDATE.md step 1.4): that host's TPM firmware
    version and its own PCR values, with PCR 11 per phase from the record, and with `credentials` (the
    node's ESP credential files, {file name: bytes}) PCR 12 as systemd-stub will measure them
    (espcreds.pcr12). PCR 12 has one value for both phases: nothing extends it after the initrd (measured
    in the unlock boot test, #215). It is never given by hand: a set that should hold it is made from the
    files. It is REQUIRED: a set without it would leave PCR 12 unattested, the gap #66 closed, and after
    stage B2 a host with no credentials cannot be unlocked unattended anyway."""
    load_record(membership.canonical(record))
    require(isinstance(pcrs, dict) and "11" not in pcrs, "the host's PCR values must not give PCR 11: it comes from the image's record, per phase")
    require("12" not in pcrs, "the host's PCR values must not give PCR 12: it is computed from the node's credential files (--credentials)")
    require(isinstance(credentials, dict), "the node's credential files are required: PCR 12 is attested, and comes from them")
    require(any(espcreds.measured(n) for n in credentials), "the credential directory holds no credential the stub measures: PCR 12 would "
            "be all zero, which is a host with no per-host configuration")
    pcrs = dict(pcrs, **{"12": espcreds.pcr12(credentials)})
    entry = {"label": label, "tpm_firmware_version": firmware, "pcrs": pcrs,
             "phases": {phase: {"11": record["pcr11"][phase]} for phase in attest.PHASES}}
    try:
        attest.validate_sets([entry], "set")
    except attest.Refused as refusal:
        raise Refused(str(refusal))
    return entry


# ---- the command ----

def _inputs(args):
    return {k: getattr(args, k) for k in INPUTS if getattr(args, k)}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python3 -m deploy.baremetal.uki", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    def input_args(c):
        for key in INPUTS:
            c.add_argument("--" + key.replace("_", "-"), required=key != "microcode")
        c.add_argument("--uname", required=True)

    c = sub.add_parser("build", help="build the unsigned image and its record")
    input_args(c)
    c.add_argument("--name", required=True)
    c.add_argument("--out", required=True)
    c = sub.add_parser("sign", help="rebuild, sign PCR 11 per phase, sign for Secure Boot")
    input_args(c)
    c.add_argument("--record", required=True)
    c.add_argument("--second-record", required=True, help="the same image's record from another builder; it must be identical")
    c.add_argument("--out", required=True)
    for role in ("initrd", "system", "secure-boot"):
        c.add_argument("--%s-key" % role, required=True, help="a key file, or a PKCS#11 URI with --key-source engine:pkcs11")
        c.add_argument("--%s-cert" % role, required=True, help="the key's X.509 certificate (PEM file)")
    c.add_argument("--key-source", default="file", choices=KEY_SOURCES)
    c = sub.add_parser("verify", help="check a signed image against its record")
    c.add_argument("--image", required=True)
    c.add_argument("--record", required=True)
    c.add_argument("--initrd-pub", required=True, help="the initrd-phase PCR key: public key or certificate (PEM)")
    c.add_argument("--system-pub", required=True, help="the system-phase PCR key: public key or certificate (PEM)")
    c.add_argument("--secure-boot-cert", required=True, help="the Secure Boot certificate the record names: it is what covers the stub")
    c = sub.add_parser("set", help="print the measurement set of this image for one host")
    c.add_argument("--record", required=True)
    c.add_argument("--label", required=True)
    c.add_argument("--tpm-firmware-version", required=True)
    c.add_argument("--pcrs", required=True, help='a JSON file: {"0": "<64 hex>", "7": ...}, the host\'s own values, without PCR 11 or 12')
    c.add_argument("--esp", metavar="ROOT", required=True, help="the node's ESP as it will be: PCR 12 is computed from ROOT/loader/credentials")
    c.add_argument("--credentials-record", metavar="OUT", help="write what PCR 12 was computed from (espcreds.record)")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            record = build(_inputs(args), args.uname, args.name, args.out)
            print("built %s: unsigned image %s" % (record["name"], record["unsigned_sha256"]))
        elif args.command == "sign":
            keys = {"initrd": (args.initrd_key, args.initrd_cert), "system": (args.system_key, args.system_cert),
                    "secure_boot": (args.secure_boot_key, args.secure_boot_cert)}
            record = sign(_inputs(args), load_record(read(args.record, 64 * 1024), signed=False), keys, args.key_source, args.out,
                          second_record=load_record(read(args.second_record, 64 * 1024), signed=False))
            print("signed %s: image %s" % (record["name"], record["signed"]["image_sha256"]))
        elif args.command == "verify":
            record = load_record(read(args.record, 64 * 1024), signed=True)
            verify(args.image, record, {"initrd": read(args.initrd_pub, 65536), "system": read(args.system_pub, 65536)}, args.secure_boot_cert)
            print("VERIFIED %s: the image is the record's, and both PCR signatures verify" % record["name"])
        else:
            record = load_record(read(args.record, 64 * 1024))
            files = credential_files(args.esp)
            entry = measurement_set(record, args.label, args.tpm_firmware_version, membership.load(read(args.pcrs, 65536)), files)
            if args.credentials_record:
                fd = os.open(args.credentials_record, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
                with os.fdopen(fd, "w") as f:
                    f.write(json.dumps(espcreds.record(files), indent=2, sort_keys=True) + "\n")
            print(json.dumps(entry, indent=2, sort_keys=True))
            return 0
        for phase in attest.PHASES:
            print("  PCR 11, %-6s (%s): %s" % (phase, PHASE_PATHS[phase], record["pcr11"][phase]))
        return 0
    except (Refused, OSError) as refusal:
        print("REFUSED: %s" % refusal, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
