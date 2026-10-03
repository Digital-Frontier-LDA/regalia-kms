#!/usr/bin/env python3
"""The boot image of a KMS host: one unified kernel image (UKI), built the same on any machine, with a
record of what it will measure, and signed in a separate step by keys that are on no host (#57).

    python3 -Es -m deploy.baremetal.uki build   INPUTS --name NAME --out DIR
    python3 -Es -m deploy.baremetal.uki sign    INPUTS --record DIR/NAME.record.json --out DIR
                                            --initrd-key K --initrd-cert C --system-key K --system-cert C
                                            --secure-boot-key K --secure-boot-cert C [--key-source file|engine:pkcs11]
    python3 -Es -m deploy.baremetal.uki verify  --image IMAGE --record RECORD [--secure-boot-cert C]
    python3 -Es -m deploy.baremetal.uki set     --record RECORD --label LABEL --tpm-firmware-version HEX --pcrs FILE
                                            [--credentials DIR [--credentials-record OUT]]

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
sign    builds the image again from the same inputs, which must hash to the record's values; signs the
        initrd-phase PCR 11 with one key and the booted-phase PCR 11 with another (two keys, so a secret
        sealed for the booted system does not open in the initrd); checks both signatures itself with
        OpenSSL against the policy it computed; attaches them (.pcrsig); requires the measured sections
        to be unchanged; then signs the file for Secure Boot and checks that too.
        The key options take files, or with --key-source engine:pkcs11 the PKCS#11 URIs of keys in a
        token (the certificates are always files). No option takes a PIN: the token's PIN is asked for
        by OpenSSL's pkcs11 engine at the terminal. A PIN in a URI (`pin-value=`) is refused.
verify  what a host's operator runs before installing an image: its measured sections are the record's,
        its two PCR signatures verify under the keys the record names, for the PCR 11 the record
        predicts, and with --secure-boot-cert its Secure Boot signature verifies.

THE KEYS. Three RSA-2048 keys: the two PCR keys and the Secure Boot key, each different from the others
(refused otherwise). RSA because systemd seals only to an RSA key (systemd-measure itself would sign
with an EC key, and nothing could use the result); 2048 because the host's TPM has to load the public
key, and that is the size every TPM 2.0 has. The public half of the SYSTEM key is a section of the image
(.pcrpkey) and so is itself measured: it is an input of `build`. The initrd-phase key's public half is
given where the initrd's secret is sealed (unlock.seal_local).

WHAT THIS DOES NOT DO. It does not fetch or pin the inputs, build the initrd, review what the initrd
does (KERNEL-UPDATE.md step 2.2a), or install anything. The command-line check is a short refusal list
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
    out, seen = [], set()
    for i in range(count):
        entry = table + 40 * i
        raw_name = data[entry:entry + 8].rstrip(b"\0")
        require(re.fullmatch(rb"\.[a-z]{1,7}", raw_name) is not None, "section %d has the name %r" % (i, raw_name))
        name = raw_name.decode("ascii")
        virtual_size, _, raw_size, pointer = struct.unpack_from("<IIII", data, entry + 8)
        require(name not in seen, "the image has two %s sections" % name)
        seen.add(name)
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
    for word in text.split():
        if re.fullmatch(CMDLINE_HARDENING, word):
            continue
        for pattern in CMDLINE_REFUSED:
            require(re.fullmatch(pattern, word) is None, "the command line holds %r, which a KMS host's image does not carry" % word)
    return text


INPUTS = ("linux", "initrd", "microcode", "cmdline", "os_release", "stub", "pcrpkey")


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
    with tempfile.TemporaryDirectory(dir=out_dir) as work:
        image = os.path.join(work, "image.efi")
        data = _ukify(inputs, uname, image, run, tools)
        parts = measured(data)
        require(".pcrsig" not in dict(sections(data)), "an unsigned image must have no .pcrsig section")
        _check_sections(parts, inputs, uname)
        values, _ = _predict(parts, run, tools, work)
        record = {
            "schema": SCHEMA, "name": name, "uname": uname,
            "inputs": {k: {"sha256": sha256(read(inputs[k])), "size": os.path.getsize(inputs[k])} for k in INPUTS if inputs.get(k)},
            "sections": {"." + n: sha256(c) for n, c in parts.items()},
            "unsigned_sha256": sha256(data), "phase_paths": dict(PHASE_PATHS), "pcr11": values, "pcrpkey_pkfp": fingerprint,
            "tools": {"ukify": _tool_version(run, [tools["ukify"], "--version"]),
                      "systemd_measure": _tool_version(run, [tools["measure"], "--version"])}}
        os.replace(image, os.path.join(out_dir, name + ".unsigned.efi"))
    _write(os.path.join(out_dir, name + ".record.json"), record)
    return record


def _write(path, record):
    with open(path, "wb") as f:
        f.write(json.dumps(record, indent=2, sort_keys=True).encode("ascii") + b"\n")


RECORD_KEYS = ("schema", "name", "uname", "inputs", "sections", "unsigned_sha256", "phase_paths", "pcr11", "pcrpkey_pkfp", "tools")


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
    membership.exact(record["pcr11"], attest.PHASES, "record.pcr11")
    for field in [record["unsigned_sha256"], record["pcrpkey_pkfp"]] + list(record["pcr11"].values()):
        require(attest.is_hex(field, 64), "the record holds a value that is not a SHA-256 in lowercase hex")
    require(isinstance(record["sections"], dict) and set(record["sections"]) <= {"." + n for n in OURS}
            and all(attest.is_hex(v, 64) for v in record["sections"].values()), "record.sections is not a map of this tool's sections")
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
        document = json.loads(raw.rstrip(b"\0").decode("ascii"))
        entries = document["sha256"]
        require(set(document) == {"sha256"} and isinstance(entries, list), "the PCR signatures cover a bank other than SHA-256")
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        raise Refused("the image's .pcrsig is not a PCR signature document")
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


def _key_argument(value, source, what):
    """A key option: a file, or with engine:pkcs11 a PKCS#11 URI that carries no PIN."""
    if source == "file":
        require(os.path.isfile(value), "%s: %s is not a file (with a token, pass --key-source engine:pkcs11 and a PKCS#11 URI)" % (what, value))
    else:
        require(re.fullmatch(r"pkcs11:[A-Za-z0-9;=%._~:@/?&+-]{1,400}", value) is not None, "%s must be a PKCS#11 URI" % what)
        require(re.search(r"pin-(value|source)", value) is None, "%s carries a PIN or a PIN file in the URI: the engine asks for the PIN "
                "at the terminal" % what)
    return value


def sign(inputs, record, keys, source, out_dir, run=subprocess.run, tools=TOOLS):
    """Signs the image `record` describes, rebuilt from `inputs`. `keys`: {"initrd" | "system" |
    "secure_boot": (key file or PKCS#11 URI, certificate file)}. Writes NAME.efi and NAME.signed.json."""
    require(source in KEY_SOURCES, "--key-source is one of %s" % ", ".join(KEY_SOURCES))
    load_record(membership.canonical(record), signed=False)
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
    with tempfile.TemporaryDirectory(dir=out_dir) as work:
        # the third build: this machine must get the bytes the record names before it signs anything
        data = _ukify(inputs, uname, os.path.join(work, "unsigned.efi"), run, tools)
        require(sha256(data) == record["unsigned_sha256"], "this machine built another image than the record's (%s, not %s): "
                "nothing is signed" % (sha256(data), record["unsigned_sha256"]))
        parts = measured(data)
        values, flags = _predict(parts, run, tools, work)
        require(values == record["pcr11"], "the image does not measure what its record says")
        pcrsig = None
        for phase in attest.PHASES:
            argv = [tools["measure"], "sign", "--bank=sha256", "--phase=" + PHASE_PATHS[phase], "--private-key=" + keys[phase][0],
                    "--certificate=" + keys[phase][1]] + ["%s=%s" % (flags[n], os.path.join(work, "section." + n)) for n in parts]
            if source != "file":
                argv.append("--private-key-source=" + source)
            if pcrsig:
                argv.append("--append=" + pcrsig)
            out = _run(run, argv, "signing the %s-phase PCR 11" % phase)
            pcrsig = os.path.join(work, "pcrsig-%s.json" % phase)
            with open(pcrsig, "wb") as f:
                f.write(out)
        signatures = check_pcrsig(read(pcrsig, 65536), record, public, run, tools)
        carrying = _ukify(inputs, uname, os.path.join(work, "pcrsigned.efi"), run, tools, pcrsig=pcrsig)
        require(measured(carrying) == parts, "attaching the PCR signatures changed a measured section")
        check_pcrsig(dict(sections(carrying))[".pcrsig"], record, public, run, tools)
        final = os.path.join(work, "signed.efi")
        argv = [tools["sbsign"], "--key", keys["secure_boot"][0], "--cert", keys["secure_boot"][1], "--output", final, os.path.join(work, "pcrsigned.efi")]
        if source != "file":
            argv[1:1] = ["--engine", source.split(":", 1)[1]]
        _run(run, argv, "the Secure Boot signature")
        _run(run, [tools["sbverify"], "--cert", keys["secure_boot"][1], final], "checking the Secure Boot signature")
        signed = read(final)
        require(measured(signed) == parts, "the Secure Boot signature changed a measured section")
        certificate = _run(run, [tools["openssl"], "x509", "-outform", "der"], "reading the Secure Boot certificate", input=read(keys["secure_boot"][1], 65536))
        os.replace(final, os.path.join(out_dir, name + ".efi"))
    result = dict(record, signed={"image_sha256": sha256(signed), "pcr_signatures": signatures, "secure_boot_cert_sha256": sha256(certificate)})
    _write(os.path.join(out_dir, name + ".signed.json"), result)
    return result


def verify(image, record, public_keys, secure_boot_cert=None, run=subprocess.run, tools=TOOLS):
    """`image` is the signed image `record` (a signed record) describes. `public_keys`: {phase: PEM} of the
    two PCR keys; their fingerprints must be the record's. Returns the record's PCR 11 values."""
    load_record(membership.canonical(record), signed=True)
    data = read(image)
    require(sha256(data) == record["signed"]["image_sha256"], "the image is not the file the record names")
    parts = measured(data)
    require({"." + n: sha256(c) for n, c in parts.items()} == record["sections"], "the image's measured sections are not the record's")
    require({phase: pcr11(parts, path) for phase, path in PHASE_PATHS.items()} == record["pcr11"], "the image does not measure what its record says")
    keys = {phase: public_key(public_keys[phase], "the %s-phase public key" % phase, run, tools) for phase in attest.PHASES}
    for phase in attest.PHASES:
        require(keys[phase][0] == record["signed"]["pcr_signatures"][phase]["pkfp"], "the %s-phase key given is not the one the record names" % phase)
    require(keys["system"][0] == record["pcrpkey_pkfp"] and public_key(parts["pcrpkey"], "the image's .pcrpkey", run, tools)[0] == keys["system"][0],
            "the image's .pcrpkey is not the system-phase key")
    found = dict(sections(data)).get(".pcrsig")
    require(found is not None, "the image carries no PCR signatures")
    check_pcrsig(found, record, keys, run, tools)
    if secure_boot_cert:
        certificate = _run(run, [tools["openssl"], "x509", "-outform", "der"], "reading the Secure Boot certificate", input=read(secure_boot_cert, 65536))
        require(sha256(certificate) == record["signed"]["secure_boot_cert_sha256"], "the Secure Boot certificate given is not the one the record names")
        _run(run, [tools["sbverify"], "--cert", secure_boot_cert, image], "checking the Secure Boot signature")
    return dict(record["pcr11"])


MAX_CREDENTIALS = 32
MAX_CREDENTIAL_BYTES = 1024 * 1024


def credential_files(directory):
    """{file name: bytes} of a node's ESP credential directory (<ESP>/loader/credentials), as the stub reads
    it: regular files only, no link (the stub would read the target; a reviewer reading the directory would
    not), bounded in number and size."""
    names = sorted(os.listdir(directory))
    require(len(names) <= MAX_CREDENTIALS, "%s holds %d files; a KMS host has a handful of credentials" % (directory, len(names)))
    files = {}
    for name in names:
        path = os.path.join(directory, name)
        require(not os.path.islink(path) and os.path.isfile(path), "%s is not a regular file: a credential directory holds files only" % path)
        files[name] = read(path, MAX_CREDENTIAL_BYTES)
    return files


def measurement_set(record, label, firmware, pcrs, credentials=None):
    """The measurement set of this image on one host (KERNEL-UPDATE.md step 1.4): that host's TPM firmware
    version and its own PCR values, with PCR 11 per phase from the record, and with `credentials` (the
    node's ESP credential files, {file name: bytes}) PCR 12 as systemd-stub will measure them
    (espcreds.pcr12). PCR 12 has one value for both phases: nothing extends it after the initrd (measured
    in the unlock boot test, #215). It is never given by hand: a set that should hold it is made from the
    files."""
    load_record(membership.canonical(record))
    require(isinstance(pcrs, dict) and "11" not in pcrs, "the host's PCR values must not give PCR 11: it comes from the image's record, per phase")
    require("12" not in pcrs, "the host's PCR values must not give PCR 12: it is computed from the node's credential files (--credentials)")
    if credentials is not None:
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
    c.add_argument("--secure-boot-cert")
    c = sub.add_parser("set", help="print the measurement set of this image for one host")
    c.add_argument("--record", required=True)
    c.add_argument("--label", required=True)
    c.add_argument("--tpm-firmware-version", required=True)
    c.add_argument("--pcrs", required=True, help='a JSON file: {"0": "<64 hex>", "7": ...}, the host\'s own values, without PCR 11 or 12')
    c.add_argument("--credentials", metavar="DIR", help="the node's ESP credential directory (loader/credentials): PCR 12 is computed from it")
    c.add_argument("--credentials-record", metavar="OUT", help="with --credentials: write what PCR 12 was computed from (espcreds.record)")
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            record = build(_inputs(args), args.uname, args.name, args.out)
            print("built %s: unsigned image %s" % (record["name"], record["unsigned_sha256"]))
        elif args.command == "sign":
            keys = {"initrd": (args.initrd_key, args.initrd_cert), "system": (args.system_key, args.system_cert),
                    "secure_boot": (args.secure_boot_key, args.secure_boot_cert)}
            record = sign(_inputs(args), load_record(read(args.record, 64 * 1024), signed=False), keys, args.key_source, args.out)
            print("signed %s: image %s" % (record["name"], record["signed"]["image_sha256"]))
        elif args.command == "verify":
            record = load_record(read(args.record, 64 * 1024), signed=True)
            verify(args.image, record, {"initrd": read(args.initrd_pub, 65536), "system": read(args.system_pub, 65536)}, args.secure_boot_cert)
            print("VERIFIED %s: the image is the record's, and both PCR signatures verify" % record["name"])
        else:
            record = load_record(read(args.record, 64 * 1024))
            require(args.credentials or not args.credentials_record, "--credentials-record needs --credentials")
            files = credential_files(args.credentials) if args.credentials else None
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
