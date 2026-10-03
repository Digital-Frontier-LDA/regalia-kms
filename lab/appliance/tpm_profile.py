"""Apply the reviewed ESYS-only TPM laboratory profile, before bootstrap.

Caller must first authenticate the complete source archive with
deploy.images.source. This profile is not appliance package admission.
"""
import argparse
import hashlib
from pathlib import Path

INPUTS = {
    "bootstrap": "2e009317eb1deb5a2320a873564419fc350c0bfc3c5c23bc49489485208e51e9",
    "configure.ac": "09b65622708d1583f306c32a1843e3eda140f4040e8bb64a03cb262369f488df",
    "Makefile.am": "f1a71f2533cb641b8d37c6c8ddc5b192108a613a3dc27d4105f4af50e64aea7e",
}
REPLACEMENTS = {
    "bootstrap": [("git describe --tags --always --dirty > VERSION", "printf '%s\\n' '5.7' > VERSION")],
    "configure.ac": [("PKG_CHECK_MODULES([CURL], [libcurl])", "")],
    "Makefile.am": [(" $(CURL_CFLAGS)", ""), (" $(CURL_LIBS)", ""),
                    ("    tools/tpm2_getekcertificate.c \\\n", ""),
                    ("    man/man1/tpm2_getekcertificate.1 \\\n", "")],
}


def apply(root):
    outputs = {}
    for name, digest in INPUTS.items():
        path = root / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise ValueError("nonregular or oversized source input")
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("source input differs from reviewed TPM source")
        text = content.decode("utf-8")
        for old, new in REPLACEMENTS[name]:
            if text.count(old) != 1:
                raise ValueError("unexpected source replacement count")
            text = text.replace(old, new)
        outputs[name] = text
    # Validate every input before changing any of the files.
    for name, text in outputs.items():
        (root / name).write_text(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_directory", type=Path)
    args = parser.parse_args()
    try:
        apply(args.source_directory)
    except (OSError, ValueError) as error:
        parser.exit(1, f"REFUSED: {error}\n")


if __name__ == "__main__":
    main()
