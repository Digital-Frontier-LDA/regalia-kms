"""A PKCS#11 URI (RFC 7512) that names one card and one key, and carries nothing else.

Shared by the UKI build (uki.py: its keys through the pkcs11 engine) and the manifest signer (manifest.py:
the membership root on its Nitrokey, #156), so one rule decides what a key URI may say. Every attribute
name is on an allow-list, so no PIN, PIN file or module path gets in under any spelling; there is no
query part; the card is named by serial= AND token=, the key by object= or id=, and type=private."""
import re

from deploy.baremetal.membership import require

ATTRIBUTES = ("token", "serial", "object", "id", "type", "manufacturer", "model")


def parse(value, what):
    """The URI's attributes, {name: value}, or Refused. id= stays percent-encoded here; see key_id()."""
    require(isinstance(value, str) and value.startswith("pkcs11:") and len(value) <= 400, "%s must be a PKCS#11 URI" % what)
    require("?" not in value, "%s has a query part: a PKCS#11 URI here names a card and a key, nothing else (no PIN, no module)" % what)
    attributes = {}
    for part in value[len("pkcs11:"):].split(";"):
        name, sep, val = part.partition("=")
        require(sep and name in ATTRIBUTES, "%s names %r, which is not one of %s (no PIN, no PIN file, no module path)"
                % (what, name, ", ".join(ATTRIBUTES)))
        require(name not in attributes, "%s gives %s twice" % (what, name))
        # percent-encoding only in id (bytes); everywhere else plain printable text, so nothing hides behind an escape
        allowed = r"(%[0-9a-fA-F]{2})+" if name == "id" else r"[A-Za-z0-9 ._()-]+"
        require(re.fullmatch(allowed, val) is not None, "%s: %s=%r is not allowed" % (what, name, val))
        attributes[name] = val
    require("serial" in attributes and "token" in attributes, "%s must name the card by serial= and token=: the engine would "
            "otherwise take the first token that holds a matching key" % what)
    require("object" in attributes or "id" in attributes, "%s must name the key by object= or id=" % what)
    require(attributes.get("type") == "private", "%s must say type=private" % what)
    return attributes


def key_id(attributes):
    """id= as lowercase hex (CKA_ID), or None when the URI names the key by object= only."""
    if "id" not in attributes:
        return None
    return "".join(attributes["id"][i + 1:i + 3] for i in range(0, len(attributes["id"]), 3)).lower()
