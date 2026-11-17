"""Where this host's own files live on a verity-/usr host (#61, the dm-verity design of 2026-10-05).

/ is a tmpfs and /etc is made at every boot from the image's /usr/share/factory/etc
(units/00-regalia-etc.tmpfiles.conf), so a file written under /etc is gone at the next boot. A file that is this
host's own (its configuration, its keys, its sealed credentials) is kept on /var, the host's LUKS2 volume,
under VAR_ETC at the same relative path, and its /etc name is a link there made by the same tmpfiles file. Readers keep
the /etc name. A WRITER writes the /var name, from persistent(): through a link it would be refused by enrol's
trusted-directory walk (O_NOFOLLOW), and on a host whose link was never made it would write to the tmpfs and lose it.

PER_HOST is the list; deploy/baremetal/image/etc-inventory.txt says, for each, who writes it, who reads it and why
it is per host, with every /etc path that is NOT here and why. tests/test_baremetal_etc_inventory.py holds the three
(this list, the inventory, the tmpfiles links) equal, and tests/test_baremetal_etc_writes.py refuses a write by the
/etc name anywhere in deploy/ and the units.
"""

import os

VAR_ETC = "/var/lib/regalia-etc"

# /etc path -> what it is (the inventory has the rest). A directory covers everything below it.
PER_HOST = {
    "/etc/regalia": "the node's configuration directory: node.json, the site configuration, the WG-SERVICE key, "
                    "etcd.conf.yml and etcd/, the audit shipper's and node_exporter's certificates",
    "/etc/regalia-kms": "the KMS daemon's configuration: config.json, opensc.conf",
    "/etc/credstore.encrypted": "the TPM-sealed credentials: the PINs, etcd's peer key",
    "/etc/chrony/regalia.conf": "chronyd's configuration, rendered at enrolment from the site's NTS servers",
    "/etc/ssh/ssh_host_ed25519_key": "the SSH host key (private)",
    "/etc/ssh/ssh_host_ed25519_key.pub": "the SSH host key the manifest names (ssh_host_pub)",
    "/etc/nftables.d/regalia-kms.nft": "the host firewall's ruleset, rendered for this host",
    "/etc/default/prometheus-node-exporter": "node_exporter's ARGS, rendered from the site configuration",
}


# The PER_HOST entries that are DIRECTORIES (the rest are files). Their /var directory must exist for the link to be
# usable at all, so tmpfiles makes it (a `d` line in 00-regalia-etc.tmpfiles.conf) and e2e/etc-factory.sh checks it is
# there in the booted layout: said here, not inferred from that file, so a `d` line removed is a failure, not a skip.
DIRECTORIES = ("/etc/regalia", "/etc/regalia-kms", "/etc/credstore.encrypted")


class NotPerHost(ValueError):
    pass


def covering(path):
    """The PER_HOST entry `path` is, or lies under; None if none."""
    for entry in PER_HOST:
        if path == entry or path.startswith(entry + "/"):
            return entry
    return None


def persistent(path):
    """The /var name of a per-host /etc path (an absolute, normalized path at or under a PER_HOST entry); a path that
    is not one is refused, so a caller cannot write somewhere this list does not name."""
    if not isinstance(path, str) or not path.startswith("/") or "\0" in path or os.path.normpath(path) != path:
        raise NotPerHost("%r is not an absolute, normalized path" % (path,))
    if covering(path) is None:
        raise NotPerHost("%s is not one of this host's own /etc files (hostpaths.PER_HOST)" % path)
    return VAR_ETC + path[len("/etc"):]
