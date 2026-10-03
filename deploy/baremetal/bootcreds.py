"""The boot credentials of a KMS host: what its initrd needs to ask its peers for its disk (#66).

    render(manifest, site, device)       {credential name: bytes}, the files the initrd reads
    esp_files(site, envelopes, root_key, device)
                                         {path on the ESP: bytes}: the ONE call enrol and the update path make

render() is deterministic: the same manifest and site config give the same bytes on every machine, so a
peer (or a reviewer) recomputes what a host's ESP must hold, and from it the PCR 12 the host measures
(espcreds.pcr12). It composes the renderers that already exist (unlock.boot_config, bootnet's boot
WireGuard configuration and ruleset) and writes JSON as membership.canonical does. It reads nothing and
writes nothing.

esp_files() verifies the signed chain itself (membership.accept_chain, under the pinned root) and returns
what the ESP must hold FOR THE CURRENT STAGE of #66's B3, so that its callers do not change between stages:
today the credentials render() gives, from the chain's current manifest, under loader/credentials/ (each
measured into PCR 12 by systemd-stub). Once the initrd verifies the chain and renders these itself (B3's
wiring), the ESP holds the measured site configuration and the signed chain instead, and a membership
change no longer moves PCR 12. The sealed credentials (the local half, the WG-BOOT key) are not here: they
are made once, at enrolment, by whoever holds the TPM.
"""
from deploy.baremetal import bootnet, membership, unlock

Refused, require = membership.Refused, membership.require

# The PCRs a booting host's quote covers, and its peers judge: the Secure Boot state, the signed image's
# PCR 11, and the ESP credentials (espcreds).
UNLOCK_PCRS = (7, 11, 12)
CREDENTIALS_DIR = "loader/credentials"
# the credentials render() gives, by name (each is <name>.cred on the ESP)
RENDERED = ("regalia.unlock-config", "regalia.wg-boot-conf", "regalia.boot-nft", "regalia.boot-env")


def boot_env(site):
    """regalia.boot-env, as initrd/wg-boot reads it: the card by MAC address, host_ipv4 with its prefix, the
    gateway (empty when the peers are on the link) and the node's address inside the tunnel."""
    mesh = site["boot_mesh"]
    require(mesh is not None, "the site config has no boot_mesh: this is a single-site host")
    return ("BOOT_NIC_MAC=%s\nBOOT_ADDRESS=%s/%d\nBOOT_GATEWAY=%s\nBOOT_TUNNEL=%s\n"
            % (mesh["nic_mac"], site["host_ipv4"], mesh["prefix"], mesh["gateway"] or "", mesh["address"])).encode()


def render(manifest, site, device):
    """The credentials a host's initrd reads under `manifest`, for the host `site` (a sitecfg-validated site
    configuration with a boot_mesh) whose root volume is `device`: {name: bytes}."""
    endpoints = bootnet.unlock_endpoints(site, manifest)
    config = unlock.boot_config(manifest, site["boot_mesh"]["node_id"], device, UNLOCK_PCRS, endpoints)
    return {"regalia.unlock-config": membership.canonical(config),
            "regalia.wg-boot-conf": bootnet.boot_wg_conf(site, manifest).encode(),
            "regalia.boot-nft": bootnet.boot_ruleset(site, manifest).encode(),
            "regalia.boot-env": boot_env(site)}


def esp_files(site, envelopes, root_key, device):
    """{path on the ESP: bytes} for the host `site` describes, under the chain `envelopes` (a list of signed
    envelopes from epoch 1) verified against `root_key`. Refused when the chain does not verify or leaves
    the host no peer."""
    require(isinstance(envelopes, list) and envelopes, "the membership chain must be a non-empty list of envelopes")
    manifest = membership.accept_chain(None, envelopes, root_key)
    return {"%s/%s.cred" % (CREDENTIALS_DIR, name): body for name, body in sorted(render(manifest, site, device).items())}
