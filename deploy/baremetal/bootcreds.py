"""The boot credentials of a KMS host: what its initrd needs to ask its peers for its disk (#66).

    render(manifest, site, device)       {credential name: bytes}, the files the initrd reads
    esp_files(site, envelopes, root_key, device, anchor)
                                         {path on the ESP: bytes}: the ONE call enrol and the update path make

render() is deterministic: the same manifest and site config give the same bytes on every machine, so a
peer (or a reviewer) recomputes what a host's ESP must hold, and from it the PCR 12 the host measures
(espcreds.pcr12). It composes the renderers that already exist (unlock.boot_config, bootnet's boot
WireGuard configuration and ruleset) and writes JSON as membership.canonical does. It reads nothing and
writes nothing.

esp_files() verifies the signed chain itself (membership.accept_chain, under the pinned root) AND against this
host's TPM high-water anchor (`anchor`, its membership.HighWater), as Store.load does before it writes: a
validly signed chain that is stale (below the anchor: a restored disk, a withheld update) or that forks from
the manifest the TPM recorded is refused. A stale chain would render an older manifest's peers, a node
revoked since among them, and a PCR 12 the peers no longer expect. It returns
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


def anchored(envelopes, root_key, anchor):
    """The current manifest of `envelopes`, verified from epoch 1 under `root_key` and against the TPM anchor
    as Store.load does before it writes (cmd/regalia-unlock/membership.Anchored, the initrd's, decides alike):
    a chain below the high-water is a ROLLBACK, one whose manifest at the recorded epoch is not the recorded
    one is a CONFLICT (the crash window, a record one epoch behind the counter, is accepted as verify does),
    and one further ahead than advance() would go is an anomaly. Reads the TPM; changes nothing.

    It reads without the writer's lock (it runs as root, the writer as regalia-sync): a commit racing it can
    show as the crash window (accepted), as "the anchor changed during the read", or as a CONFLICT that is the
    commit and not a fork. Enrolment and the update path are rerun, and a second read decides."""
    require(isinstance(envelopes, list) and envelopes, "the membership chain must be a non-empty list of envelopes")
    current, manifests = None, []
    for envelope in envelopes:
        nxt = membership.accept(current, envelope, root_key)
        require(nxt is not current, "the chain repeats epoch %d" % nxt["epoch"])
        manifests.append(nxt)
        current = nxt
    high = anchor.value()
    require(current["epoch"] >= high, "ROLLBACK: the chain ends at epoch %d but the TPM high-water is %d; fetch the chain from a peer"
            % (current["epoch"], high))
    digests = membership.Store._digests(manifests)

    def digest_of(epoch):
        # a commit between the two reads can move the high-water past this chain: that is a ROLLBACK too,
        # never an IndexError
        require(epoch <= len(manifests), "ROLLBACK: the chain ends at epoch %d but the TPM recorded epoch %d; fetch the chain from a peer"
                % (len(manifests), epoch))
        return digests(epoch)
    high = anchor.verify(digest_of, lock=False)
    require(current["epoch"] - high <= anchor.MAX_JUMP, "epoch jump %d exceeds the bound %d: anomaly" % (current["epoch"] - high, anchor.MAX_JUMP))
    return current


def esp_files(site, envelopes, root_key, device, anchor):
    """{path on the ESP: bytes} for the host `site` describes, under the chain `envelopes` (a list of signed
    envelopes from epoch 1) verified against `root_key` and this host's TPM anchor (`anchored`). Refused
    when the chain does not verify, is not the anchored one, or leaves the host no peer."""
    manifest = anchored(envelopes, root_key, anchor)
    return {"%s/%s.cred" % (CREDENTIALS_DIR, name): body for name, body in sorted(render(manifest, site, device).items())}
