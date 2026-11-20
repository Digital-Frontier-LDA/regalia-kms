# Single-node KMS: analysis and design (regalia-kms-dx7)

> **Status: design, decided, not built.** The owner questions were decided on 2026-11-18 (section 7). Nothing in this document is implemented yet. It records the owner's requirement, the inventory of what assumes three nodes today, the proposed one-node design, what one node loses, and the slices that build it.
> The full inventory, with file:line for each entry, is in [single-node-inventory.md](single-node-inventory.md).

## 1. The requirement

- **Owner, 2026-11-17:** the KMS must support a **1-node** deployment as well as today's **3-node** one.
  - 5, 7 and other odd sizes come later. They are not built now, but nothing built here may hard-code a size that would block them.
- **Owner, same day:** some features can't be supported on a single node, and that is accepted.
  - The documentation must tell the user clearly, with a "1 node vs 3 nodes" table (section 5).
  - Genesis must make the operator acknowledge the limits (section 6).
- **Invariant of this design:** the node count is a **genesis-time choice, recorded in the root-signed manifest**.
  - It is never inferred at runtime, for example from how many peers answer, how many nodes are ACTIVE, or how many tombstones there are.
  - A node that finds itself alone in a three-node manifest is a three-node cluster in an outage. It is not a one-node cluster.

## 2. What assumes three nodes today: summary

The inventory found 499 places:
- 145 constants or literals to parameterize (a);
- 214 security properties that change with one node (b);
- 2 that are both;
- 138 test-only (c).

The ones that decide the design:

| # | Where | What it does today | With one node |
|---|---|---|---|
| 1 | `deploy/baremetal/membership.py:140`, `:517-518`; Go twin `cmd/regalia-unlock/membership/v4.go:25-26`, `:145-153` | `HEARTBEAT_FLOOR = NODE_RULE_FLOOR = 2`, "no single party keeps a cluster alive or revokes alone" | A 1-node rule `{threshold 2, parties [n1]}` is invalid, so a 1-node **genesis cannot even be proposed today** |
| 2 | `deploy/baremetal/manifest.py:333-335` | Genesis writes heartbeat `{2, nodes+owner}`, activation `{2, nodes+owner}`, revocation `[{2, nodes}, {1, owner}]` | The node revocation rule fails validation. Heartbeat and activation would need the owner every time |
| 3 | `deploy/baremetal/unlock.py:2`, `:605-622`, `:1031`; `cmd/regalia-unlock/config.go:85`, `bootcfg/bootcfg.go:213,329`; `enrol.py:1475` | The root disk opens with **the TPM and one peer, never the TPM alone** (S1, #67, #135) | There is no peer. Enrolment refuses ("no path can be made"), and only the LUKS recovery key opens the disk |
| 4 | `deploy/baremetal/lease.py:2`, `:439`; `node.py:967` | A running node serves only while **another** node issues its 30 s runtime lease ("a node does not vouch for itself") | The node never gets a lease and never serves |
| 5 | `internal/admission/admission.go:449-454`; `admission.py:94-97` | The only lease-less mode is `recovery` (lone survivor), in which the Go daemon serves nothing | The node would sit permanently in a mode that serves nothing |
| 6 | `deploy/baremetal/activation.py:240-325`, `beat.py:197-209`, `revoke.py:104-118` | Issuance is proposer plus **exactly one** co-signer (a 2-signature literal) | No co-signer exists. (At N=5 the threshold of 3 is not met either: this blocks odd N later) |
| 7 | `deploy/baremetal/reanchor.py:93-102`, `recover.py:239-265`, `convergence.py:137-182`, `recount.py:31,138` | Re-anchor and crash-window recovery need chains from **two other nodes**, or one node plus the owner | No source exists. Any anchor damage becomes a new genesis |
| 8 | `deploy/baremetal/rollout.py:212-235`, `:286-329`; `update.py:298-301` | A reboot is allowed only when every other authorizer has vouched. Retiring a set needs peers to have seen the node | `may_reboot` is always refused, and retiring always needs `--emergency` |
| 9 | `deploy/baremetal/sitecfg.py:224,255`, `firewall.py:64-85`, `etcdconf.py:230`, `bootnet.py:91,136`, `initrd/wg-boot:99` | The boot mesh needs 1 to 8 peers, the service mesh needs a boot mesh, and etcd peer URLs must be on the mesh | No service mesh exists, so etcd cannot bind its peer URL |
| 10 | `deploy/monitoring/regalia-node.rules.yml:122,133,159` | The "BehindFleet" alerts compare a node with the others. `RegaliaNextBootNeedsRecoveryKey` fires when no peer can unlock | The fleet comparison is blind, and the recovery-key alert fires for ever |
| 11 | `e2e/lib/threenode.py:1017-1019`, `:1744`, `:1889`; ten `e2e/three-node-*.py`; `.github/workflows/node-units.yml:24-64,165-540` | The fixture already takes `names` (`Cluster(work, names=("a",))` builds), but its genesis thresholds are 2, `unlock()` indexes peer path 0, and every scenario hard-codes a/b/c and its pass count | No one-node scenario exists, and none can run until 1 to 9 land |

**Already one-node aware** (keep as is):
- `survivor.py:225-227` refuses a survivor authorization when the node "counts alone": "a one-node membership, commissioned by a new manifest, not an outage" (LIMITATIONS, regalia-4rt).
- `internal/approval/approval.go:76-82` already provides for "a single-node deployment" (an empty `Signer`).
- Several Go opstate tests already run a 1-member etcd.

**Not node-bound** (unchanged with one node):
- Operation approvals (m-of-n): `policy.RequiredApprovals` counts approver card holders, not nodes (`internal/policy`, `internal/approval`, `spendaudit.py`).
- The two owner cards and K_A.
- The card record.
- Shamir root custody.

## 3. Principles of the design

1. **Topology is signed, never inferred.**
   - A new root-only manifest field, `topology`, is fixed at genesis.
   - Every rule that depends on N reads it. No code counts the nodes it can see.
2. **Thresholds come from the manifest, never from a literal.**
   - The format floor becomes a function of the topology. It is the majority of the node parties, so that any two node quorums intersect.
   - N=1 gives 1. N=3 gives 2, exactly today's floor. N=5 gives 3, and N=7 gives 4.
   - Code that collects co-signatures collects "threshold − 1" of them, not "one".
3. **One node is a profile of its own, not a permanent outage.**
   - It never runs in the lone-survivor or recovery modes.
   - Those stay what they are: the degraded state of a multi-node cluster.
4. **What one node cannot guarantee is refused, or made explicit and attended. It is never silently weakened.**
   - Where a peer used to be the "somebody with current knowledge" (unlock, image retirement, revocation reach), the **owner**, present and touching a card, takes that place.
   - Where nobody can take that place (surviving a node loss), the guarantee is listed as lost.
5. **Odd N stays open.**
   - Nothing here hard-codes 1 or 3.
   - The places that still assume "one co-signer" or "two returners" are listed in section 8 as blockers for N≥5. They are left for that later epic.

## 4. The one-node design

### 4.1 Membership: the `topology` field (schema `regalia.membership/v5`)

- **Why v5.** A new required field is a schema step, as v3 and v4 were. A verifier that knows only v4 (the initrd's Go `accept()`) must refuse the whole manifest, not misread it.
- **Timing.** No production genesis has been held yet (LIMITATIONS, "Overall"), so production can start at v5.
- **The field:**

  ```json
  "topology": {
    "profile": "single-node" | "multi-node",
    "nodes": 1 | 3,
    "single_node_limits_sha256": "<64 hex>"
  }
  ```

  - `single_node_limits_sha256` is present only when `profile` is `single-node`.
  - `nodes` is the **designed** size. In this epic it is 1 or 3. 5 and 7 are refused until their epic lands, and an even size is refused for ever.
- **Who may change it.** `topology` joins `ROOT_FIELDS`, so a quorum can never touch it.
  - In this epic, not even the root may change it after genesis (decision Q3).
  - A change of profile is a new genesis.
- **Validation (Python `membership.validate` and the Go twin, held equal by a vector):**
  - **single-node:**
    - at most one node that is not RETIRED or REVOKED_STOLEN, and exactly one until the owner revokes it: the owner's REVOKED_STOLEN (4.4) leaves none, and the KMS stays stopped until a root-signed manifest enrols a replacement. Never a second live node;
    - the rules below name that node (after a revocation, the revoked node, until the root names its replacement);
    - `heartbeat_signers = {1, [n]}`;
    - `activation_signers = {1, [n]}`;
    - `revocation_signers = [{1, ["owner"]}]`, with no node rule.
    - A root-signed **replacement** (old node RETIRED, new node ACTIVE in one step) keeps the profile valid.
  - **multi-node:**
    - the node floor is `floor(nodes/2)+1` over the node parties;
    - the owner counts as one extra party, as today;
    - the number of non-terminal nodes may be below `nodes` (an outage, a retirement awaiting replacement) but never above it.
  - The disjoint-quorum check that LIMITATIONS states for activation is enforced, not just documented: any node-only quorum is a majority of the designed nodes.

### 4.2 Genesis

- **The command.** `manifest propose --genesis --topology single-node|multi-node`.
  - The flag is **required**: no default, and it is never deduced from the number of `--node` arguments.
  - Thresholds are computed from the topology (4.1), replacing the literals at `manifest.py:333-335`.
  - One `--node` with `multi-node` is refused, and so are three with `single-node`.
- **The acknowledgement** is section 6.

### 4.3 Quorum, activation and serving

- **Activation lease:** `{1, [n]}`.
  - The node signs its own activation lease. Its grant record (TPM NV counter, then the record, then the signature: `activation.py:201-237`) still applies, so the activation epoch still only rises.
  - Mutual exclusion holds because the manifest names one node and its signing key never leaves its TPM.
  - What one node does **not** give: a second, independent signer that would refuse a root-compromised node.
- **Runtime lease (`lease.py`):** a **self-issued** lease, allowed only under `single-node`.
  - Issuer equals subject, over the node's own TPM quote by its AK.
  - It keeps every other binding: the 30 s life, the measured boot (PCR 11 against the manifest's measurements), `cluster_id`, `state_epoch`, `state_revision` and the revision floor, and the daemon's `session_key`.
  - It is a local liveness and binding check, not a vouch: nobody outside the node can stop renewing it.
- **Admission:** a third mode, `single`, beside `lease` and `recovery` (`admission.py`, `internal/admission`).
  - It serves stateless and stateful operations under the self-issued lease.
  - `recovery` stays refused under `single-node`: there is nothing to survive. `survivor.py:225` already refuses, and the Go `state_epoch.go:324-345` check must refuse it too instead of passing vacuously.
- **Fence, take-over, rejoin:** not applicable.
  - `owner.py sign-survivor`, `fence`, `takeover.py` and `rejoin.py` refuse under `single-node`, naming the profile.

### 4.4 Heartbeats and revocations

- **Heartbeat:** `{1, [n]}`, self-signed by the node's TPM key on its NV sequence counter (`beat.py` collects threshold − 1 = 0 co-signatures).
  - It keeps one meaning: the node's own view of its manifest is fresh, which `heartbeat.authorize` and the watch read.
  - It loses its main one: bounding how long a **peer** keeps helping a revoked node. There is no peer.
  - The owner co-signed path (`owner.py beat`) is not needed and is refused under `single-node` (decision Q2).
- **Revocation:** the owner alone (`revocation_signers = [{1, [owner]}]`), through the existing `revoke.py export` / `import` and `deliver`.
  - Revoking or quarantining the only node is a **shutdown of the KMS**. The tool says so, and asks for a typed phrase.
  - A stolen node is defended by 4.5, not by a revocation reaching peers: there are none.

### 4.5 Boot unlock: the owner takes the peer's place (decision Q1)

- **What the peer protects today.** It gives its half of the LUKS credential only to a node that is still a member, on an image the current manifest still lists (#67, #135). This is the defence against a stolen server booting an old signed image.
- **Proposal:** the owner's laptop plays the peer in the **existing** protocol (`unlock.py`, `cmd/regalia-unlock`), unchanged on the wire.
  - **At enrolment,** the contribution for path `(n, owner)` is 32 random bytes encrypted to **both owner cards' DEC keys**, as `ownerauth` envelopes are today. It is never stored on the node.
  - **At boot,** the owner runs `owner.py unlock` (new) on the management network, over the boot mesh with the owner as its only WireGuard peer.
    - The tool asks for the node's quote.
    - It judges the quote with the same `replacement.may_unlock` / `attest.Verifier` logic a peer uses, under the owner's copy of the chain (4.7).
    - It decrypts the contribution with a card touch.
    - It answers under RSA-OAEP to the boot-session key, as a peer does.
  - **The response signature.** A peer signs its response with its TPM AK. The owner signs with an owner key instead, which the node checks against `owner_keys`, held in the boot configuration beside the peer pins.
- **What it keeps:**
  - the disk never opens on the TPM alone;
  - a stolen node does not boot unless the owner unlocks it;
  - an image the manifest no longer lists is refused.
- **What it costs:** every reboot is **attended**. A power cut means downtime until the owner acts.
  - The recovery key stays break-glass, as today.
  - `RegaliaNextBootNeedsRecoveryKey` is replaced by `RegaliaNextBootNeedsOwner`, an informational alert under `single-node`.
- **Rejected alternatives:**
  - **TPM-only unlock** (`systemd-cryptenroll --tpm2` with a signed PCR policy). It reopens #135: any signed image the policy ever accepted opens a stolen disk. It would be an explicit genesis opt-in only, and this design does not offer it (Q1).
  - **An external unlock witness**, a Tang-like service at another location running `may_unlock`. That is a second node in all but name, so it belongs to "3 nodes", not to "1 node".

### 4.6 Rolling measured-boot update and site advance

- **Update.** Each reboot is a **planned outage** under `single-node`.
  - `rollout.may_reboot` gets a single-node rule:
    - the node is ACTIVE;
    - two sets are accepted (both the current and the NEXT image, so the reboot can fall back);
    - the operator passes `--planned-outage`, which the trail records.
  - The judge of the new image is the owner's unlock tool, which refuses an unlisted PCR 11 exactly as a peer does.
  - **Retire evidence** (`retire_ready`, `stranded`: today "seen on the target set by at least one other node") is the owner tool's record of a **post-boot attestation**: a fresh quote the owner's tool takes from the running node in its booted (system) phase, over the target set's PCR values, after the node has come up and renewed its runtime lease under the new image.
    - The owner's **unlock** record is not enough: it shows only that the initrd phase passed, and a boot that fails after unlock would then retire the working fallback.
    - It never comes from the node's own state, which "says nothing about itself".
- **Site advance.** It changes PCR 12, and the owner's unlock tool judges it the same way.
- **Docs.** `KERNEL-UPDATE.md` gets a single-node runbook: a maintenance window, the owner present, the expected downtime.

### 4.7 Re-anchor and recovery (decision Q5)

- **The trust question.** With no peer, the only off-node copies of the chain are:
  - the owner's: the chain is root-signed and public, and the owner's tool keeps every manifest it has delivered;
  - the external audit collector's view of which epoch the node announced.
- **Proposal:** a new source type in `convergence.agreed`, `owner-chain`.
  - It is the whole chain, verified from the pinned root, with an owner signature over its tip digest and the node's boot session (the `sign-recovery` statement).
  - It is cross-checked against the collector's highest epoch for that node. A collector that has seen a higher epoch is a refusal, and so is a collector that does not answer: the cross-check is never skipped (the collector is mandatory, decision Q4). Recovery waits for the collector, or is a new genesis.
  - Under `single-node` this one source is enough, for both:
    - `recover` in the crash window (`convergence.py:182`'s "2");
    - `reanchor` (`reanchor.py:93`'s "2").
- **Recount** (a lost freshness state) takes its floor from the owner's statement and the collector, instead of "another node's freshness state".
- **What it loses:** rollback protection after anchor damage rests on the owner's copy and the collector, not on two independent TPM anchors.
  - A compromised owner laptop together with a damaged anchor can roll the node back to an older, still root-signed manifest, but no lower than the collector's highest recorded epoch, which recovery requires.
  - A compromised owner laptop together with a compromised collector is not bounded.
- **A dead TPM or a destroyed node** is a node replacement: root-signed, keeping the profile (4.1).
  - The HSM keys come back from the DKEK backup, as in any replacement.

### 4.8 etcd and operational state

- **Proposal:** keep etcd, as a **single-member cluster on a loopback peer URL**, so that `opstate`, Reserve, the watch cache and the state epoch keep one code path.
  - `etcdconf.check` accepts a loopback peer URL under `single-node` only. Today it requires the mesh prefix.
  - `timings()` uses etcd's defaults: there is no round trip to measure.
  - `MAX_LEARNERS` is irrelevant at N=1.
- **What it loses:**
  - **Replication.** Spend-once, Cosmos sequences and key state rest on one disk. A spend or sequence lost with that disk is a double-spend risk on restore.
  - **Mitigation:** an etcd restore under `single-node` must raise the state epoch above a floor that survives the loss of the node, so that a restored snapshot can never be mistaken for the live history. (Take-over, which raises it with three nodes, is refused here.)
    - The floor is the higher of the collector's highest recorded state epoch for the cluster and the owner tool's ledger of the restore epochs it has issued. The owner signs the restore statement that names the new epoch.
    - The owner's tool issues each restore epoch once, so restoring one snapshot twice gives two different epochs. Only one of the two nodes can be the cluster's live node (4.1).
  - The collector's spend audit (`spendaudit.py`) then detects a re-spent approval. It does not prevent one.

### 4.9 Network

- Under `single-node` the node has:
  - no boot mesh between nodes: the boot mesh's only peer is the owner's unlock endpoint (4.5);
  - no `wg-svc`;
  - no sync between peers.
- `sitecfg`, `firewall`, `wgsvc`, `bootnet` and `initrd/wg-boot` accept that shape **only** when the manifest's profile says so.
- `nft`'s empty `{ }` set (`firewall.py:64`) is avoided by not rendering the rule.
- **Built (dx7.6).** The owner's WireGuard public key is pinned in the manifest as `owner_wg_pub`. It is a v5 field of the single-node profile only, root-only like the other ROOT_FIELDS, and unique against every node key. `propose --genesis --topology single-node` takes it as `--owner-wg-pub`. The owner endpoint's underlay and tunnel address are in the site config as `boot_mesh.owner`, with `peers: []` and `service_mesh: null`. `bootnet` renders the initrd's boot mesh to the owner and the owner's side (`owner_wg_conf`), and each boot-mesh shape is accepted only under its own profile. The boot-credential renderers (`bootcreds.render` and the initrd's `bootcfg.Render`, dx7.35) make the single-node unlock configuration (`regalia.unlock-boot/v2`, dx7.5) with exactly the owner peer and the manifest's Ed25519 owner keys. Shared generated vectors hold all four credentials to byte-for-byte parity. A single-node manifest with no Ed25519 owner key is refused. A v5 multi-node manifest with only P-256 owner keys still renders `regalia.unlock-boot/v1` for eligible node peers. Separately, either profile paired with the other profile's site shape is refused.
- `regalia-sync` still serves the owner's `deliver` and exposes the chain for the collector.

### 4.10 Approvals

- **Unchanged.** m-of-n approvals are card holders, not nodes.
- An approval is still bound to its signer node (`regalia-approval-v3`), here always the one node.
- There is no failover, so there is no re-approval for another node.

### 4.11 Audit and monitoring

- **The external audit collector becomes mandatory** (decision Q4).
  - Under `single-node` it is the only witness besides the owner: the cross-node checks are gone.
  - Admission refuses stateful operations while the shipper has no collector configured. It does not refuse merely because the collector is down, which only alerts.
- **Monitoring**, gated on a new metric, `regalia_topology_nodes`, from the manifest:
  - `RegaliaMembershipBehindFleet` and `RegaliaAnchorBehindFleet` are replaced by "behind the collector" rules.
  - `RegaliaSurvivorRecoveryActive` never fires, because `regalia_admission_recovery` stays 0.
  - The recovery-key alert becomes the owner-unlock alert (4.5).
  - A new `RegaliaSingleNodeDown` pages at once: any downtime is an outage.
  - Heartbeat-life warnings follow the self-signed renewal, not the owner's 1 h path.

### 4.12 The owner's role with one node

| Act | 3 nodes | 1 node |
|---|---|---|
| Boot unlock | Never, unless every peer is gone | **Every boot** (card touch, `owner.py unlock`) |
| Heartbeat | Hand recovery only (`owner.py beat`) | Never: the node self-signs |
| Revocation | Alone (1-of-owner), or two nodes | Alone, the only path. It stops the KMS |
| Re-anchor / crash-window recovery | The second source when one peer is left | **The** source (with the collector's cross-check) |
| Rolling update / site advance | Not involved | Present at each reboot, as the image's judge |
| Lone survivor, fence, directives | Yes | Not applicable (refused) |
| Activation | Recovery path only, never alone | Never (the node self-activates) |
| Approvals (m-of-n), root, K_A, card record | As configured | Unchanged |

## 5. 1 node vs 3 nodes: what each supports

This table was the source for the user-facing table in README and LIMITATIONS (slice dx7.11). Since dx7.11 the canonical text is [`docs/single-node-limits.md`](../single-node-limits.md), and `tests/test_single_node_limits.py` holds the README and LIMITATIONS copies equal to it. Words used:
- **supported**: the guarantee holds as on three nodes;
- **degraded**: it works, with the consequence named;
- **not supported**: the guarantee does not exist on one node.

| Feature or guarantee | 1 node | 3 nodes | Why / consequence |
|---|---|---|---|
| Signing and decryption (stateless) | supported | supported | One HSM per node holds the keys either way |
| Stateful operations (approval spend-once, Cosmos sequence, key state) | degraded | supported | Committed to a single-member etcd on one disk: no replica, so a lost disk loses the latest spends. Restore raises the state epoch, and the collector detects a re-spend; it does not prevent one |
| Activation (who may serve) | degraded | supported | The node activates itself (1 of 1): no second signer refuses a root-compromised node |
| Runtime lease (a revoked or cut-off node stops within 30 s) | degraded | supported | Self-issued: it still binds the measured boot and current state, but nobody outside the node can withhold it |
| Survives the loss of a node | not supported | supported | Any node failure, reboot or maintenance is a full outage |
| Survives a site, provider or network-path outage (A4) | not supported | supported | One site is a single failure domain |
| Unattended reboot | not supported | supported | Every boot needs the owner's card (4.5), or the recovery key |
| Theft of a powered-off node | supported | supported | The disk opens only with the owner's contribution (3 nodes: a peer's), so a stolen box does not unlock |
| Theft of a running node (hot theft) | degraded | supported | No peer stops leasing it. It serves until power is lost or the owner's revocation is imported on that very node, so revocation does not reach a node that is no longer reachable |
| Root compromise of the node | not supported | degraded | 3 nodes: no lease without two co-signers. 1 node: the node is the only signer |
| Retiring an old signed boot image | supported | supported | The owner's unlock tool refuses an image the manifest no longer lists (3 nodes: the peers) |
| Revocation | degraded | supported | Owner alone. Revoking the only node stops the KMS |
| Heartbeats | degraded | supported | Self-signed: they prove only the node's own freshness, with no peer bound to stop helping |
| Rolling measured-boot update | degraded | supported | A planned outage per reboot, with the owner present to judge the new image |
| Site advance (PCR 12) | degraded | supported | The same: a planned outage, the owner judges |
| Rollback protection of the membership (TPM anchor) | supported | supported | The TPM counter and record work alone |
| Re-anchor after anchor damage | degraded | supported | From the owner's chain plus the collector instead of two independent nodes. A compromised owner laptop can roll back within what the collector saw |
| Recovery after a total outage | degraded | supported | One owner-attended boot. There is no "rest of the cluster" to restore |
| Lone-survivor mode, fencing, take-over, rejoin | not supported | supported | Nothing to survive or fence: refused by name |
| Cross-node detection (BehindFleet alerts, a withheld chain) | not supported | supported | No fleet to compare. Replaced by comparison with the audit collector |
| Audit trail | supported | supported | The external collector is mandatory with one node: it is the only witness besides the owner |
| Operation approvals (m-of-n card holders) | supported | supported | Not node-bound. An approval names the one node, with no failover |
| Key backup and restore (DKEK, Shamir) | supported | supported | Unchanged |
| Latency of stateful operations | supported | supported | No majority round trip: faster than 3 nodes |
| Cost | — | — | One server and one HSM instead of three of each |

## 6. How the operator is told

1. **At genesis** (slice dx7.2):
   - `--topology single-node` prints the "1 node" column of section 5 **verbatim from** `docs/single-node-limits.md`, the canonical text written by slice dx7.11.
   - It then reads, from the terminal itself (never an argument, as reanchor does), the phrase `single node: I accept the limits <first 8 hex of the text's SHA-256>`.
   - The full SHA-256 goes into `topology.single_node_limits_sha256`.
   - `manifest sign --genesis` on the ceremony laptop shows the profile and the digest beside the root fingerprint, and refuses a digest that is not the one the tool ships.
   - The root signature covers the acknowledgement.
   - A manifest with one node and `multi-node`, or `single-node` without the digest, is invalid (4.1).
2. **On the node:**
   - `regalia_topology_nodes` and `profile` are exported (metrics, `/readyz` detail).
   - The daemon logs the profile once at start.
   - Every refusal of a three-node-only operation (survivor, fence, peer unlock, owner beat) names the profile.
3. **In the docs** (slice dx7.11):
   - README gets "1 node or 3 nodes?" with the table.
   - LIMITATIONS gets a "Single-node deployments" section, with each "not supported" and "degraded" row as an **accepted** entry citing dx7.
   - THREE-SITE-THREAT-MODEL gets a "single-node profile" stating which of A1-A4 and S1-S4 hold.

## 7. Owner decisions (2026-11-18)

The owner delegated these on 2026-11-18 ("you assess and you do your recommendations; most KMS are single node, so you can inspire yourself from them"). Each was decided as recommended; the rationale cites the single-node KMS practice it follows where there is one.

| # | Question | Decision (2026-11-18) | Rationale |
|---|---|---|---|
| **Q1** | With one node, who gives the second half of the disk key at boot? (a) the owner's card, every boot; (b) TPM-only, as a genesis opt-in; (c) an external unlock witness | **(a) The owner's card at every boot; reboots are attended.** (b) is not offered; (c) is not built | Keeps theft resistance and image retirement (#67, #135), as Vault/OpenBao require a Shamir unseal and a network HSM requires activation after every restart; (b) would let any old signed image open a stolen disk, and (c) is a second node in all but name |
| **Q2** | Heartbeats with one node: self-signed, or node plus owner? | **Self-signed** (threshold 1 of the node) | The heartbeat bounds peers and there are none; an owner touch every hour is unworkable and adds nothing |
| **Q3** | May a deployment change size in place (1→3, 3→1)? | **Not in this epic: a new genesis.** 1→3 in place comes later as its own root-signed slice; 3→1 in place never | 1→3 can raise the floors and enrol two nodes in one root-signed step later (as Vault's raft grows in place); 3→1 would silently drop guarantees the operator acknowledged |
| **Q4** | Make the external audit collector mandatory for one node? | **Yes: stateful operations are refused without a configured collector** | It is the only witness besides the owner, and re-anchor (4.7) and spend detection (4.8) lean on it; Vault likewise refuses requests when no audit device can log |
| **Q5** | After anchor damage on one node: re-anchor from the owner's chain plus the collector, or always a new genesis? | **The owner's chain plus the collector's cross-check** | A new genesis for every damaged NV index would re-enrol the node and rotate K_A for a fault, not an attack |
| **Q6** | Keep the two owner cards (D30.7) with one node? | **Yes, unchanged** | They hold the owner's unlock contribution (4.5); one lost card must not strand the node |
| **Q7** | Is the hot-theft row ("degraded": a running stolen node serves until it loses power) acceptable? | **Accepted and documented** | A server is normally powered off to be moved, and then 4.5 holds; an owner-issued lease every few minutes is not workable |

**Added from single-node KMS practice:** with no peer to restore from, the recovery path *is* the backup. A timed **restore-to-replacement drill** (the DKEK backup plus the owner cards onto a fresh node) is part of the 1-node production gate, and its measured time is the 1-node recovery time objective (slice dx7.13).

## 8. Slices (beads under regalia-kms-dx7)

Each slice is a bead with its own acceptance criteria: slice dx7.N is bead `regalia-kms-dx7.N`. Dependencies use `bd dep add <blocked> <blocker>`.

| Slice | What | Depends on |
|---|---|---|
| dx7.1 | Membership v5: the `topology` field, floors as majority-of-designed-nodes, the single-node validation; Python and Go in lock-step, with a v5 vector | — |
| dx7.11 | User docs: `docs/single-node-limits.md` (the canonical text genesis hashes), README "1 node or 3 nodes?", LIMITATIONS "Single-node deployments", threat-model profile | — (decisions in section 7) |
| dx7.2 | Genesis: `--topology` (required), thresholds from topology, the typed acknowledgement and its digest, `sign --genesis` display | dx7.1, dx7.11 |
| dx7.3 | Serving: self-issued runtime lease, 1-of-1 activation, admission mode `single` (Python and Go), survivor, fence, take-over and rejoin refusing by profile | dx7.1 |
| dx7.4 | Heartbeats and revocation: `beat.py`, `activation.py` and `revoke.py` collect threshold − 1 co-signatures (0 here), owner-only revocation with the shutdown phrase | dx7.1 |
| dx7.5 | Boot unlock with the owner as the peer: owner-encrypted contribution at enrolment, `owner.py unlock`, owner-signed responses in `regalia-unlock` and `bootcfg` | dx7.1 |
| dx7.6 | Network and etcd: `sitecfg`, `firewall`, `wgsvc`, `bootnet` and `wg-boot` for the single-node shape; single-member etcd on loopback; restore raises the state epoch | dx7.1 |
| dx7.7 | Re-anchor and recovery from the owner's chain plus the collector; `recount` floor | dx7.1, dx7.5 |
| dx7.8 | Rolling update and site advance: `--planned-outage`, retire evidence from the owner tool, KERNEL-UPDATE single-node runbook | dx7.5 |
| dx7.9 | Monitoring and audit: `regalia_topology_nodes`, the collector-relative behind alerts, `RegaliaSingleNodeDown`, the owner-unlock alert, collector mandatory | dx7.3 |
| dx7.10 | **One-node e2e in CI**: the fixture parameterized by topology, `e2e/one-node.py` (genesis with acknowledgement, owner unlock, self-lease serving, owner revocation stopping it, planned-outage update, owner-chain re-anchor), and a `one-node` job in `node-units.yml` with its paths | dx7.2, dx7.3, dx7.4, dx7.5, dx7.6 (dx7.7 and dx7.8 extend it) |
| dx7.13 | **Hardware acceptance on one DL360**: boot, owner-card unlock, a timed restore-to-replacement from the DKEK backup plus the owner cards (its time is the 1-node RTO), and a 72 h burn-in. Owner-run | dx7.5, dx7.10 |

**Gate:** bead `regalia-kms-2jd` ("Regalia KMS single-node (1 node) production ready") depends on dx7.1–dx7.11, dx7.13 and the appliance, PCR-policy, token, SSD and ceremony prerequisites; it closes only with the owner's sign-off on the ceremony and acceptance.

**Left for the odd-N epic** (recorded on the deferred bead regalia-kms-dx7.12, P4, not built), so that 5 and 7 are not blocked silently:
- `activation.propose` and `beat.Proposer` stop after one co-signer (fixed by dx7.4's threshold − 1).
- `etcdconf.MAX_LEARNERS = 2` and `rejoin.py`'s "two returners".
- `rollout.may_reboot` requires every authorizer rather than a quorum.
- admission's serial peer renewal: (N−1)·2·3 s is 36 s at N=7, longer than the 30 s lease.
- `sitecfg`'s 8-peer cap (N ≤ 9).
- Every "two of the three" sentence in the docs.

## 9. What this slice does not decide

- Changing size in place (Q3: a new genesis in this epic; 1→3 in place is a later slice).
- Even sizes (refused for ever: a 2-node cluster has neither one node's simplicity nor a majority that survives a loss).
- 5 and 7 nodes.
