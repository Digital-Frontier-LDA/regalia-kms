# Single-node design: inventory of three-node assumptions (regalia-kms-dx7)

Companion to [single-node.md](single-node.md). Every place where the code, units, schemas, docs, e2e or CI assume exactly three nodes, as found on `main` at ccb32377 (2026-11-17).

The inventory was swept by area with `rg` and then read file by file. Each line number was checked against the file. Line numbers move with later commits, so treat each entry as a pointer to re-check before editing.

**Category:**
- **a**: a constant or literal to parameterize.
- **b**: a security property that changes with one node.
- **c**: test-only.

**a+b** marks a literal that also carries a security property. Where one line serves several areas, it is listed once, under the area it matters most to.

Totals: 499 entries. a: 145, b: 214, a+b: 2, c: 138.

Not counted (false positives checked and left out):
- the two owner cards and two release cards;
- Shamir 2-of-3 shares and the HSM's PKA 2-of-3;
- the three NTS servers;
- PIV slot numbers;
- retry counts of 3;
- the swtpm session-slot limit of 3;
- the LUKS keyslot numbers;
- the A/B measurement sets (`len(sets) == 2`);
- "three token configurations".

## Membership (29)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `.github/workflows/node-units.yml:165` | c | job three-node-netns (ubuntu-26.04, 20 min) |
| `.github/workflows/node-units.yml:192` | c | grep '^three-node-netns: 44 passed, 0 failed$': exact check counts pinned per job; an N=1 variant needs its own count |
| `.github/workflows/node-units.yml:394` | c | job three-node-replace; count 23 at :422 |
| `deploy/baremetal/membership.py:40` | a | "Schema v4 (#199: the three nodes and the owner sign…)" → "the N nodes and the owner sign". |
| `deploy/baremetal/membership.py:105` | b | capability matrix "ACTIVE serves, requests bootstrap and authorizes peers". "authorize" means nothing when N=1 (nobody to authorize, nobody authorizing you). |
| `deploy/baremetal/membership.py:196` | c | TODO "once the three-node fixture reaches its TPMs…": test fixture is 3 nodes. Needs a 1-node (and 5-node) fixture. |
| `deploy/baremetal/node.py:737` | a | "this is not a node of a three-site cluster": the refusal text bakes in 3 sites (the check itself is boot_mesh/service_mesh presence). |
| `deploy/baremetal/node.py:822` | b | peers(): every other non-terminal node (lines 822-825). Empty at N=1, which feeds :967. |
| `e2e/lib/threenode.py:479` | c | Cluster(work, names=NAMES): already takes a names list; the cheap hook for N=1 (Cluster(work, names=("a",))) |
| `e2e/lib/threenode.py:503` | c | NodeHere(i+1) per name: generic for any N |
| `e2e/lib/threenode.py:1433` | c | add_node: index max+1, generic |
| `e2e/lib/threenode.py:1484` | b | replace() needs a running seed other than old and new (raises at 1485-1486); N=1 replacement is impossible this way, so a deliver-to-new-node path is needed |
| `e2e/node-replacement-swtpm.sh:2` | c | three TPMs: old a, replacement a2, peer b (only one peer, so not strictly 3-node; at N=1 there is no peer b) |
| `e2e/regalia-sync-netns.py:46` | c | NODES = ("a","b","c") |
| `e2e/rolling-threenode.py:208` | c | a, b, c = names: exactly 3 |
| `e2e/three-node-leases.py:89` | c | names = ["a","b","c"] literal |
| `e2e/three-node-netns.py:209` | c | Cluster(work, audit=True) takes the default three names |
| `e2e/three-node-outage.py:234` | c | Cluster default three names |
| `e2e/three-node-reanchor.py:134` | c | a, b, c = names: unpacking requires exactly 3 |
| `e2e/three-node-replace.py:78` | c | names = ["a","b","c"] |
| `e2e/three-node-replace.py:110` | b | replace("c","c2"): a and b carry the new epoch and lease c2; no N=1 equivalent (see threenode.py:1484) |
| `e2e/three-node-site-advance.py:150` | c | a, b, c = names: exactly 3 |
| `e2e/three-node-theft.py:80` | c | names = ["a","b","c"] |
| `e2e/three-node-wan.py:111` | c | names = ["a","b","c"] |
| `LIMITATIONS.md:64` | b | KEY: "no authorization when every other node is RETIRED or REVOKED_STOLEN … that is a one-node membership, commissioned by a new manifest, not an outage. … Whether such a node may instead serve alone under an empty fence is not decided, so it stays …" (elided). Under `single-node` the one node is the membership, not a survivor under an empty fence (design 4.3). |
| `tests/test_threenode_abrmd.py:100` | c | builds a 2-node Cluster ("ab") by object.__new__: already proves names is free; add a 1-node case |
| `tests/vectors/make-highwater-v1.py:66` | c | nodes for i in (1, 2, 3): a 3-node v4 chain. |
| `tests/vectors/make-membership-v4.py:64` | c | records whatever tests/test_baremetal_membership_v4.py does. The resulting membership-v4.json has 162 manifests with 3 nodes and 2 with 4; activation 2-of-3 ×152, heartbeat 2-of-4 ×146. No 1-node or 5-node manifest is accepted; the 1-party rules present are the owner-alone revocation rule only. dx7.1 adds a v5 vector with one-node manifests. |
| `THREE-SITE-THREAT-MODEL.md:38` | b | S2 says eligibility "to authorize (give a contribution): ACTIVE only". With no other node, nobody can authorize. |

## Quorum and signer-rule floors (24)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `.github/workflows/node-units.yml:473` | c | job three-node-leases; count 20 at :501 |
| `cmd/regalia-unlock/membership/v4.go:25` | a | heartbeatFloor = 2 (and :26 nodeRuleFloor = 2): Go mirror of membership.py:140. Must change in lock-step. |
| `cmd/regalia-unlock/membership/v4.go:145` | a | least = heartbeatFloor/nodeRuleFloor, 1 only for [owner]; :152 threshold > len(parties) refused (the same N=1 genesis failure as membership.py:518). |
| `deploy/baremetal/membership.py:68` | a | doc "heartbeat and activation thresholds are at least 2, a revocation rule that names a node needs at least 2" → make the floor a function of the number of node parties (1 when N=1, otherwise floor(N/2)+1, or a policy constant). |
| `deploy/baremetal/membership.py:140` | a+b | HEARTBEAT_FLOOR = NODE_RULE_FLOOR = 2 ("no single party keeps a cluster alive or revokes alone"). This is the core literal. N=1: floor 1 for node-only rules, or keep 2 and require the owner as the second party. Odd N: majority floor. |
| `deploy/baremetal/membership.py:517` | a | least = 1 only for [owner]; otherwise NODE_RULE_FLOOR / HEARTBEAT_FLOOR (2). Together with :518 this refuses every node-only rule over one node ({1, [n1]} is below the floor, {2, [n1]} has more threshold than parties). An owner-plus-node rule {2, [n1, owner]} passes, which is why N=1 would otherwise need the owner's touch for every heartbeat. |
| `deploy/baremetal/membership.py:518` | b | require(least <= t <= len(parties)): with 1 node, {"threshold":2,"parties":[n1]} is invalid, so the genesis revocation rule is unbuildable. |
| `e2e/three-node-leases.py:15` | c | "a's next renewal comes from the other peer": failover needs >=2 peers |
| `e2e/three-node-leases.py:118` | c | other = next(n for n in ("b","c") if n != issuer): fixed peer set |
| `e2e/three-node-wan.py:152` | c | the "other" peer takes over after the issuer is cut off; needs >=3 |
| `e2e/three-node-wan.py:173` | c | "the two connected nodes serve throughout" |
| `FENCING.md:13` | a | "Two of the three servers co-sign it… the server's own signature must be one of them" → majority of N, with self counted. At N=1: self only. |
| `FENCING.md:21` | b | "A server cut off from the majority can't renew": the partition safety argument; N=1 has no partition. |
| `FENCING.md:27` | b | "A stateful operation is committed by a majority before the HSM is used" (etcd majority). N=1 etcd majority = itself; spend-once then rests on one disk. |
| `FENCING.md:66` | b | "Stateful keys wait for a majority." |
| `FENCING.md:104` | a | "Only stateful operations pay a majority round trip": latency claim; 0 at N=1. |
| `LIMITATIONS.md:431` | a | "EtcdState (one Reserve, one majority transaction before the HSM)". The majority is of the etcd member count. |
| `README.md:43` | a | "every server serves while it holds its own lease, which 2 of the 3 servers co-sign. Stateful operations commit on a majority". This should say "a majority of N". |
| `tests/test_baremetal_membership_v4.py:66` | c | nodes4()` builds ("a","b","c"); it is reused by `test_baremetal_heartbeat_v4.py:33` and `test_baremetal_revoke.py:35`. |
| `tests/test_baremetal_membership_v4.py:75-77` | c | heartbeat {2, [a,b,c,owner]}, activation {2, [a,b,c]}, revocation [{2,[a,b,c]},{1,[owner]}]. |
| `tests/test_baremetal_membership_v4.py:133-140` | c | tests pinning the floor ("threshold of 1" refused). These would flip for N=1. |
| `tests/vectors/make-highwater-v1.py:72` | c | heartbeat {2, [n1,n2,n3,owner]}, activation {2, [n1,n2,n3]} (:73), revocation [{2,[n1,n2,n3]},{1,[owner]}] (:74). Needs 1-node and 5-node chains. |
| `THREE-SITE-THREAT-MODEL.md:19` | b | "every server serves under its own majority-co-signed lease, and stateful operations commit on a majority". The majority is of N. At N=1 the majority is the node itself, so nothing is co-signed. |
| `THREE-SITE-THREAT-MODEL.md:27` | b | "A partition minority cannot activate itself. Two compromised servers could". There is no partition at N=1. The bound should be "a majority of compromised servers"; at N=1 that is one. |

## Genesis and ceremony (21)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `deploy/baremetal/enrol.py:842` | a | "The first three hosts enrol on epoch 1; a host added later (a fourth node…)" → "the genesis hosts (N)". |
| `deploy/baremetal/manifest.py:15` | a | Usage line `propose --genesis … --node …` (repeated per node). No 3 here; informational. |
| `deploy/baremetal/manifest.py:161` | a | Comment: "the owner is ONE party, so '2 of {a, b, c, owner}' already means at least one node signs every heartbeat and activation lease". This explains the fixed 2. For N it should be a majority of nodes; at N=1 the literal 2 would mean node+owner always, which decision Q2 rejects: the node self-signs, {1, [n]}. |
| `deploy/baremetal/manifest.py:298` | a | len(owners) == 2` means exactly two owner cards. This is not a node count. It is listed because a smaller 1-node shop might want one owner card. Keep it unless decided otherwise. |
| `deploy/baremetal/manifest.py:304` | a | genesis takes any number of node entries (only requires ≥1) and does no count check. Fine for N, but the thresholds above don't follow the count. |
| `deploy/baremetal/manifest.py:333` | a | "heartbeat_signers": {"threshold": 2, "parties": ids + [owner]}. Hard-coded 2. N=1: 1, the node alone (decision Q2; node+owner on every beat is rejected). N=5: 3. |
| `deploy/baremetal/manifest.py:334` | a+b | "activation_signers": {"threshold": 2, …}. With N=1, activation.verify's node-only path can never reach 2. Needs N-derived thresholds (majority of nodes). |
| `deploy/baremetal/manifest.py:335` | a | "revocation_signers": [{"threshold": 2, "parties": ids}, {"threshold": 1, "parties": [owner]}]. With ids=[n1] this fails membership.py:518, so genesis is refused. N=1: drop the node rule or make it threshold 1. Odd N: majority. |
| `deploy/baremetal/README.md:430` | a | "Attestation key (three-site, #65)". A label. |
| `LIMITATIONS.md:15` | a | "EK certificates: measured on one of the three … unknown on the other two". This is per-host status and should be a per-host list. |
| `LIMITATIONS.md:25` | a | ekroots/servers/server-1.json`, "The other two are open (server-2.json, server-3.json)". The per-server file set is fixed at 3 and should be generated per node. |
| `PIN-CUSTODY.md:16` | b | "ratification of 2-of-3 public-key authentication (B8) was reversed … the quorum stays on restore and the ceremony". This is an HSM PKA quorum, not a node count, but "2-of-3" must not be read as a node count. Informational. |
| `PIN-CUSTODY.md:252` | a | "A 2-of-3 scheme is a later experiment". This is a recovery-key secret-sharing scheme, not a node count. Informational. |
| `tests/test_baremetal_manifest.py:914` | c | The ProposeGenesis fixture uses `nodes4()`, so it has 3 nodes. |
| `tests/test_baremetal_manifest.py:994` | c | ["ACTIVE"] * 3`. |
| `tests/test_baremetal_manifest.py:997` | c | Asserts heartbeat_signers == {2, [a, b, c, owner]}, and at line 998 revocation_signers == [{2, [a, b, c]}, {1, [owner]}]. There is no N=1 genesis test. |
| `tests/vectors/ownerauth-v1-gen.py:4` | c | The vector is "ownerauth(nodes a, b, c)". The ownerauth record itself is a per-node map with no count check (ownerauth.py:181), so it is fine for N=1. |
| `tools/custody_manifest.py:362` | b | "production object requires at least 2 hardware bindings". These are two devices, not two sites. A 1-node host needs 2 tokens attached (or a declared exception). |
| `tools/custody_manifest.py:375` | b | "FIDO enrollments must be held in separate custody: at least two distinct sites". "Site" here is a custody location, not a KMS node. A 1-site deployment needs a second custody location declared. |
| `tools/custody_manifest.py:389` | a | minimum_replicas != 2` → "must equal 2". Shamir replica count, not node count. Informational. |
| `tools/custody_manifest.py:400` | b | "YubiKey multi-enrollment needs at least two tokens held at two distinct sites". The same custody-site rule. |

## Activation and runtime leases (31)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `deploy/baremetal/activation.py:7` | b | "WHY IT IS NOT ANY 2 OF {a, b, c, owner}": the mutual-exclusion argument assumes two node quorums always intersect. N=1: one node is its own quorum, so there is no intersection argument at all. Exclusion then rests on the single node's GrantRecord and its TPM-held signing key (design 4.3). |
| `deploy/baremetal/activation.py:10` | a | "NORMAL: activation_signers' threshold of NODE parties (2 of the 3)" → "floor(N/2)+1 of N". |
| `deploy/baremetal/activation.py:12` | b | RECOVERY path: "the owner with fewer nodes… the other node parties QUARANTINED or REVOKED". N=1: "other" is empty, so owner+self would satisfy recovery trivially. |
| `deploy/baremetal/activation.py:108` | b | node-only path requires len(node_parties) >= threshold. With N=1 and threshold 2, normal activation is impossible; with threshold 1, one node self-activates (no co-signer). |
| `deploy/baremetal/activation.py:113` | b | "the owner alone never activates a site": still holds for N=1, but owner+the only node on the recovery path becomes the ONLY way to activate if the threshold stays 2. |
| `deploy/baremetal/activation.py:115` | b | others` (lines 115-118): every other node party must be NOT_COUNTING. Empty when N=1, so the check passes vacuously. |
| `deploy/baremetal/activation.py:240` | a | "the proposer is the node to be activated; one other node co-signs": fixed at exactly 1 co-signer. |
| `deploy/baremetal/activation.py:254` | b | synced(): "pulled from every node its current manifest lets authorize". Vacuously true at N=1 (the "two fenced nodes powered back on inside a partition" protection disappears). |
| `deploy/baremetal/activation.py:260` | b | cosign: require(caller in counting and caller != me). A node can never co-sign itself, so N=1 has no co-signer. |
| `deploy/baremetal/activation.py:301` | a | propose(): loops over peers and returns on the FIRST co-signature (lines 301-319). |
| `deploy/baremetal/activation.py:316` | a | done = {"lease": lease, "signatures": [own, theirs]}: exactly 2 signatures, so this only works when threshold == 2. N=1 needs [own] only. N=5 (threshold 3) needs to collect threshold-1 co-signers before :317 verify() would pass. |
| `deploy/baremetal/activation.py:325` | b | "no node co-signed this activation": the terminal refusal is guaranteed when N=1. |
| `deploy/baremetal/admission.py:374-376` | b | recovery writes `requested = 0`, "no peer vouched". With N=1 nothing ever vouches. |
| `e2e/lib/threenode.py:1018` | b | activation_signers {threshold 2, parties nodes}: cannot be met with one node; needs threshold 1 (and a decision whether one node may activate alone) or floor(N/2)+1 |
| `internal/admission/admission.go:449-454` | b | ModeRecovery`: "this daemon has no stateless-only gate yet: it serves nothing". An N=1 node can only serve under a peer lease (impossible) or recovery (refused), so today it serves nothing. |
| `internal/opstate/state_epoch.go:324-345` | b | a lone survivor "needs every other node quarantined, revoked or retired". At N=1 `loose` and `must` are empty, so the survivor check passes vacuously. What the fence evidence (347-350) means with no other nodes is undefined. |
| `LIMITATIONS.md:222` | b | Admission v3 mode: lease (a peer's lease) or recovery (the owner's survivor authorization). At N=1 there is no peer lease, so the node is permanently in recovery, which "the daemon serves nothing in" (line 230). A third mode is needed: a sole-node lease. |
| `LIMITATIONS.md:232` | a | "D28.6 as first written (2 of {a, b, c, owner})". Threshold and party list. |
| `LIMITATIONS.md:240` | b | The runtime lease is "issued by one peer over the subject's re-attested TPM … A node cut off from both peers stops within 30 s … renew through the third node". The lease issuer is always another node. At N=1 no lease can be issued, so the node never serves; dx7.3 adds the self-issued lease under `single-node` (design 4.3). |
| `LIMITATIONS.md:251` | b | "The normal path is 2 of the 3 nodes, which always overlap. ({a, b} and {c, owner} share no signer.)" The overlap proof is for N=3 with threshold 2. For odd N the threshold must be floor(N/2)+1 over the nodes, and the owner path must not form a disjoint quorum with a node majority: it stays the recovery step behind its conditions (LIMITATIONS.md:252). |
| `LIMITATIONS.md:252` | b | "Activation by the owner plus one node is a recovery step behind three conditions" (quarantine epoch, fencing attestation, wait). At N=1, under today's threshold of 2, owner+node would be the only path, with conditions 1–2 vacuous. The design instead has the node activate itself, {1, [n]} (design 4.3), and the owner never activates. |
| `LIMITATIONS.md:257` | b | "The owner alone never activates." This should stay true at N=1, so the node must always sign. |
| `LIMITATIONS.md:260` | b | "with one node dead … an unplanned reboot of a second node stops lease renewals". This is N=3 arithmetic. |
| `LIMITATIONS.md:465` | b | "production must set the three settings. Without them … its node requests no lease". This is three config settings, not three nodes. Listed only because the lease is peer-issued. |
| `LIMITATIONS.md:468` | b | "Every issuer's revision floor refuses too". The issuers are peers. |
| `LIMITATIONS.md:641` | c | "three-node-outage's step 5 … a's Proposer". The fixture names node a. |
| `tests/test_baremetal_admission.py:104, 112` | c | issuer "c". |
| `THREE-SITE-THREAT-MODEL.md:24` | a | "needs two signatures from {node a, node b, node c, the owner}, two of the three servers being the normal path". This should become a node-only quorum of floor(N/2)+1 of the nodes, so that any two node quorums intersect. The owner-assisted path stays the separate recovery step behind its conditions (LIMITATIONS.md:252), never a threshold over the nodes plus the owner, which would admit disjoint quorums such as {a, b} and {c, owner}. At N=1 the node quorum is the node itself (decisions Q2 and Q1: self-signed heartbeats and activation; the owner's card at boot). |
| `THREE-SITE-THREAT-MODEL.md:46` | a | S4: "co-signed by two of the three servers". This should be "a majority of N". At N=1 the node signs its own lease. |
| `THREE-SITE-THREAT-MODEL.md:57` | b | Root-compromise row: "no runtime lease without two co-signers". At N=1 a root-compromised node needs no co-signer. |
| `THREE-SITE-THREAT-MODEL.md:120` | a | "co-signed by 2 of the 3 servers and non-exclusive". This should be "a majority of N". |

## Fence and lone survivor (14)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `deploy/baremetal/fence.py:7` | b | "a node holding its peers' power would let one stolen node turn the other two off" → "the other N-1". At N=1 fencing (G1) has nothing to fence. |
| `deploy/baremetal/fence.py:15` | c | example `--node b --node c` with credentials {"b","c"} (lines 15-18): a 3-node fixture (a survivor plus 2 fenced). |
| `deploy/baremetal/fence.py:46` | b | "the nodes to fence are every other node but the RETIRED and REVOKED_STOLEN ones (survivor.fenceable)". Empty set at N=1, so the survivor authorization's fence evidence becomes {} (must be explicitly allowed or the flow skipped). |
| `deploy/baremetal/owner.py:282` | b | sign-survivor: "the owner's ONE authorization for a lone survivor", with `--how` "how the other servers are fenced" (line 286). It is refused when no other counting node exists (LIMITATIONS:64). |
| `deploy/baremetal/owner.py:426` | a | "give it to the survivor, and to the majority when it returns": majority language. |
| `deploy/baremetal/survivor.py:15` | a | "it rules out the other two forming a majority". This should read "the other N-1". |
| `deploy/baremetal/survivor.py:61` | a | The full-scope wait rationale "the far side is 2 of 3" (lines 61-62). For odd N the far side is a majority of N-1. |
| `FENCING.md:61` | b | "A lone survivor serves only under the owner's recovery authorization", stateless only (lines 61-66). At N=1 the normal state looks like a "lone survivor"; must be distinguished. |
| `LIMITATIONS.md:55` | b | The survivor authorization needs "every other server stopped and the owner's typed fencing attestation". Not applicable at N=1. |
| `LIMITATIONS.md:68` | b | "the owner's one-server decision (2026-10-05): scope full … from the owner's attestation plus 900 s plus 60 s". The wait exists to let the fenced far side's spends expire. At N=1 there is no far side. |
| `LIMITATIONS.md:100` | a | "whether a management VPN reaches all three sites' iLOs". This should be "all N". |
| `LIMITATIONS.md:103` | b | A fenced server turned back on "holds an older epoch and its peers halt it (G4)". The defence is peers; none exist at N=1. |
| `LIMITATIONS.md:258` | b | "Two active sites remain possible only if a fencing attestation is false". n/a at N=1. |
| `THREE-SITE-THREAT-MODEL.md:29` | a | "the surviving site stops serving" names the two-site legacy fence. It should be phrased for N. |

## Approvals (6)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `e2e/three-node-recovery.py:159` | c | sorted(got["leases"]) == ["b","c"]: a's leases come from exactly b and c |
| `internal/approval/approval.go:76-82` | b | `Binding.Signer` is "the ONE node that may spend this approval … Empty only where no node ID is configured (a single-node deployment)". This hook already exists; with N=1 approvals are not node-bound when NodeID is unset (`coordinator.go:309-316` fills it from the node's configuration). With one node the binding names that node; nothing changes. |
| `internal/operations/approvals_test.go:207-245` | c | approvals for site-b refused on site-a. Assumes at least 2 nodes, but is harmless at N=1. |
| `internal/operations/coordinator.go:190-192` | a | "re-enabling it is the majority's act". Assumes a majority of other nodes exists after a lone-survivor period. |
| `LIMITATIONS.md:196` | b | "An approval is for one node … a client's failover to another node needs fresh approvals". Node-pinning is harmless at N=1, but there is no failover. |
| `LIMITATIONS.md:206` | b | "A lone survivor's full scope waits that long, plus 60 s". Survivor-only; n/a at N=1. |

## Heartbeats (41)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `deploy/baremetal/admission.py:106-109` | a | RENEW_TIMEOUT = 3`; "a round with both peers silent ends within 2 * 2 * RENEW_TIMEOUT" (12 s). The round time is really (N-1)·2·3 s. **At N=7 that is 36 s, more than the 30 s lease**, so the timeout or the parallelism must scale with N. |
| `deploy/baremetal/beat.py:3` | a | "a heartbeat counts when two of {a, b, c, owner} signed it": a fixed party list and threshold in the docs. |
| `deploy/baremetal/beat.py:15` | b | the proposer "asks the other counting nodes in order … until one co-signs". It assumes exactly one co-signer is enough (t=2). It should collect t-1 co-signers; for N=1 (t=1) it needs none. |
| `deploy/baremetal/beat.py:34-35` | b | the safety argument "two different heartbeats with one sequence would need four distinct signers" only holds for t=2 over {a,b,c,owner}. In general it needs 2t > the number of counting parties. For N=1 it rests on that node's signing counter alone. |
| `deploy/baremetal/beat.py:60-61` | b | counting_nodes` excludes the owner, so only nodes propose. For N=1 there is one proposer and no possible co-signer. |
| `deploy/baremetal/beat.py:197-200` | a | for peer in [... if n != self.node_id]` builds `{"signatures": [mine, theirs]}`: exactly 2 signatures are hard-coded. 5 and 7 nodes need t-1 co-signatures gathered; N=1 needs `[mine]` alone (if t=1 is allowed). |
| `deploy/baremetal/beat.py:209` | b | raise Refused("no node co-signed … no other node counts")`. With N=1 every proposal fails and no heartbeat is ever produced automatically. |
| `deploy/baremetal/heartbeat.py:6-7` | b | "the nodes sign, by quorum … a short-lived statement that a manifest is still the current one". With N=1 no second node can say the membership is current, so a heartbeat is either self-signed (it proves only that the node's clock and counter moved) or owner co-signed. Decision Q2: self-signed. |
| `deploy/baremetal/heartbeat.py:23` | a | doc: "two of the nodes and the owner". Should read "the manifest's heartbeat_signers threshold". |
| `deploy/baremetal/heartbeat.py:53-56` | b | the lifetime bound is "how long a peer cut off from the others goes on authorizing a node that was revoked". With N=1 there is no partitioned peer, so the bound only means time until the node stops. |
| `deploy/baremetal/heartbeat.py:179` | a | docstring repeats "two of the nodes and the owner". |
| `deploy/baremetal/heartbeat.py:188-190` | a | membership.meets(rule, parties)` already reads the threshold from the manifest, so it is N-generic. Only the floor blocks t=1. |
| `deploy/baremetal/heartbeat.py:216-218` | b | an owner-co-signed heartbeat lives at most `owner_heartbeat_lifetime_s` (1 h by genesis default, 300 s minimum). With N=1 today the only valid heartbeat is node + owner, so the owner would have to sign hourly or the node stops. Needs a single-node rule or an hourly owner touch. Decision Q2: a self-signed {1, [n]} rule under `single-node`. |
| `deploy/baremetal/lease.py:2` | b | "a running node keeps serving only while a PEER keeps vouching for it". N=1: no peer, so no runtime lease, so it never serves. Needs a self-lease or owner lease, or dropping the condition. |
| `deploy/baremetal/lease.py:52` | b | "A PEER ISSUES only if… it is not the subject". Single-issuer, but must be another node. |
| `deploy/baremetal/lease.py:71` | b | PARTITION limit: "issuing peers" bound the lease. Not meaningful at N=1. |
| `deploy/baremetal/lease.py:439` | b | require(issuer_id != subject_id, "a node does not vouch for itself"). Hard refusal at N=1. |
| `deploy/baremetal/lease.py:548` | a | Holder keeps the later of "the other peer"'s lease. Assumes ≥2 issuers; harmless with 1. |
| `deploy/baremetal/membership.py:55` | b | an owner-signed heartbeat is "always the owner AND at least one node: the heartbeat threshold is at least 2". With N=1 and threshold 2 over [n1, owner], EVERY heartbeat needs an owner touch: nodes can no longer sign their own 6 h beats. N=1 needs either a {1, [n]} heartbeat rule or an owner touch on every heartbeat. Decision Q2: {1, [n]}. |
| `deploy/baremetal/node.py:967` | b | admission renew: require(peers, "no peer to ask for a lease"). N=1 can never get a runtime lease, so it is never admitted. |
| `deploy/baremetal/owner.py:9` | b | hand recovery: "no other node is up to co-sign one… makes this node and the owner the two signers a v4 heartbeat needs". At N=1 this is not recovery but the ONLY heartbeat path (every 6 h, or every owner_heartbeat_lifetime_s ≤ 1 h by default). |
| `deploy/baremetal/owner.py:14` | a | "long enough for the node to unlock the other two" → "the others". |
| `deploy/baremetal/owner.py:26` | a | "Peers pull it from here." No peers at N=1. |
| `deploy/baremetal/owner.py:79` | b | parties == [node.node_id, membership.OWNER]` means the owner envelope is exactly node+owner. Not used at N=1: under `single-node` the owner co-signed path is refused (decision Q2, design 4.4). |
| `deploy/baremetal/README.md:885` | b | "signed by two of {the nodes, the owner} … If no two of them can sign … stays locked … or the owner co-signs (owner.py beat, at most an hour)". At N=1 the node self-signs every heartbeat, {1, [n]} (decision Q2), and owner.py beat is refused under `single-node`. |
| `deploy/baremetal/README.md:1272` | a | "Heartbeats need two signatures from {node a, node b, node c, the owner}". Threshold and party list. |
| `deploy/baremetal/README.md:1278` | b | "The hand recovery when fewer than two nodes run". At N=1 this is permanent. |
| `e2e/lib/threenode.py:1017` | b | heartbeat_signers {threshold 2, parties nodes+OWNER}: with N=1 only node+owner reach 2. Decision Q2: under `single-node` the rule is {1, [n]} and the owner's beat is refused. For odd N the threshold is a majority of the designed nodes (dx7.1). |
| `e2e/lib/threenode.py:1884` | b | docstring: "With one, nobody can co-sign it"; a lone counting node never self-heartbeats; N=1 is permanently in this state |
| `e2e/lib/threenode.py:1889` | a | if len(counting) >= 2` waits for node-signed beats; the literal 2 should be the manifest's heartbeat threshold |
| `e2e/three-node-netns.py:108` | c | with a down, b and c answer each other; needs >=3 nodes |
| `e2e/three-node-netns.py:113` | c | "b and c answer its pulls" after a restarts; named peers |
| `e2e/three-node-outage.py:19` | b | hand recovery: X plus an owner key sign X's heartbeat; at N=1 this is the only steady state, not a recovery |
| `e2e/three-node-recovery.py:316` | b | counting survivors; `len(counting) == 1` (322) falls back to hand recovery: the 1-node path already exists here as a special case |
| `e2e/three-node-replace.py:115` | c | fresh(["a","b"]): two signers |
| `e2e/three-node-theft.py:144` | b | "b and c sign epoch 2's heartbeat together, with no owner": 2 counting nodes |
| `tests/test_baremetal_beat.py:49, 83` | c | three-node `Parts` fixture. |
| `tests/test_baremetal_heartbeat_v4.py:43, 80` | c | quorum (B, C) and a {2, [a,b,owner]} rule. |
| `tests/test_baremetal_heartbeat.py:47` | c | a/b/c manifest. |
| `THREE-SITE-THREAT-MODEL.md:100` | a | "two signatures from {node a, node b, node c, the owner}". The heartbeat rule's node-only quorum should be a majority of the nodes (any two intersect); the owner's co-signature stays the hand-recovery path (`owner.py beat`), bounded by `owner_heartbeat_lifetime_s`. At N=1: self-signed {1, [n]} (decision Q2), not node + owner. |
| `THREE-SITE-THREAT-MODEL.md:110` | b | "how long the nodes may go without a quorum (or the owner's hand recovery, owner.py beat)". At N=1 there is no quorum to go without: the node self-signs {1, [n]} (decision Q2), and owner.py beat is refused under `single-node`. |

## Revocations (26)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `.github/workflows/node-units.yml:432` | c | job three-node-theft; count 24 at :460 |
| `deploy/baremetal/README.md:1282` | a | revocation_signers is "two nodes, each from root at its own console … or the owner alone". The node rule is 2-of-nodes and is impossible at N=1; only the owner rule remains. |
| `deploy/baremetal/revoke.py:2-3` | b | "REVOKED_STOLEN by two nodes … or by the owner alone". With N=1 there is no other node to revoke and no second node to co-sign; only the owner path (`export` / `import`) applies. Revoking the sole node is a total shutdown. |
| `deploy/baremetal/revoke.py:25` | a | "two counting nodes, or the owner alone": a literal threshold in the docs. Should read the manifest's `revocation_signers`. |
| `deploy/baremetal/revoke.py:104-118` | a | cosign()`, "Root at the second node", is a two-step propose/cosign flow. `met()` at 97-101 is generic, but the user experience assumes t=2. For 5 and 7 nodes the half-signed envelope has to circulate through t-1 consoles. |
| `deploy/baremetal/revoke.py:189-190` | a | prints "co-sign it on a second node". Should say how many signatures remain. |
| `deploy/baremetal/unlock.py:85` | b | "a peer that has not heard of a revocation helps until its heartbeat expires". N/A at N=1. |
| `e2e/convergence-swtpm.sh:2` | c | "two software TPMs: peers b and c", with a revoked (line 8); a 3-node manifest with a third absent node |
| `e2e/lib/threenode.py:1019` | b | revocation_signers [{2, nodes}, {1, OWNER}]: the nodes' quorum cannot be met at N=1; only the owner can revoke; for N it becomes a majority |
| `e2e/lib/threenode.py:1531` | b | revoke_by_nodes(proposer, cosigner): exactly two node signatures (2-of-N); unavailable at N=1 |
| `e2e/lib/threenode.py:1561` | a | _spread pulls into "every other running node"; an empty list at N=1 is harmless |
| `e2e/peer-unlock-swtpm.sh:17` | c | "both peers refuse and drop their halves" |
| `e2e/regalia-sync-netns.py:252` | c | revoke c, peers converge; built on tests.test_baremetal_heartbeat's three-node manifest (tests/test_baremetal_heartbeat.py:47) |
| `e2e/three-node-leases.py:18` | b | "running a revoked by b and c ... both peers refuse" |
| `e2e/three-node-leases.py:175` | b | revoke_by_nodes("b","c","a"): 2-of-3 |
| `e2e/three-node-leases.py:179` | c | checks wg-svc on ("b","c") |
| `e2e/three-node-outage.py:132` | c | step 4 "two nodes revoke the third" |
| `e2e/three-node-outage.py:139` | b | revoke_by_nodes("a","b","c"): 2-of-3 node revocation |
| `e2e/three-node-outage.py:205` | c | "b commits" with signers containing a and b: exactly two node signatures |
| `e2e/three-node-theft.py:115` | b | "one node stolen and one cut off: no two nodes can co-sign, so the owner revokes": N=1 is always this case |
| `e2e/three-node-theft.py:132` | b | the WINDOW: a stale peer (c) unlocks the stolen a; at N=1 a stolen node has no peer to unlock it (stronger), but the owner must act at once |
| `e2e/three-node-theft.py:146` | c | checks unlock tunnels on ("b","c") |
| `KERNEL-UPDATE.md:163` | a | "QUARANTINED; the revocation key may sign it. The others then update without it". This is stale (pre-#199 authority key) and assumes others exist. |
| `LIMITATIONS.md:269` | b | "a one-peer recovery cannot see a revocation that two nodes signed". Two-node revocation is the N=3 rule. |
| `tests/test_baremetal_convergence.py:55, 554` | c | a/b/c manifests. |
| `tests/test_baremetal_revoke.py:46` | c | half(target="c", by="a")`. |

## Boot unlock (peer-assisted disk unlock) (59)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `.github/workflows/ci.yml:1099` | c | job peer-unlock-swtpm (3 TPMs), draft-skipped ("heavy"), invoked at :1122 |
| `cmd/regalia-unlock/agent.go:148` | b | attempt(): asks each config.Peers entry; key = credential(local, contribution, …). |
| `cmd/regalia-unlock/agent.go:176` | b | "the disk stays locked: it has no path from any peer… the console asks for the recovery key". At N=1 the recovery key is the ONLY unlock. |
| `cmd/regalia-unlock/bootcfg/bootcfg.go:213` | a | boot_mesh.peers: len < 1 \|\| > 8 → refuse("peer-count"). |
| `cmd/regalia-unlock/bootcfg/bootcfg.go:227` | b | peer node_id "must be another node's ID". |
| `cmd/regalia-unlock/bootcfg/bootcfg.go:329` | b | len(pins)==0 → "the manifest leaves %s no peer with an address"; :332 len > 8. |
| `cmd/regalia-unlock/config.go:85` | a | len(c.Peers) < 1 \|\| > 8 → "peers must list 1 to 8 peers" (mirror of unlock.py:605). |
| `cmd/regalia-unlock/config.go:98` | b | "peer %s is listed twice, or is the node itself". |
| `cmd/regalia-unlock/disk.go:46` | b | path token refused when t.Target == t.Peer: no self-path. |
| `cmd/regalia-unlock/main.go:2` | b | "a key that needs the host's TPM and one peer, never the TPM alone". |
| `cmd/regalia-unlock/wire.go:58` | b | credential(local, contribution, target, peer, epoch): two-party HKDF, peer is mandatory. |
| `deploy/baremetal/attest.py:4` | b | "A peer decides whether to help a node boot from a TPM quote". There is no remote verifier at N=1. |
| `deploy/baremetal/bootcreds.py:1` | a | "what its initrd needs to ask its peers for its disk": the whole boot-credential set is peer-oriented. |
| `deploy/baremetal/bootcreds.py:145` | b | render refused when it "leaves the host no peer" (via unlock.boot_config at :101). |
| `deploy/baremetal/enrol.py:1394` | b | peers_to_enrol(): every other node that may authorize (lines 1394-1396). Empty at N=1. |
| `deploy/baremetal/enrol.py:1475` | b | require(peers, "no other node may authorize… no path can be made"). Enrolment of a 1-node host cannot finish, and local.bin is never shredded. |
| `deploy/baremetal/enrol.py:1514` | a | "ENROLLED: a path from every peer": "every" is a free parameter, but zero peers never reaches here. |
| `deploy/baremetal/enrolpeer.py:192` | b | require(peer != node_id and peer in nodes, "…is not another node of the manifest"). |
| `deploy/baremetal/evidence.py:28` | a | example `"unlock_peers": ["b", "c"]`. An empty list is legal (line 155), which is fine for N=1. |
| `deploy/baremetal/heartbeat.py:538-543` | b | authorize()`: `require(peer_id != requester_id, "a node does not authorize itself")`. With N=1 nobody can authorize an unlock or issue a lease. N=1 needs a non-peer path (local TPM + PIN / recovery key, or a self-lease mode). |
| `deploy/baremetal/host_probe.py:735, 768` | b | the peer-assisted shape is "the TPM AND a peer, never the TPM alone". N=1 cannot use it, so it falls back to the systemd-tpm2 (local TPM + PIN) shape. That loses "a peer refuses a retired or unapproved image". |
| `deploy/baremetal/host_probe.py:932-934` | b | same property, stated for the volume check. |
| `deploy/baremetal/initrd/dracut/90regalia-unlock/crypttab:3` | a | "once a peer has given its half". |
| `deploy/baremetal/initrd/regalia-unlock.service:4` | a | "once a peer has given its half… Until a peer…" (lines 4-15). |
| `deploy/baremetal/initrd/regalia-unlock.service:18` | b | Description "Give the root volume's key: TPM plus one peer". |
| `deploy/baremetal/measurements.py:205-206` | b | "a peer's policy never lists the peer itself". With N=1 every attestation policy is empty, so nobody verifies the node's measurements. |
| `deploy/baremetal/README.md:79` | b | "Full-disk encryption (LUKS2), opened in the initrd by the host's TPM and one peer (#67)". There is no peer at N=1. |
| `deploy/baremetal/README.md:592` | b | "Peer-assisted disk unlock (three-site, #67)". At line 594, TPM-only is "the single-site baseline" that "cannot retire a boot image". N=1 falls back to this weaker baseline. |
| `deploy/baremetal/README.md:596` | b | "the disk needs the host's TPM and one peer". |
| `deploy/baremetal/README.md:880` | a | "enrol both peer paths". A fixed 2. It should be N-1 paths, which is zero at N=1. |
| `deploy/baremetal/README.md:882` | a | unlock.judge_tokens` judges "one path per expected peer". The header check expects N-1 tokens, so at N=1 it must accept zero. |
| `deploy/baremetal/unlock.py:2` | b | "root disk opens with its TPM AND one peer, never the TPM alone": the core property. N=1 must either accept TPM-only (reopening #135: old signed images unlock a stolen box) or substitute a non-node second factor (owner YubiKey / recovery key / remote service). |
| `deploy/baremetal/unlock.py:11` | b | credential = HKDF(local_T \|\| contribution_P->T): one keyslot per peer path. N=1 has no P. |
| `deploy/baremetal/unlock.py:43` | b | P decides with may_unlock: membership matrix + live heartbeat + quote. The revocation/retirement decision lives on the peer; at N=1 nobody makes it. |
| `deploy/baremetal/unlock.py:605` | a | validate_boot_config: "peers must list 1 to 8 peers". Floor 1 refuses N=1; the ceiling of 8 caps the cluster at 9 nodes. |
| `deploy/baremetal/unlock.py:609` | b | "peer … is the node itself" refused: self-path forbidden. |
| `deploy/baremetal/unlock.py:620` | b | boot_config: peers = others that may authorize (lines 620-622), then require(peers, "…no peer with an address"). |
| `deploy/baremetal/unlock.py:1031` | b | contribute(): require(peer != target, "a node is not its own peer"). |
| `e2e/lib/threenode.py:1641` | b | enrol(): one keyslot per OTHER node; at N=1 none, so the disk has only the recovery keyslot (S1's "TPM + one peer" cannot hold) |
| `e2e/lib/threenode.py:1659` | a | peers default = all other authorizing nodes (empty at N=1) |
| `e2e/lib/threenode.py:1744` | c | unlock(): tokens[0]["local"] raises IndexError when the disk has no peer path (N=1); needs a guard or a 1-node unlock mode |
| `e2e/peer-unlock-swtpm.sh:3` | c | "Three software TPMs (target a, peers b and c)": runs tests.test_baremetal_unlock OnSwtpm (tests/test_baremetal_unlock.py:1044, 1064, 1155 fix a,b,c) |
| `e2e/peer-unlock-swtpm.sh:13` | b | PoC 7.2-7.4 "with b down, c restores a; with no peer the disk stays locked": at N=1 "no peer" is permanent, so the disk opens only with the recovery key (S1 property gone) |
| `e2e/three-node-recovery.py:15` | c | "three disks ... one path from each other node" |
| `e2e/three-node-recovery.py:166` | c | permutations(names, 2) plus "third": all directed pairs with a third node off; needs N>=3 |
| `e2e/three-node-replace.py:123` | c | enrol("c2", peers=["a","b"]) |
| `e2e/wg-boot-netns.sh:235` | c | "alder reaches both peers' unlock port" |
| `PIN-CUSTODY.md:152` | b | "The root disk opens only with the TPM and a peer: each keyslot needs a half sealed to this TPM … and a half a peer gives". The PIN seal's revocability rests on peer unlock (#135). At N=1 a retired image cannot be locked out without a peer, so the PIN seal loses that property unless the owner's card takes the peer's place at every boot (decision Q1, design 4.5). |
| `PIN-CUSTODY.md:160` | c | "both peers refuse it naming PCR 11". This is the QEMU test with two peers. |
| `PIN-CUSTODY.md:243` | b | The recovery key covers "a total outage of all three sites (threat model A3) … or a node with no healthy peer". At N=1 that is every cold boot, so the recovery key becomes routine rather than break-glass. That conflicts with "Using it spends it" (line 276). |
| `tests/vectors/make-bootcreds-v1.py:26` | c | site(node, nodes=("a","b","c")) and manifest(order=("a","b","c")) (:42). Extra cases "with d" (:60), "b only" (:61), "no peers" refused (:138), "nine peers" refused (:139). There is no 1-node site that renders. |
| `tests/vectors/unlock-v1.json:15` | c | a two-party transcript, target "alder" and peer "birch" (info "regalia/luks/v1/alder/birch/7", :38). The two-party shape is the protocol itself. |
| `THREE-SITE-THREAT-MODEL.md:33` | b | S1: "no single location holds what unlocks a node's disk: the node's TPM contribution and one authorized peer's contribution are both required". This is impossible at N=1. The peer half needs a substitute (owner card, network escrow), or S1 is explicitly not held. Decision Q1: the owner's card is the second location at every boot (design 4.5). |
| `THREE-SITE-THREAT-MODEL.md:56` | b | Theft row: "no peer contribution once revoked or once away from the datacenter networks". The theft defence rests on a peer refusing. At N=1 a stolen box's TPM half alone is not enough only if a second factor exists. |
| `THREE-SITE-THREAT-MODEL.md:61` | b | Malicious-peer row: "The alternate peer path (A1)". There is no alternate path at N=1 or N=2. |
| `THREE-SITE-THREAT-MODEL.md:64` | b | TPM row: "S1 still needs a peer contribution". This does not hold at N=1. |
| `THREE-SITE-THREAT-MODEL.md:74` | b | Attacker case 1 (theft) depends on reaching "a peer over WG-BOOT from a declared datacenter address". It is void at N=1. |
| `THREE-SITE-THREAT-MODEL.md:82` | b | Case 3: "Can deny service (handled by the other path)". This assumes at least two peers. |
| `THREE-SITE-THREAT-MODEL.md:136` | b | "profiles C and D cannot meet the unattended-availability invariants A1 and A2". At N=1, profile A cannot meet them either. |

## Network (boot mesh, service mesh, firewall) (41)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `.github/workflows/ci.yml:380` | c | e2e-netns-disk (:359) runs wg-boot-netns.sh (alder plus 2 peers) and regalia-sync-netns.py at :398 |
| `.github/workflows/node-units.yml:511` | c | job three-node-wan on ubuntu-24.04 (netem); count 33 at :540 |
| `deploy/baremetal/bootnet.py:59` | a | _others(): "the other nodes the manifest lets do action" (lines 59-71). |
| `deploy/baremetal/bootnet.py:91` | b | require(peers, "the manifest leaves %s no peer that may authorize"): wg-unlock config refused at N=1. |
| `deploy/baremetal/bootnet.py:136` | b | same refusal for the initrd nftables ruleset. |
| `deploy/baremetal/etcdconf.py:230` | b | `check()` requires every peer URL on `fd72:6567:6c61:` (the service mesh). On N=1 there is no `wg-svc` (see `sitecfg` below), so the address does not exist and etcd cannot bind `listen-peer-urls`. It needs a loopback or local exception, or a `wg-svc` with a local address. Design 4.8: a loopback peer URL, accepted under `single-node` only. |
| `deploy/baremetal/firewall.py:18` | a | "With a `boot_mesh` (three-site, #66)". |
| `deploy/baremetal/firewall.py:64` | b | _set([...peers...])` (lines 64-65). An empty peers list would render `{ }`, which is invalid in nft. This is guarded only because `sitecfg` requires at least one peer. |
| `deploy/baremetal/firewall.py:85` | b | The `service_mesh` WireGuard underlays are taken from `boot_mesh` peers. With N=1 there is no peer, so there is no service mesh. |
| `deploy/baremetal/initrd/regalia-wg-boot.service:15` | a | "Boot mesh: WireGuard to the peers, before root": the unit is useless at N=1. |
| `deploy/baremetal/initrd/wg-boot:99` | b | fail "the interface has no key or no peer after the configuration was applied" (lines 99-100). Zero peers is a hard failure. |
| `deploy/baremetal/README.md:909` | a | "The running services of the three nodes talk over a second WireGuard interface". The service mesh is meaningless at N=1. |
| `deploy/baremetal/sitecfg.py:23` | a | "boot_mesh: null — a single-site host; or, in a three-site cluster". A null mesh is already allowed, so this is mostly fine for N=1. |
| `deploy/baremetal/sitecfg.py:40-43` | a | the docstring example lists exactly two peers (birch, acacia). |
| `deploy/baremetal/sitecfg.py:224` | a | 1 <= len(mesh["peers"]) <= 8`. N=1 must use a null mesh; N≤9 fits. |
| `deploy/baremetal/sitecfg.py:255` | b | service_mesh` needs a `boot_mesh`. For N=1 the service tunnel, which etcd peers and sync rely on, cannot be configured. |
| `deploy/baremetal/sync.py:134` | a | The rate bucket `"lease": (18, 60)` is sized for "two asks a renewal ... at one peer when the other is down" (lines 134-137), i.e. exactly two peers. For N=5/7 the per-peer load differs. For N=1 there are no lease peers. |
| `deploy/baremetal/units/regalia-admission.service:2` | b | "it asks the peers for a lease over the service tunnel". With N=1 there is no peer to issue a lease, so the daemon never serves. This needs a self-lease or owner-lease design (activation area). |
| `deploy/baremetal/units/regalia-etcd.service:50` | b | IPAddressAllow=fd72:6567:6c61::/48` only. Harmless for N=1 if peer URLs move to localhost, otherwise see `etcdconf.py:230`. |
| `deploy/baremetal/units/regalia-sync.service:8` | a | Description "between the three sites"; line 1 says "three-site transport". |
| `deploy/baremetal/units/regalia.sysusers.conf:2` | a | User description "Regalia KMS three-site transport". |
| `deploy/baremetal/wgsvc.py:9` | b | conf()` gives "one peer for every other node". For N=1 that is zero peers. `conf()` and `verify()` (217-227) appear to accept an empty set, but nothing tests it. |
| `e2e/lib/threenode.py:41` | c | node i on the underlay at 192.0.2.(10*i)/24; works up to N=25, fine for 1/5/7 |
| `e2e/lib/threenode.py:1094` | a | site_config: boot_mesh.peers = all other nodes; empty at N=1 (wg-unlock with no peers, untested) |
| `e2e/lib/threenode.py:1100` | c | nic_mac 0x50+index: fine to N~175 |
| `e2e/regalia-sync-netns.py:6` | c | "Three throwaway namespaces ... the nodes a, b and c" |
| `e2e/regalia-sync-netns.py:48` | c | UNDERLAY dict for three nodes |
| `e2e/regalia-sync-netns.py:197` | c | a's peers == {b, c} |
| `e2e/three-node-leases.py:145` | c | partition("a", ["b"]), then expects c to renew; needs >=3 |
| `e2e/three-node-netns.py:2` | c | Three-node netns smoke test. |
| `e2e/three-node-netns.py:14` | c | "every node reaches both others' service addresses" |
| `e2e/three-node-netns.py:83` | c | ok(len(peers) == 2 ...): wg-svc peer count fixed at 2; becomes N-1 |
| `e2e/three-node-netns.py:126` | c | said.count("refused") == 3: isolation probe over three paths (likely the other nodes' dirs plus one); would scale with N |
| `e2e/three-node-wan.py:97` | c | ring pairs (a,b),(b,c),(c,a) hard-coded; becomes all pairs of N (none at N=1) |
| `e2e/three-node-wan.py:104` | c | ("a","b","c")` hard-coded in `cut_off` and `scenario` (line 111). |
| `e2e/three-node-wan.py:122` | c | same ring pairs |
| `e2e/wg-boot-netns.sh:12` | c | "two running peers" birch and acacia for booting alder |
| `e2e/wg-boot-netns.sh:52` | c | NS=(alder birch acacia outsider away): three cluster hosts |
| `e2e/wg-boot-netns.sh:84` | c | "the three site configs" |
| `e2e/wg-boot-netns.sh:293` | c | `wg show wg-boot peers \| wc -l` = 2; becomes N-1 (0 at N=1: the boot mesh is empty) |
| `LIMITATIONS.md:635` | c | "three-node-wan … measures today's services across a WAN". Three-node only. |

## Site advance (10)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `.github/workflows/node-units.yml:280` | c | job three-node-site-advance (90 min); count 40 at :308 |
| `deploy/baremetal/siteadvance.py:5-8` | b | "changes every node's PCR 12. The peers accept a PCR 12 only as part of a set". The PCR 12 check is done by peers; with N=1 nobody judges the site document. (Line 51 `len(sets) == 2` is about measurement sets, not nodes: false positive.) |
| `e2e/three-node-netns.py:133` | c | cluster.advance("b") uses a fixed seed name |
| `e2e/three-node-site-advance.py:23` | c | "the two others freshly leased while it was down" |
| `e2e/three-node-site-advance.py:105` | b | served_while_down: each other node freshly leased by "the third"; at N=1 nothing serves during a reboot (an outage by design) |
| `e2e/three-node-site-advance.py:216` | c | "both peers see %s on the moved set" |
| `e2e/three-node-site-advance.py:234` | b | "both peers refuse it for its PCR 12": at N=1 no peer judges PCR 12 (only the node's own TPM policy does) |
| `LIMITATIONS.md:47` | b | Root epochs are given "to ONE running node with deliver … and the others pull it". At N=1 there are no others, and the pull/sync path is moot. |
| `LIMITATIONS.md:343` | c | "three-node fixture (an ESP directory per node)". |
| `LIMITATIONS.md:346` | c | "Rehearsed on the three-node fixture … e2e/three-node-site-advance.py". |

## Rolling measured-boot and policy update (43)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `.github/workflows/ci.yml:288` | c | e2e-swtpm step rolling-policy-swtpm (3 TPMs); also node-replacement-swtpm :266 and convergence-swtpm :281 in the same job (:190) |
| `.github/workflows/node-units.yml:241` | c | job rolling-threenode (90 min); count 50 at :269 |
| `deploy/baremetal/attest.py:91` | a | state sizing: "4 MiB is some 10,000 boots a node across three nodes". Per-node capacity shrinks as N grows; re-size for 7. |
| `deploy/baremetal/bootnext.py:15` | a | trial boot "HANGS (… waiting for peers that refuse it)": rollout recovery assumes peers judge the new image. At N=1 nothing refuses an image. |
| `deploy/baremetal/README.md:436` | a | "Updating the kernel on three nodes without locking the cluster out". This is a one-at-a-time rollout with peers. At N=1 an update means downtime plus an unlock path. |
| `deploy/baremetal/README.md:498` | b | "two nodes can then be down together. Three cannot." This is N=3 arithmetic. |
| `deploy/baremetal/README.md:501` | b | "while the next node is down the third may get no renewal and stop serving". Assumes a third node. |
| `deploy/baremetal/README.md:536` | c | "Proven on three software TPMs". |
| `deploy/baremetal/README.md:543` | a | "the timing of three reboots are for the DL360s". |
| `deploy/baremetal/rollout.py:4` | a | "An update rolls a new boot image through three nodes". |
| `deploy/baremetal/rollout.py:8` | b | the risk "rebooting a node when nobody is left to unlock it". With N=1 every reboot is in this state. |
| `deploy/baremetal/rollout.py:24-32` | b | rule 4: "every other node that may authorize has vouched" means all N-1 peers, not a quorum. Under 5/7, one slow peer blocks the update. |
| `deploy/baremetal/rollout.py:40-43` | b | "a node's own state says nothing about itself". Witnesses are peers only. |
| `deploy/baremetal/rollout.py:63-64` | a | "One remaining authorizer is accepted when the manifest leaves only one". This is the floor of 1 other node; it does not cover zero. |
| `deploy/baremetal/rollout.py:72` | a | "Two nodes down at once … is possible; three are not". This reasoning is specific to 3 nodes and must be restated for N. |
| `deploy/baremetal/rollout.py:212-213` | b | authorizers = [n … if n != node_id …]`; `require(authorizers, "no other node may authorize … nobody would unlock")`. `may_reboot` is always refused for N=1. A single-node update path is needed (local unlock, attended). |
| `deploy/baremetal/rollout.py:233-235` | b | missing = [n for n in authorizers if n not in left]` requires a live lease from every authorizer. For 5 and 7 this should probably be a quorum; for N=1 it is impossible. |
| `deploy/baremetal/rollout.py:250-252` | a | the state of every node that may authorize is required (all N files). |
| `deploy/baremetal/update.py:18-21` | a | "asks each other node that may authorize for a lease … two nonce and two lease requests per peer". The load is per peer, but the sync limit (6 per 60 s) is per caller, so it holds for any N. |
| `deploy/baremetal/update.py:34` | a | "a moment after both peers vouched": "both" is a literal 2-peer assumption. |
| `deploy/baremetal/update.py:95-96` | b | authorizers()` excludes self, so it is empty for N=1. |
| `deploy/baremetal/update.py:231-232` | a | "Its peers %s vouch" joined with " and ": wording that assumes two peers. |
| `deploy/baremetal/update.py:298-301` | b | promote` requires at least one peer lease ("no peer gave this boot a lease"). Always refused for N=1. |
| `e2e/rolling-policy-swtpm.sh:2` | c | "rolled through three nodes on three software TPMs": runs tests.test_baremetal_rollout.OnSwtpm, NODES = ("a","b","c") at tests/test_baremetal_rollout.py:938 |
| `e2e/rolling-policy-swtpm.sh:8` | c | "judges the other two" |
| `e2e/rolling-policy-swtpm.sh:19` | b | "b goes when it has itself seen a back on NEXT and both peers vouch" |
| `e2e/rolling-threenode.py:2` | c | "a new image rolled through three nodes" |
| `e2e/rolling-threenode.py:34` | b | "During every reboot the two other nodes must be given FRESH leases": at N=1 a rolling update is a full outage |
| `e2e/rolling-threenode.py:146` | b | "The cluster serves on two (regalia-kms-51)": a serving floor of N-1 >= 2 |
| `e2e/rolling-threenode.py:225` | b | "both peers refuse it for its PCR 11": a NEXT image before approval is refused only by peers; at N=1 only the local TPM policy refuses |
| `e2e/rolling-threenode.py:284` | b | rollout.check_lockout over the peers' state files; at N=1 no peer has seen the node on NEXT, so the retire check has no evidence |
| `KERNEL-UPDATE.md:12-13, 19` | b | "comes up unattended only because its peers help it"; "the three hosts must not be down together". N=1 is never unattended across a reboot. |
| `KERNEL-UPDATE.md:19` | b | "the three hosts must not be down together, or nobody is left to unlock anybody". At N=1 every reboot leaves nobody to unlock. |
| `KERNEL-UPDATE.md:66` | a | precondition 0.1: "All three hosts are ACTIVE … hold runtime leases from both peers". |
| `KERNEL-UPDATE.md:94-95` | a | "Bring manifest N+1 … to all three hosts"; "check that all three hold epoch N+1 … compare the three answers". |
| `KERNEL-UPDATE.md:110` | a | step 3.2: "a fresh lease from each peer … both peers vouch for this boot now". |
| `KERNEL-UPDATE.md:112, 114, 116` | b | "unlocked by a peer", "its peers unlock it", "at least one peer has just given this boot a lease". |
| `KERNEL-UPDATE.md:122, 130` | a | --state a=A.json --state b=B.json --state c=C.json`: a fixed a/b/c list. |
| `KERNEL-UPDATE.md:176` | c | "no key from either peer while the other two serve" (rolling-threenode). |
| `tests/test_baremetal_rollout_cli.py:65, 291, 301` | c | "abc" documents and states. |
| `tests/test_baremetal_rollout.py:44-46, 109` | c | CURRENT/BOTH/NEXT for "abc". |
| `tests/test_baremetal_rollout.py:600` | b | "for up to the lease lifetime two nodes can be off their feet. Three cannot.": rolling serving floor |
| `tests/test_baremetal_update.py:122, 126, 152` | c | peers ["b","c"]. |

## Re-anchor and recovery (71)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `.github/workflows/node-units.yml:24` | c | CI jobs list `three-node-*` (lines 24-30). No 1-node job exists. |
| `.github/workflows/node-units.yml:202` | c | job three-node-recovery (60 min); count 69 at :230 |
| `.github/workflows/node-units.yml:318` | c | job three-node-outage; count 39 at :346 |
| `.github/workflows/node-units.yml:356` | c | job three-node-reanchor; count 29 at :384 |
| `deploy/baremetal/convergence.py:137` | b | require(len(sources) >= minimum, …)`: recovery needs whole chains from other nodes. N=1 has no peer source. |
| `deploy/baremetal/convergence.py:155-157` | b | each source must be "a node the newest manifest lets authorize". An owner-held or offline chain cannot be a source. N=1 needs an owner or offline source. |
| `deploy/baremetal/convergence.py:181-182` | a | minimum = 1 if store.pinned() else 2`. The default of 2 assumes at least 2 peers (true for N=3). For N=1 this crash case is unrecoverable from peers; for 5 and 7 the default may stay 2. |
| `deploy/baremetal/convergence.py:182` | a | minimum = 1 if store.pinned() else 2`. This is the 2-source default behind `recover`. With N=1 an unpinned (crash-window) store can never be recovered from peers. |
| `deploy/baremetal/MEMBERSHIP-RECOVERY.md:14` | b | The crash window "needs whole chains from 2 different sources", with an example of two peers a and c and an "only one such node left" fallback. Rewrite for N=1 (no peer) and k-of-N. |
| `deploy/baremetal/MEMBERSHIP-RECOVERY.md:48` | b | Re-anchor needs "at least two other nodes", described as "the nodes' quorum, as for heartbeats and revocations" (lines 48-53). With N=1 there is no such quorum. |
| `deploy/baremetal/MEMBERSHIP-RECOVERY.md:136` | b | "#199: 2 of {a, b, c, owner}" is a fixed site list and threshold. Make it k-of-{nodes ∪ owner}. |
| `deploy/baremetal/MEMBERSHIP-RECOVERY.md:177` | b | "that is the 2-of-{a, b, c, owner} rule itself". Residual-risk analysis that assumes three nodes. |
| `deploy/baremetal/MEMBERSHIP-RECOVERY.md:194` | a | "All three servers are down": the total-outage runbook (lines 194-223) is scripted for b damaged and a and c as sources. |
| `deploy/baremetal/MEMBERSHIP-RECOVERY.md:196` | c | Rehearsed only by `e2e/three-node-reanchor.py` (CI job `three-node-reanchor`). |
| `deploy/baremetal/MEMBERSHIP-RECOVERY.md:225` | b | "A server whose two peers are both destroyed is not re-anchored... root ceremony" (lines 225-233). For N=1 a root ceremony would be the only path after any anchor damage. Decision Q5 instead re-anchors from the owner's chain plus the collector's cross-check (design 4.7). |
| `deploy/baremetal/MEMBERSHIP-RECOVERY.md:255` | c | The one-peer-left path is "not run on three nodes". The rehearsal matrix is shaped for three nodes. |
| `deploy/baremetal/MEMBERSHIP-RECOVERY.md:278` | c | "The whole operation on three nodes is not run in CI yet (#391)." |
| `deploy/baremetal/membership.py:102` | b | ROLLBACK/CONFLICT "is recovered by fetching the chain from a peer". N=1 has no peer: recovery has to come from an off-host copy (owner/ESP/backup), which becomes a new trust path. |
| `deploy/baremetal/membership.py:1460` | b | reanchor "an operator's decision, taken on two other nodes that agree" → N=1 has zero other nodes. Odd N: "a majority of the others". |
| `deploy/baremetal/membership.py:1470` | a | crash window: "convergence.recover then asks for two sources" (literal 2 sources). N=1 → 0 sources available. |
| `deploy/baremetal/membership.py:1619` | b | Store.reanchor docstring "reanchor.py takes it from two other nodes that agree". Same as :1460. |
| `deploy/baremetal/owner.py:264` | b | sign-recovery is "the owner as the second source of a one-peer recovery or re-anchor". It needs a peer chain, so it cannot be used at N=1. |
| `deploy/baremetal/reanchor.py:17` | b | Docstring: a re-anchor needs whole chains from at least two other nodes, "the quorum everything else rests on". With N=1 there is no other node, so a re-anchor is impossible. It needs a rule like `min(2, N-1)` plus the owner, or a root ceremony. For odd N: whole chains from a majority of the other nodes. N=1: the owner's chain plus the collector's cross-check (decision Q5, design 4.7). |
| `deploy/baremetal/reanchor.py:23` | b | --one-source` (one peer plus an owner statement) still needs exactly one other node. With N=1 there is no path at all. It would need an owner-plus-root (or owner-only) source with no peer. |
| `deploy/baremetal/reanchor.py:93` | a | require(len(sources) >= 2, ...)` is a literal 2. Make it a function of the manifest's node count and threshold. For N=1 it is 0 peers plus another authority. |
| `deploy/baremetal/reanchor.py:95` | a | --one-source` requires `len(sources) == 1`. N=1 needs a zero-peer variant. |
| `deploy/baremetal/reanchor.py:96` | b | The node may not be its own source. That is correct, but with N=1 it leaves nothing to vouch except the owner or root. |
| `deploy/baremetal/reanchor.py:102` | a | convergence.agreed(..., 2 if owner is None else 1, floor)` hard-codes minimum 2/1. Parameterize it as threshold minus the owner's contribution. |
| `deploy/baremetal/reanchor.py:409` | a | --peer` help says "at least two". Derive it from the threshold. |
| `deploy/baremetal/reanchor.py:416` | c | Help text mentions "the three-node fixture". |
| `deploy/baremetal/recount.py:31` | b | If the node's own freshness state is lost, the floor comes from "any other node's freshness state" (lines 31-32). With N=1 there is none, so a lost state file plus a lost counter leaves no floor. A source off the node (the owner's statement and the audit collector) must give the floor (design 4.7). |
| `deploy/baremetal/recount.py:138` | b | require(held, ...)` "Give the node's freshness state, or another node's" (lines 138-139). Same issue. |
| `deploy/baremetal/recover.py:3` | b | "2 of {a, b, c, owner}" names three nodes plus the owner. For N=1 recovery comes from the owner's chain plus the collector (decision Q5, design 4.7). For odd N it needs a general rule over a majority of the nodes. |
| `deploy/baremetal/recover.py:15` | b | In the crash window, two different nodes must agree. Impossible with N=1. |
| `deploy/baremetal/recover.py:17` | b | --one-source` only "when one other node is left". N=1 never has another node. |
| `deploy/baremetal/recover.py:208` | b | second_node_answers` enumerates authorizing nodes other than this node and the peer. For N=1 the list is empty, so the check passes vacuously. Fine, but the security meaning changes. |
| `deploy/baremetal/recover.py:239` | a | Error text says "from two nodes, not with the owner". Make it count-generic. |
| `deploy/baremetal/recover.py:258` | a | minimum = None if one_source is None else 1`: the None case defers to the default 2 in convergence. Parameterize. |
| `deploy/baremetal/recover.py:265` | a | --one-source` requires exactly one `--peer`. N=1 needs zero. |
| `deploy/baremetal/survivor.py:2` | b | The whole module assumes "the other servers fenced" and one lone survivor. For N=1, normal operation is "alone" but no survivor authorization applies. The design must say which survivor guarantees (stateless-only scope, owner directives) do or do not apply. |
| `deploy/baremetal/survivor.py:20` | b | "stateful keys wait for a majority". For N=1 the majority is the node itself. |
| `deploy/baremetal/survivor.py:225` | b | require(others, "... is the only node ... it counts alone, and no survivor authorization applies")`. This already handles N=1 by refusing. Keep it, and document that 1-node is "counts alone", not "recovery". |
| `deploy/baremetal/survivor.py:227` | b | Everyone else RETIRED or REVOKED_STOLEN means "a new membership ... commission it with a new manifest". That is the shrink path to N=1. |
| `e2e/lib/threenode.py:166` | c | NAMES = ("a", "b", "c")`. The fixture used by all three-node e2e tests. |
| `e2e/lib/threenode.py:1269` | b | _caught_up only syncs from a running peer that may authorize; at N=1 a node that fell behind never catches up by sync (only deliver/owner) |
| `e2e/three-node-outage.py:2` | c | Total outage on three nodes. |
| `e2e/three-node-outage.py:14` | c | "then the other two by themselves, through that node" |
| `e2e/three-node-reanchor.py:2` | c | Re-anchor rehearsed on three nodes only. |
| `e2e/three-node-reanchor.py:11` | b | "reanchor needs whole chains from two OTHER nodes": impossible at N=1 (and N=2); becomes "owner as second source" (#387) or a root ceremony |
| `e2e/three-node-reanchor.py:255` | b | asserts refusal text "at least two other nodes": the 2 is a constant in reanchor (other area) and the test pins it |
| `e2e/three-node-recovery.py:2` | c | Peer-recovery paths on three nodes. |
| `e2e/three-node-recovery.py:19` | c | "the two others power-cycled and both unlocked through the survivor" |
| `e2e/three-node-recovery.py:217` | c | survivor, crashed, rebooted = "a","b","c" |
| `KERNEL-UPDATE.md:165` | a | "All three hosts are down". |
| `LIMITATIONS.md:53` | b | "The lone survivor (ADR-0002 D32 item 6)". The survivor mode is a degraded state of N≥2. At N=1 the node is always "alone", so survivor rules must not be the steady state. |
| `LIMITATIONS.md:62` | b | "until the majority commits the directives on its return (not built)". There is no majority to return at N=1. |
| `LIMITATIONS.md:145` | b | "The directives live on the survivor alone until the majority returns". This is the steady state at N=1, with a single copy on disk. |
| `LIMITATIONS.md:263` | b | "Recovery with only one surviving peer … --one-source … owner.py sign-recovery". This assumes at least one peer exists. At N=1 there is no source chain, and per line 267 that is "a new root ceremony, by design". |
| `LIMITATIONS.md:267` | b | "With both peers gone, recovery is a new root ceremony, by design." At N=1 every lost anchor means a new genesis. That must be decided, or the owner statement must be allowed over the node's own exported chain. |
| `LIMITATIONS.md:281` | b | "reanchor … needs two peer chains, or one and the owner's statement". This is a fixed 2 and should become "N-1 peer chains, or …". Impossible at N=1. |
| `LIMITATIONS.md:336` | c | "rehearsed on software TPMs only (#391, e2e/three-node-reanchor.py)". Three-node fixture. |
| `LIMITATIONS.md:338` | c | "The one-peer and both-peers-destroyed cases aren't rehearsed". The N=1 case (zero peers) is the both-destroyed case. |
| `LIMITATIONS.md:617` | b | "This matters for the one-peer recovery witness (#387)". Peer-based. |
| `PIN-CUSTODY.md:259` | b | "re-anchored from its two peers' chains, with those peers opened the same way first". This should be "N-1 peers". Impossible at N=1. |
| `PIN-CUSTODY.md:262` | b | "With only one peer left, the owner's signature over that peer's chain is the second source". Fixed at 2 sources. |
| `PIN-CUSTODY.md:263` | b | "A host whose two peers are both destroyed is a root ceremony". At N=1 a lost anchor means a new genesis. |
| `THREE-SITE-THREAT-MODEL.md:14` | b | A1: "Any one node that reboots is restored, unattended, by either healthy ACTIVE peer". With N=1 there is no peer, so A1 is void and every reboot needs another path (TPM-only, or the recovery key). For odd N it should read "by any of the N-1 peers". |
| `THREE-SITE-THREAT-MODEL.md:15` | b | A2: "Any two nodes that reboot are restored by the remaining healthy ACTIVE node". This should become "any N-1", and it is void at N=1. |
| `THREE-SITE-THREAT-MODEL.md:16` | a | A3: "A total outage (all three down) is restored by one manual recovery at one node, after which A1/A2 restore the rest". This should become "all N". At N=1, every reboot that has no peer path is an A3 event. |
| `THREE-SITE-THREAT-MODEL.md:63` | b | Rollback row: "the independent anchor is its peers, which each keep their own highest epoch". At N=1 a TPM-NV rollback has no independent anchor. |
| `THREE-SITE-THREAT-MODEL.md:88` | b | Case 5: "Old TPM NV contents on one node: refused by the peers' own anchors". Not available at N=1. |

## etcd cluster size (29)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `deploy/baremetal/ETCD.md:3` | a | "the three servers keep their operational state in etcd". |
| `deploy/baremetal/ETCD.md:24` | b | "etcd only reports ready once a majority has a leader, so a lone survivor waits". For N=1 it is ready at once. |
| `deploy/baremetal/ETCD.md:45` | a | The fdatasync plan is "On each of the three servers"; line 55 passes on "all three". |
| `deploy/baremetal/ETCD.md:59` | a | Timings come from "the round trip between every pair of sites". N=1 has no pair. |
| `deploy/baremetal/etcdconf.py:55` | a | "THE TWO RETURNERS CATCH UP TOGETHER" (lines 55-60). Rationale for `MAX_LEARNERS`. |
| `deploy/baremetal/etcdconf.py:61` | a | MAX_LEARNERS = 2` equals N-1 for N=3. Derive it as `max(1, N-1)`, or cap and document the window. For N=1 the value is irrelevant but harmless. |
| `deploy/baremetal/etcdconf.py:138` | a | timings()` requires a measured p99 RTT `0 < rtt <= 500`. N=1 has no peer RTT, so it needs a default (etcd's 100 ms/1000 ms). |
| `deploy/baremetal/etcdconf.py:177` | b | initial-cluster` is built from the manifest's members. N-generic, but N=1 gives a single-member cluster where a quorum of 1 equals the node itself. etcd then gives no replication and no protection against a crashed or bad disk. |
| `deploy/baremetal/etcdconf.py:241` | a | check()` requires `max-learners == MAX_LEARNERS`, "both returning servers". The check must follow the parameter. |
| `deploy/baremetal/lease.py:37` | a | "a tail the other two committed without the survivor": the 3-node etcd survivor story → "the majority". |
| `deploy/baremetal/opstate.py:2` | a | "The operational state the three servers share through etcd". |
| `deploy/baremetal/rejoin.py:5` | a | "a voting member added to a cluster of one would make the quorum two" (lines 5-6). Correct reasoning, but it assumes the survivor is the only voter. |
| `deploy/baremetal/rejoin.py:17` | a | "two returners learn at once, never more". That is N-1 = 2. For N=5/7 there are 4/6 returners. |
| `deploy/baremetal/rejoin.py:38` | a | "commits, now needing two of two". The size of the voting set during rejoin is hard-coded. |
| `deploy/baremetal/rejoin.py:40` | b | The two-of-two window analysis (lines 40-44) is for N=3 only. For N=5 it is a 2→3→4→5 sequence with windows where no failure can be tolerated. For N=1 it does not apply. |
| `deploy/baremetal/takeover.py:3` | a | "With two of three servers fenced ... the survivor's etcd has no quorum". For N=1 etcd always has quorum and takeover is never needed. For odd N it should say "a majority of N fenced". |
| `deploy/baremetal/takeover.py:114` | b | alone()` requires the member list to equal `[node_id]`. That is the one-member state a 1-node cluster is in permanently, so "alone" stops meaning "recovery". |
| `deploy/baremetal/units/regalia-etcd.service:1` | a | Comment says "the three servers' operational-state store"; line 9 Description says "shared by the three servers". |
| `deploy/baremetal/units/regalia-etcd.service:24` | b | "ready only once a majority has elected a leader: a lone survivor waits", with `TimeoutStartSec=infinity`. Fine for N=1. For N≥3 a lone node hangs at start. |
| `internal/config/config.go:105-106` | a | "etcd replicates across the three servers". |
| `internal/opstate/cache.go:1-2` | a | "etcd orders and replicates across the three servers". |
| `internal/opstate/etcd.go:24-25, 44` | b | linearizable read "the majority agreed on"; `WithRequireLeader`, "a member cut off from the majority". Trivially satisfied by a single member, so the partition detection becomes meaningless. |
| `internal/opstate/reserve.go:22-23` | b | a Reserve is "committed by a majority BEFORE the HSM is used". At N=1 the majority is the one member: single use rests on one disk, with no copy on another host. |
| `LIMITATIONS.md:44` | a | "a multi-member cluster [has] not run under the unit". The etcd plan is multi-member. N=1 would be a single-member etcd, which is the only thing that has run in CI. |
| `LIMITATIONS.md:116` | a | "Both returning nodes come back as etcd learners at once, never a third". The rejoin is hard-coded for 2 returners. It should take N-1 returners (max-learners = N-1). |
| `LIMITATIONS.md:125` | b | "from the first returner's promotion until the second's, the cluster is two voting members". The two-of-two window is specific to N=3. |
| `LIMITATIONS.md:160` | a | "max-learners: 2, so after a survivor's take-over both fenced servers rejoin". This should be max-learners = N-1, and 0 or n/a at N=1. |
| `LIMITATIONS.md:161` | b | "This shrinks the two-of-two window". The window is an N=3 artefact. |
| `LIMITATIONS.md:163` | a | "admits the two returners as learners together, never a third (rejoin.admit)". The code hard-codes 2. |

## Monitoring and alert rules (13)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `deploy/baremetal/drill.py:2` | c | "drills on the real three servers". |
| `deploy/baremetal/drill.py:222` | a | REQUIRED_CHECKS` includes `"three-serving"`. Rename it to `all-N-serving`. |
| `deploy/baremetal/heartbeat_watch.py:39-41, 69` | a | warnings fire at 50/25/10% of the heartbeat's life, which assumes the nodes renew every 15 min. Under `single-node` the node self-signs its heartbeats (decision Q2), so they keep the same renewal model; the thresholds need checking against the single-node beat interval only. |
| `deploy/baremetal/metrics.py:96` | b | regalia_admission_recovery` is defined as "1 while this node serves ALONE under the owner's survivor authorization". With N=1, serving alone is normal and the gauge must stay 0. Keep the meaning as "survivor mode", not "alone". |
| `deploy/baremetal/MONITORING.md:4` | a | "no Prometheus or Alertmanager runs on the three KMS servers" (line 21 also says "outside the three servers"). |
| `deploy/baremetal/MONITORING.md:36` | b | "Scrape the three nodes' node_exporter in one job"; the fleet comparisons (lines 38-40) assume more than one node. |
| `deploy/monitoring/regalia-node.rules.yml:46` | b | Summary says "no quorum of the nodes has signed a newer one" (also line 54). For N=1 the signer is the node alone (decision Q2), and the summary must say so. |
| `deploy/monitoring/regalia-node.rules.yml:75` | b | RegaliaSurvivorRecoveryActive` assumes the other servers are fenced. It must not fire for a 1-node deployment. |
| `deploy/monitoring/regalia-node.rules.yml:122` | b | RegaliaMembershipBehindFleet` compares against `max by (job)`. With one node it can never fire, so a node withholding the newer chain goes undetected. N=1 needs a reference from outside the node (collector or owner). |
| `deploy/monitoring/regalia-node.rules.yml:133` | b | RegaliaAnchorBehindFleet` has the same blind spot with N=1. |
| `deploy/monitoring/regalia-node.rules.yml:159` | b | RegaliaNextBootNeedsRecoveryKey`: "no peer ... next boot asks for the recovery key" (line 164). `bootnet.py:91/136` refuses with "no peer that may authorize", so with N=1 this alert fires permanently. Unattended boot needs a design (unlock/boot area). |
| `LIMITATIONS.md:354` | b | "It is caught ACROSS the nodes: RegaliaMembershipBehindFleet … RegaliaAnchorBehindFleet". This detection needs at least 2 nodes. At N=1 a compromised regalia-sync that stops publishing is undetected. |
| `LIMITATIONS.md:358` | b | "needs … at least one honest peer ahead". Void at N=1. |

## Audit (10)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `deploy/baremetal/AUDIT-COLLECTOR.md:4` | a | "audit collector outside the three servers". For N=1 the collector becomes the only witness besides the owner, which matters more. |
| `e2e/three-node-leases.py:225` | c | step 5's renewals == 2, both by c |
| `e2e/three-node-outage.py:201` | c | len(through) == 2 * len(names): (N-1) unlocks per first node, fixed at 2; becomes (N-1)*N |
| `e2e/three-node-reanchor.py:326` | c | audit match on "at least two other nodes" |
| `e2e/three-node-replace.py:200` | c | len(unlocks) == 2 |
| `e2e/three-node-replace.py:203` | c | len(leases) == 2 |
| `LIMITATIONS.md:140` | b | "the majority committing a directive as a key-state change on its return". Majority of N. |
| `LIMITATIONS.md:597` | c | "never checked end to end in a three-node scenario". |
| `LIMITATIONS.md:614` | c | "In the three-node fixture, advance() prints the puller's trail". |
| `tests/test_threenode_moving_line.py:2` | c | "three-node scenarios' audit steps": wording only; moving_line itself is N-agnostic |

## Other docs and wording (31)

| Where | Cat | What it assumes, and what it becomes for N=1 (and odd N) |
|---|---|---|
| `.github/workflows/ci.yml:1223` | c | ci-gate needs: covers ci.yml jobs only; the node-units three-node jobs are NOT required checks (node-units.yml:1-3 says so) |
| `.github/workflows/node-units.yml:10` | c | nightly cron '23 2 * * *' runs every three-node job unfiltered; a one-node job joins it automatically |
| `deploy/baremetal/image/packages.txt:84` | a | Drill is described as "against the three hosts". |
| `deploy/baremetal/node.py:353` | c | "main's three-node-recovery" fixture reference. |
| `deploy/baremetal/node.py:1257` | c | --esp-trail help "the three-node fixture gives each node its own" (also :1260 --esp-lock). |
| `deploy/baremetal/README.md:4` | a | "Three DL360 Gen9 … one per site, all three active (D32), at three sites (regalia#46)". This should be N hosts. |
| `deploy/baremetal/README.md:931` | a | "The node's running services (three-site, #80)". A label. |
| `deploy/baremetal/signkey.py:3` | b | "one party of a quorum ... the three nodes and the owner keep each other fresh". For N=1 the node's key plus the owner's is the whole quorum. |
| `deploy/baremetal/site.example.json:3` | a | "site": "site-a"`, a label from the a/b/c naming scheme (cosmetic). |
| `deploy/baremetal/SSH.md:19` | a | "replicated across the three hosts". |
| `e2e/lib/threenode.py:1` | c | module title "Three KMS nodes on one machine"; becomes "N nodes (N>=1)" |
| `e2e/three-node-netns.py:10` | c | "three nodes built ... one chain naming all three" |
| `FENCING.md:120` | c | commissioning test "a cut-off minority stops serving within one lease". |
| `FENCING.md:121` | c | commissioning test "when one server dies, the other two keep serving" → "the remaining majority". |
| `FENCING.md:130` | c | test "a lone survivor serves stateless keys only". |
| `FENCING.md:157` | a | "After a restart of all three servers at once, nothing serves for about one lease" → "all N". |
| `KERNEL-UPDATE.md:1, 3` | a | "Updating the kernel on the three KMS hosts", "three-site KMS". |
| `KERNEL-UPDATE.md:204, 212` | a | "collecting the three hosts' answers", "the three DL360s". |
| `LIMITATIONS.md:14` | a | "The three production hosts (HPE DL360 Gen9…)". This should be "the production hosts (N)". |
| `LIMITATIONS.md:31` | c | "Every three-node scenario so far runs on a software TPM". The e2e fixtures are three-node only, and N=1 has no scenario. |
| `LIMITATIONS.md:49` | c | "In the three-node scenarios, an owner-signed epoch is committed by the harness". The fixture is three-node. |
| `PIN-CUSTODY.md:67` | a | Example `--id hsm-site-a` uses lettered site IDs. The same at lines 76, 77, 82, 83 and 105. Naming only. |
| `README.md:89` | a | "Two HSMs you buy once, on hosts you already run". This is an older two-device availability story that contradicts both 3-node and 1-node. It should be restated per N. |
| `README.md:93` | a | Cost row "~€220 once — two Nitrokey HSM 2". This should be N HSMs. |
| `README.md:100` | b | "Availability: cold standby with a human RTO of hours … two hot signers on one account is worse than an outage". This conflicts with D32 (all active). For N=1 it is accurate. |
| `THREE-SITE-THREAT-MODEL.md:1` | a | The title and scope are "Three-site KMS". This should become an N-site threat model, with N=1 as a named profile. |
| `THREE-SITE-THREAT-MODEL.md:18` | b | A4: "No single provider, datacenter, network path or device failure stops the cluster from serving". This cannot hold at N=1. It needs N≥3 at distinct providers and should be stated as conditional on N. |
| `THREE-SITE-THREAT-MODEL.md:59` | a | "two sites may share provider X … The site at provider Y" is a three-site topology with two providers. It should be stated per deployment. |
| `THREE-SITE-THREAT-MODEL.md:90` | a | Case 6: "two sites at one provider are one domain". This is topology-specific. |
| `THREE-SITE-THREAT-MODEL.md:147` | a | Lab baseline: "Three YubiKeys (staging)". This is an inventory, not a rule. Low priority. |
| `THREE-SITE-THREAT-MODEL.md:149` | a | "HPE DL360 Gen9 ×3", with "the other two are not measured". The fleet is fixed at 3. |
