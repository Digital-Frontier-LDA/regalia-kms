# etcd on the KMS servers

ADR-0002 D32 (regalia#571): every server serves, and the three servers keep their **operational state** in etcd. That state is the leases, key state, spent approvals and per-key high-water marks. etcd holds **no secrets** and is not the authority to serve; the TPM-attested lease is. The design is on regalia-kms#432. This page covers what's in the image, how it runs, and how its disks are measured.

## Which etcd: upstream v3.6.15, built from source (decided 2026-10-05, regalia-kms-d9 for #432)

`deploy/baremetal/image/etcd.pin` names:
- the tag (`v3.6.15`);
- the commit the tag must point to (`a3346427…`). A tag moved upstream is refused, never followed;
- the Go release upstream builds it with (`go1.26.8`, from its `.go-version` and `server/go.mod`).

`build-rootfs.sh` fetches the tag outside the build tree, checks the commit, and downloads the modules of `server`, `etcdctl` and `etcdutl`, verified by etcd's `go.sum` and the Go checksum database. It then builds them inside the build tree with no network, the way upstream's `scripts/build_lib.sh` does: `CGO_ENABLED=0`, `-trimpath`, and the GitSHA stamped. They go to `/usr/bin/etcd`, `/usr/bin/etcdctl` and `/usr/bin/etcdutl`. The record (`rootfs-build.json`, `etcd`) names the tag, the commit, the Go release and each program's sha256. The rootfs reproducibility job builds it twice like everything else.

**Why not Debian 13's `etcd-server` (3.5.16-4):**
- **Security fixes.** 3.5.16 (Sept 2024) predates two 2026 RBAC-bypass fixes in nested transactions: CVE-2026-33343, and CVE-2026-44283 (fixed in 3.5.30 and 3.6.11, May 2026; [etcd blog](https://etcd.io/blog/2026/may-patch-release/), [GHSA-x35m-3gp4-4fh5](https://github.com/advisories/GHSA-x35m-3gp4-4fh5)). D32 relies on etcd's mutual TLS and its own authorization between members, so those fixes matter here more than in Kubernetes, which doesn't use etcd's RBAC.
- **Debian's security support for Go packages is limited.** Static linking means a fix in a library needs every dependant rebuilt, and Debian's release notes warn that such updates may lag.
- **Upstream patches every month or so on 3.6** (3.6.15, September 2026), and 3.6 is the line Kubernetes runs.
- **The rest of our build works this way already.** The KMS daemon is built from source with a pinned Go release and verified modules; etcd is built the same way, from a reviewed commit.

**Updating:** change `etcd.pin` (the tag, its commit, upstream's Go release) in a pull request that names the changelog entries it brings. The build refuses a mismatch on any of the three.

## How it runs: `deploy/baremetal/units/regalia-etcd.service`
- **User `regalia-etcd`** (sysusers), with no capability, `NoNewPrivileges`, `ProtectSystem=strict` and `MemoryDenyWriteExecute`. The system-call filter is `@system-service` minus `@privileged @resources`, and a denied call fails with `EPERM` rather than killing etcd (Go's runtime may call setrlimit). `systemd-analyze security` scores it 1.2.
- **Starting:** `Type=notify` with `TimeoutStartSec=infinity`. etcd only reports ready once a majority has a leader, so a lone survivor waits rather than restart-looping, and its clients connect lazily.
- **Data:** `/var/lib/regalia-etcd` (StateDirectory, 0700), holding the WAL and the snapshots. Under the dm-verity design (#61) `/var` is the only persistent filesystem, the encrypted volume.
- **Network:** peers on the WireGuard mesh only (`IPAddressAllow=fd72:6567:6c61::/48`, mutual TLS).
- **Local clients use a unix socket, `/run/regalia-etcd/client.sock:0`.**
  - etcd takes no absolute unix path, so it's `unix://client.sock:0` with the directory as the working directory.
  - The directory is a tmpfiles line, `2750 regalia-etcd:regalia-etcd-client`, not a `RuntimeDirectory=`, which would take the unit's own group. The setgid bit gives the socket the client group, and `UMask=0007` makes it 0770. Only members of `regalia-etcd-client` connect; a client's unit joins the group with `SupplementaryGroups=`.
  - **Measured with v3.6.15 under umask 0007:**
    - the db, the WAL and every directory are 0600/0700;
    - the Raft `.snap` files are 0660, but group `regalia-etcd` has no other member and they sit in 0700 directories;
    - a socket left by a killed etcd is replaced at the next start.
  - **CI** (`e2e/etcd-unit-sandbox.sh`, in the rootfs job) runs the image's own etcd under the image's own unit. It checks:
    - a start that reaches ready with no restart and no killed system call;
    - the socket's mode and group;
    - a client in the group served, and one outside it refused;
    - nothing in the data directory open to others.
- **Keys:** one, the peer TLS key, `LoadCredentialEncrypted` (sealed to the host's TPM), read from `/run/credentials/regalia-etcd.service/`. Clients have no TLS: etcd ignores client TLS and `client-cert-auth` on a `unix://` URL (measured with v3.6.15, #491), so the socket's group is the client's admission. The renderer's `check()` refuses a client TLS block.
- **Configuration:** `/etc/regalia/etcd.conf.yml`, rendered at enrolment. It holds the member name, the initial cluster from the root-signed manifest, the certificate paths, and the heartbeat and election timeout from the measured round trip (D32 item 5). Until it exists the unit is **skipped**, not failed.

## One member, under the single-node profile (regalia-kms-dx7.6)

A v5 manifest of topology single-node has one node, and its etcd is a cluster of one (docs/design/single-node.md 4.8):
the same opstate, Reserve, watch cache and state epoch as three nodes, with no replication.

- `etcdconf.render` gives that member `https://127.0.0.1:2380` (`LOOPBACK_PEER_URL`) as its only peer URL, etcd's default
  timings (100 ms, 1000 ms: there is no round trip to measure, and none is taken), and the initial cluster of itself alone.
  Peer TLS stays on, against its own bound certificate.
- `etcdconf.check(text, profile)` takes that shape only when the caller passes the single-node profile it read from the
  verified manifest. Every other caller, and every multi-node configuration, still requires each peer URL on the service
  mesh's prefix.
- `e2e/etcd-unit-sandbox.sh` starts this rendered configuration under the image's own `regalia-etcd.service` (test keys
  only). The unit is unchanged: one member dials no peer, and `IPAddressDeny=` drops traffic, it does not stop a bind.
- **Restore** (`deploy/baremetal/restore.py`). With one disk, a restored snapshot is an older history: a spend or a
  sequence used since the snapshot could be used again. The owner's tool issues a restore statement (`sign-statement`) whose
  state epoch is above the collector's highest recorded one and above every epoch its ledger has issued, each issued once.
  On the node, `restore.py run` restores the snapshot into a staging directory, runs etcd on it under a `/run` drop-in, writes
  the state-epoch entry carrying the statement (`opstate.verify_restore`, in Python and Go), and exchanges the staging and
  live member directories in one `renameat2(RENAME_EXCHANGE)`. The daemon starts only once the live store holds the raised
  epoch. A statement that does not raise the store's epoch is refused, and the daemon stays stopped.
  - **Two outcomes of the swap**, which the run says on stdout: "the store it replaced is kept in
    /var/lib/regalia-etcd/restore/member" when a live member directory existed (the two were exchanged: the old store
    is kept for the operator to inspect, then remove), or "there was no live store to replace" when it did not (a
    replacement disk: the staging directory was renamed into place, and nothing is kept).
  - The statement must raise the **live** store's epoch too, read before anything stops. If etcd is stopped, it is started
    on the live store for the read, and a store it will not start on is refused. Only when the live member directory is
    gone (the lost disk) is no live epoch read. The statement's floor then stands for it, and nothing on the node
    enforces single use. The restored entry keeps the signed statement, so deleting the input file enforces nothing.
    Single use is the **owner's procedure**: a statement handed to the node is consumed whatever happens next. After a
    restore whose outcome is unknown (interrupted, crashed, refused after the services stopped), the owner signs a new
    statement (the ledger issues the next epoch) before any retry, and never gives the same one again. Its window is
    at most a day. Beyond that there is only partial detection: the collector's spend audit flags an approval spent
    twice in the streams it receives. It does not detect every replayed history, and the collector is not yet running
    (LIMITATIONS.md).
  - A refusal before the swap leaves the live store untouched. With no live store, etcd is never restarted onto the
    empty directory. The verified copy of the snapshot (`/var/lib/regalia-etcd/restore.snapshot`) is removed on an early
    refusal, best-effort; the snapshot itself is never touched. If that removal fails, or a failed `etcdutl` leaves
    `restore/` behind, the next run refuses until the operator has looked at the artifact and moved it aside. The
    refusal names it. One restore runs at a time, under `/run/lock/regalia-restore.lock`. Before etcd ran on staging, both units are started again
    as they were. After that, etcd is put back on its live store and the daemon is left stopped. In both cases the staging
    directory is kept for inspection, and a new run refuses until it is moved away.
  - **The boot guard: `/etc/regalia/restore-pending`** (regalia-kms-dx7.26). Etcd's configuration says
    `initial-cluster-state: new` under single-node, so etcd started on an empty data directory forms a new, empty
    one-member cluster, and the daemon would serve on it at state epoch 0. While the marker exists, neither
    `regalia-etcd.service` nor `regalia-kms.service` starts, at any boot (`10-restore-pending.conf` in each unit's
    drop-in directory: `ConditionPathExists=!`, so the units read skipped, not failed). It persists: `/etc/regalia`
    links to `/var`, and every writer writes its `/var` name.
    - **Written** by `enrol commit` under single-node **without `--bootstrap`** (a replacement disk), as its first
      persistent write, before `node.json`; by `restore.py run` when there is no live store, before it stops anything; and
      by hand with `restore.py mark-pending` (root, at the console). `--bootstrap` is the cluster's genesis only, when no
      etcd history ever existed. Never use it to re-enrol a lost disk: the commit is refused when the verified chain
      proves non-genesis (see below), and no marker is written on the one residual case where it is not refused.
    - **Lifted for etcd alone** by the restore's `/run` drop-in, whose empty `ConditionPathExists=` resets the
      conditions before it and lists the unit's own two gates again. systemd reads drop-ins in file-name order whatever their
      directory, so `10-restore-pending.conf` sorts before `50-restore.conf`. The order is pinned by a test.
    - **Removed** only by `restore.py run`, once the restored store is exchanged into place and before etcd's restart.
      The daemon then starts only on the raised epoch read back. Every refusal keeps it. When the exchange's fsync failed,
      the refusal says when it may be removed by hand: only once the live etcd reads the raised epoch.
    - **`--bootstrap` is refused when the verified chain proves non-genesis.** `enrol commit --bootstrap` is the
      network's genesis: epoch 1, no replacement, and this node a **genesis member** — first named at epoch 1 of the
      verified chain (`is_genesis_member`, enrol.py). When the chain proves otherwise — a later epoch (heartbeats were
      issued), a replacement (`--replace`, or the sole node's revocation), or a node not first named at epoch 1 — the
      commit is refused before anything is written. A node no manifest names is refused too (it fails closed: a signing
      KMS never treats "unknown" as genesis), though `check_manifest` already refuses that earlier (enrol.py:922). The
      refusal names the correct path: `enrol commit` without `--bootstrap` (which writes the marker), or `restore.py run`
      once the restore's exchange has raised the epoch.
    - **The same-epoch-1 residual.** A re-enrolment on the very same epoch-1 manifest that the original genesis used
      (the owner rolled the chain back, or reused it) cannot be told apart from genesis: the epoch is 1, no
      replacement is named, and the node is first named at epoch 1. The refusal does not fire, and
      no marker is written. In that case the operator holds the marker by hand: `restore.py mark-pending` (root, at
      the console) before the reboot, then `restore.py run` once the restored store is ready. This is the one case
      where the operator must act; the docs and the `mark-pending` subcommand exist for it.
- A take-over and a rejoin are refused under single-node (dx7.3), and a restore statement is refused under multi-node.

## The disks: an fdatasync measurement plan for the DL360s (before production)
etcd commits each Raft entry with an `fdatasync` of its WAL. etcd's hardware guidance asks for a **99th percentile WAL fdatasync under 10 ms**. A slow disk shows as leader elections and slow stateful operations (D32: about 10–40 ms each at 5–20 ms RTT, plus this).

**On each of the three servers, on the disk and filesystem that will hold `/var/lib/regalia-etcd`** (the LUKS2 volume, ext4), with the Smart Array's write cache in its production setting (battery or flash-backed write-back, which must be confirmed healthy in iLO first):

```
mkdir /var/lib/regalia-etcd-fio && cd /var/lib/regalia-etcd-fio
fio --name=etcd-wal --rw=write --ioengine=sync --fdatasync=1 --size=22m --bs=2300 --directory=. --output-format=json > fio-$(hostname).json
cd / && rm -r /var/lib/regalia-etcd-fio
```
(This is etcd's documented test: 2300-byte writes, each followed by `fdatasync`.)

**Record** `sync.lat_ns.percentile["99.000000"]` and `["99.900000"]` from the JSON, per server, on #432, with the controller model, the cache setting and the firmware.
- **Pass:** p99 < 10 ms on all three.
- **Fail:** no server runs etcd with a p99 ≥ 10 ms. Fix the cache or controller first, or record the waiver and its tuning on #432.

**Also measure, and record on #432:**
- **The round trip between every pair of sites** over the mesh: `ping -c 1000 -i 0.2` p50, p99 and max. The heartbeat interval and election timeout are set from the worst p99 (D32 item 5).
- **A 10-minute run of `etcdctl check perf --load=s`** on the assembled cluster before the ceremony, which must report PASS.

## Limitations (also in LIMITATIONS.md)
- **Built and pinned, not yet run on a host.** No cluster has been formed. The configuration renderer, the certificates issued at enrolment, member add/remove from the manifest and the netem scenario are #432's build (48 leads).
- **etcd tolerates crashes, not malicious members (D32).** Every entry carries its own authorization and is verified before it's applied.
- **The TLS trust has no CA** (regalia-kms-ed on #484, agreed). Each member's certificate is self-signed at enrolment and pinned by its SHA-256 in the root-signed manifest. The trusted bundle each member loads is rendered from the manifest, so a member the root didn't approve can't join. The manifest field is to be agreed with 48 and 95 on #432.
- **Not built yet:**
  - generating the member's key in a pipe straight into `systemd-creds encrypt`, never written in clear;
  - which PCRs that credential is sealed to (7 and 11, as the other node credentials; to confirm with 95);
  - a test of the rendered configuration that asserts its safety settings (client URL is the unix socket only, peer URLs on the mesh, `client-cert-auth` and `peer-client-cert-auth` true, the tuned heartbeat and election timeout).

  These come with the renderer (#432).
- **Under the hermetic /usr design (#61),** `/etc/regalia/etcd.conf.yml` and `/etc/credstore.encrypted` must move to `/var` (the /etc inventory).
- **The disk measurement above hasn't been made.** It needs the DL360s.
