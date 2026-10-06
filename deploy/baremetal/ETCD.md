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
