#!/usr/bin/env bash
# etcd-unit-sandbox.sh — the etcd the image builds, run under the image's own regalia-etcd.service (ADR-0002 D32, #484).
#
#   sudo e2e/etcd-unit-sandbox.sh ROOTFS_TAR
#
# The unit's sandbox (its system-call filter, its UMask, its address and path restrictions) is only proven by running
# the real binary under it: a denied call would kill etcd, a 0700 socket would lock every client out (regalia-kms-ed on
# #484). So, on this machine's systemd: etcd, etcdctl and the unit are taken from ROOTFS_TAR (the unit with its
# ExecStart pointed at the extracted binary, nothing else changed), the user, group and socket directory made as the
# image's sysusers.d and tmpfiles.d make them, a one-member configuration written, and the peer TLS key credential
# encrypted with this machine's credential key. The configuration is etcdconf.render's for a single-node manifest
# (regalia-kms-dx7.6, docs/design/single-node.md 4.8: one member on its loopback peer URL, peer TLS against its own bound
# certificate, etcd's default timings), checked by etcdconf.check under that profile, with TEST keys only
# (tests/test_baremetal_etcdconf.py's). Then:
#   the unit starts, reaches ready (sd_notify) and stays up, with no restart and no killed system call;
#   etcd answers as a cluster of that one member, on the loopback peer URL;
#   the socket is /run/regalia-etcd/client.sock:0, mode 0770, group regalia-etcd-client;
#   a process in that group puts and reads a key through it; one outside the group is refused;
#   the data directory is 0700, owned by regalia-etcd; every file in it is unreadable by others.
#   with /etc/regalia/restore-pending there, the image's 10-restore-pending.conf drop-ins skip etcd and a stub daemon
#   (ConditionResult=no); restore.py's /run drop-in, read after them, starts etcd on staging and the daemon stays skipped;
#   with the marker removed both start (regalia-kms-dx7.26).
# It removes what it made by its exact paths (the user and the groups too).
# shellcheck disable=SC2319  # file-wide: `ok $?` reads the check made just before it, on purpose
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C
[ "$(id -u)" = 0 ] || { echo "etcd-unit-sandbox: run as root"; exit 2; }
TAR="${1:?usage: etcd-unit-sandbox.sh ROOTFS_TAR}"
# not under /run (often noexec) nor /tmp or /var/tmp (the unit's PrivateTmp hides them): where an executable is run from
W="$(mktemp -d /usr/local/lib/etcd-unit-sandbox.XXXXXX)"
# mktemp makes it 0700 root's: the unit's user, regalia-etcd, could not reach the binary under it (203/EXEC)
chmod 0755 "$W"
UNIT=/run/systemd/system/regalia-etcd.service
CONF=/etc/regalia/etcd.conf.yml
CERTS=/etc/regalia/etcd
CRED=/etc/credstore.encrypted
made_regalia_dir=0 made_cred_dir=0 made_cert_dir=0 made_node_json=0
# regalia-kms-dx7.26: the restore-pending guard. The shipped drop-ins go under /etc (the unit is under /run, restore's
# drop-in too): systemd reads drop-ins from every directory in FILE-NAME order, which is what is shown
MARK=/etc/regalia/restore-pending
NODE_JSON=/etc/regalia/node.json
ETCD_GUARD=/etc/systemd/system/regalia-etcd.service.d
KMS_STUB=/run/systemd/system/regalia-kms.service
KMS_GUARD=/etc/systemd/system/regalia-kms.service.d
RESTORE_DROPIN=/run/systemd/system/regalia-etcd.service.d/50-restore.conf
passed=0 failed=0
ok(){ if [ "$1" = 0 ]; then passed=$((passed + 1)); echo "  PASS $2"; else failed=$((failed + 1)); echo "  FAIL $2"; fi; }
cleanup(){
  systemctl stop regalia-etcd.service regalia-kms.service 2>/dev/null || true
  rm -f -- "$MARK" "$ETCD_GUARD/10-restore-pending.conf" "$KMS_GUARD/10-restore-pending.conf" "$KMS_STUB" "$RESTORE_DROPIN"
  rmdir "$ETCD_GUARD" "$KMS_GUARD" "$(dirname "$RESTORE_DROPIN")" 2>/dev/null
  [ "$made_node_json" = 1 ] && rm -f -- "$NODE_JSON"
  rm -f -- "$UNIT" "$CONF" "$CRED/regalia-etcd-peer.key" "$CERTS/peer.crt" "$CERTS/peers.pem"
  [ "$made_cert_dir" = 1 ] && rmdir "$CERTS" 2>/dev/null
  [ "$made_regalia_dir" = 1 ] && rmdir /etc/regalia 2>/dev/null
  [ "$made_cred_dir" = 1 ] && rmdir "$CRED" 2>/dev/null
  systemctl daemon-reload || true
  rm -rf --one-file-system -- /run/regalia-etcd /var/lib/regalia-etcd "$W"
  id regalia-etcd >/dev/null 2>&1 && userdel regalia-etcd
  getent group regalia-etcd >/dev/null && groupdel regalia-etcd
  getent group regalia-etcd-client >/dev/null && groupdel regalia-etcd-client
  return 0
}
trap cleanup EXIT

# what the image holds: the binaries and the unit, from the archive itself
tar -xf "$TAR" -C "$W" ./usr/bin/etcd ./usr/bin/etcdctl ./usr/lib/systemd/system/regalia-etcd.service \
  ./usr/lib/systemd/system/regalia-etcd.service.d/10-restore-pending.conf ./usr/lib/systemd/system/regalia-kms.service.d/10-restore-pending.conf
sed 's|^ExecStart=/usr/bin/etcd |ExecStart='"$W"'/usr/bin/etcd |' "$W/usr/lib/systemd/system/regalia-etcd.service" > "$UNIT"
[ "$(diff "$W/usr/lib/systemd/system/regalia-etcd.service" "$UNIT" | grep -c '^[<>]')" = 2 ]; ok $? "the unit is the image's, with only ExecStart's path changed"
# the user, the groups and the socket directory, as the image's sysusers.d and tmpfiles.d lines make them
groupadd --system regalia-etcd-client
useradd --system --user-group --home-dir /var/lib/regalia-etcd --no-create-home --shell /usr/sbin/nologin regalia-etcd
install -d -m 2750 -o regalia-etcd -g regalia-etcd-client /run/regalia-etcd
grep -qx 'd /run/regalia-etcd 2750 regalia-etcd regalia-etcd-client -' deploy/baremetal/units/regalia.tmpfiles.conf; ok $? "the socket directory is the image's tmpfiles line"
# a one-member cluster as etcdconf renders it under the single-node profile (dx7.6): the peer on loopback over TLS (the
# unit's IPAddressDeny drops traffic, it does not stop a bind; one member dials no peer). Rendered into $W, the key
# included (a TEST key), then put where the unit reads each: the key only as an encrypted credential
[ -d /etc/regalia ] || { mkdir -p /etc/regalia; made_regalia_dir=1; }
[ -d "$CERTS" ] || { mkdir -p "$CERTS"; made_cert_dir=1; }
python3 -I - "$W" <<'EOF'
import pathlib, sys
sys.path.insert(0, ".")
from cryptography.hazmat.primitives import serialization
from deploy.baremetal import etcdconf, membership
from tests.test_baremetal_etcdconf import GENESIS, bound
from tests.test_baremetal_membership_v4 import p256
from tests.test_baremetal_membership_v5 import single5
manifest = single5(1, "")
certs = etcdconf.choose(manifest, {"a": [bound("a")]})
config, bundle = etcdconf.render(manifest, "a", GENESIS, certs, None)
etcdconf.check(config, membership.SINGLE_NODE)
out = pathlib.Path(sys.argv[1])
(out / "etcd.conf.yml").write_text(config)
(out / "peers.pem").write_text(bundle)
(out / "peer.crt").write_text(certs["a"])
(out / "peer.key").write_bytes(p256(500).private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))      # CERTS["a"]'s key (a test key)
EOF
install -m 0644 "$W/etcd.conf.yml" "$CONF"
install -m 0644 "$W/peer.crt" "$CERTS/peer.crt"
install -m 0644 "$W/peers.pem" "$CERTS/peers.pem"
grep -q '"initial-cluster": "a=https://127.0.0.1:2380"' "$CONF"; ok $? "the configuration is a one-member cluster on the loopback peer URL"
[ -d "$CRED" ] || { mkdir -p "$CRED"; made_cred_dir=1; }
systemd-creds encrypt --with-key=host --name=etcd-peer.key "$W/peer.key" "$CRED/regalia-etcd-peer.key"
rm -f -- "$W/peer.key"
systemctl daemon-reload

set +e
echo "### the unit, started"
timeout 90 systemctl start regalia-etcd.service; started=$?
ok "$started" "it starts and reaches ready (Type=notify)"
# a start that failed says why: the unit's own status and etcd's last lines, not only "see journalctl"
[ "$started" = 0 ] || { systemctl status regalia-etcd.service --no-pager -l 2>&1 | tail -15; journalctl -u regalia-etcd.service --no-pager -o cat | tail -40; }
sleep 5
[ "$(systemctl is-active regalia-etcd.service)" = active ] && [ "$(systemctl show -p NRestarts --value regalia-etcd.service)" = 0 ]
ok $? "it stays up, with no restart"
! journalctl -u regalia-etcd.service --no-pager -o cat | grep -qiE "SIGSYS|bad system call|core-dump"; ok $? "no system call was killed"

echo "### the socket"
S="/run/regalia-etcd/client.sock:0"
[ "$(stat -c '%F %a %U %G' "$S")" = "socket 770 regalia-etcd regalia-etcd-client" ]; ok $? "the socket is 0770, group regalia-etcd-client ($(stat -c '%a %U:%G' "$S" 2>&1))"
client(){ (cd /run/regalia-etcd && setpriv --reuid=nobody --regid=nogroup --groups="$1" "$W/usr/bin/etcdctl" --dial-timeout=3s --command-timeout=5s \
            --endpoints unix://client.sock:0 "${@:2}"); }
client "$(getent group regalia-etcd-client | cut -d: -f3)" put sandbox ok >/dev/null && \
  [ "$(client "$(getent group regalia-etcd-client | cut -d: -f3)" get --print-value-only sandbox)" = ok ]
ok $? "a member of regalia-etcd-client writes and reads through it"
members="$(client "$(getent group regalia-etcd-client | cut -d: -f3)" member list -w simple 2>&1)"
[ "$(printf '%s\n' "$members" | grep -c .)" = 1 ] && printf '%s\n' "$members" | grep -q ', started, a, https://127.0.0.1:2380, '
ok $? "etcd answers as a cluster of one member, a, on the loopback peer URL ($members)"
client "$(getent group nogroup | cut -d: -f3)" get sandbox >/dev/null 2>&1; [ $? != 0 ]; ok $? "a process outside the group is refused"

echo "### the data directory"
[ "$(stat -c '%a %U' /var/lib/regalia-etcd)" = "700 regalia-etcd" ]; ok $? "/var/lib/regalia-etcd is 0700, regalia-etcd's"
[ -z "$(find /var/lib/regalia-etcd -perm /o=rwx)" ]; ok $? "nothing in it is open to others"

echo "### the restore-pending guard (regalia-kms-dx7.26)"
# the image's own drop-ins; a stub daemon (sleep) carries the kms one. The marker present: both are skipped
for u in regalia-etcd regalia-kms; do d=/etc/systemd/system/$u.service.d; mkdir -p "$d"
  install -m 0644 "$W/usr/lib/systemd/system/$u.service.d/10-restore-pending.conf" "$d/10-restore-pending.conf"; done
printf '[Unit]\nDescription=a stub regalia-kms.service (the sandbox)\n[Service]\nExecStart=/bin/sleep infinity\n' > "$KMS_STUB"
[ -e "$NODE_JSON" ] || { printf '{}\n' > "$NODE_JSON"; made_node_json=1; }
systemctl stop regalia-etcd.service
printf '{"schema": "regalia.restore-pending/v1"}\n' > "$MARK"
systemctl daemon-reload
skipped(){ timeout 90 systemctl start "$1" && sleep 1 && [ "$(systemctl is-active "$1")" != active ] && \
           [ "$(systemctl show -p ConditionResult --value "$1")" = no ]; }
started(){ timeout 90 systemctl start "$1" && sleep 1 && [ "$(systemctl is-active "$1")" = active ] && \
           [ "$(systemctl show -p ConditionResult --value "$1")" = yes ]; }
skipped regalia-etcd.service; ok $? "with the marker, etcd is skipped (ConditionResult=no), not started on an empty store"
skipped regalia-kms.service; ok $? "with the marker, the daemon is skipped (ConditionResult=no)"
# restore's own drop-in (restore.dropin(), only etcd's path changed to the extracted binary) on staging: etcd starts
python3 -I - "$W" > "$W/50-restore.conf" <<'EOF'
import sys
sys.path.insert(0, ".")
from deploy.baremetal import restore, takeover
print(restore.dropin().replace("ExecStart=%s " % takeover.ETCD, "ExecStart=%s/usr/bin/etcd " % sys.argv[1]), end="")
EOF
mkdir -p "$(dirname "$RESTORE_DROPIN")"
install -m 0644 "$W/50-restore.conf" "$RESTORE_DROPIN"
install -m 0600 -o regalia-etcd -g regalia-etcd "$CONF" /run/regalia-etcd/restore.conf.yml
systemctl daemon-reload
dropins="$(systemctl show -p DropInPaths --value regalia-etcd.service)"
case "$dropins" in *"$ETCD_GUARD/10-restore-pending.conf $RESTORE_DROPIN"*) true;; *) false;; esac
ok $? "systemd reads 10-restore-pending.conf before restore's 50-restore.conf ($dropins)"
started regalia-etcd.service; ok $? "with restore's drop-in, etcd starts on staging though the marker is there (ConditionResult=yes)"
skipped regalia-kms.service; ok $? "and the daemon is still skipped"
systemctl stop regalia-etcd.service
rm -f -- "$RESTORE_DROPIN" /run/regalia-etcd/restore.conf.yml
systemctl daemon-reload
skipped regalia-etcd.service; ok $? "the drop-in gone and the marker still there: etcd is skipped again"
rm -f -- "$MARK"
systemctl daemon-reload
started regalia-etcd.service; ok $? "the marker removed (the restore's exchange): etcd starts"
started regalia-kms.service; ok $? "and so does the daemon"
systemctl stop regalia-kms.service

echo
echo "etcd-unit-sandbox: $passed passed, $failed failed"
[ "$failed" = 0 ]
