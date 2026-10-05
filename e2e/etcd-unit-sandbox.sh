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
# encrypted with this machine's credential key. Then:
#   the unit starts, reaches ready (sd_notify) and stays up, with no restart and no killed system call;
#   the socket is /run/regalia-etcd/client.sock:0, mode 0770, group regalia-etcd-client;
#   a process in that group puts and reads a key through it; one outside the group is refused;
#   the data directory is 0700, owned by regalia-etcd; every file in it is unreadable by others.
# It removes what it made by its exact paths (the user and the groups too).
# shellcheck disable=SC2319  # file-wide: `ok $?` reads the check made just before it, on purpose
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C
[ "$(id -u)" = 0 ] || { echo "etcd-unit-sandbox: run as root"; exit 2; }
TAR="${1:?usage: etcd-unit-sandbox.sh ROOTFS_TAR}"
# not under /run (often noexec) nor /tmp or /var/tmp (the unit's PrivateTmp hides them): where an executable is run from
W="$(mktemp -d /usr/local/lib/etcd-unit-sandbox.XXXXXX)"
UNIT=/run/systemd/system/regalia-etcd.service
CONF=/etc/regalia/etcd.conf.yml
CRED=/etc/credstore.encrypted
made_regalia_dir=0 made_cred_dir=0
passed=0 failed=0
ok(){ if [ "$1" = 0 ]; then passed=$((passed + 1)); echo "  PASS $2"; else failed=$((failed + 1)); echo "  FAIL $2"; fi; }
cleanup(){
  systemctl stop regalia-etcd.service 2>/dev/null || true
  rm -f -- "$UNIT" "$CONF" "$CRED/regalia-etcd-peer.key"
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
tar -xf "$TAR" -C "$W" ./usr/bin/etcd ./usr/bin/etcdctl ./usr/lib/systemd/system/regalia-etcd.service
sed 's|^ExecStart=/usr/bin/etcd |ExecStart='"$W"'/usr/bin/etcd |' "$W/usr/lib/systemd/system/regalia-etcd.service" > "$UNIT"
[ "$(diff "$W/usr/lib/systemd/system/regalia-etcd.service" "$UNIT" | grep -c '^[<>]')" = 2 ]; ok $? "the unit is the image's, with only ExecStart's path changed"
# the user, the groups and the socket directory, as the image's sysusers.d and tmpfiles.d lines make them
groupadd --system regalia-etcd-client
useradd --system --user-group --home-dir /var/lib/regalia-etcd --no-create-home --shell /usr/sbin/nologin regalia-etcd
install -d -m 2750 -o regalia-etcd -g regalia-etcd-client /run/regalia-etcd
grep -qx 'd /run/regalia-etcd 2750 regalia-etcd regalia-etcd-client -' deploy/baremetal/units/regalia.tmpfiles.conf; ok $? "the socket directory is the image's tmpfiles line"
# a one-member cluster; the peer on loopback (the unit's IPAddressDeny drops traffic, it does not stop a bind)
[ -d /etc/regalia ] || { mkdir -p /etc/regalia; made_regalia_dir=1; }
cat > "$CONF" <<'EOF'
name: sandbox
data-dir: /var/lib/regalia-etcd/data
listen-client-urls: unix://client.sock:0
advertise-client-urls: unix://client.sock:0
listen-peer-urls: http://127.0.0.1:23890
initial-advertise-peer-urls: http://127.0.0.1:23890
initial-cluster: sandbox=http://127.0.0.1:23890
initial-cluster-state: new
EOF
[ -d "$CRED" ] || { mkdir -p "$CRED"; made_cred_dir=1; }
head -c 32 /dev/urandom | systemd-creds encrypt --with-key=host --name=etcd-peer.key - "$CRED/regalia-etcd-peer.key"
systemctl daemon-reload

set +e
echo "### the unit, started"
timeout 90 systemctl start regalia-etcd.service; ok $? "it starts and reaches ready (Type=notify)"
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
client "$(getent group nogroup | cut -d: -f3)" get sandbox >/dev/null 2>&1; [ $? != 0 ]; ok $? "a process outside the group is refused"

echo "### the data directory"
[ "$(stat -c '%a %U' /var/lib/regalia-etcd)" = "700 regalia-etcd" ]; ok $? "/var/lib/regalia-etcd is 0700, regalia-etcd's"
[ -z "$(find /var/lib/regalia-etcd -perm /o=rwx)" ]; ok $? "nothing in it is open to others"

echo
echo "etcd-unit-sandbox: $passed passed, $failed failed"
[ "$failed" = 0 ]
