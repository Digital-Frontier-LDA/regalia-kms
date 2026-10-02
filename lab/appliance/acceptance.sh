#!/bin/sh
set -eu
trap 'echo REGALIA_FAIL:acceptance-command' EXIT
fail() { echo "REGALIA_FAIL:$1"; /sbin/poweroff -f; exit 1; }
check() { "$@" || fail "$1"; }
echo REGALIA_ACCEPTANCE_BEGIN
check test "$(cat /etc/debian_version | cut -d. -f1)" = 13
check test "$(cat /proc/1/comm)" = systemd
check test ! -e /etc/regalia-kms/config.json
check test ! -e /etc/regalia-kms/commissioned
check test -x /usr/local/sbin/regalia-kms
for directory in /go /.cache/go-build /root/go /tmp/regalia-build; do
  check test ! -e "$directory"
done
kernel_count=$(dpkg-query -W -f='${db:Status-Status}\n' 'linux-image-[0-9]*' | grep -c '^installed$')
check test "$kernel_count" = 1
/usr/local/sbin/regalia-kms -version
check systemctl start regalia-kms.service
check test "$(systemctl show regalia-kms.service -p ActiveState --value)" = inactive
check test "$(systemctl show regalia-kms.service -p ConditionResult --value)" = no
check test "$(systemctl show regalia-kms.service -p NoNewPrivileges --value)" = yes
check test "$(systemctl show regalia-kms.service -p ProtectSystem --value)" = strict
check test -z "$(systemctl show regalia-kms.service -p CapabilityBoundingSet --value)"
check systemctl is-active nftables.service
check sh -c 'nft list chain inet regalia input | grep -q "policy drop"'
check sh -c 'nft list chain inet regalia output | grep -q "policy drop"'
check sh -c 'grep -q "^root:[!*]" /etc/shadow'
check sh -c 'getent passwd regalia-kms | grep -q "/usr/sbin/nologin$"'
check sh -c 'test -z "$(ss -H -lnt)"'
check sh -c 'test "$(cat /sys/module/apparmor/parameters/enabled)" = Y'
check sh -c 'test "$(cat /proc/sys/kernel/dmesg_restrict)" = 1'
check sh -c 'test "$(cat /proc/sys/kernel/kptr_restrict)" = 2'
check sh -c 'test -z "$(swapon --noheadings --show)"'
for package in openssh-server docker.io avahi-daemon cups bluez golang-go gcc vim-tiny vim-common nano; do
  if dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null | grep -q '^installed$'; then
    fail "unexpected-package-$package"
  fi
done
echo REGALIA_PACKAGE_INVENTORY_BEGIN
cat /var/log/regalia-packages.tsv
echo REGALIA_PACKAGE_INVENTORY_END
mkdir -p /mnt/regalia-export
check mount -t 9p -o trans=virtio,version=9p2000.L regalia_export /mnt/regalia-export
cp /var/log/regalia-packages.tsv /mnt/regalia-export/packages.tsv
cp /var/log/regalia-go-version.txt /mnt/regalia-export/go-version.txt
cp /var/log/regalia-binary-build.txt /mnt/regalia-export/binary-build.txt
cp /usr/local/sbin/regalia-kms /mnt/regalia-export/regalia-kms
# Remove the automatic verification boot flag after the successful prototype
# test; normal boots retain the same commissioning and network restrictions.
sed -i 's/ regalia.image_verify=1//' /etc/default/grub
update-grub
truncate -s 0 /etc/machine-id
rm -f /var/lib/systemd/random-seed
tar --one-file-system --exclude='./proc' --exclude='./sys' --exclude='./dev' \
  --exclude='./run' --exclude='./tmp' --exclude='./mnt' --exclude='./var/log/journal' \
  -C / -I 'gzip -1' -cf /mnt/regalia-export/rootfs.tar.gz .
sync
echo REGALIA_ACCEPTANCE_PASS
trap - EXIT
/sbin/poweroff
