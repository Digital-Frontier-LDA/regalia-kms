#!/bin/busybox sh
export PATH=/usr/bin:/usr/sbin:/bin:/sbin
/bin/busybox --install -s /bin
mkdir -p /dev /proc /sys /run /tmp /newroot
mount -t devtmpfs devtmpfs /dev
ln -s /proc/self/fd /dev/fd
ln -s fd/0 /dev/stdin
ln -s fd/1 /dev/stdout
ln -s fd/2 /dev/stderr
mount -t proc proc /proc
mount -t sysfs sysfs /sys
for module in virtio_pci virtio_blk virtio_net tpm_tis wireguard dm_crypt ext4 xts; do
  if modprobe "$module" >/dev/null 2>&1; then
    echo "REGALIA_MODULE_READY_$module"
  else
    echo "REGALIA_MODULE_UNAVAILABLE_$module"
  fi
done
ip link set eth0 up
ip addr add 10.0.2.15/24 dev eth0
ip route add default via 10.0.2.2
export TPM2TOOLS_TCTI=device:/dev/tpmrm0 PYTHONPATH=/bootstrap PYTHONDONTWRITEBYTECODE=1
python3 -c 'print("REGALIA_PYTHON_READY")'
if python3 /bootstrap/guest.py | cryptsetup open --batch-mode --key-file - /dev/vda root; then
  echo REGALIA_DISK_OPENED
  if grep -q 'lab.format=1' /proc/cmdline; then
    mkfs.ext4 -q -F /dev/mapper/root
    mount /dev/mapper/root /newroot || poweroff -f
    mkdir -p /newroot/bin /newroot/dev /newroot/proc /newroot/sys /newroot/tmp
    cp /bin/busybox /newroot/bin/busybox
    ln -s busybox /newroot/bin/sh
    cp /root-init /newroot/root-init
    chmod 755 /newroot/root-init
    echo disposable-encrypted-root > /newroot/marker
  else
    mount /dev/mapper/root /newroot || poweroff -f
  fi
  mount --move /dev /newroot/dev
  mount --move /proc /newroot/proc
  mount --move /sys /newroot/sys
  exec switch_root /newroot /bin/busybox sh /root-init
else
  cryptsetup status root >/dev/null 2>&1
  mapper_status=$?
  if [ "$mapper_status" -eq 4 ] && [ ! -e /dev/mapper/root ]; then
    echo REGALIA_UNLOCK_REFUSED_ROOT_CLOSED
  fi
fi
poweroff -f
