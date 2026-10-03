#!/bin/sh
set -eu
umask 077
exec >>/var/log/regalia-image-build.log 2>&1
trap 'status=$?; if [ "$status" -ne 0 ]; then
  echo REGALIA_BUILD_FAILED >/dev/ttyS0
  tail -n 60 /var/log/regalia-image-build.log >/dev/ttyS0
fi' EXIT
echo REGALIA_BUILD_BEGIN >/dev/ttyS0
# d-i leaves its cdrom entry active until later installer cleanup. The chroot
# cannot refresh it. Disable that entry; keep network Release signatures intact.
if [ -f /etc/apt/sources.list ]; then
  sed -i '/^[[:space:]]*deb.*cdrom:/s/^/# installer-only: /' /etc/apt/sources.list
fi
# Installer media can contain older packages than the authenticated security
# repository. Upgrade the complete installed set before compiling or cleanup.
# APT retains its Release signature/package hash and expiry verification.
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get --no-install-recommends dist-upgrade -y
mkdir -p /tmp/regalia-source
tar -xf /tmp/regalia-source.tar -C /tmp/regalia-source
cd /tmp/regalia-source
revision=$(cat BUILD_COMMIT)
case "$revision" in *[!0-9a-f]*|'') exit 1 ;; esac
# Debian authenticates the compiler package. Go's automatic newer toolchain and
# module downloads use its checksum database; never disable those checks.
export GOSUMDB=sum.golang.org GOPROXY=https://proxy.golang.org GOTOOLCHAIN=auto
export GONOSUMDB= GONOPROXY= CGO_ENABLED=1
# d-i's in-target environment can set HOME=/, making Go default to /go. Use
# explicit disposable paths so toolchains/modules cannot survive image cleanup.
export GOPATH=/tmp/regalia-build/gopath GOCACHE=/tmp/regalia-build/cache
export GOMODCACHE=/tmp/regalia-build/modules
go version >/var/log/regalia-go-version.txt
go mod download
go mod verify
go build -trimpath -buildvcs=false -ldflags="-buildid= -X main.version=appliance-lab-$revision" \
  -o /usr/local/sbin/regalia-kms ./cmd/regalia-kms
# The build umask must not prevent the service account executing its public
# binary or systemd reading its public unit/drop-ins. All remain root-owned.
chmod 0755 /usr/local/sbin/regalia-kms
go version -m /usr/local/sbin/regalia-kms >/var/log/regalia-binary-build.txt
# Public planned bindings only. Acceptance needs a structurally valid manifest
# under the current daemon contract; it removes this fixture before export.
install -d -m 0755 /usr/local/share/regalia-appliance
install -m 0644 config/custody-manifest.example.json /usr/local/share/regalia-appliance/custody-fixture.json
install -m 0644 deploy/systemd/regalia-kms.service /etc/systemd/system/regalia-kms.service
mkdir -p /etc/systemd/system/regalia-kms.service.d /etc/regalia-kms
chmod 0755 /etc/systemd/system/regalia-kms.service.d
install -m 0644 deploy/baremetal/regalia-kms-hardening.conf.example \
  /etc/systemd/system/regalia-kms.service.d/hardening.conf
install -m 0644 deploy/baremetal/apparmor/usr.local.sbin.regalia-kms /etc/apparmor.d/
# Compilation checks the exact installed profile; kernel enforcement is checked
# during guest acceptance. No '-' prefix permits a missing profile fallback.
apparmor_parser --skip-kernel-load -Q /etc/apparmor.d/usr.local.sbin.regalia-kms
cat >/etc/systemd/system/regalia-kms.service.d/commissioning.conf <<'EOF'
[Unit]
ConditionPathExists=/etc/regalia-kms/commissioned
ConditionPathExists=/etc/regalia-kms/config.json
[Service]
CapabilityBoundingSet=
LockPersonality=yes
EOF
chmod 0644 /etc/systemd/system/regalia-kms.service.d/commissioning.conf
useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin regalia-kms
# The private build umask creates this directory as root-only. The daemon must
# be able to traverse it to read commissioned configuration, without write access.
install -d -m 0750 -o root -g regalia-kms /etc/regalia-kms
passwd -l root
systemctl enable regalia-kms.service nftables.service apparmor.service
systemctl mask systemd-random-seed.service
# The verification service writes to ttyS0. A serial getty can revoke that TTY
# while the export is running, losing the final marker. Accounts are locked and
# this uncommissioned template needs no serial login service.
systemctl mask serial-getty@ttyS0.service
sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="console=ttyS0,115200 regalia.image_verify=1 apparmor=1 security=apparmor"/' /etc/default/grub
update-grub
cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset
table inet regalia {
  chain input { type filter hook input priority 0; policy drop; iifname "lo" accept; }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy drop; oifname "lo" accept; }
}
EOF
cat >/etc/sysctl.d/90-regalia.conf <<'EOF'
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.yama.ptrace_scope=2
fs.protected_hardlinks=1
fs.protected_symlinks=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv6.conf.all.accept_redirects=0
EOF
mkdir -p /etc/systemd/journald.conf.d
cat >/etc/systemd/journald.conf.d/regalia.conf <<'EOF'
[Journal]
Storage=volatile
SystemMaxUse=32M
EOF
# No credentials or private configuration are generated in this reusable disk.
# Remove build-time tools, source, toolchain caches and installer SSH host keys.
apt-get purge -y golang-go gcc libc6-dev
# The reusable appliance has no interactive administration account. Editors
# belong on recovery media; remove their parser attack surface from this disk.
for package in vim-tiny vim-common nano; do
  if dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null | grep -q '^installed$'; then
    apt-get purge -y "$package"
  fi
done
# Remove reviewed installer/partition tools, unused libraries and binutils left
# from compilation. APT must not expand this list or remove required roles.
python3 -I /tmp/regalia-source/lab/appliance/minimize.py --apply >/var/log/regalia-minimization.json
apt-get autoremove --purge -y
# A fresh baseline carries one current kernel. CURRENT/NEXT overlap belongs to
# the controlled update procedure, rather than an unreviewed installer fallback.
keep_kernel=$(dpkg-query -W -f='${Depends}\n' linux-image-amd64 | awk '{print $1}')
case "$keep_kernel" in linux-image-[0-9]*-amd64) ;; *) exit 1 ;; esac
for package in $(dpkg-query -W -f='${Package} ${db:Status-Status}\n' 'linux-image-[0-9]*' | awk '$2 == "installed" {print $1}'); do
  if [ "$package" != "$keep_kernel" ]; then apt-get purge -y "$package"; fi
done
# Exercise the update path after removing compilation tools. A freshly generated
# initramfs and GRUB configuration must still reach guest acceptance/normal boot.
update-initramfs -u -k all
update-grub
# locales post-removal deletes its old config; write the builtin locale after
# all package cleanup has finished. C.UTF-8 is supplied by libc, without locales.
printf '%s\n' 'LANG=C.UTF-8' >/etc/locale.conf
apt-get clean
rm -rf /root/go /root/.cache /tmp/regalia-build /tmp/regalia-source /tmp/regalia-source.tar
rm -f /etc/ssh/ssh_host_* /var/lib/systemd/random-seed
rm -rf /var/lib/apt/lists/*
truncate -s 0 /etc/machine-id
rm -f /var/lib/dbus/machine-id
dpkg-query -W -f='${Package}\t${Version}\n' >/var/log/regalia-packages.tsv
install -m 0700 /tmp/regalia-acceptance.sh /usr/local/sbin/regalia-image-acceptance
cat >/etc/systemd/system/regalia-image-acceptance.service <<'EOF'
[Unit]
Description=Verify uncommissioned Regalia image in QEMU
ConditionKernelCommandLine=regalia.image_verify=1
After=nftables.service apparmor.service systemd-sysctl.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/regalia-image-acceptance
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyS0
[Install]
WantedBy=multi-user.target
EOF
systemctl enable regalia-image-acceptance.service
# The serial console records only fixed markers and public inventory, not build
# logs or any credential. The host must require this marker before publishing.
echo REGALIA_BUILD_COMPLETE >/dev/ttyS0
rm -f /tmp/regalia-finish.sh /tmp/regalia-acceptance.sh
