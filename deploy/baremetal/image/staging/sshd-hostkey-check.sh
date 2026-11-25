#!/bin/sh
# STAGING IMAGE VARIANT ONLY (regalia-kms-u2t): regalia-staging-sshd's host-key check. The staging host's SSH host key
# is made ONCE off-box, per node, and installed onto /var by the per-host step (stage-perhost) before the first boot, so
# the operator pins its fingerprint from the bundle and no connection ever trusts a key on first use. sshd never makes
# one here: a host key that is missing, empty, readable by group or others, not a regular file, or without the public
# half the operator pinned refuses the start (fail closed), naming what is wrong. A key made at first start was the
# trust-on-first-use step of the 2026-11-25 --wipe reinstall.
set -eu
key=${1:-/var/lib/regalia-staging/ssh/ssh_host_ed25519_key}
fix="install the node's bundled host key with stage-perhost (regalia-kms-u2t); sshd never makes one"
refuse() { echo "sshd-hostkey-check: $1: refusing to start regalia-staging-sshd; $fix" >&2; exit 1; }
[ -e "$key" ] || [ -L "$key" ] || refuse "no host key at $key"
if [ -L "$key" ] || [ ! -f "$key" ]; then refuse "$key is not a regular file"; fi
[ -s "$key" ] || refuse "$key is empty"
case "$(stat -c %a "$key")" in
  600|400) ;;
  *) refuse "$key is mode $(stat -c %a "$key"), not 0600 (or 0400)" ;;
esac
[ -s "$key.pub" ] || refuse "no public half at $key.pub (the operator's pin comes from the bundle's copy)"
