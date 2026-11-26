#!/bin/sh
# STAGING IMAGE VARIANT ONLY (regalia-kms-u2t): regalia-staging-sshd's host-key check. The staging host's SSH host key
# is made ONCE off-box, per node, and installed onto /var by the per-host step (stage-perhost) before the first boot, so
# the operator pins its fingerprint from the bundle and no connection ever trusts a key on first use. sshd never makes
# one here. The start is refused (fail closed), naming what is wrong, when the private half is missing, empty, not a
# regular file, not root's, or readable by group or others; when the public half is missing, not a regular file, not
# root's, or not the private half's own public key (ssh-keygen -y, compared by algorithm and key blob); or when a
# directory holding them is not root's or is writable by group or others. A key made at first start was the
# trust-on-first-use step of the 2026-11-25 --wipe reinstall.
set -eu
key=${1:-/var/lib/regalia-staging/ssh/ssh_host_ed25519_key}
# the directories that must be root's and closed to group/other writes (the tests pass their own top)
top=${2:-/var/lib/regalia-staging}
fix="install the node's bundled host key with stage-perhost (regalia-kms-u2t); sshd never makes one"
refuse() { echo "sshd-hostkey-check: $1: refusing to start regalia-staging-sshd; $fix" >&2; exit 1; }
owner=${3:-0}   # root; the tests run unprivileged and pass their own uid (the unit passes no arguments)
regular() {  # $1 path, $2 what
  [ -e "$1" ] || [ -L "$1" ] || refuse "no $2 at $1"
  if [ -L "$1" ] || [ ! -f "$1" ]; then refuse "$1 is not a regular file"; fi
  [ -s "$1" ] || refuse "$1 is empty"
  [ "$(stat -c %u "$1")" = "$owner" ] || refuse "$1 is owned by uid $(stat -c %u "$1"), not $owner"
}
regular "$key" "host key"
case "$(stat -c %a "$key")" in
  600|400) ;;
  *) refuse "$key is mode $(stat -c %a "$key"), not 0600 (or 0400)" ;;
esac
regular "$key.pub" "public half (the operator's pin comes from the bundle's copy)"
case "$(stat -c %a "$key.pub")" in
  644|444|600|400) ;;
  *) refuse "$key.pub is mode $(stat -c %a "$key.pub"), writable by group or others" ;;
esac
# every directory from the key's up to $top: root's, and no group/other write (nobody else may swap a half in)
d=$(dirname "$key")
while :; do
  [ -d "$d" ] && [ ! -L "$d" ] || refuse "$d is not a directory"
  [ "$(stat -c %u "$d")" = "$owner" ] || refuse "$d is owned by uid $(stat -c %u "$d"), not $owner"
  case "$(stat -c %A "$d")" in ?????w????|????????w?) refuse "$d is writable by group or others";; esac
  [ "$d" = "$top" ] && break
  case "$d" in "$top"/*) d=$(dirname "$d") ;; *) refuse "$key is not under $top" ;; esac
done
derived=$(ssh-keygen -y -P "" -f "$key" 2>/dev/null </dev/null) || refuse "$key is not a readable unencrypted private key"
read -r ptype pblob _ < "$key.pub" || true
[ "$ptype" = ssh-ed25519 ] || refuse "$key.pub is ${ptype:-empty}, not ssh-ed25519"
set -- $derived
[ "$1 $2" = "$ptype $pblob" ] || refuse "$key.pub is not the public half of $key (the two are not one pair)"
