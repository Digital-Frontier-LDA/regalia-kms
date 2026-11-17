#!/usr/bin/env bash
# etc-factory.sh — does a verity-/usr host's /etc come back from the image, with the image's users? (regalia-kms#61)
#
#   sudo e2e/etc-factory.sh ROOTFS      (ROOTFS: build-rootfs.sh's rootfs.tar, or a directory holding such a tree)
#
# A booted host has / on a tmpfs and /usr from the verity image: /etc is EMPTY until something makes it. This makes
# such a root from the image's own /usr, nothing else (an empty /etc and /var), and runs the image's own
# systemd-tmpfiles and systemd-sysusers in it (chroot), in the two orders a boot could take:
#
#   CONTROL  systemd's order without regalia-etc-factory.service: systemd-sysusers on the empty /etc, then the copy.
#            sysusers writes /etc/passwd itself, allocating the image's system users again in its own order, and the
#            copy then leaves that file alone (C never replaces). It MUST differ from the image: if it does not, this
#            test cannot tell the orders apart and fails rather than pass on nothing.
#   SHIPPED  the order the image's units give: regalia-etc-factory.service's ExecStart (read from the unit in the
#            image), then systemd-sysusers (which must find every account and change nothing), then the full
#            systemd-tmpfiles-setup pass. passwd, group, shadow and gshadow must be the image's byte for byte, and
#            the whole factory tree must be in /etc (type, mode, owner, content), PID 1's machine-id excepted.
#
# Also: every per-host /etc path is a link to its /var name and that directory is made; the factory copy holds none
# of them (L+ ones excepted: a package's file the link replaces); the copied files keep the image's mtimes.
# It needs root (chroot, ownership), and nothing but the tree: no network, no boot. CI: rootfs-reproducible.sh runs it
# on the build it has just made. The units' order itself is a boot's: K61V-4's QEMU boots measure it.
set -euo pipefail
cd "$(dirname "$0")/.."
export LC_ALL=C
[ "$(id -u)" = 0 ] || { echo "etc-factory: run as root"; exit 2; }
SRC="${1:?usage: etc-factory.sh ROOTFS (rootfs.tar or a tree)}"
W="$(mktemp -d /var/tmp/regalia-etc-factory.XXXXXX)"
case "$W" in /var/tmp/regalia-etc-factory.??????) ;; *) echo "etc-factory: unexpected work directory $W"; exit 2 ;; esac
MOUNTS=()
# Unmount everything under $W (newest first), and remove $W only if nothing is mounted there any more: a bind of the
# image's /usr (or of /proc) left mounted would otherwise be descended into, --one-file-system or not (a bind of the
# same filesystem is not another one).
cleanup(){
  local i
  for (( i=${#MOUNTS[@]}-1; i>=0; i-- )); do umount "${MOUNTS[$i]}" 2>/dev/null || umount -l "${MOUNTS[$i]}" 2>/dev/null || true; done
  if awk -v w="$W/" 'index($2 "/", w) == 1 { found = 1 } END { exit !found }' /proc/self/mounts; then
    echo "etc-factory: something is still mounted under $W: left in place, not removed" >&2
    return 0
  fi
  rm -rf --one-file-system -- "$W"
}
trap cleanup EXIT
fails=0; checks=0
ok(){ checks=$((checks + 1)); echo "  ok    $*"; }
bad(){ checks=$((checks + 1)); fails=$((fails + 1)); echo "  FAIL  $*"; }

if [ -d "$SRC" ]; then IMG="$SRC"; else IMG="$W/img"; mkdir "$IMG"; tar -x --numeric-owner -f "$SRC" -C "$IMG"; fi
F="$IMG/usr/share/factory/etc"
[ -d "$F" ] || { echo "etc-factory: $SRC has no /usr/share/factory/etc"; exit 2; }
UNIT="$IMG/usr/lib/systemd/system/regalia-etc-factory.service"
CONF="$IMG/usr/lib/tmpfiles.d/00-regalia-etc.conf"
[ -f "$UNIT" ] && [ -f "$CONF" ] || { echo "etc-factory: the image lacks regalia-etc-factory.service or tmpfiles.d/00-regalia-etc.conf"; exit 2; }
EXEC="$(sed -n 's/^ExecStart=//p' "$UNIT")"
[ -n "$EXEC" ] || { echo "etc-factory: the unit has no ExecStart"; exit 2; }
echo "### the image's systemd: $(chroot "$IMG" systemd-tmpfiles --version | head -1)"
echo "### regalia-etc-factory.service runs: $EXEC"

# a root as a booted host has it: the image's /usr (read-only), the merged-/usr links, everything else empty. Sets
# NEWROOT; called in THIS shell (never in $(...)), so every mount is recorded in MOUNTS for cleanup.
newroot(){
  local r="$W/$1"
  mkdir -p "$r/usr" "$r/etc" "$r/var" "$r/run" "$r/tmp" "$r/proc" "$r/dev"
  for l in bin sbin lib lib64 lib32 libx32; do [ -L "$IMG/$l" ] && cp -P "$IMG/$l" "$r/$l"; done
  mount --bind "$IMG/usr" "$r/usr"; MOUNTS+=("$r/usr")
  mount -o remount,bind,ro "$r/usr" || { echo "etc-factory: the image's /usr could not be made read-only"; exit 2; }
  mount --bind /proc "$r/proc"; MOUNTS+=("$r/proc")
  NEWROOT="$r"
}
inroot(){ local r="$1"; shift; chroot "$r" env -i PATH=/usr/sbin:/usr/bin LC_ALL=C SYSTEMD_LOG_LEVEL=warning "$@"; }
accounts="passwd group shadow gshadow"

echo "### CONTROL: systemd-sysusers on the empty /etc, then the factory copy"
newroot control; C="$NEWROOT"
inroot "$C" systemd-sysusers >"$W/control-sysusers.log" 2>&1 || true
inroot "$C" systemd-tmpfiles --create --boot --prefix=/etc /usr/lib/tmpfiles.d/00-regalia-etc.conf >"$W/control-tmpfiles.log" 2>&1 || true
differ=""
for f in $accounts; do cmp -s "$C/etc/$f" "$F/$f" || differ="$differ $f"; done
if [ -n "$differ" ]; then
  ok "the other order loses the image's accounts:$differ differ from the image's"
  # name what moved: an account missing, or at another ID
  python3 -I - "$F/passwd" "$C/etc/passwd" "$F/group" "$C/etc/group" <<'PY'
import sys
def ids(path):
    try:
        return {l.split(":")[0]: l.split(":")[2] for l in open(path) if l.count(":") >= 3}
    except FileNotFoundError:
        return {}
for kind, (image, control) in (("user", sys.argv[1:3]), ("group", sys.argv[3:5])):
    a, b = ids(image), ids(control)
    moved = ["%s %s->%s" % (n, a[n], b[n]) for n in sorted(a) if n in b and a[n] != b[n]]
    missing = sorted(set(a) - set(b))
    print("        %ss at another ID (image->control): %s" % (kind, ", ".join(moved) or "none"))
    print("        %ss missing: %s" % (kind, ", ".join(missing) or "none"))
PY
else
  bad "CONTROL: the other order gives the image's accounts too, so this test cannot show the order matters"
fi

echo "### SHIPPED: regalia-etc-factory.service, then systemd-sysusers, then systemd-tmpfiles-setup"
newroot shipped; S="$NEWROOT"
printf '0123456789abcdef0123456789abcdef\n' > "$S/etc/machine-id"     # what PID 1 has written before any unit
read -r -a argv <<< "$EXEC"
inroot "$S" "${argv[@]}" >"$W/shipped-factory.log" 2>&1 && ok "the unit's ExecStart ran" || { bad "the unit's ExecStart failed:"; cat "$W/shipped-factory.log"; }
for f in $accounts; do cp -p "$S/etc/$f" "$W/before-sysusers.$f" 2>/dev/null || true; done
inroot "$S" systemd-sysusers >"$W/shipped-sysusers.log" 2>&1 && ok "systemd-sysusers ran" || { bad "systemd-sysusers failed:"; cat "$W/shipped-sysusers.log"; }
changed=""
for f in $accounts; do cmp -s "$S/etc/$f" "$W/before-sysusers.$f" || changed="$changed $f"; done
[ -z "$changed" ] && ok "systemd-sysusers found every account and changed nothing" || bad "systemd-sysusers changed:$changed"
# a cache compiled from another image's profiles, left on /var: the full pass must empty it
mkdir -p "$S/var/cache/apparmor/stale.0" && echo stale > "$S/var/cache/apparmor/stale.0/usr.sbin.regalia-kms"
inroot "$S" systemd-tmpfiles --create --remove --boot --exclude-prefix=/dev >"$W/shipped-setup.log" 2>&1 \
  && ok "the full tmpfiles pass (systemd-tmpfiles-setup's) ran" || { bad "the full tmpfiles pass failed:"; tail -20 "$W/shipped-setup.log"; }
for f in $accounts; do
  cmp -s "$S/etc/$f" "$F/$f" && ok "/etc/$f is the image's, byte for byte" || bad "/etc/$f differs from the image's"
done
ids="$(python3 -I -c 'import sys; print(", ".join(l.split(":")[0] + "=" + l.split(":")[2] for l in open(sys.argv[1]) if l.startswith("regalia")))' "$S/etc/passwd")"
echo "        the image's regalia users, kept: $ids"

echo "### the factory tree is in /etc"
python3 -I - "$F" "$S/etc" "$CONF" <<'PY' && ok "every factory entry is in /etc: type, mode, owner, content, mtime (per-host links and PID 1's machine-id aside)" || bad "the factory tree is not what /etc holds (above)"
import hashlib, os, stat, sys
factory, etc, conf = sys.argv[1:4]
links = {}
for line in open(conf):
    f = line.split()
    if f and f[0] in ("L", "L+") and f[1].startswith("/etc/"):
        links[f[1][len("/etc/"):]] = f[6]
bad = []
for dirpath, dirs, files in os.walk(factory):
    for name in dirs + files:
        p = os.path.join(dirpath, name)
        rel = os.path.relpath(p, factory)
        if rel == "machine-id" or any(rel == l or rel.startswith(l + "/") for l in links):
            continue
        q = os.path.join(etc, rel)
        try:
            a, b = os.lstat(p), os.lstat(q)
        except FileNotFoundError:
            bad.append("missing " + rel)
            continue
        if (stat.S_IFMT(a.st_mode), stat.S_IMODE(a.st_mode), a.st_uid, a.st_gid) != (stat.S_IFMT(b.st_mode), stat.S_IMODE(b.st_mode), b.st_uid, b.st_gid):
            bad.append("%s: %o %d:%d, image %o %d:%d" % (rel, b.st_mode, b.st_uid, b.st_gid, a.st_mode, a.st_uid, a.st_gid))
        elif stat.S_ISLNK(a.st_mode) and os.readlink(p) != os.readlink(q):
            bad.append("%s -> %s, image -> %s" % (rel, os.readlink(q), os.readlink(p)))
        elif stat.S_ISREG(a.st_mode):
            if hashlib.sha256(open(p, "rb").read()).digest() != hashlib.sha256(open(q, "rb").read()).digest():
                bad.append("%s: other content" % rel)
            elif int(a.st_mtime) != int(b.st_mtime):
                bad.append("%s: mtime %d, image %d" % (rel, b.st_mtime, a.st_mtime))
for b in bad[:40]:
    print("        " + b)
if bad:
    print("        (%d differences)" % len(bad))
sys.exit(1 if bad else 0)
PY
extra="$(cd "$S/etc" && find . -mindepth 1 | sed 's|^\./||' | sort | while read -r p; do [ -e "$F/$p" ] || [ -L "$F/$p" ] || echo "$p"; done | paste -sd' ' -)"
echo "        in /etc and not in the factory copy (links, and what systemd's own tmpfiles add): ${extra:-nothing}"
[ "$(cat "$S/etc/machine-id")" = 0123456789abcdef0123456789abcdef ] && ok "PID 1's /etc/machine-id was not replaced by the image's empty one" \
  || bad "/etc/machine-id was replaced"

echo "### the machine ID and the AppArmor cache, on /var"
[ "$(cat "$S/var/lib/dbus/machine-id" 2>/dev/null)" = 0123456789abcdef0123456789abcdef ] && [ ! -L "$S/var/lib/dbus/machine-id" ] \
  && ok "PID 1's machine ID is kept on /var (/var/lib/dbus/machine-id, a file, not dbus.conf's link back to /etc)" \
  || bad "/var/lib/dbus/machine-id is $(readlink "$S/var/lib/dbus/machine-id" || cat "$S/var/lib/dbus/machine-id" 2>&1), not PID 1's ID"
[ -d "$S/var/cache/apparmor" ] && [ -z "$(ls -A "$S/var/cache/apparmor")" ] && ok "the AppArmor cache is emptied" \
  || bad "the AppArmor cache still holds: $(ls -A "$S/var/cache/apparmor" 2>&1)"

echo "### this host's files: links to /var"
# the directory-backed ones, as the IMAGE's deploy package says (hostpaths.DIRECTORIES), never read from the tmpfiles
# file under test: a `d` line removed there must fail here
DIRS="$(python3 -I -c 'import sys; sys.path.insert(0, sys.argv[1]); from deploy.baremetal import hostpaths
print(" ".join(hostpaths.persistent(p) for p in hostpaths.DIRECTORIES))' "$IMG/usr/lib/regalia-kms")" \
  || { echo "etc-factory: the image's deploy/baremetal/hostpaths.py has no DIRECTORIES"; exit 2; }
[ -n "$DIRS" ] || { echo "etc-factory: hostpaths.DIRECTORIES is empty"; exit 2; }
while read -r kind path _ _ _ _ target; do
  case "$kind" in L|L+) ;; *) continue ;; esac
  [ "$(readlink "$S$path")" = "$target" ] && ok "$path -> $target" || bad "$path is $(readlink "$S$path" || echo 'not a link'), not a link to $target"
  case "$target" in
    /usr/*) [ -f "$S$target" ] && ok "  $target is in the image" || bad "  $target is not in the image" ;;
    *) if [[ " $DIRS " == *" $target "* ]]; then          # a directory-backed link: the target itself (#723 review)
         [ -d "$S$target" ] && [ ! -L "$S$target" ] && ok "  $target is made, a directory" || bad "  $target is not made (a directory)"
       else
         [ -d "$S$(dirname "$target")" ] && ok "  $(dirname "$target") is made" || bad "  $(dirname "$target") is not made"
       fi ;;
  esac
  if [ "$kind" = L ] && { [ -e "$F${path#/etc}" ] || [ -L "$F${path#/etc}" ]; }; then bad "  the factory copy holds ${path}: the image carries a per-host file"; fi
done < <(grep -E '^L\+? ' "$CONF")

if [ "$fails" = 0 ]; then echo "etc-factory: PASS ($checks checks)"; else echo "etc-factory: FAIL ($fails of $checks)"; exit 1; fi
