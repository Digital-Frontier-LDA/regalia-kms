#!/usr/bin/env bash
# dracut-module-check.sh SYSROOT MODULE_DIR: run a dracut module's own check() against the tree an initrd is
# about to be built from, as dracut would, and pass only if it says "include me when asked" (255).
#
# #330: dracut stops for a requested module whose check() fails, so a requirement the module gains and a build
# does not meet ends that build at dracut, with nothing compared. Running check() ITSELF, rather than a list of
# what it requires, sees any requirement whatever its form (a fixed path, one of several libraries, a line in an
# installed unit, a binary). The tree is read as dracut's --sysroot: dracutsysrootdir is SYSROOT, so a chroot's
# absolute paths and this check's agree.
#
# Provided here, as dracut provides them: derror (to stderr), require_binaries (each on the tree's PATH dirs),
# moddir, systemdsystemunitdir, and hostonly unset (the drift and boot builds pass --no-hostonly).
set -uo pipefail
SYSROOT="${1:?usage: dracut-module-check.sh SYSROOT MODULE_DIR}"
MODULE_DIR="${2:?usage: dracut-module-check.sh SYSROOT MODULE_DIR}"
[ -f "$MODULE_DIR/module-setup.sh" ] || { echo "dracut-module-check: no module-setup.sh in $MODULE_DIR" >&2; exit 2; }
out="$(
  derror() { echo "$*" >&2; }
  require_binaries() {
    local b d
    for b in "$@"; do
      for d in /usr/bin /usr/sbin /bin /sbin; do [ -x "$SYSROOT$d/$b" ] && continue 2; done
      derror "dracut-module-check: $b is not in the tree's PATH (require_binaries)"
      return 1
    done
  }
  export dracutsysrootdir="$SYSROOT" moddir="$MODULE_DIR" systemdsystemunitdir=/usr/lib/systemd/system
  unset hostonly
  # shellcheck source=/dev/null
  . "$MODULE_DIR/module-setup.sh"
  check
  echo "rc=$?"
)" 2>&1
rc="$(sed -n 's/^rc=//p' <<< "$out" | tail -1)"
msgs="$(grep -v '^rc=' <<< "$out")"
if [ "$rc" = 255 ]; then
  echo "dracut-module-check: $(basename "$MODULE_DIR")'s check() passes on $SYSROOT"
  exit 0
fi
echo "dracut-module-check: $(basename "$MODULE_DIR")'s check() returned ${rc:-nothing} on $SYSROOT, not 255: dracut would stop at it" >&2
[ -z "$msgs" ] || printf '%s\n' "$msgs" >&2
exit 1
