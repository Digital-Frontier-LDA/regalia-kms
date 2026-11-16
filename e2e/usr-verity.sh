#!/usr/bin/env bash
# usr-verity.sh — deploy/baremetal/image/usr-verity.sh on a stand-in /usr: the erofs + dm-verity image is reproducible,
# holds exactly the tree, and refuses a changed byte (#61, the dm-verity design, first slice).
#
#   sudo e2e/usr-verity.sh            (needs mkfs.erofs, fsck.erofs, veritysetup, python3: erofs-utils, cryptsetup-bin)
#
# A stand-in tree (owners, modes with setuid, a relative and an absolute symlink, a hard link, an empty file and
# directory, a 1 MiB file) is made twice: the second copy in reverse order, under another umask, with other times and at
# another path. Then:
#   REPRODUCIBLE   both trees give byte-identical usr.erofs, usr.verity and usr-verity.txt, at one seed and epoch,
#                  although only tree A's bin/tool carries an extended attribute (the builder's, never the image's)
#   THE CONTENT    the image, extracted by fsck.erofs, is the tree (path, type, mode, owner, sha256, link target), and
#                  every inode's time is the epoch
#   THE RECORD     the root hash is the one veritysetup verify accepts; usr_partuuid and usr_verity_partuuid are the
#                  first and the last 128 bits of it (systemd-veritysetup-generator's usrhash= convention); the salt and
#                  UUID in usr.verity's superblock are the record's
#   TAMPER         after ONE byte changed in the erofs superblock, in the 1 MiB file's data, or in the hash tree, and
#                  with one hex digit of the root hash changed, veritysetup verify refuses; the untouched copy, verified
#                  the same way just before, passes (the control)
#   INPUTS COUNT   another seed, another epoch, or one byte changed in one file gives another root hash
#   REFUSALS       a non-empty --out, a seed that is not a commit, a --usr that is a symlink, no --epoch: exit 2, --out
#                  left as it was
# Nothing here uses device-mapper or the kernel's erofs: the booted halt on a tampered block is the QEMU slice's.
# It writes only under one mktemp -d directory, removed at exit.
# shellcheck disable=SC2319  # file-wide: `ok $?` reads the check made just before it, on purpose
set -uo pipefail             # no -e: every check is counted by ok, and a failed one must not end the run unreported
cd "$(dirname "$0")/.." || exit 2
export LC_ALL=C TZ=UTC
[ "$(id -u)" = 0 ] || { echo "usr-verity: run as root (the stand-in tree has other owners)"; exit 2; }
for t in mkfs.erofs fsck.erofs veritysetup python3; do command -v "$t" >/dev/null || { echo "usr-verity: $t is required"; exit 2; }; done
BUILDER="$PWD/deploy/baremetal/image/usr-verity.sh"
W="$(mktemp -d /var/tmp/usr-verity-e2e.XXXXXX)" || exit 2
case "$W" in /var/tmp/usr-verity-e2e.*) ;; *) echo "usr-verity: unexpected work directory $W"; exit 2 ;; esac
trap 'rm -rf --one-file-system -- "$W"' EXIT
SEED=0123456789abcdef0123456789abcdef01234567
EPOCH=1760000000
passed=0 failed=0
ok(){ if [ "$1" = 0 ]; then passed=$((passed + 1)); echo "  PASS $2"; else failed=$((failed + 1)); echo "  FAIL $2"; fi; }
rec(){ sed -n "s/^$2=//p" "$1/usr-verity.txt"; }

# the stand-in /usr: ENTRIES in order; make_tree DIR forward|reverse
ENTRIES=(
  "d bin 0755 0 0" "f bin/tool 0755 0 0 tool" "f bin/setuid-tool 4755 0 0 setuid"
  "d lib 0755 0 0" "d lib/regalia-kms 0750 0 993" "f lib/regalia-kms/conf 0640 0 993 conf"
  "f lib/big 0644 0 0 BIG" "f lib/empty 0644 0 0 -" "d share/empty-dir 0700 105 110"
  "d share 0755 0 0" "f share/owned 0600 105 110 owned" "l share/rel ../bin/tool" "l share/abs /usr/bin/tool"
  "h share/hard lib/regalia-kms/conf"
)
make_tree(){
  local dir="$1" order="$2" i kind path mode uid gid content
  local -a idx
  mkdir -p "$dir"
  if [ "$order" = reverse ]; then for ((i = ${#ENTRIES[@]} - 1; i >= 0; i--)); do idx+=("$i"); done
  else for ((i = 0; i < ${#ENTRIES[@]}; i++)); do idx+=("$i"); done; fi
  for i in "${idx[@]}"; do
    read -r kind path mode uid gid content <<< "${ENTRIES[$i]}"
    mkdir -p "$dir/$(dirname "$path")"
    case "$kind" in
      d) mkdir -p "$dir/$path" ;;
      f) case "$content" in
           BIG) python3 -I -c 'import hashlib,sys; sys.stdout.buffer.write(b"".join(hashlib.sha256(b"%d" % i).digest() for i in range(32768)))' > "$dir/$path" ;;
           -) : > "$dir/$path" ;;
           *) printf '%s\n' "$content" > "$dir/$path" ;;
         esac ;;
      l) ln -sfn "$mode" "$dir/$path"; continue ;;
      h) continue ;;
    esac
  done
  for i in "${idx[@]}"; do      # owners and modes last (a reverse order made the parents after their children)
    read -r kind path mode uid gid content <<< "${ENTRIES[$i]}"
    case "$kind" in
      d|f) chown "$uid:$gid" "$dir/$path"; chmod "$mode" "$dir/$path" ;;
      h) ln "$dir/$mode" "$dir/$path" ;;
    esac
  done
  chmod 0755 "$dir"; chown 0:0 "$dir"
}
build(){ mkdir -p "$2"; "$BUILDER" --usr "$1" --seed "${3:-$SEED}" --epoch "${4:-$EPOCH}" --out "$2" >"$2.log" 2>&1; }
listing(){   # path, type, mode, uid, gid, sha256, link target, of every entry under $1 (sorted)
  python3 -I - "$1" <<'PY'
import hashlib, os, stat, sys
top = sys.argv[1]
for base, dirs, files in os.walk(top):
    dirs.sort()
    for name in sorted(dirs + files):
        p = os.path.join(base, name)
        s = os.lstat(p)
        kind = "l" if stat.S_ISLNK(s.st_mode) else "d" if stat.S_ISDIR(s.st_mode) else "f" if stat.S_ISREG(s.st_mode) else "?"
        digest = hashlib.sha256(open(p, "rb").read()).hexdigest() if kind == "f" else ""
        link = os.readlink(p) if kind == "l" else ""
        print("\t".join([os.path.relpath(p, top), kind, "%o" % stat.S_IMODE(s.st_mode), str(s.st_uid), str(s.st_gid), digest, link]))
PY
}

echo "### reproducible: two trees made differently, one image"
make_tree "$W/tree-a" forward
( umask 077; make_tree "$W/elsewhere/tree-b" reverse )
touch -d '2001-02-03 04:05:06' "$W/elsewhere/tree-b/lib/big" "$W/elsewhere/tree-b/share"
# an extended attribute on tree A only, as a builder's filesystem can add (a label, a user attribute): not the image's
python3 -I -c 'import os,sys; os.setxattr(sys.argv[1], "user.regalia-builder", b"1"); print(os.listxattr(sys.argv[1]))' "$W/tree-a/bin/tool" \
  | grep -q regalia-builder; ok $? "control: tree A's bin/tool carries a builder's xattr, tree B's does not"
build "$W/tree-a" "$W/out-a"; ok $? "the builder makes an image from tree A"
build "$W/elsewhere/tree-b" "$W/out-b"; ok $? "the builder makes an image from tree B (reverse order, umask 077, other times, other path)"
[ "$(listing "$W/tree-a")" = "$(listing "$W/elsewhere/tree-b")" ]; ok $? "control: the two trees hold the same entries"
for f in usr.erofs usr.verity usr-verity.txt; do cmp -s "$W/out-a/$f" "$W/out-b/$f"; ok $? "$f is byte-identical from both trees"; done
[ "$(ls -A "$W/out-a" | tr '\n' ' ')" = "usr-verity.txt usr.erofs usr.verity " ]; ok $? "--out holds exactly the three outputs"
[ "$(stat -c %a "$W/out-a/usr.erofs") $(stat -c %a "$W/out-a/usr.verity") $(stat -c %a "$W/out-a/usr-verity.txt")" = "644 644 644" ]
ok $? "the three outputs are mode 0644"

echo "### the content: the image is the tree"
mkdir -p "$W/extract"
fsck.erofs --extract="$W/extract/usr" --preserve "$W/out-a/usr.erofs" >"$W/extract.log" 2>&1; ok $? "fsck.erofs extracts the image"
[ "$(listing "$W/extract/usr")" = "$(listing "$W/tree-a")" ]; ok $? "the extracted tree is the source tree (path, type, mode, owner, sha256, link)"
diff <(listing "$W/extract/usr") <(listing "$W/tree-a") | head -10 || true
bad_time="$(find "$W/extract/usr" -mindepth 1 ! -type l ! -newermt "@$((EPOCH - 1))" -print -quit; find "$W/extract/usr" -mindepth 1 ! -type l -newermt "@$EPOCH" -print -quit)"
[ -z "$bad_time" ]; ok $? "every extracted inode's time is the epoch (${bad_time:-none other})"
[ "$(stat -c %s "$W/out-a/usr.erofs")" = "$(rec "$W/out-a" erofs_size)" ] && [ $(( $(rec "$W/out-a" erofs_size) % 4096 )) = 0 ]
ok $? "usr.erofs is the recorded size, a whole number of 4096-byte blocks"

echo "### the record"
RH="$(rec "$W/out-a" roothash)"
[[ "$RH" =~ ^[0-9a-f]{64}$ ]]; ok $? "the root hash is 64 hex ($RH)"
veritysetup verify "$W/out-a/usr.erofs" "$W/out-a/usr.verity" "$RH" >/dev/null 2>&1; ok $? "veritysetup verify accepts the image with the recorded root hash"
uuid(){ printf '%s-%s-%s-%s-%s' "${1:0:8}" "${1:8:4}" "${1:12:4}" "${1:16:4}" "${1:20:12}"; }
[ "$(rec "$W/out-a" usr_partuuid)" = "$(uuid "${RH:0:32}")" ]; ok $? "usr_partuuid is the root hash's first 128 bits ($(rec "$W/out-a" usr_partuuid))"
[ "$(rec "$W/out-a" usr_verity_partuuid)" = "$(uuid "${RH:32:32}")" ]; ok $? "usr_verity_partuuid is its last 128 bits ($(rec "$W/out-a" usr_verity_partuuid))"
veritysetup dump "$W/out-a/usr.verity" > "$W/dump.txt" 2>&1
grep -qiE "^Salt:[[:space:]]*$(rec "$W/out-a" verity_salt)\$" "$W/dump.txt"; ok $? "usr.verity's superblock carries the recorded salt"
grep -qiE "^UUID:[[:space:]]*$(rec "$W/out-a" verity_uuid)\$" "$W/dump.txt"; ok $? "usr.verity's superblock carries the recorded UUID"
grep -qiE "^Hash algorithm:[[:space:]]*sha256\$" "$W/dump.txt" && grep -qiE "^Data block size:[[:space:]]*4096\$" "$W/dump.txt" \
  && grep -qiE "^Hash block size:[[:space:]]*4096\$" "$W/dump.txt"; ok $? "usr.verity is sha256 over 4096-byte data and hash blocks"
want_salt="$(printf 'regalia-kms usr-verity salt v1\0%s' "$SEED" | sha256sum | cut -d' ' -f1)"
[ "$(rec "$W/out-a" verity_salt)" = "$want_salt" ]; ok $? "the salt is the seed's documented derivation"
[ "$(sha256sum < "$W/out-a/usr.erofs" | cut -d' ' -f1)" = "$(rec "$W/out-a" erofs_sha256)" ] \
  && [ "$(sha256sum < "$W/out-a/usr.verity" | cut -d' ' -f1)" = "$(rec "$W/out-a" verity_sha256)" ]; ok $? "the record's sha256s are the files'"

echo "### tamper: one byte, each against its control"
flip(){   # flip FILE OFFSET: xor the byte at OFFSET with 0x01
  python3 -I -c 'import sys; f=open(sys.argv[1],"r+b"); o=int(sys.argv[2]); f.seek(o); b=f.read(1); f.seek(o); f.write(bytes([b[0]^1]))' "$1" "$2"
}
big_offset="$(python3 -I - "$W/out-a/usr.erofs" "$W/tree-a/lib/big" <<'PY'
import sys
image, needle = open(sys.argv[1], "rb").read(), open(sys.argv[2], "rb").read()[4096 * 100: 4096 * 100 + 64]
at = image.find(needle)
print(at if at >= 0 and image.find(needle, at + 1) < 0 else -1)
PY
)"
[ "$big_offset" -gt 0 ]; ok $? "control: the 1 MiB file's 101st block is found once in the image (at $big_offset)"
for case in "superblock:usr.erofs:1024" "file-data:usr.erofs:$((big_offset > 0 ? big_offset + 17 : 0))" "hash-tree:usr.verity:$((4096 + 40))"; do
  IFS=: read -r name file offset <<< "$case"
  rm -rf "$W/t"; cp -a "$W/out-a" "$W/t"
  veritysetup verify "$W/t/usr.erofs" "$W/t/usr.verity" "$RH" >/dev/null 2>&1; ok $? "control ($name): the copy verifies before the change"
  flip "$W/t/$file" "$offset"
  ! veritysetup verify "$W/t/usr.erofs" "$W/t/usr.verity" "$RH" >"$W/t.log" 2>&1; ok $? "one byte changed in the $name ($file @$offset): veritysetup verify refuses"
  cmp -s "$W/t/$file" "$W/out-a/$file" && ok 1 "the $name change was not made" || true
done
wrong="${RH:0:63}$(printf '%x' $(( (0x${RH:63:1} + 1) % 16 )))"
! veritysetup verify "$W/out-a/usr.erofs" "$W/out-a/usr.verity" "$wrong" >/dev/null 2>&1; ok $? "one hex digit of the root hash changed: veritysetup verify refuses"

echo "### every input counts"
build "$W/tree-a" "$W/out-seed" fedcba9876543210fedcba9876543210fedcba98
[ "$(rec "$W/out-seed" roothash)" != "$RH" ] && [ "$(rec "$W/out-seed" verity_salt)" != "$(rec "$W/out-a" verity_salt)" ]
ok $? "another seed: another salt and root hash"
build "$W/tree-a" "$W/out-epoch" "$SEED" $((EPOCH + 1))
[ "$(rec "$W/out-epoch" erofs_sha256)" != "$(rec "$W/out-a" erofs_sha256)" ] && [ "$(rec "$W/out-epoch" roothash)" != "$RH" ]
ok $? "another epoch: another image and root hash"
cp -a "$W/tree-a" "$W/tree-c"; printf 'conF\n' > "$W/tree-c/lib/regalia-kms/conf"
build "$W/tree-c" "$W/out-c"; [ "$(rec "$W/out-c" roothash)" != "$RH" ]; ok $? "one byte changed in one file of the tree: another root hash"

echo "### refusals: exit 2, --out as it was"
refused(){   # refused NAME OUTDIR ARGS...: exit 2, and OUTDIR's listing unchanged
  local name="$1" out="$2" before rc=0; shift 2
  before="$(ls -A "$out" | tr '\n' ' ')"
  "$BUILDER" "$@" >"$W/refused.log" 2>&1 || rc=$?
  [ "$rc" = 2 ] && [ "$(ls -A "$out" | tr '\n' ' ')" = "$before" ]; ok $? "$name: refused (exit $rc: $(head -1 "$W/refused.log"))"
}
mkdir -p "$W/full" "$W/empty1" "$W/empty2" "$W/empty3"; : > "$W/full/leftover"
refused "a non-empty --out" "$W/full" --usr "$W/tree-a" --seed "$SEED" --epoch "$EPOCH" --out "$W/full"
refused "a seed that is not a commit" "$W/empty1" --usr "$W/tree-a" --seed main --epoch "$EPOCH" --out "$W/empty1"
ln -s "$W/tree-a" "$W/tree-link"
refused "a --usr that is a symlink" "$W/empty2" --usr "$W/tree-link" --seed "$SEED" --epoch "$EPOCH" --out "$W/empty2"
refused "no --epoch" "$W/empty3" --usr "$W/tree-a" --seed "$SEED" --out "$W/empty3"

echo "usr-verity: $(rec "$W/out-a" mkfs_erofs); $(rec "$W/out-a" veritysetup)"
echo "usr-verity: $passed passed, $failed failed"
[ "$failed" = 0 ]
