# shellcheck shell=bash
# Sourced by build-initrd.sh (#246, #330): this initrd's inventory against the COMMITTED one, the reviewed one, line for
# line, CLASS and ORIGIN included, and on a mismatch everything needed to read why, kept.
#
#   inventory_check COMMITTED BUILT WORK OUT   0 when BUILT equals COMMITTED without its comment lines; 1 when they
#                                              differ; 2 when either cannot be read. WORK is the builder's working
#                                              directory, OUT its --out directory.
#
# * ON A MISMATCH, OUT KEEPS THREE TEXT FILES, and never the initrd: initrd-inventory.built.txt (the whole built
#   inventory, for a snapshot move to review, KERNEL-UPDATE.md), initrd-inventory.committed.txt (the committed lines it
#   was compared with) and initrd-inventory.diff (the whole difference). Every job that runs a builder uploads them on
#   a failure, so a mismatch's cause can still be read after the run.
# * THE SIZE COMES FIRST, the excerpt after: how many committed lines the built initrd lacks and how many built lines
#   are not committed, then the diff's first 60 lines. A cut excerpt read as the difference's size once made at least 51
#   missing shared libraries (libc6 among them, regalia-kms#620's run 40636249776) look like "about 60 lines".
# * FILES, NEVER A LIVE PIPE: both sides are written out and compared as files. `grep | cmp -s` and `diff | head` made
#   their writers die of SIGPIPE ("grep: write error: Broken pipe"), which read as the failure's cause; it was only a
#   symptom of a mismatch already found.

inventory_check(){
  local committed="$1" built="$2" work="$3" out="$4" status=0 counts
  grep -v '^#' "$committed" > "$work/inventory.committed.txt" || status=$?
  [ "$status" -le 1 ] || { echo "build-initrd: the committed inventory $committed cannot be read" >&2; return 2; }
  [ -f "$built" ] || { echo "build-initrd: the built inventory $built is missing" >&2; return 2; }
  cmp -s "$work/inventory.committed.txt" "$built" && return 0
  cp -- "$built" "$out/initrd-inventory.built.txt"
  cp -- "$work/inventory.committed.txt" "$out/initrd-inventory.committed.txt"
  status=0
  diff -- "$work/inventory.committed.txt" "$built" > "$out/initrd-inventory.diff" || status=$?
  [ "$status" -eq 1 ] || { echo "build-initrd: the inventories could not be compared (diff exit $status)" >&2; return 2; }
  counts="$(awk '/^< /{c++} /^> /{b++} END{printf "%d committed line(s) the built initrd lacks, %d built line(s) not committed", c, b}' \
    "$out/initrd-inventory.diff")"
  echo "build-initrd: this initrd's inventory differs from $committed: $counts"
  echo "build-initrd: the whole difference is $out/initrd-inventory.diff (both inventories beside it); its first 60 lines:"
  sed -n '1,60p' "$out/initrd-inventory.diff"
  return 1
}
