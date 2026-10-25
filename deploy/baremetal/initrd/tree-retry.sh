# shellcheck shell=bash
# Sourced by build-initrd.sh and build-rootfs.sh (#503): the tree build (mmdebstrap), retried when, and only when, apt
# failed to FETCH. A TLS connection reset by snapshot.debian.org mid-download ("OpenSSL system call error ... 104:
# Connection reset by peer") is not one of the failures apt's own Acquire::Retries retries, so one reset failed a whole
# reproducible build in its first second (run 37395663372, attempt 1; attempt 2 passed).
#
#   TREE_RETRY_BASE=DIR                the builder's own working directory (its mktemp -d), which every TARGET must lie
#                                      strictly inside: set by the builder right after it makes it.
#   retry_tree LOG TARGET COMMAND...   run COMMAND (which builds the tree at TARGET) with its output in LOG, at most three
#                                      times; 0 when an attempt succeeds, else COMMAND's last status.
#
# * ONLY A FETCH FAILURE IS RETRIED: LOG ends with apt's "E: Failed to fetch" or "E: Unable to fetch some archives".
#   Any other failure (a package that does not exist, a signature that does not verify, a hook that fails) returns at
#   once, as before: a retry would only hide it.
# * EACH ATTEMPT STARTS FROM NOTHING: TARGET is removed, by its exact path, before every attempt, so no tree is ever
#   built on top of a half-fetched one. That is an rm -rf in a sourced library, so it defends itself rather than
#   trusting its callers (b9 on #575): TARGET, resolved (realpath -m: //, /., .. and trailing slashes), must lie strictly
#   inside TREE_RETRY_BASE, itself an existing directory other than /. A pattern on TARGET alone admitted //, /. and,
#   with W set but empty, "$W/root" = /root.
# * REPRODUCIBILITY IS UNCHANGED: every attempt fetches the same pinned snapshot, every .deb is checked by apt against
#   the snapshot's signed index (and in the initrd again by debverify), and only a whole attempt's tree is used.
# * The waits are 30 s then 90 s (TREE_RETRY_WAITS, which the tests set to 0). Each retry says which URL failed.

retry_tree(){
  local log="$1" target="$2" base="${TREE_RETRY_BASE:-}" waits status=0 attempt=1 url resolved within
  shift 2
  if [ -z "$base" ] || [ ! -d "$base" ] || ! within="$(realpath -- "$base")" || [ "$within" = / ]; then
    echo "retry_tree: TREE_RETRY_BASE must name the builder's own directory (not '$base'): nothing is removed" >&2
    return 2
  fi
  if [ -z "$target" ] || ! resolved="$(realpath -m -- "$target")"; then
    echo "retry_tree: the tree's target cannot be resolved ('$target'): nothing is removed" >&2
    return 2
  fi
  case "$resolved" in
    "$within"/?*) ;;
    *) echo "retry_tree: the tree's target '$target' ($resolved) is not inside $within: nothing is removed" >&2; return 2 ;;
  esac
  read -r -a waits <<<"${TREE_RETRY_WAITS:-30 90}"
  while :; do
    rm -rf -- "$resolved"
    if "$@" >"$log" 2>&1; then
      return 0
    else
      status=$?
    fi
    if [ "$attempt" -gt "${#waits[@]}" ] || ! grep -qE '^E: (Failed to fetch|Unable to fetch some archives)' "$log"; then
      return "$status"
    fi
    url="$(grep -m1 -oE '^E: Failed to fetch [^ ]+' "$log" | cut -d' ' -f5)" || url=""   # none named: set -e callers
    echo "retry_tree: attempt $attempt failed to fetch ${url:-an archive}; attempt $((attempt + 1)) of $((${#waits[@]} + 1)) in ${waits[attempt - 1]}s, into a new tree" >&2
    sleep "${waits[attempt - 1]}"
    attempt=$((attempt + 1))
  done
}
