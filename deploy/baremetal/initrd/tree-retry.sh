# shellcheck shell=bash
# Sourced by build-initrd.sh and build-rootfs.sh (#503): the tree build (mmdebstrap), retried when, and only when, apt
# failed to FETCH. A TLS connection reset by snapshot.debian.org mid-download ("OpenSSL system call error ... 104:
# Connection reset by peer") is not one of the failures apt's own Acquire::Retries retries, so one reset failed a whole
# reproducible build in its first second (run 37395663372, attempt 1; attempt 2 passed).
#
#   retry_tree LOG TARGET COMMAND...   run COMMAND (which builds the tree at TARGET) with its output in LOG, at most three
#                                      times; 0 when an attempt succeeds, else COMMAND's last status.
#
# * ONLY A FETCH FAILURE IS RETRIED: LOG ends with apt's "E: Failed to fetch" or "E: Unable to fetch some archives".
#   Any other failure (a package that does not exist, a signature that does not verify, a hook that fails) returns at
#   once, as before: a retry would only hide it.
# * EACH ATTEMPT STARTS FROM NOTHING: TARGET is removed, by its exact path, before every attempt, so no tree is ever
#   built on top of a half-fetched one. TARGET must be an absolute path other than / (it is the build's own directory).
# * REPRODUCIBILITY IS UNCHANGED: every attempt fetches the same pinned snapshot, every .deb is checked by apt against
#   the snapshot's signed index (and in the initrd again by debverify), and only a whole attempt's tree is used.
# * The waits are 30 s then 90 s (TREE_RETRY_WAITS, which the tests set to 0). Each retry says which URL failed.

retry_tree(){
  local log="$1" target="$2" waits status=0 attempt=1 url
  shift 2
  case "$target" in
    /?*) ;;
    *) echo "retry_tree: the tree's target must be an absolute path other than /, not '$target'" >&2; return 2 ;;
  esac
  read -r -a waits <<<"${TREE_RETRY_WAITS:-30 90}"
  while :; do
    rm -rf -- "$target"
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
