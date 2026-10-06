# shellcheck shell=bash
# A Debian tree built with mmdebstrap, retried ONLY when a download from the snapshot failed on the network
# (regalia-kms#503). Sourced by build-initrd.sh and build-rootfs.sh; listed in their REPO_FILES, so its hash is in
# each build record.
#
# WHY. apt's Acquire::Retries retries what apt classes as transient (a timeout, a name-resolution failure, an HTTP
# 5xx), not an OpenSSL "Connection reset by peer" in the middle of a download: one such reset from
# snapshot.debian.org failed a reproducible build outright (#503, run 37395663372), with nothing retried.
#
# WHAT IS RETRIED. A failed run whose log has at least one apt error, every one of them a fetch that failed for a
# network cause (FETCH_RETRY_NETWORK below), and no line naming a verification failure (FETCH_RETRY_NEVER): a hash
# or size mismatch, a bad or missing signature, an invalid Release file. apt words a hash mismatch as "Failed to
# fetch ... Hash Sum mismatch" too, so "Failed to fetch" alone is never enough. Anything else fails at once, as
# before. A retry fetches the same pinned snapshot, and apt checks every package against the snapshot's signed index
# again: reproducibility is unchanged.
#
# HOW. At most FETCH_RETRY_ATTEMPTS runs, FETCH_RETRY_DELAYS seconds apart; each run into a fresh target, the failed
# one removed by its exact path (never a glob). Each retry is printed with the URL and the cause.

FETCH_RETRY_ATTEMPTS=3
FETCH_RETRY_DELAYS=(30 90)
FETCH_RETRY_NETWORK='Connection reset by peer|Connection timed out|Could not connect to|Could not resolve|Temporary failure resolving|Connection failed|Network is unreachable|No route to host|Undetermined Error|50[234] [A-Za-z ]+|Operation timed out|unexpected EOF|connection closed'
FETCH_RETRY_NEVER='Hash Sum mismatch|Size mismatch|File has unexpected size|BADSIG|NO_PUBKEY|EXPKEYSIG|REVKEYSIG|is not signed|signature|Signed-By|Release file .* is not valid|Clearsigned file|Mirror sync in progress'

# fetch_retry_transient LOG: true (0) only when every apt error in LOG is a fetch that failed on the network
fetch_retry_transient(){
  local log="$1" errors
  # judged on apt's errors and warnings (and the line after each, where apt wraps the reason), never on progress output
  grep -A1 -E '^[EW]: ' "$log" | grep -qiE "$FETCH_RETRY_NEVER" && return 1
  errors="$(grep -E '^E: ' "$log")" || return 1
  # "Unable to fetch some archives" and mmdebstrap's own summary ("mmdebstrap failed to run", its apt-get call failed)
  # follow a failed fetch; any other E: line (a dependency, a script, a full disk) is not a download and is final
  ! printf '%s\n' "$errors" | grep -vE '^E: (Unable to fetch some archives|Some index files failed to download|Failed to fetch |mmdebstrap failed to run|apt-get (--yes )?(download|install|update)?.*failed)' | grep -q . || return 1
  # each failed fetch names a network cause: on its own line, or on apt's next line (it wraps the reason)
  local fetches causes
  fetches="$(grep -cE '^E: Failed to fetch ' "$log")"
  [ "$fetches" -gt 0 ] || return 1
  causes="$(grep -A1 -E '^E: Failed to fetch ' "$log" | grep -cE "$FETCH_RETRY_NETWORK")"
  [ "$causes" -ge "$fetches" ]
}

# fetch_retry_tree LABEL LOG TARGET -- COMMAND...: COMMAND (an mmdebstrap building TARGET, its output in LOG),
# retried as above. Returns COMMAND's last status.
fetch_retry_tree(){
  local label="$1" log="$2" target="$3" attempt=1 status
  shift 3
  [ "$1" = -- ] && shift
  while :; do
    "$@" >"$log" 2>&1 && return 0
    status=$?
    [ "$attempt" -lt "$FETCH_RETRY_ATTEMPTS" ] && fetch_retry_transient "$log" || return "$status"
    echo "$label: a download failed on the network (attempt $attempt of $FETCH_RETRY_ATTEMPTS); retrying in ${FETCH_RETRY_DELAYS[$((attempt - 1))]} s into a fresh tree:"
    grep -A1 -E '^E: Failed to fetch ' "$log" | head -4 | sed 's/^/  /'
    cp -- "$log" "$log.attempt$attempt"
    rm -rf --one-file-system -- "$target"
    sleep "${FETCH_RETRY_DELAYS[$((attempt - 1))]}"
    attempt=$((attempt + 1))
  done
}
