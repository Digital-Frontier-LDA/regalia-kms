#!/usr/bin/env bash
# fetch-pinned-asset.sh <release-url> <rest-asset-url> <sha256> <output>
#
# regalia-kms-dq7, adopting openmix-1q7te (Flynn#2129): an intermittent 504 on
# github.com/<o>/<r>/releases/download turned main red with no code failure, while
# api.github.com kept serving the same asset. Each round tries the release URL, then the REST asset
# API (the pinned asset id of the SAME owner/repo, Accept: application/octet-stream, the job's
# GH_TOKEN through a curl config fd, never argv).
#
# What retries (PR #784 GA review 6053675011): only an outage, meaning an HTTP 5xx, a 429, no
# HTTP answer at all (timeout, connection or TLS failure), or a 200 whose body died mid-transfer. Any other HTTP status, such as a 404
# (wrong pin) or a 403, is fatal at once, with no fallback: retrying it would only hide a broken pin.
# The sha256 pin is the trust anchor: a mismatch from either host is fatal and never retried.
#
# Bounded: no attempt starts after DEADLINE seconds (default 150), and each attempt is capped at
# ATTEMPT_MAX_TIME seconds (default 90), so the worst case is DEADLINE + ATTEMPT_MAX_TIME (4 min)
# per asset, under the steps' timeout-minutes: 5, so this script's own message is what CI shows.
set -euo pipefail
[ $# -eq 4 ] || { echo "usage: $0 <release-url> <rest-asset-url> <sha256> <output>" >&2; exit 2; }
url=$1 api=$2 sha=$3 out=$4
deadline=${DEADLINE:-150}
max_time=${ATTEMPT_MAX_TIME:-90}
[[ $sha =~ ^[0-9a-f]{64}$ ]] || { echo "fetch-pinned-asset: malformed sha256 pin" >&2; exit 2; }
[[ $url =~ ^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/releases/download/[^[:space:]]+$ ]] \
  || { echo "fetch-pinned-asset: malformed release URL" >&2; exit 2; }
repo="${BASH_REMATCH[1]}/${BASH_REMATCH[2]}"
[[ $api =~ ^https://api\.github\.com/repos/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/releases/assets/[0-9]+$ ]] \
  && [ "${BASH_REMATCH[1]}" = "$repo" ] \
  || { echo "fetch-pinned-asset: the REST asset URL is not an asset of $repo" >&2; exit 2; }
part="$out.part"
rm -f "$part" "$out"
common=(--location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time "$max_time"
        --silent --show-error --write-out '%{http_code}')

# attempt <label> <curl args...>: 0 fetched and verified; 1 an outage, try the next; exits otherwise.
attempt() {
  local label=$1 code rc=0
  shift
  code=$(curl "${common[@]}" --output "$part" "$@") || rc=$?
  if [ "$rc" -eq 0 ] && [ "$code" = 200 ]; then
    local got
    got=$(sha256sum "$part" | cut -d' ' -f1)
    if [ "$got" != "$sha" ]; then
      rm -f "$part"
      echo "fetch-pinned-asset: sha256 mismatch from $label (got $got, pinned $sha): refused, not retried" >&2
      exit 3
    fi
    mv "$part" "$out"
    echo "fetch-pinned-asset: $(basename "$out") verified (sha256 $sha) from $label"
    return 0
  fi
  rm -f "$part"
  # A 200 whose body then died (curl exit 18, 28 or 56: a stall or a reset mid-transfer) is an
  # outage, not an answer (#784 council review).
  [ "$rc" -ne 0 ] && [ "$code" = 200 ] && code=000
  case $code in
    5??|429|000) echo "fetch-pinned-asset: $label: an outage (HTTP $code, curl exit $rc)" >&2; return 1 ;;
    *) echo "fetch-pinned-asset: $label answered HTTP $code (curl exit $rc): fatal, not retried, no fallback" >&2; exit 5 ;;
  esac
}

round=0
while [ "$SECONDS" -lt "$deadline" ]; do
  round=$((round + 1))
  attempt "the release URL" "$url" && exit 0
  [ "$SECONDS" -lt "$deadline" ] || break
  if [ -n "${GH_TOKEN:-}" ]; then
    attempt "the REST asset API" --config <(printf 'header = "Authorization: Bearer %s"\n' "$GH_TOKEN") \
      --header 'Accept: application/octet-stream' "$api" && exit 0
  else
    attempt "the REST asset API" --header 'Accept: application/octet-stream' "$api" && exit 0
  fi
  echo "fetch-pinned-asset: round $round failed on both hosts" >&2
  [ "$SECONDS" -lt "$deadline" ] && sleep $((round < 4 ? round * 10 : 30))
done
echo "fetch-pinned-asset: no host served $url within ${deadline}s ($round rounds)" >&2
exit 4
