#!/usr/bin/env bash
# fetch-pinned-asset.sh <release-url> <rest-asset-url> <sha256> <output>
#
# regalia-kms-dq7, adopting openmix-1q7te (Flynn#2129): an intermittent 504 on
# github.com/<o>/<r>/releases/download turned main red with no code failure, while
# api.github.com kept serving the same asset. Each round tries the release URL, then the REST asset
# API (pinned asset id, Accept: application/octet-stream, the job's GH_TOKEN), with bounded backoff.
# The sha256 pin is the trust anchor and is unchanged: a mismatch is refused and NEVER retried, so a
# tampered asset cannot be raced past it. The token goes to curl through a config fd, never argv.
set -uo pipefail
[ $# -eq 4 ] || { echo "usage: $0 <release-url> <rest-asset-url> <sha256> <output>" >&2; exit 2; }
url=$1 api=$2 sha=$3 out=$4
[[ $sha =~ ^[0-9a-f]{64}$ ]] || { echo "fetch-pinned-asset: malformed sha256 pin" >&2; exit 2; }
[[ $api =~ ^https://api\.github\.com/repos/[^/]+/[^/]+/releases/assets/[0-9]+$ ]] \
  || { echo "fetch-pinned-asset: malformed REST asset URL" >&2; exit 2; }
part="$out.part"
rm -f "$part" "$out"
common=(--fail --location --proto '=https' --tlsv1.2 --connect-timeout 20 --max-time 300 --silent --show-error)

verify() {
  local got
  got=$(sha256sum "$part" | cut -d' ' -f1)
  if [ "$got" != "$sha" ]; then
    rm -f "$part"
    echo "fetch-pinned-asset: sha256 mismatch from $1 (got $got, pinned $sha): refused, not retried" >&2
    exit 3
  fi
  mv "$part" "$out"
  echo "fetch-pinned-asset: $(basename "$out") verified (sha256 $sha) from $1"
  exit 0
}

for round in 1 2 3 4; do
  if curl "${common[@]}" --output "$part" "$url"; then verify "the release URL"; fi
  echo "fetch-pinned-asset: round $round: the release URL failed; trying the REST asset API" >&2
  if [ -n "${GH_TOKEN:-}" ]; then
    if curl "${common[@]}" --config <(printf 'header = "Authorization: Bearer %s"\n' "$GH_TOKEN") \
         --header 'Accept: application/octet-stream' --output "$part" "$api"; then verify "the REST asset API"; fi
  else
    if curl "${common[@]}" --header 'Accept: application/octet-stream' --output "$part" "$api"; then verify "the REST asset API"; fi
  fi
  rm -f "$part"
  [ $round -lt 4 ] && { echo "fetch-pinned-asset: round $round failed on both hosts; backing off" >&2; sleep $((round * 20)); }
done
echo "fetch-pinned-asset: both hosts failed for 4 rounds: $url" >&2
exit 4
