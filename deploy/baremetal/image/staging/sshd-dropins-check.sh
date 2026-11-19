#!/bin/sh
# STAGING IMAGE VARIANT ONLY (regalia-kms-dx7.14): regalia-staging-sshd's first ExecStartPre. The host's per-host sshd
# drop-ins (the Include at the end of sshd_config: /var/lib/regalia-staging/sshd_config.d/*.conf) may hold ONLY
# ListenAddress and AllowUsers. sshd keeps the first value it reads for a keyword, but a Match block in a drop-in opens
# a conditional section whose PasswordAuthentication, PermitRootLogin or AuthenticationMethods DO apply to the
# connections it matches. So any other keyword, Match included, refuses the start (fail closed): the unit never runs
# sshd on a drop-in it has not judged.
set -eu
dir=${1:-/var/lib/regalia-staging/sshd_config.d}
[ -d "$dir" ] || { echo "sshd-dropins-check: $dir is missing" >&2; exit 1; }
bad=0
for f in "$dir"/*.conf; do
  [ -e "$f" ] || [ -L "$f" ] || continue                # no drop-in at all: nothing to judge
  if [ -L "$f" ] || [ ! -f "$f" ]; then echo "sshd-dropins-check: $f is not a regular file" >&2; bad=1; continue; fi
  # sshd splits a line's keyword from its value at whitespace or '=', and matches keywords case-insensitively
  awk '
    { line = $0; sub(/^[ \t\r]+/, "", line) }
    line == "" || line ~ /^#/ { next }
    { key = line; sub(/[ \t\r=].*$/, "", key); k = tolower(key)
      if (k != "listenaddress" && k != "allowusers") {
        printf "sshd-dropins-check: %s:%d: %s is not allowed (only ListenAddress and AllowUsers)\n", FILENAME, FNR, key > "/dev/stderr"
        bad = 1 } }
    END { exit bad }' "$f" || bad=1
done
[ "$bad" = 0 ] || { echo "sshd-dropins-check: refusing to start regalia-staging-sshd" >&2; exit 1; }
