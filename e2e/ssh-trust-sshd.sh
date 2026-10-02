#!/usr/bin/env bash
# ssh-trust-sshd.sh — a real sshd on deploy/baremetal/sshd-regalia-kms.conf.example, and a real ssh on the
# known_hosts and ssh_config that deploy/baremetal/ssh_trust.py writes from a membership manifest.
# regalia-kms#143. No hardware, no root, no port (ssh's ProxyCommand runs `sshd -i`); it runs in CI.
#
#   e2e/ssh-trust-sshd.sh
#
#   1  the example is a configuration sshd accepts, with one host key and no other
#   2  a certificate from the user CA logs in to the node it names; either of the two CA keys can issue,
#      a third cannot, and a CA taken out of the trusted file stops at once
#   3  a node cannot answer for another; a retired or stolen node's key is refused as REVOKED under every
#      name and address; a host outside the manifest is refused
#   4  only a certificate logs in: no bare key, and the server offers no password
#   5  another CA, an expired or not-yet-valid certificate, an unlisted principal: refused
#   6  a revoked certificate is refused; without the revocation list or a principals file, nobody logs in
#   7  the example as written (FIDO-only) refuses a software key
#
# These are the tests of tests/test_baremetal_ssh_trust.py's OnSshd class, run where sshd must be present:
# a skip here is a failure. The FIDO path itself needs a token and is a bench drill (deploy/baremetal/SSH.md).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
for t in ssh ssh-keygen python3; do
  command -v "$t" >/dev/null || { echo "ssh-trust-sshd: $t is required (openssh-client, python3)"; exit 2; }
done
[ -n "${REGALIA_SSHD:-}" ] || command -v sshd >/dev/null || [ -x /usr/sbin/sshd ] || { echo "ssh-trust-sshd: sshd is required (openssh-server)"; exit 2; }
out="$(REGALIA_EXPECT_SSHD=1 python3 -Es -m unittest -v tests.test_baremetal_ssh_trust.OnSshd 2>&1)"; rc=$?
printf '%s\n' "$out"
[ "$rc" = 0 ] || { echo "ssh-trust-sshd: FAILED"; exit 1; }
grep -q '^Ran 12 tests' <<< "$out" && ! grep -qi 'skipped' <<< "$out" || { echo "ssh-trust-sshd: the sshd tests did not all run"; exit 1; }
echo "ssh-trust-sshd: 12 passed, 0 failed"
