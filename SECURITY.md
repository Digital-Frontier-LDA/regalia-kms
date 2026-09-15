# Security Policy

## Status

Regalia KMS is **pre-production**. Production hardware qualification is not yet complete — do not use
it to protect production keys yet. See the README for the full does/doesn't-do scope.

## Reporting a vulnerability

Please report security issues **privately**, never in a public issue or pull request.

Use GitHub's private vulnerability reporting:
**Security → Advisories → [Report a vulnerability](https://github.com/Digital-Frontier-LDA/regalia-kms/security/advisories/new)**.

Include the affected version/commit, a description, and a reproduction if you have one. We aim to
acknowledge within a few business days and will coordinate disclosure with you.

## Scope

In scope: the code in this repository — the KMS daemon, backends (PKCS#11 / PIV / OpenPGP), the
policy/registry, envelope storage, audit, fencing, and the SOPS adapter.

Out of scope: the operators' private infrastructure, deployment topology, and anything not built
from this repository.

## Committed secrets

This repository is scanned for committed credentials by gitleaks in CI (fail-closed, full history)
and by GitHub secret scanning with push protection. If you believe a credential was committed,
report it privately — the fix is **rotation**, not deletion (a secret removed in a later commit is
still published in history).
