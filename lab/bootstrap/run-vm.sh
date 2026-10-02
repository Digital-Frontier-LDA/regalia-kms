#!/usr/bin/env bash
set -euo pipefail
export REGALIA_LAB_GUEST=1
# Match the production x86 servers. Debian's arm64 kernel does not provide the
# TPM TIS driver needed by the selected QEMU TPM frontend.
export REGALIA_LAB_PLATFORM=linux/amd64
exec bash "$(dirname "${BASH_SOURCE[0]}")/run-network.sh"
