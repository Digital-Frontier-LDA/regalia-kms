#!/usr/bin/env bash
set -euo pipefail
export REGALIA_LAB_CLUSTER=1 REGALIA_LAB_GUEST=0
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p .artifacts
if [[ ! -x .artifacts/host-venv/bin/python ]]; then
  python3 -I -m venv .artifacts/host-venv
fi
.artifacts/host-venv/bin/python -I -m pip install --disable-pip-version-check --quiet -r harness-requirements.txt
export REGALIA_CLUSTER_PYTHON="$PWD/.artifacts/host-venv/bin/python"
bash run-network.sh
