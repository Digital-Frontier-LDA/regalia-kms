#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p .artifacts
python3 ../../deploy/images/inventory.py > .artifacts/image-inputs.json
if [[ "${REGALIA_LAB_GUEST:-0}" == 1 ]]; then
  export REGALIA_MESH_TARGET=vm REGALIA_MESH_IMAGE=regalia-bootstrap-vm:dev REGALIA_LAB_TMPFS_SIZE=1g
fi
if [[ "${REGALIA_LAB_CLUSTER:-0}" == 1 ]]; then
  export REGALIA_MESH_TARGET=cluster REGALIA_MESH_IMAGE=regalia-bootstrap-cluster:dev
fi
export REGALIA_LAB_COMMIT="$(git rev-parse HEAD)"
export REGALIA_LAB_DAEMON_PLATFORM="$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')"
export REGALIA_LAB_PLATFORM="${REGALIA_LAB_PLATFORM:-$REGALIA_LAB_DAEMON_PLATFORM}"
if [[ "$REGALIA_LAB_PLATFORM" != "$REGALIA_LAB_DAEMON_PLATFORM" ]]; then
  export REGALIA_LAB_SWTPM_SECCOMP="${REGALIA_LAB_SWTPM_SECCOMP:-none}"
else
  export REGALIA_LAB_SWTPM_SECCOMP="${REGALIA_LAB_SWTPM_SECCOMP:-kill}"
fi
env -u DOCKER_DEFAULT_PLATFORM docker compose --file compose.network.yaml build
export REGALIA_LAB_IMAGE_ID="$(docker image inspect "${REGALIA_MESH_IMAGE:-regalia-bootstrap-mesh:dev}" --format '{{.Id}}')"
if [[ "${REGALIA_LAB_CLUSTER:-0}" == 1 ]]; then
  env -u DOCKER_DEFAULT_PLATFORM "$REGALIA_CLUSTER_PYTHON" cluster_mesh.py
else
  env -u DOCKER_DEFAULT_PLATFORM python3 mesh.py
fi
