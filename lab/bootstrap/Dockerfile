# Multi-architecture index: supports native arm64 development and amd64 labs.
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a AS tools

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-cryptography python3-yaml swtpm tpm2-tools libtss2-tcti-swtpm0 \
      cryptsetup-bin wireguard-tools openssl \
    && dpkg-query -W -f='${Package}\t${Version}\n' > /opt/packages.tsv \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

FROM tools AS ipc
COPY lab.py tpm_soak.py peer.py peer_cases.py membership_cases.py /opt/
USER 65532:65532
ENTRYPOINT ["python3", "/opt/lab.py"]

FROM tools AS network-tools
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 nftables \
    && dpkg-query -W -f='${Package}\t${Version}\n' > /opt/packages.tsv \
    && rm -rf /var/lib/apt/lists/*
FROM network-tools AS network
COPY lab.py peer.py peer_cases.py membership_cases.py network.py /opt/
ENTRYPOINT ["python3", "/opt/network.py"]

FROM network-tools AS cluster-tools
RUN apt-get update && apt-get install -y --no-install-recommends softhsm2 python3-pykcs11 \
    && dpkg-query -W -f='${Package}\t${Version}\n' > /opt/packages.tsv \
    && rm -rf /var/lib/apt/lists/*
FROM cluster-tools AS cluster
COPY lab.py peer.py network.py cluster.py tokens.py leases.py device.py /opt/
ENTRYPOINT ["python3", "/opt/cluster.py"]

FROM network-tools AS vm-tools
ARG TARGETARCH
RUN apt-get update && case "$TARGETARCH" in \
      arm64) apt-get install -y --no-install-recommends qemu-system-arm linux-image-arm64 ;; \
      amd64) apt-get install -y --no-install-recommends qemu-system-x86 linux-image-amd64 ;; \
      *) exit 1 ;; esac \
    && apt-get install -y --no-install-recommends busybox-static kmod cpio e2fsprogs \
    && dpkg-query -W -f='${Package}\t${Version}\n' > /opt/packages.tsv \
    && rm -rf /var/lib/apt/lists/*
FROM vm-tools AS vm
COPY lab.py peer.py peer_cases.py membership_cases.py network.py vm.py guest.py guest-init.sh root-init.sh /opt/
ENTRYPOINT ["python3", "/opt/network.py"]
