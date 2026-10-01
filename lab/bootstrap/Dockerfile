# Multi-architecture index: supports native arm64 development and amd64 labs.
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-cryptography swtpm tpm2-tools libtss2-tcti-swtpm0 \
      cryptsetup-bin wireguard-tools openssl \
    && dpkg-query -W -f='${Package}\t${Version}\n' > /opt/packages.tsv \
    && rm -rf /var/lib/apt/lists/*

COPY lab.py /opt/lab.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
ENTRYPOINT ["python3", "/opt/lab.py"]
