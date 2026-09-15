# Regalia SOPS key-service adapter

This isolated module implements the two RPCs in the upstream SOPS `keyservice.proto` and maps them to
the KMS `/v1/operations/wrap` and `/v1/operations/unwrap` endpoints. It has no HSM, PKCS#11, GPG,
age, YubiKey or private-key code. The KMS HTTP client accepts an injected authenticated HTTPS client;
redirects are disabled, request/response sizes are bounded, and errors return no data or backend
detail.

SOPS 3.13.x has no custom key type and its key-service request contains no filename. For stock-client
interoperability, Regalia uses the otherwise unused AWS-KMS carrier:

```text
arn:aws:kms:regalia:000000000000:key/<logical-object-id>
```

Exactly four SOPS KMS context values are mandatory: `repository`, normalized relative `path`,
`environment`, and `purpose`. AWS role/profile fields and every other SOPS key type are rejected. The
adapter serializes these fields as authenticated envelope context; KMS policy must independently
allowlist them. A modified encrypted file therefore cannot silently change its binding.

The local SOPS-facing gRPC protocol has no authentication upstream, so the adapter exposes only a
new mode-0600 Unix socket and refuses to replace an existing path. Never expose it over TCP. Invoke
SOPS with exactly one adapter and disable its in-process key service:

```sh
sops --enable-local-keyservice=false \
  --keyservice unix:///run/user/1000/regalia-sops.sock \
  --kms arn:aws:kms:regalia:000000000000:key/production-sops \
  --encryption-context repository:regalia-kms/infrastructure,path:clusters/prod/secrets.enc.yaml,environment:production,purpose:sops-data-key \
  --encrypt clusters/prod/secrets.yaml
```

This is mandatory because upstream SOPS otherwise tries its local key service first and will try
multiple remote services until one succeeds—both behaviors would be policy bypasses.

The adapter-to-KMS client is TLS 1.3 mTLS with explicit roots and server identity, no ambient proxy,
no redirects, and bounded timeouts. Its private key input is a `crypto.Signer` so the production
launcher can use a hardware-backed workload key without exporting it. See `../../SOPS-TRANSPORT.md`.

`sopsrpc` is a minimal wire-compatible implementation pinned to getsops/sops v3.13.3 field and RPC
numbers. It intentionally decodes only the AWS KMS carrier and avoids importing SOPS's provider-heavy
Go package. The integration test runs a real installed SOPS 3.13.x binary when available. CI unit
tests always exercise the gRPC wire path; a release image must additionally run the real-binary test
against its pinned, checksum-verified SOPS 3.13.3 binary.

The parent KMS module runs a stronger local E2E twice over: real SOPS CLI through this Unix service
and a real TLS 1.3 client certificate to the complete KMS policy/audit path backed by an ephemeral
SoftHSM RSA key — once against the adapter linked as a library, and once against the DEPLOYED
EXECUTABLE built and launched by the test with its own config file. The library run proves that
encryption and decryption use no local-key fallback, context changes invalidate the wrapped data
key, and both operations produce correlated audit events. The executable run proves the deployment
shape itself: a missing identity half refuses to start and creates no socket, wrong hostname /
untrusting CA / expired / wrong-purpose certificates are all refused before any hardware call (the
audit journal records nothing), and the sidecar writes nothing beyond its provisioned files.

`cmd/regalia-sops-kms` is the deployable sidecar and `../../deploy/systemd/regalia-sops-kms.service`
is its hardened service unit. It accepts one strict configuration path, creates only a private Unix
socket, and loads the KMS CA, workload certificate and short-lived workload key from bounded,
non-symlinked protected files. The example unit delivers the key through a TPM-sealed systemd
credential; it is not stored in the repository or passed in an environment variable or command
argument. A workload-agent or hardware `crypto.Signer` is preferred where available. Remaining
production evidence is physical-backend dependency loss and firewall probing, not adapter code.
