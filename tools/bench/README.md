# PKCS#11 throughput benchmark

`hsm-bench.py` measures per-key-type throughput on a PKCS#11 token: RSA sign and decrypt, ECDSA sign,
and ECDH key agreement, on whatever private keys the token already holds. It reports mean, median
and nearest-rank p90 over `BENCH_N` samples.

```sh
pip install --require-hashes -r tools/bench/requirements.txt
HSM_PIN=… PKCS11_MODULE=/usr/lib/$(uname -m)-linux-gnu/opensc-pkcs11.so BENCH_N=25 \
  python3 -Es tools/bench/hsm-bench.py
```

**One session, logged in once — on the normal path.** Spawning `pkcs11-tool` per operation costs
roughly 300 ms of process start, PKCS#11 init and `C_Login`, which swamps the card: an early
measurement taken that way produced a figure about 5× wrong and reached a design document. The
harness opens one session, logs in once, and loops — and it labels each key by its *real* curve or
modulus size rather than assuming.

There is one exception, and it is deliberate. A failed operation can leave the session's operation
ACTIVE — a failed `C_Sign` does not always terminate it — after which every later call returns
`CKR_OPERATION_ACTIVE`; measured 2026-09-17, one bad key blanked every EC row after it. Closing the
session is what ends that state, so on a failure the harness closes, reopens and logs in again,
then re-resolves the key by its `CKA_ID` (handles belong to the session that issued them). So a run
that hits N failures performs N+1 logins. Those re-logins are not inside a measurement, but they do
spend PIN verifications on the card, and on a token with a PIN retry counter that is worth knowing
before running a long benchmark against a card you care about.

**Read the transport before trusting the numbers.** On a token behind USB/IP (a Qubes `qvm-usb`
attachment, say), a single APDU round trip measured 154 ms on the bench, and an EC signature is
about two of those. Numbers taken that way are an upper bound on latency, not the card's capacity;
measure on native USB before using them for capacity planning.

Measured on a Nitrokey HSM 2 (fw 4.1) over USB/IP, 2026-09-17, `BENCH_N=25`, for shape only:
RSA-2048 sign 1184.7 ms, RSA-2048 decrypt 2366.4 ms, secp256k1 ECDSA sign 318.9 ms, P-256 ECDSA sign
319.0 ms.

## ECDH

An EC key gets an `ECDH derive (+read, destroy)` row only if the token says it may derive
(`CKA_DERIVE`). A key that may not is never asked: a refused derive is a failed operation, and a
failed operation costs a session reopen and a PIN verification. When no key allows it, the output
ends with `ECDH    : not measured (…)`, so a missing figure is stated, not inferred.

Each sample is one key agreement as the daemon performs it (`internal/backend/nitrokey`, `Derive`):
`CKM_ECDH1_DERIVE` with `CKD_NULL` into a session object, read its value, destroy it. All three are
timed; only the derive reaches the card. The peer public key is generated on the host with
`cryptography`, once, before the timed loop.

This is the figure ADR-0002 D20 needs to choose the class KEK for software-executed keys
(regalia#532): with an RSA KEK, `software-per-operation` costs one RSA decrypt per use, about 0.4/s
on a Nitrokey HSM 2 over USB/IP. To measure the ECDH alternative, the token needs a P-256 key with
derive usage, for example:

```sh
pkcs11-tool --module "$PKCS11_MODULE" --login --keypairgen --key-type EC:prime256v1 \
  --usage-derive --label bench-ecdh --id 7e
```

Not yet measured on a Nitrokey. Checked against SoftHSM 2.6 (2026-10-02), where it derives on
P-256 and P-384 and gives a sign-only key no ECDH row; those timings are a software token's and say
nothing about a card.
