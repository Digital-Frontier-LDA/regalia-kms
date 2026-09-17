# PKCS#11 throughput benchmark

`hsm-bench.py` measures per-key-type throughput on a PKCS#11 token: RSA sign and decrypt, and ECDSA
sign, on whatever private keys the token already holds. It reports mean, median and nearest-rank p90
over `BENCH_N` samples.

```sh
pip install --require-hashes -r tools/bench/requirements.txt
HSM_PIN=… PKCS11_MODULE=/usr/lib/$(uname -m)-linux-gnu/opensc-pkcs11.so BENCH_N=25 \
  python3 tools/bench/hsm-bench.py
```

**One session, logged in once.** Spawning `pkcs11-tool` per operation costs roughly 300 ms of
process start, PKCS#11 init and `C_Login`, which swamps the card: an early measurement taken that
way produced a figure about 5× wrong and reached a design document. The harness opens one session,
logs in once, and loops — and it labels each key by its *real* curve or modulus size rather than
assuming.

**Read the transport before trusting the numbers.** On a token behind USB/IP (a Qubes `qvm-usb`
attachment, say), a single APDU round trip measured 154 ms on the bench, and an EC signature is
about two of those. Numbers taken that way are an upper bound on latency, not the card's capacity;
measure on native USB before using them for capacity planning.

Measured on a Nitrokey HSM 2 (fw 4.1) over USB/IP, 2026-09-17, `BENCH_N=25`, for shape only:
RSA-2048 sign 1184.7 ms, RSA-2048 decrypt 2366.4 ms, secp256k1 ECDSA sign 318.9 ms, P-256 ECDSA sign
319.0 ms.
