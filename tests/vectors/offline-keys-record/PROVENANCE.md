# offline-keys-record fixtures

These are regalia-ceremony's own `offline-keys.py generate` output, read by `tests/test_baremetal_manifest.py`
(`ProposeGenesis.test_k_a_comes_from_the_root_signed_generation_record`). None of them comes from a ceremony. Every
key in them was generated for a throwaway run, and the shares, sealed file and break-glass copy were not kept.

| file | producer | domain | read as |
|---|---|---|---|
| `offline-keys.record.json`, `root.hex` | regalia-ceremony main `2e24e691004bf9a15215a1e1db5619d60bfaae9c` (contains regalia-avz, #178, merged `04255c29`), run once on 2026-11-10 | `regalia.offline-keys-record/v1\0` | accepted |
| `offline-keys.record.fd8df0a.json`, `root-fd8df0a.hex` | regalia-ceremony `fd8df0a` (before regalia-avz) | `regalia-ceremony-record/v1\0` (retired) | refused |
| `offline-keys.record.rc133.json`, `root-rc133.hex` | regalia-ceremony#133 head `178e358` (before regalia-avz) | `regalia-ceremony-record/v1\0` (retired) | refused |

## How the current record was made

This was a simulation run with throwaway keys. It is not a ceremony and no physical card was used. It ran in the
`golang:1.26.10` linux/amd64 image as a non-root user:
- regalia-ceremony's `qubes/requirements.txt` was installed with `pip --require-hashes` into a venv, which gives
  `cryptography` 50.0.2 and `shamir-mnemonic` 0.3.0;
- age v1.3.2 was installed with the sha256 pins in regalia-ceremony's `emulator.yml`.

```sh
export CEREMONY_SIMULATE=1 CEREMONY_ALLOW_NONTMPFS=1 CEREMONY_ALLOW_SWAP=1
age-keygen -pq -o "$W/bg.key"; age-keygen -y "$W/bg.key" > "$W/breakglass.recipient"
python3 -Es qubes/scripts/offline-keys.py generate --threshold 2 --shares 3 --out "$W/out" --breakglass-recipient "$W/breakglass.recipient"
```

From that run, only `offline-keys.record.json` was kept, plus `root.hex`, which is its `root_entry.key`. The working
directory, the shares, the sealed file and the break-glass key were deleted.

The record verifies under `regalia.offline-keys-record/v1\0` and does not verify under the retired domain. The
producer's own `RECORD_DOMAIN` and `RETIRED_RECORD_DOMAIN` were checked in the same run.

The output is not byte-reproducible because it holds fresh keys and a timestamp. Like `card-ceremony-record/writer-run/`,
it is a fixture made once for each producer change, not something a test regenerates.
