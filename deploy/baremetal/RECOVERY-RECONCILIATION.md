# Explicit recovery reconciliation

`recovery-reconcile.py` is an opt-in console repair tool for interrupted disk
recovery enrollment/replacement. `recovery-key.sh` repairs only what the header marks (the same
keys typed again, a marked replace pair, empty recovery tokens) and reports every other header as
`STATE: unknown`, changing nothing: this tool is the way forward from that state.
Stop other header writers and use a trusted, serialized root console.

Inspect without changing keyslots:

```sh
sudo python3 -I deploy/baremetal/recovery-reconcile.py /dev/ROOT_PARTITION
```

The JSON describes the actual header: recovery mappings, unlabelled passphrases,
ignored priorities, ambiguous owners and empty recovery tokens. Exit 0 means a
single clean recovery mapping with no unlabelled slots; unreadable or incomplete
metadata fails. A status check creates only a private instance mutex in `/run/lock`.

A custodian chooses which card to keep and exactly which slots to retire:

```sh
sudo python3 -I deploy/baremetal/recovery-reconcile.py /dev/ROOT_PARTITION \
  --keep-slot 2 --retire-slot 1
```

Prompts accept the kept card's key followed by each retired card's key, hidden on
an interactive console. The utility proves every selected, present slot before
any write. It refuses unknown cards, conflicting selections, shared/ambiguous
token mappings and slots owned by TPM or other token types. No slot is selected
for deletion automatically. Non-interactive input uses one key per line; no key
is accepted in argv or the environment, written to disk, or included in reports.

The sequence is: normalize only the selected kept slot's priority if needed;
label it if unlabelled; prove a generic boot unlock; retire only explicitly
selected and proven slots; remove empty **recovery** tokens; read the header
again and prove the kept card. A retired card that still opens an unselected
copy causes refusal; that copy is preserved for a further explicit custody choice. Other slots' identities/metadata are checked after
every mutation and left unchanged. An unselected passphrase remains visible as
`needs-review` and causes exit 1 even when the selected repair finished.

**A kill inside a retirement (#175, d9's read).** luksKillSlot wipes a slot's key material (with
random bytes) before it updates the metadata. A kill between the two leaves the retired slot listed
while its card opens nothing, and the header alone cannot tell that slot from a live one. So, before
each retirement, and only after proving the retired card, the tool records `regalia_retiring:
[[slot, salt]]` on the kept slot's token. This is one in-place token replace, measured atomic on
cryptsetup 2.7.5. A retry may then finish a listed slot whose card opens nothing only when that mark
names it by number and salt, and cryptsetup itself answers "no key" (exit 2) for the card. Without
the mark, a card that opens nothing is still refused. Once the slot is gone, the mark is cleared, so
a finished header's token is the plain one. systemd-cryptenroll lists a marked token as `recovery`,
a boot prompt opens through it, and `--wipe-slot=recovery` removes it (tested).

**One tool at a time.** This tool and `recovery-key.sh` take the same lock,
`/run/lock/regalia-recovery-<device>.lock` (`recovery_state.lock_path`). They also read the header with
the same classifier (`recovery_state.py`); the JSON this tool prints carries it as `header_state`.

There is no undo. A failure reports the observed header; repeating the same
explicit selections/cards handles slots that were already retired. A pending
read or write can fail again, and no success is reported without its checks.
SIGINT/TERM/HUP are ignored during one child header update; KILL remains a
possible interruption. The separate mutex excludes other instances of this tool
without holding cryptsetup's own device lock. It does **not** coordinate with
other header tools or protect against a malicious root process.

## Security findings

Current-main crash tests still show unfinished recovery states and failed normal
retries. This tool supplies an explicit repair path, not an unattended custody
policy. The custodian must choose the kept card and prove retired cards. Unknown
slots are preserved. Systemd-generated key custody and recovery ceremony changes
in #175 are separate decisions; this PR does not close that issue.

## Checks performed

The real-LUKS2 matrix freezes the tested utility bytes before execution. It uses
disposable private file-backed volumes, an installer key, old/new recovery keys,
and an additional unknown key. It interrupts every successful command boundary,
repeats identical operator selections, and independently checks normal unlocks,
keyslot metadata, orphan cleanup and preservation of the unknown slot. Wrong
cards and non-recovery-owned mappings refuse without changing the header. See
`lab/recovery/RECONCILIATION-VALIDATION.md` for measured results.

## Residual risk

The tests cover command boundaries, not libcryptsetup sector writes, physical
power loss, malicious concurrent writers or physical custody. Python immutable
secret strings cannot be guaranteed to be zeroized; their process lifetime is
short, and subprocesses receive secrets only through anonymous descriptors.
The tool makes no recovery-key entropy claim from syntax and never creates a
fast-KDF slot. Existing enrollment/ceremony behavior remains unchanged.

## Recommendation

Keep this change in a draft PR for review and rehearse using disposable images.
Do not use it to remove operational slots until the custodian has chosen cards
and reviewed the actual header. An unknown slot is a refusal/review condition,
not authority to remove it or wipe all password slots.
