from pathlib import Path


ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "e2e" / "softhsm-pkcs11.sh"


def test_soft_hsm_credentials_are_per_run_and_not_fixed():
    source = SCRIPT.read_text()
    assert 'SO_PIN="$(openssl rand -hex 16)"' in source
    assert 'E2E_PIN="$(openssl rand -hex 16)"' in source
    assert "--so-pin 12345678" not in source
    assert "--pin 123456" not in source


def test_cosmos_signing_receives_the_ephemeral_pin():
    source = SCRIPT.read_text()
    assert 'REGALIA_COSMOS_PKCS11_PIN="$E2E_PIN"' in source


def _command_invoking(source, needle):
    """The logical shell command (continuation lines joined, comments stripped) that runs needle."""
    logical, current = [], ""
    for line in source.splitlines():
        code = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
        current += code.rstrip()
        if current.endswith("\\"):
            current = current[:-1] + " "
            continue
        logical.append(current)
        current = ""
    matches = [command for command in logical if needle in command]
    assert len(matches) == 1, matches
    return matches[0]


def test_soft_hsm_cosmos_run_does_not_inherit_a_physical_slot_selector():
    # The physical bench run exports REGALIA_COSMOS_PKCS11_SLOT=4. Inherited into the SoftHSM run it
    # makes the signer select a slot that does not exist there (CKR_SLOT_ID_INVALID, observed). The
    # empty assignment must sit in the prefix of the SAME command that runs the signer: anywhere else,
    # including a comment, the child would still inherit the physical slot.
    command = _command_invoking(SCRIPT.read_text(), "cosmos-hardware-sign-verify.sh")
    assert "REGALIA_COSMOS_PKCS11_SLOT=''" in command.split("cosmos-hardware-sign-verify.sh")[0]
