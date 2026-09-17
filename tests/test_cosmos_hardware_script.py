"""Fail-closed contract tests for the opt-in Cosmos PKCS#11 runner."""

import os
import subprocess
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "e2e" / "cosmos-hardware-sign-verify.sh"


def run_script(**overrides):
    # Start from no REGALIA_COSMOS_* at all. The physical bench run exports a slot selector, and an
    # inherited REGALIA_COSMOS_PKCS11_SLOT satisfies the token-selector check, so the missing-label
    # case would pass for the wrong reason in any shell that had just run the hardware test.
    env = {k: v for k, v in os.environ.items() if not k.startswith("REGALIA_COSMOS_")}
    for key, value in overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return subprocess.run([str(SCRIPT)], text=True, capture_output=True, env=env)


def test_missing_module_is_refused_before_any_token_selector():
    result = run_script(
        REGALIA_COSMOS_PKCS11_MODULE=None,
        REGALIA_COSMOS_PKCS11_TOKEN_LABEL="staging",
        REGALIA_COSMOS_PKCS11_PIN="not-a-real-pin",
    )
    assert result.returncode == 2
    assert "REGALIA_COSMOS_PKCS11_MODULE is required" in result.stderr
    assert "not-a-real-pin" not in result.stderr + result.stdout


def test_nonexistent_module_is_refused_before_login(tmp_path):
    result = run_script(
        REGALIA_COSMOS_PKCS11_MODULE=str(tmp_path / "missing.so"),
        REGALIA_COSMOS_PKCS11_TOKEN_LABEL="staging",
        REGALIA_COSMOS_PKCS11_PIN="not-a-real-pin",
    )
    assert result.returncode == 2
    assert "PKCS#11 module does not exist" in result.stderr
    assert "not-a-real-pin" not in result.stderr + result.stdout


def test_missing_token_label_is_refused_after_module_path_check(tmp_path):
    module = tmp_path / "module.so"
    module.touch()
    result = run_script(
        REGALIA_COSMOS_PKCS11_MODULE=str(module),
        REGALIA_COSMOS_PKCS11_TOKEN_LABEL=None,
        REGALIA_COSMOS_PKCS11_PIN="not-a-real-pin",
    )
    assert result.returncode == 2
    assert "REGALIA_COSMOS_PKCS11_TOKEN_LABEL or REGALIA_COSMOS_PKCS11_SLOT is required" in result.stderr
    assert "not-a-real-pin" not in result.stderr + result.stdout


def test_missing_object_id_is_refused_instead_of_defaulting(tmp_path):
    module = tmp_path / "module.so"
    module.touch()
    result = run_script(
        REGALIA_COSMOS_PKCS11_MODULE=str(module),
        REGALIA_COSMOS_PKCS11_TOKEN_LABEL="staging",
        REGALIA_COSMOS_PKCS11_OBJECT_ID=None,
        REGALIA_COSMOS_PKCS11_PIN="not-a-real-pin",
    )
    assert result.returncode == 2
    assert "REGALIA_COSMOS_PKCS11_OBJECT_ID is required" in result.stderr
    assert "not-a-real-pin" not in result.stderr + result.stdout


def test_non_hex_object_id_is_refused_before_login(tmp_path):
    module = tmp_path / "module.so"
    module.touch()
    result = run_script(
        REGALIA_COSMOS_PKCS11_MODULE=str(module),
        REGALIA_COSMOS_PKCS11_TOKEN_LABEL="staging",
        REGALIA_COSMOS_PKCS11_OBJECT_ID="../../wrong",
        REGALIA_COSMOS_PKCS11_PIN="not-a-real-pin",
    )
    assert result.returncode == 2
    assert "must be hexadecimal" in result.stderr
    assert "not-a-real-pin" not in result.stderr + result.stdout


def test_non_decimal_slot_is_refused_before_login(tmp_path):
    module = tmp_path / "module.so"
    module.touch()
    result = run_script(
        REGALIA_COSMOS_PKCS11_MODULE=str(module),
        REGALIA_COSMOS_PKCS11_SLOT="4; rm -rf /",
        REGALIA_COSMOS_PKCS11_OBJECT_ID="01",
        REGALIA_COSMOS_PKCS11_PIN="not-a-real-pin",
    )
    assert result.returncode == 2
    assert "slot must be a decimal number" in result.stderr
    assert "not-a-real-pin" not in result.stderr + result.stdout


def _selector_passed_to_pkcs11_tool(tmp_path, **selector):
    """Run the signer with a recording pkcs11-tool stub and return the arguments it received."""
    module = tmp_path / "module.so"
    module.touch()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    record = tmp_path / "argv"
    stub = bin_dir / "pkcs11-tool"
    # Record, then fail, so set -e stops the script at its first token call.
    stub.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{record}"\nexit 3\n')
    stub.chmod(0o755)
    result = run_script(
        PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        REGALIA_COSMOS_PKCS11_MODULE=str(module),
        REGALIA_COSMOS_PKCS11_OBJECT_ID="01",
        REGALIA_COSMOS_PKCS11_PIN="not-a-real-pin",
        **selector,
    )
    assert result.returncode != 0 and record.exists(), result.stderr
    return record.read_text().splitlines()


def test_a_slot_selects_the_token_even_when_a_label_is_also_given(tmp_path):
    # Both Pico HSMs carry the label Pico-HSM. Selecting by label aimed the PIN at the other card
    # (CKR_PIN_INCORRECT, observed on the bench), so when a slot is supplied it must win outright.
    argv = _selector_passed_to_pkcs11_tool(
        tmp_path,
        REGALIA_COSMOS_PKCS11_SLOT="4",
        REGALIA_COSMOS_PKCS11_TOKEN_LABEL="Pico-HSM",
    )
    assert argv[argv.index("--slot") + 1] == "4"
    assert "--token-label" not in argv
    assert "not-a-real-pin" not in argv


def test_without_a_slot_the_label_selects_the_token(tmp_path):
    argv = _selector_passed_to_pkcs11_tool(tmp_path, REGALIA_COSMOS_PKCS11_TOKEN_LABEL="regalia-kms-e2e")
    assert argv[argv.index("--token-label") + 1] == "regalia-kms-e2e"
    assert "--slot" not in argv
