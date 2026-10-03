"""Every e2e script that drives a REAL card through OpenSC sees only its own cards and presents a PIN only
behind a serial gate (regalia-kms#174).

OpenSC with its defaults enumerates every reader on the bench: it probes the other cards, leaves a
YubiKey's PIV applet selected (three PIV PIN tries were lost that way on 2026-10-02), and numbers slots
over all readers, so a login "on the same slot" can reach another card after a reader leaves
(DENK0404380 slid into DENK0404144's slot 0x4, measured). So a script that runs pkcs11-tool,
sc-hsm-tool, opensc-tool or pkcs15-tool against real cards must

  * ISOLATE: give OpenSC a configuration that shows only the cards under test (e2e/lib/bench_cards.sh's
    bench_isolate, or e2e/lib/opensc_isolate.py directly), or one that shows no card at all; and
  * GATE: every line that can present a PIN, the SO-PIN, or initialise a card is preceded, within a few
    lines, by a serial gate (bench_gate, or a drill's gate/target_ok/p11l/hsm_login), or calls a helper
    whose own body is gated.

This reads the scripts. It cannot prove a gate is correct; it proves no PIN line was written without one.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
E2E = ROOT / "e2e"

TOOLS = re.compile(r"(?<![\w/.-])(pkcs11-tool|sc-hsm-tool|opensc-tool|pkcs15-tool)\b")
PIN = re.compile(r"--login\b|sc-hsm-pty\.py|--so-pin\b|--init-token\b|--initialize\b|--pin-file\b|\"\$SEAL\"")
# The gates themselves. A drill's own wrappers (p11l, hsm_login, …) count only through gated_functions:
# a wrapper is a gate when its body is.
GATE_WORDS = r"bench_gate|gate|target_ok"
GATE = re.compile(r"\b(%s)\b" % GATE_WORDS)
ISOLATION = re.compile(r"\bbench_isolate\b|opensc_isolate\.py|ignored_readers = \" \"")
FUNCTION = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{")
WINDOW = 4
# A script that drives both a real card and an emulated one marks the emulated lines with this comment
# within the window above them.
EMULATED = "# emulated token: no real card"

# Scripts whose OpenSC tools never meet a real card, and why.
NO_REAL_CARD = {
    "pcr-signed-policy-swtpm.sh": "pkcs11-tool and opensc-tool are replaced by stubs written in the script",
}


def softhsm_only(text):
    return "libsofthsm2" in text and "opensc-pkcs11" not in text


def code_lines(text):
    """The script's lines, with comment lines and here-documents blanked out (line numbers kept)."""
    lines, out, heredoc = text.splitlines(), [], None
    for line in lines:
        if heredoc is not None:
            out.append("")
            if line.strip() == heredoc:
                heredoc = None
            continue
        m = re.search(r"<<-?\s*'?\"?([A-Za-z_]+)'?\"?", line)
        if m and "<<<" not in line:
            heredoc = m.group(1)
        out.append("" if line.lstrip().startswith("#") else line)
    return out


def gated_functions(lines):
    """Names of the shell functions whose own body contains a serial gate."""
    names, i = set(), 0
    while i < len(lines):
        m = FUNCTION.match(lines[i])
        if not m:
            i += 1
            continue
        body, depth, j = [], 0, i
        while j < len(lines):
            body.append(lines[j])
            depth += lines[j].count("{") - lines[j].count("}")
            j += 1
            if depth <= 0:
                break
        if GATE.search("\n".join(body)):
            names.add(m.group(1))
        i = j
    return names


def real_card_scripts():
    for path in sorted(E2E.glob("*.sh")):
        text = path.read_text()
        lines = code_lines(text)
        if not any(TOOLS.search(line) for line in lines):
            continue
        if path.name in NO_REAL_CARD or softhsm_only(text):
            continue
        yield path, text, lines


def ungated_pin_lines(lines, raw=None):
    raw = raw if raw is not None else lines
    gated = gated_functions(lines)
    calls_gated = re.compile(r"\b(%s)\b" % "|".join(sorted(map(re.escape, gated)))) if gated else None
    for i, line in enumerate(lines):
        if not PIN.search(line):
            continue
        window = "\n".join(lines[max(0, i - WINDOW):i + 1])
        if GATE.search(window) or (calls_gated and calls_gated.search(line)):
            continue
        if any(EMULATED in above for above in raw[max(0, i - WINDOW):i + 1]):
            continue
        yield i + 1, line.strip()


class RealCardScriptsAreIsolatedAndGated(unittest.TestCase):

    def test_the_drills_named_in_the_issue_are_among_the_scripts_checked(self):
        checked = {path.name for path, _, _ in real_card_scripts()}
        for name in ("nitrokey-pin-import-drill.sh", "nitrokey-token-swap-drill.sh", "nitrokey-cross-card-restore-drill.sh",
                     "nitrokey-envelope-restore-drill.sh", "nitrokey-two-site-failover-drill.sh", "nitrokey-pin-custody-drill.sh",
                     "yubikey-pin-custody-drill.sh", "pkcs11-contract.sh", "pkcs11-removal.sh", "cosmos-hardware-sign-verify.sh",
                     "kms-two-token-systemd.sh"):
            self.assertIn(name, checked, f"{name} is not recognised as a script that drives a real card")

    def test_every_real_card_script_isolates_opensc(self):
        for path, text, _ in real_card_scripts():
            with self.subTest(script=path.name):
                self.assertRegex(text, ISOLATION, f"{path.name} drives a real card through OpenSC without showing OpenSC only its cards "
                                 "(source e2e/lib/bench_cards.sh and call bench_isolate)")

    def test_every_pin_line_is_behind_a_serial_gate(self):
        for path, text, lines in real_card_scripts():
            for number, line in ungated_pin_lines(lines, text.splitlines()):
                with self.subTest(script=path.name, line=number):
                    self.fail(f"{path.name}:{number}: a PIN, SO-PIN or initialisation with no serial gate (bench_gate) "
                              f"within {WINDOW} lines above, and not through a gated helper: {line[:120]}")


class TheCheckItself(unittest.TestCase):
    """The rule must catch what it is for."""

    def test_an_ungated_login_is_caught(self):
        lines = code_lines('x(){ :; }\nPKCS11_PIN="$P" pkcs11-tool --module m --slot 0 --login --pin env:PKCS11_PIN -O\n')
        self.assertEqual([n for n, _ in ungated_pin_lines(lines)], [2])

    def test_a_gate_a_few_lines_above_passes_and_one_further_up_does_not(self):
        near = "bench_gate S\n" + "true\n" * 3 + "pkcs11-tool --login\n"
        far = "bench_gate S\n" + "true\n" * 5 + "pkcs11-tool --login\n"
        self.assertEqual(list(ungated_pin_lines(code_lines(near))), [])
        self.assertEqual(len(list(ungated_pin_lines(code_lines(far)))), 1)

    def test_a_call_through_a_gated_helper_passes_and_through_an_ungated_one_does_not(self):
        script = ('good(){ bench_gate "$1" || return 97\n  pkcs11-tool --login "$@"; }\n'
                  'bad(){ pkcs11-tool --list-slots; }\n' + "true\n" * 6 +
                  'good S --login -O\n' + "true\n" * 6 + 'bad --login\n')
        lines = code_lines(script)
        self.assertEqual(gated_functions(lines), {"good"})
        self.assertEqual([line for _, line in ungated_pin_lines(lines)], ["bad --login"])

    def test_an_emulated_line_must_be_marked(self):
        marked = "x=1\n" + EMULATED + "\nsofthsm2-util --init-token --so-pin x\n"
        unmarked = "x=1\nsofthsm2-util --init-token --so-pin x\n"
        self.assertEqual(list(ungated_pin_lines(code_lines(marked), marked.splitlines())), [])
        self.assertEqual(len(list(ungated_pin_lines(code_lines(unmarked), unmarked.splitlines()))), 1)

    def test_comments_and_here_documents_are_not_code(self):
        script = "# pkcs11-tool --login in a comment\ncat <<'PY'\npkcs11-tool --login\nPY\n"
        self.assertEqual(list(ungated_pin_lines(code_lines(script))), [])

    def test_a_softhsm_only_script_is_not_a_real_card_script(self):
        self.assertTrue(softhsm_only('MODULE=/usr/lib/softhsm/libsofthsm2.so\npkcs11-tool --module "$MODULE" --login'))
        self.assertFalse(softhsm_only('M=/usr/lib/softhsm/libsofthsm2.so\nN=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so'))


if __name__ == "__main__":
    unittest.main()
