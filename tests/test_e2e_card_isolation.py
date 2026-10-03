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

TOOLS = re.compile(r"(?<![\w/.-])(pkcs11-tool|sc-hsm-tool|opensc-tool|pkcs15-tool|pkcs15-init|opensc-explorer)\b")
# What presents a PIN, an SO-PIN, a PIN file, or initialises a card, in every spelling these scripts use
# or could: the tools' own flags, the ceremony helpers, a PIN handed to a Go test or a systemd unit.
PIN = re.compile(r"--login\b|--pin\b|--so-pin\b|--new-pin\b|--change-pin\b|--unlock-pin\b|--unblock-pin\b|--puk\b"
                 r"|--init-token\b|--initialize\b|--pin-file\b|--wrap-key\b|--unwrap-key\b|\bpkcs15-init\b|\bopensc-explorer\b"
                 r"|sc-hsm-pty\.py|\"\$SEAL\"|(?<!export )\bREGALIA_[A-Z0-9_]*PIN(_[A-Z])?=|LoadCredential(Encrypted)?="
                 r"|\bsystemctl\s+(re)?start\b")
# The serial gates. bench_gate (e2e/lib/bench_cards.sh), target_ok (the #62 suites) and yk_gate (a
# YubiKey named by serial). A drill's wrapper is a gate only through gated_functions.
GATES = ("bench_gate", "target_ok", "yk_gate")
ISOLATION = re.compile(r"\bbench_isolate\b|opensc_isolate\.py|ignored_readers = \" \"")
FUNCTION = re.compile(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\))?\s*\{")
WINDOW = 4
# A script that drives both a real card and SoftHSM marks each SoftHSM line with this comment on the line
# directly above, and the marked line must itself name SoftHSM.
EMULATED = "# emulated token: no real card"
CALL_START = r"(?:^|[;&|({]|\bthen\b|\bdo\b|\belse\b|\bif\b|\b!)\s*"

# Scripts whose OpenSC tools never meet a real card, and why.
NO_REAL_CARD = {
    "pcr-signed-policy-swtpm.sh": "pkcs11-tool and opensc-tool are replaced by stubs written in the script",
}


def softhsm_only(text):
    return "libsofthsm2" in text and "opensc-pkcs11" not in text


def strip_strings(line, blank=True, every=False):
    """The line with any trailing comment removed and, with blank, the contents of every quoted string
    that holds whitespace (a message: a gate's name or a flag in a message is not a call). A string with
    no whitespace (a path, "$VAR", "Key=value") is kept: it is part of the command."""
    out, quote, buf, i = [], None, [], 0
    while i < len(line):
        c = line[i]
        if quote:
            if c == "\\" and quote == '"':
                buf.append(line[i:i + 2])
                i += 2
                continue
            if c == quote:
                content = "".join(buf)
                out.append(("" if blank and (every or re.search(r"\s", content)) else content) + c)
                quote, buf = None, []
            else:
                buf.append(c)
        elif c in "'\"":
            quote = c
            out.append(c)
        elif c == "#" and (i == 0 or line[i - 1] in " \t;"):
            break
        else:
            out.append(c)
        i += 1
    if quote:
        out.append("".join(buf))
    return "".join(out)


def code_lines(text, blank_strings=False):
    """The script's lines as code: comments and here-documents blanked (line numbers kept), and with
    blank_strings the contents of quoted strings too (for finding calls: a word in a message is not one)."""
    out, heredoc = [], None
    for line in text.splitlines():
        if heredoc is not None:
            out.append("")
            if line.strip() == heredoc:
                heredoc = None
            continue
        code = strip_strings(line, blank=blank_strings)
        bare = strip_strings(line)
        m = re.search(r"(?<![<$(])<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", line)
        if m and "<<<" not in line and "$((" not in line and "<<" in bare:
            heredoc = m.group(1)
        out.append("" if line.lstrip().startswith("#") else code)
    return out


def calls(names):
    return re.compile(CALL_START + r"(%s)\b" % "|".join(sorted(map(re.escape, names))))


def functions(bare):
    """(name, first line, end line, header end) of every shell function. Braces are counted with EVERY
    quoted string blanked: a "{" in a string is not a brace."""
    bare = [strip_strings(line, every=True) for line in bare]
    found, i = [], 0
    while i < len(bare):
        m = FUNCTION.match(bare[i])
        if not m:
            i += 1
            continue
        depth, j = 0, i
        while j < len(bare):
            depth += bare[j].count("{") - bare[j].count("}")
            j += 1
            if depth <= 0:
                break
        found.append((m.group(1), i, j, m.end()))
        i = j
    return found


def gated_functions(lines, bare=None):
    """Shell functions whose body calls a gate (or a gated function) before its first PIN line."""
    bare = bare if bare is not None else lines
    defs, gated = functions(bare), set()
    while True:
        gate_call = calls(GATES + tuple(gated))
        added, ungated = set(), set()
        for name, start, end, head in defs:
            if name in gated:
                continue
            first_gate = first_pin = None
            for k in range(start, end):
                code_b = bare[k][head:] if k == start else bare[k]
                code_l = lines[k][head:] if k == start else lines[k]
                g, pin = gate_call.search(code_b), PIN.search(code_l)
                if first_gate is None and g:
                    first_gate = (k, g.start())
                if first_pin is None and pin:
                    first_pin = (k, pin.start())
            if first_gate is not None and (first_pin is None or first_gate < first_pin):
                added.add(name)
            else:
                ungated.add(name)
        added -= ungated
        if not added:
            return gated
        gated |= added


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
    """lines: code_lines(text); raw: text.splitlines()."""
    raw = raw if raw is not None else lines
    bare = code_lines("\n".join(raw), blank_strings=True) if raw is not lines else lines
    gated = gated_functions(lines, bare)
    gate_call = calls(GATES + tuple(gated))
    helper_call = calls(tuple(gated)) if gated else None
    # A function's header is not a call of it, so every header is removed before looking for calls.
    # And a line inside a function looks for its gate only inside that function: a gate in the function
    # defined just above it is not this function's.
    calls_only = [FUNCTION.sub("", line, count=1) for line in bare]
    owner = [None] * len(lines)
    for _, start, end, _ in functions(bare):
        for k in range(start, end):
            owner[k] = start
    for i, line in enumerate(lines):
        pin = PIN.search(line)
        if not pin:
            continue
        floor = max(0, i - WINDOW) if owner[i] is None else max(owner[i], i - WINDOW)
        if owner[i] is None:
            # outside a function, the window must not reach into one
            floor = max([floor] + [k + 1 for k in range(floor, i) if owner[k] is not None])
        here = calls_only[i]
        cut = max(0, pin.start() - (len(bare[i]) - len(here)))
        before = calls_only[floor:i] + [here[:cut]]
        if any(gate_call.search(l) for l in before) or (helper_call and helper_call.search(here)):
            continue
        if i > 0 and raw[i - 1].strip().startswith(EMULATED) and re.search(r"softhsm", raw[i], re.I):
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
                self.assertRegex("\n".join(code_lines(text)), ISOLATION, f"{path.name} drives a real card through OpenSC without showing OpenSC only its cards "
                                 "(source e2e/lib/bench_cards.sh and call bench_isolate)")

    def test_every_pin_line_is_behind_a_serial_gate(self):
        for path, text, lines in real_card_scripts():
            for number, line in ungated_pin_lines(lines, text.splitlines()):
                with self.subTest(script=path.name, line=number):
                    self.fail(f"{path.name}:{number}: a PIN, SO-PIN or initialisation with no serial gate (bench_gate) "
                              f"within {WINDOW} lines above, and not through a gated helper: {line[:120]}")


class TheCheckItself(unittest.TestCase):
    """The rule must catch what it is for (each case is one a review found or could have found)."""

    def ungated(self, script):
        return [line for _, line in ungated_pin_lines(code_lines(script), script.splitlines())]

    def test_an_ungated_login_is_caught_in_every_spelling(self):
        for line in ("pkcs11-tool --slot 0 --login --pin env:P -O", "pkcs11-tool --change-pin --pin env:A --new-pin env:B",
                     "pkcs11-tool --unlock-pin --puk env:P", "sc-hsm-tool --pin env:P --wrap-key k", "sc-hsm-tool --unwrap-key k",
                     "pkcs15-tool --unblock-pin", "pkcs15-init --erase-card", "opensc-explorer -r 0",
                     'REGALIA_X_PIN="$P" go test ./x', "systemd-run -p LoadCredentialEncrypted=x.pin:/c true",
                     'python3 e2e/lib/sc-hsm-pty.py sc-hsm-tool --initialize', '"$IMPORT" --pin-file f'):
            with self.subTest(line):
                self.assertEqual(self.ungated("true\n" + line + "\n"), [line])

    def test_a_gate_must_be_called_and_before_the_pin(self):
        for script in ('echo "bench_gate S"\npkcs11-tool --login\n', "true # bench_gate S\npkcs11-tool --login\n",
                       "x --bench_gate\npkcs11-tool --login\n", "pkcs11-tool --login; bench_gate S\n",
                       "bench_gate S\n" + "true\n" * 5 + "pkcs11-tool --login\n", "gate S\npkcs11-tool --login\n"):
            with self.subTest(script):
                self.assertEqual(len(self.ungated(script)), 1)
        for script in ("bench_gate S\n" + "true\n" * 3 + "pkcs11-tool --login\n", "bench_gate S || exit; pkcs11-tool --login\n",
                       "if bench_gate S; then pkcs11-tool --login; fi\n", "target_ok && pkcs11-tool --login\n"):
            with self.subTest(script):
                self.assertEqual(self.ungated(script), [])

    def test_a_helper_is_a_gate_only_if_it_gates_before_its_pin(self):
        script = ('good(){ bench_gate "$1" || return 97\n  pkcs11-tool --login "$@"; }\n' + "true\n" * 6 +
                  'late(){ pkcs11-tool --login "$@"; bench_gate S; }\n'
                  'talk(){ echo "no bench_gate here"; pkcs11-tool --list-slots; }\n'
                  'gate(){ :; }\n' + "true\n" * 6 +
                  'good --login\n' + "true\n" * 6 + 'late --login\n' + "true\n" * 6 + 'talk --login\n'
                  + "true\n" * 6 + "gate S\npkcs11-tool --login\n" + "true\n" * 6 + "echo good; pkcs11-tool --login\n")
        lines = code_lines(script)
        self.assertEqual(gated_functions(lines, code_lines(script, blank_strings=True)), {"good"})
        self.assertEqual(self.ungated(script), ['late(){ pkcs11-tool --login "$@"; bench_gate S; }', "late --login", "talk --login",
                                                "pkcs11-tool --login", "echo good; pkcs11-tool --login"])

    def test_a_brace_in_a_string_does_not_join_two_functions(self):
        script = 'bad(){ echo "{"; pkcs11-tool --login; }\ngood(){ bench_gate S; pkcs11-tool --login; }\n'
        self.assertEqual(gated_functions(code_lines(script), code_lines(script, blank_strings=True)), {"good"})

    def test_comments_and_here_documents_are_not_code(self):
        script = "# pkcs11-tool --login in a comment\ncat <<'PY1'\npkcs11-tool --login\nPY1\necho $((1<<FOO))\npkcs11-tool --login\n"
        self.assertEqual(self.ungated(script), ["pkcs11-tool --login"])

    def test_the_emulated_marker_only_covers_a_softhsm_line_directly_below_it(self):
        ok = EMULATED + "\nsofthsm2-util --init-token --so-pin x\n"
        not_softhsm = EMULATED + "\npkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --login\n"
        too_far = EMULATED + "\ntrue\nsofthsm2-util --init-token --so-pin x\n"
        self.assertEqual(self.ungated(ok), [])
        self.assertEqual(len(self.ungated(not_softhsm)), 1)
        self.assertEqual(len(self.ungated(too_far)), 1)

    def test_isolation_named_only_in_a_comment_does_not_count(self):
        self.assertNotRegex("\n".join(code_lines("# we use bench_isolate elsewhere\n")), ISOLATION)

    def test_a_gate_in_the_function_above_does_not_count(self):
        script = 'a(){ bench_gate S || return 97\n  pkcs11-tool --login; }\nb(){ pkcs11-tool --login "$@"; }\n'
        self.assertEqual(self.ungated(script), ['b(){ pkcs11-tool --login "$@"; }'])

    def test_starting_a_service_is_a_pin_use(self):
        self.assertEqual(self.ungated("true\nsudo systemctl start kms.service\n"), ["sudo systemctl start kms.service"])

    def test_a_helper_that_calls_a_gated_helper_is_gated(self):
        script = 'g(){ bench_gate "$1" || exit 1; }\nw(){ g "$1"; sc-hsm-tool --initialize; }\n' + "true\n" * 6 + "w S\n"
        self.assertEqual(gated_functions(code_lines(script), code_lines(script, blank_strings=True)), {"g", "w"})

    def test_a_softhsm_only_script_is_not_a_real_card_script(self):
        self.assertTrue(softhsm_only('MODULE=/usr/lib/softhsm/libsofthsm2.so\npkcs11-tool --module "$MODULE" --login'))
        self.assertFalse(softhsm_only('M=/usr/lib/softhsm/libsofthsm2.so\nN=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so'))


if __name__ == "__main__":
    unittest.main()
