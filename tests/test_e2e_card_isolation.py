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
                 r"|sc-hsm-pty\.py|\"\$SEAL\"|LoadCredential(Encrypted)?="
                 r"|\bsystemctl\s+(re)?start\b|\bsystemctl\s+enable\s+--now\b|--verify-pin\b"
                 r"|\b(pkcs11-tool|\$P11|\$\{P11\})\b[^;|&]*\s-l\b|\s-p\s+env:")
# A PIN handed to one command in its environment, in ANY variable whose name has PIN as a word (NK_PIN, SO_PIN,
# REGALIA_X_PIN, PIN; not KEYPIN), not only REGALIA_*: a Go test or a unit reads it from there (#225). Searched
# on the view with every quoted string blanked to one word, so a quoted value is one token and only an
# assignment followed by a command word is one; reading a PIN into a shell variable is not presenting it.
PIN_PREFIX = re.compile(r"(?<![\w$-])(?<!export )(?:[A-Z0-9_]*_)?PIN(?:_[A-Z0-9_]+)?=[^\s;&|]*\s+(?=[^\s;&|#)])")


def pin_at(line, bare_line):
    """The first PIN use on a line: PIN (on the line) or PIN_PREFIX (on its blanked view, same positions)."""
    found = [m for m in (PIN.search(line), PIN_PREFIX.search(bare_line)) if m]
    return min(found, key=lambda m: m.start()) if found else None


# The serial gates. bench_gate (e2e/lib/bench_cards.sh), target_ok (the #62 suites) and yk_gate (a
# YubiKey named by serial). A drill's wrapper is a gate only through gated_functions.
GATES = ("bench_gate", "target_ok")
# A YubiKey named by serial and checked on the bus: the primitive itself, so a helper that wraps it is
# a gate through gated_functions and a no-op helper of the same name is not. (It checks ykman's view
# only: it is a gate for a YubiKey line, not for an OpenSC one; this check does not tell them apart.)
YK_PRIMITIVE = re.compile(r"ykman list --serials")
ISOLATION = re.compile(r"\bbench_isolate\b|opensc_isolate\.py|ignored_readers = \" \"")
FUNCTION = re.compile(r"^\s*(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\))?\s*\{")
WINDOW = 4
# A script that drives both a real card and SoftHSM marks each SoftHSM line with this comment on the line
# directly above, and the marked line must itself name SoftHSM.
EMULATED = "# emulated token: no real card"
CALL_START = r"(?:^|[;&|(]|(?<!\$)\{|\bthen\b|\bdo\b|\belse\b|\bif\b|\b!)\s*"

# Scripts whose OpenSC tools never meet a real card, and why.
NO_REAL_CARD = {
    "pcr-signed-policy-swtpm.sh": "pkcs11-tool and opensc-tool are replaced by stubs written in the script",
}


def softhsm_only(text):
    return "libsofthsm2" in text and "opensc-pkcs11" not in text


# What a real-card script may not do, each a way past the gate check (#225). Each finding: (line, why).
LIB_GATE_NAMES = ("bench_gate", "bench_reader_gate", "bench_isolate", "bench_slot")


def script_problems(text):
    lines, bare = code_lines(text), code_lines(text, blank_strings=True)
    found = []
    for name, start, end, _ in functions(bare):
        body = " ".join(bare[start:end])
        if name in LIB_GATE_NAMES:
            found.append((start + 1, "redefines %s, e2e/lib/bench_cards.sh's gate" % name))
        if name in ("die", "fail") and not re.search(r"\bexit\b", body):
            found.append((start + 1, "%s does not exit: a gate's \"|| %s\" would go on to the PIN" % (name, name)))
    for n, (line, b) in enumerate(zip(lines, bare), 1):
        if re.search(r"\beval\b", b):
            found.append((n, "eval: what it runs is not read by this check"))
        if re.search(r"\b(bash|sh)\b[^|;&]*<<", b):
            found.append((n, "a here-document fed to a shell: its body is not read by this check"))
        for m in re.finditer(r"\b(bash|sh)\s+-[a-z]*c\s+(\S)", line):
            literal = re.match(r"'([^']*)'", line[m.start(2):])
            if not literal:
                found.append((n, "%s -c with a command that is not one single-quoted literal" % m.group(1)))
            elif TOOLS.search(literal.group(1)) or PIN.search(literal.group(1)):
                found.append((n, "%s -c runs a card tool or a PIN line inside a string" % m.group(1)))
        if re.search(r"\b(if|while|until)\s+(!\s*)?(false|true|:)\s*;", b):
            found.append((n, "a constant condition: a gate under it may never run"))
        # (export -n UN-exports: that is the right thing, not this)
        if re.search(r"\bexport\s+(?!-n\b)(?:-\w+\s+)*(?:[A-Z0-9_]*_)?PIN(?:_[A-Z0-9_]+)?\b", line):
            found.append((n, "a PIN exported to every later command: hand it to the one gated command that uses it"))
    return found


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
                # Blanked to the SAME LENGTH, so a position in this view is the same as in the other.
                out.append(("_" * len(content) if blank and (every or re.search(r"\s", content)) else content) + c)
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


def call_view(line):
    """The line for finding CALLS: every quoted string blanked to its own length (a ";" or a gate's
    name inside a string is not a call), and "${" taken apart (a "{" in a parameter expansion is not
    the start of a command)."""
    line = strip_strings(line, every=True)
    # a whole parameter expansion, braces included, blanked to its length (nested ones from the inside)
    while True:
        new = re.sub(r"\$\{[^{}]*\}", lambda m: "$" + "_" * (len(m.group(0)) - 1), line)
        if new == line:
            return line
        line = new


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
        bare = call_view(line)
        m = re.search(r"(?<![<$(])<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", line)
        if m and "<<<" not in line and "$((" not in line and "<<" in bare:
            heredoc = m.group(1)
        out.append("" if line.lstrip().startswith("#") else (call_view(line) if blank_strings else code))
    return out


# A gate's failure must stop the PIN (#225): "|| die|exit|return|fail" (or a brace group ending in one) after the
# call, an "if gate; then" or "gate &&" that reaches the PIN only on success, or a plain statement in a "set -e"
# script outside any function. "|| true", a subshell, a command substitution, a background job or a bare call
# with nothing stopping on its status are not gates. die and fail must exit (checked below).
ABORT = re.compile(r"\|\|\s*(?:\{[^}]*?\b(?:exit|return|die|fail)\b|(?:exit|return|die|fail)\b)")
ABORT_EXITS = re.compile(r"\|\|\s*(?:\{[^}]*?\b(?:exit|die|fail)\b|(?:exit|die|fail)\b)")
SET_E = re.compile(r"(?m)^\s*set\s+-[a-z]*e")


def effective(line, match, exiting=(), set_e=False, toplevel=False, tail_of_function=False):
    """Whether this call of a gate (match.group(1) is its name, or the YubiKey bus check) stops what follows
    when it fails. `exiting`: wrappers whose own failure exits the shell, so a plain call of one is enough."""
    name_start = match.start(1) if match.re.groups else match.start()
    prefix, rest = line[:name_start], line[match.end():]
    rest = re.sub(r"\d*[<>]&\d*-?|&>>?", " ", rest)  # a redirection's "&" (2>&1, &>) is not a list operator
    if re.search(r"\$\(\s*$|(?:^|[^$\w])\(\s*$", prefix):
        return False                                   # a subshell or a command substitution: its exit ends only itself
    if re.search(r"(?<!&)&(?!&)", re.split(r"\|\||&&|;|\|", rest)[0]):
        return False                                   # in the background: nothing waits for its status
    name = match.group(1) if match.re.groups else ""
    if name in exiting:
        return True
    if ABORT.search(rest) or re.match(r"[^;|&]*&&", rest) or re.search(r"\bif\s+$", prefix):
        return True
    if tail_of_function and re.fullmatch(r"[^;&]*\s*;?\s*\}?\s*", rest):
        return True                                    # its status is the function's: the caller's "||" decides
    return set_e and toplevel and not prefix.strip() and not re.search(r"\|\||&&|\||&", rest)


class _Calls:
    """Calls of one of the names (and, unless yubikey=False, the YubiKey bus check) that are effective gates."""

    def __init__(self, names, exiting=(), yubikey=True, set_e=False):
        self.names = re.compile(CALL_START + r"(%s)\b" % "|".join(sorted(map(re.escape, names)))) if names else None
        self.exiting, self.yubikey, self.set_e = set(exiting), yubikey, set_e

    def search(self, line, toplevel=False, continued="", tail_of_function=False):
        """continued: the next line, when this one ends with a backslash (its "&&" or "||" may be there)."""
        found = list(self.names.finditer(line)) if self.names else []
        if self.yubikey:
            found += list(YK_PRIMITIVE.finditer(line))
        joined = line.rstrip()[:-1] + " " + continued if continued and line.rstrip().endswith("\\") else line
        for m in sorted(found, key=lambda m: m.start()):
            if effective(joined, m, self.exiting, self.set_e, toplevel, tail_of_function):
                return m
        return None


def calls(names, exiting=(), yubikey=True, set_e=False):
    return _Calls(names, exiting, yubikey, set_e)


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


def gated_functions(lines, bare=None, yubikey=True, with_exiting=False):
    """Shell functions whose body has an effective gate (or a gated function) before its first PIN line. With
    yubikey=False the YubiKey bus check is not a gate (for an OpenSC PIN line). With with_exiting, also the
    subset whose gate's failure exits the shell (a plain call of one of those is a gate)."""
    bare = bare if bare is not None else lines
    defs, gated, exiting = functions(bare), set(), set()
    while True:
        gate_call = calls(GATES + tuple(gated), exiting, yubikey)
        added, ungated = {}, set()
        for name, start, end, head in defs:
            if name in gated:
                continue
            first_gate = first_pin = None
            for k in range(start, end):
                code_b = bare[k][head:] if k == start else bare[k]
                code_l = lines[k][head:] if k == start else lines[k]
                g = gate_call.search(code_b, continued=bare[k + 1] if k + 1 < len(bare) else "", tail_of_function=(k == end - 1))
                pin = pin_at(code_l, code_b)
                if first_gate is None and g:
                    first_gate = (k, g.start(), g, code_b)
                if first_pin is None and pin:
                    first_pin = (k, pin.start())
            if first_gate is not None and (first_pin is None or first_gate[:2] < first_pin):
                g, code_b = first_gate[2], first_gate[3]
                called = g.group(1) if g.re.groups else ""
                added[name] = called in exiting or bool(ABORT_EXITS.search(code_b[g.end():]))
            else:
                ungated.add(name)
        for name in ungated:
            added.pop(name, None)
        if not added:
            return (gated, exiting) if with_exiting else gated
        gated |= set(added)
        exiting |= {name for name, exits in added.items() if exits}


def real_card_scripts():
    for path in sorted(E2E.glob("*.sh")):
        text = path.read_text()
        lines = code_lines(text)
        if not any(TOOLS.search(line) for line in lines):
            continue
        if path.name in NO_REAL_CARD or softhsm_only(text):
            continue
        yield path, text, lines


# A PIN line that reaches a card through OpenSC: a YubiKey on the bus (ykman's view) is no gate for it (#225).
OPENSC_PIN = re.compile(TOOLS.pattern + r"|--login\b|--so-pin\b|--pin\b|\$P11\b|\$\{P11\}|sc-hsm-pty|\s-l\b")


def ungated_pin_lines(lines, raw=None):
    """lines: code_lines(text); raw: text.splitlines()."""
    raw = raw if raw is not None else lines
    bare = code_lines("\n".join(raw), blank_strings=True) if raw is not lines else lines
    set_e = bool(SET_E.search("\n".join(lines)))
    gated, exiting = gated_functions(lines, bare, with_exiting=True)
    gated_o, exiting_o = gated_functions(lines, bare, yubikey=False, with_exiting=True)
    any_gate = calls(GATES + tuple(gated), exiting, True, set_e)
    opensc_gate = calls(GATES + tuple(gated_o), exiting_o, False, set_e)
    helper_any = re.compile(CALL_START + r"(%s)\b" % "|".join(sorted(map(re.escape, gated)))) if gated else None
    helper_o = re.compile(CALL_START + r"(%s)\b" % "|".join(sorted(map(re.escape, gated_o)))) if gated_o else None
    # A function's header is not a call of it, so every header is removed before looking for calls.
    # And a line inside a function looks for its gate only inside that function: a gate in the function
    # defined just above it is not this function's.
    calls_only = [FUNCTION.sub("", line, count=1) for line in bare]
    owner = [None] * len(lines)
    for _, start, end, _ in functions(bare):
        for k in range(start, end):
            owner[k] = start
    for i, line in enumerate(lines):
        pin = pin_at(line, bare[i])
        if not pin:
            continue
        opensc = bool(OPENSC_PIN.search(line))
        gate_call, helper_call = (opensc_gate, helper_o) if opensc else (any_gate, helper_any)
        floor = max(0, i - WINDOW) if owner[i] is None else max(owner[i], i - WINDOW)
        if owner[i] is None:
            # outside a function, the window must not reach into one
            floor = max([floor] + [k + 1 for k in range(floor, i) if owner[k] is not None])
        here = calls_only[i]
        cut = max(0, pin.start() - (len(bare[i]) - len(here)))
        before = calls_only[floor:i] + [here[:cut]]
        toplevel = owner[i] is None
        if any(gate_call.search(l, toplevel, continued=(before[j + 1] if j + 1 < len(before) else here)) for j, l in enumerate(before)) or (helper_call and helper_call.search(here) and helper_call.search(here).start() <= cut):
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


    def test_no_real_card_script_has_a_way_past_the_gate_check(self):
        for path, text, _ in real_card_scripts():
            for number, why in script_problems(text):
                with self.subTest(script=path.name, line=number):
                    self.fail(f"{path.name}:{number}: {why}")

    def test_a_softhsm_only_script_cannot_be_pointed_at_another_module(self):
        # softhsm_only exempts it from isolation and gates; a variable that could name opensc-pkcs11.so
        # instead would take a real card out of reach of both (#225)
        for path in sorted(E2E.glob("*.sh")):
            text = path.read_text()
            if softhsm_only(text):
                with self.subTest(script=path.name):
                    self.assertNotRegex(text, r"\$\{\w+:-[^}\n]*libsofthsm2", f"{path.name}'s SoftHSM module can be overridden by a variable")


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
        for script in ("set -e\nbench_gate S\n" + "true\n" * 2 + "pkcs11-tool --login\n", "bench_gate S || exit; pkcs11-tool --login\n",
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
        script = 'bad(){ echo "{"; pkcs11-tool --login; }\ngood(){ bench_gate S || return 97; pkcs11-tool --login; }\n'
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

    def test_positions_are_compared_on_the_same_text(self):
        for script in ('pkcs11-tool --label "a b c d e f g h i j k l m" --login; bench_gate S\n',
                       'f(){ say "a b c d e f g h i j k l m n o p q"; pkcs11-tool --login "$@"; bench_gate S; }\n' + "true\n" * 6 + "f -O\n",
                       'echo "x;bench_gate"\npkcs11-tool --login\n', ': "${bench_gate:=1}"\npkcs11-tool --login\n'):
            with self.subTest(script):
                self.assertTrue(self.ungated(script))

    def test_a_yubikey_gate_is_trusted_for_what_it_does_not_by_name(self):
        real = 'yk_gate(){ ykman list --serials | grep -qx "$1"; }\nphase(){ yk_gate "$2" || exit; systemd-run -p LoadCredentialEncrypted=x.pin:/c t; }\n'
        fake = 'yk_gate(){ :; }\nphase(){ yk_gate "$2" || exit; systemd-run -p LoadCredentialEncrypted=x.pin:/c t; }\n'
        self.assertEqual(self.ungated(real), [])
        self.assertEqual(len(self.ungated(fake)), 1)

    def test_the_envelope_drills_key_listing_gates_in_the_main_shell(self):
        # has_kek runs p11 in a pipeline: p11's own gate would only end a subshell, and "nothing listed"
        # would read as "no key". The gate in has_kek itself is what stops the drill.
        self.assertIn("has_kek(){ gate; p11", (E2E / "nitrokey-envelope-restore-drill.sh").read_text())

    def test_a_gated_helper_after_the_pin_on_the_same_line_does_not_count(self):
        script = 'good(){ bench_gate "$1" || return 97; }\n' + "true\n" * 6 + "pkcs11-tool --login; good S\n"
        self.assertEqual(self.ungated(script), ["pkcs11-tool --login; good S"])

    def test_short_flags_and_other_spellings(self):
        for line in ("pkcs11-tool -l -p env:P -O", "pkcs15-tool --verify-pin", "systemctl enable --now kms"):
            with self.subTest(line):
                self.assertEqual(self.ungated("true\n" + line + "\n"), [line])

    def test_a_softhsm_only_script_is_not_a_real_card_script(self):
        self.assertTrue(softhsm_only('MODULE=/usr/lib/softhsm/libsofthsm2.so\npkcs11-tool --module "$MODULE" --login'))
        self.assertFalse(softhsm_only('M=/usr/lib/softhsm/libsofthsm2.so\nN=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so'))


    def test_a_gate_whose_status_is_ignored_is_not_a_gate(self):
        """#225: a gate counts only when its failure stops what follows."""
        for script in ("bench_gate S || true\npkcs11-tool --login\n", "bench_gate S\npkcs11-tool --login\n",
                       "( bench_gate S )\npkcs11-tool --login\n", "x=$(bench_gate S)\npkcs11-tool --login\n",
                       "bench_gate S &\npkcs11-tool --login\n", "if ! bench_gate S; then :; fi\npkcs11-tool --login\n",
                       "if false; then bench_gate S; fi\npkcs11-tool --login\n",
                       "set -e\nf(){ bench_gate S; pkcs11-tool --login; }\n",
                       "w(){ bench_gate \"$1\" || return 97; }\n" + "true\n" * 6 + "w S\npkcs11-tool --login\n"):
            with self.subTest(script):
                self.assertEqual(len(self.ungated(script)), 1, script)
        for script in ("bench_gate S || die x\npkcs11-tool --login\n", "bench_gate S || { echo no; exit 2; }\npkcs11-tool --login\n",
                       "set -e\nbench_gate S\npkcs11-tool --login\n", "bench_gate S 2>&1 || exit 1\npkcs11-tool --login\n",
                       "w(){ bench_gate \"$1\" || die no; }\n" + "true\n" * 6 + "w S\npkcs11-tool --login\n",
                       "w(){ bench_gate \"$1\" || return 97; }\n" + "true\n" * 6 + "w S || exit\npkcs11-tool --login\n",
                       "bench_gate S \\\n  || exit 1\npkcs11-tool --login\n"):
            with self.subTest(script):
                self.assertEqual(self.ungated(script), [], script)

    def test_a_yubikey_on_the_bus_is_no_gate_for_an_opensc_pin(self):
        yk = 'yk_gate(){ ykman list --serials | grep -qx "$1" || return 97; }\n' + "true\n" * 6
        self.assertEqual(len(self.ungated(yk + 'yk_gate S || exit\npkcs11-tool --login\n')), 1)
        self.assertEqual(self.ungated(yk + 'yk_gate S || exit\nsystemd-run -p LoadCredentialEncrypted=x.pin:/c t\n'), [])

    def test_a_pin_in_any_variable_before_a_command_is_a_pin_line(self):
        for line in ('NK_PIN="$P" go test ./x', "PIN=1234 ./cmd", 'MY_SO_PIN="$S" ./tool --x'):
            with self.subTest(line):
                self.assertEqual(self.ungated("true\n" + line + "\n"), [line])
        self.assertEqual(self.ungated('true\nHSM_PIN="$(cat f)"\nX_PIN=1; echo ok\n'), [])   # reading a PIN is not presenting it

    def test_the_ways_past_the_check_are_refused(self):
        cases = {
            "bench_gate(){ :; }\n": "redefines bench_gate",
            "die(){ echo no; }\n": "die does not exit",
            'eval "$CMD"\n': "eval",
            "bash <<EOF\npkcs11-tool --login\nEOF\n": "here-document fed to a shell",
            'sh -c "$X"\n': "not one single-quoted literal",
            "sh -c 'pkcs11-tool --login'\n": "card tool or a PIN line inside a string",
            "if false; then bench_gate S; fi\n": "constant condition",
            'export NK_PIN="$P"\n': "PIN exported",
        }
        for script, why in cases.items():
            with self.subTest(script):
                self.assertTrue(any(why in w for _, w in script_problems(script)), script_problems(script))
        self.assertEqual(script_problems("sh -c 'ls /etc' sh x\ndie(){ echo no; exit 2; }\n"), [])


if __name__ == "__main__":
    unittest.main()
