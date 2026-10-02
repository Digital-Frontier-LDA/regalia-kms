"""No shell script here may run Python in a way that lets a file in the working directory, or a PYTHON*
variable in the caller's environment, replace a module.

`python3 -c …`, `python3 - …` (a program on standard input) and `python3 -m …` put the CURRENT DIRECTORY
first on the module path; PYTHONPATH does the same for every form. In regalia-ceremony a secrets.py
beside the ceremony chose the key a generator printed (measured 2026-10-02, regalia-ceremony#102). Here
the same forms run as root on a KMS host (deploy/baremetal/recovery-key.sh reads a LUKS header with
them) and on the bench beside real PINs (the e2e drills).

What each flag stops (measured on Python 3.13): -I everything (no working directory, no script
directory, no PYTHON* variables, no user site-packages); -E the PYTHON* variables only, so user site and
its .pth files still load, hence -s with it; -s user site-packages; -P the working directory only.

The rule, for every tracked *.sh and every other tracked file that starts with a shell "#!" line; a
comment line is not code, a line continued with a backslash is one:
  a program on the command line, on standard input or by module name     must carry -I
  a script run by path                                                  must carry -E and -s, or -I
  a Python program run through its "#!" line ("$HERE/x.py" as a command, also behind VAR=value words,
  timeout, sudo, exec, env or a pipe)                                    is a finding: start it as
                                                                          python3 -Es "$HERE/x.py"
  PYTHONPATH="$HERE" python3 …   a command that sets the module path ITSELF, to the repository, to
                            import deploy.baremetal: -P and -s for an inline program (the working
                            directory and the user site are dropped; -P alone still loads a .pth
                            under PYTHONUSERBASE, measured), -s for a script by path. The assignment
                            must be exactly PYTHONPATH="$HERE", directly before the interpreter:
                            any other PYTHONPATH= on a line of code is a finding
  python3 -m unittest …, python3 -m deploy.… / kms.… / tools.…   our own modules, started from the
                            repository root on purpose: -E and -s (the working directory is the point)
An interpreter is python3, python3.N, python, python2 or pypy3 as a word or behind a directory, and a
variable whose name says it holds one ("$PY", "$PYBIN", $python_bin): at the start of a command
always, elsewhere when an evident script follows it.

THE COMMANDS AN OPERATOR IS TOLD TO TYPE are held to the same rule: every tracked *.md, and the usage
lines of the tools under deploy/, tools/ and e2e/. Those are the production surface, run as root.

A GUARD FOR THE FORMS THESE SCRIPTS USE, NOT A PROOF. Not seen: eval of a command held in a variable,
a wrapper function, find -exec and xargs, a script with no .py and no directory in its name, workflow
steps in .github/, and Python that starts Python. Known and left: -Ps beside PYTHONPATH still honours
PYTHONHOME and searches the repository before the standard library (the stricter form is
python3 -I -c 'import sys; sys.path.append(…)').

That recovery-key.sh really is immune is run, not read: tests/test_baremetal_recovery_key.py plants a
json.py in the working directory and on PYTHONPATH and runs every mode."""
import os
import pathlib
import re
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
# WHAT COUNTS AS AN INTERPRETER: python3, python3.N, python, python2, pypy3 as a word; any of them
# behind a directory; and a variable, quoted or not, whose name says it holds one (PY, PYBIN, python_bin…).
WORD = r'(?<![\w./$-])(?:python3(?:\.\d+)?|python2?|pypy3?)(?![\w.-])["\'}]?'
PATHED = r'["\']?[\w$/{}.:-]*/(?:python(?:[23](?:\.\d+)?)?|pypy3?)(?![\w.-])["\'}]?'
VARIABLE = r'(?<![\w$])"?\$\{?(?:\w*_)?(?:py|PY|pybin|PYBIN|python3?|PYTHON3?|interp|INTERP)(?:_\w+)?(?::-[^}]*)?\}?"?(?![\w.])'
INTERP = re.compile("(?P<word>%s)|(?P<pathed>%s)|(?P<variable>%s)" % (WORD, PATHED, VARIABLE))
# A command starts here; before its first word may stand VAR=value words, timeout N, sudo, nohup, exec, env.
START = r'(?:^|[;&({!|]|\$\(|\bthen\b|\bdo\b|\bif\b|\belse\b)\s*(?:!\s*)?'
ASSIGN = r'\w+=(?:[\w./:-]*|"(?:[^"$]|\$(?!\())*")\s+'            # VAR=value, VAR="$OTHER"; not VAR="$(…)"
PREFIX = r'(?:' + ASSIGN + r'|timeout\s+\S+\s+|sudo\s+|nohup\s+|exec\s+|env\s+(?:-\S+\s+\S+\s+)*)*'
COMMAND = re.compile(START + PREFIX + r'$')
DIRECT = re.compile(START + PREFIX + r'"?(?:\$[\w{(]|\.{0,2}/|[\w.-]+/)[\w$/{}.-]*\.py"?(?=\s|$|\)|;)')
THE_PATH = re.compile(r'PYTHONPATH="\$HERE"\s+$')                # the ONLY accepted assignment, directly before the interpreter
OURS = re.compile(r"^(?:unittest$|deploy\.|kms\.|tests\.|tools\.)")       # modules run with -m from the repository root on purpose
SHELL = re.compile(r"^#!.*\b(?:ba|da)?sh\b")


def judge(rest, sets_path, piped, loose):
    """What follows the interpreter on the (joined) line -> what is wrong, or None. `loose`: the
    interpreter is a bare `python` in prose, or a variable that is not the first word of a command;
    then only an inline program or an evident script counts."""
    words = rest.split()
    flags, i, inline, module = "", 0, False, None
    while i < len(words) and len(words[i]) > 1 and words[i].startswith("-"):
        word = words[i]
        if word.startswith("-<"):                       # python3 -<<EOF: "-" and a here-document
            break
        if word == "--":
            i += 1
            break
        if word == "--check-hash-based-pycs":
            i += 2
            continue
        if word.startswith("--"):
            return None                                 # --version, --help: no program runs
        if word[:2] in ("-W", "-X"):                    # an option with a value, attached or the next word
            i += 2 if len(word) == 2 else 1
            continue
        letters = word[1:]
        cut = min([letters.index(ch) for ch in "cm" if ch in letters] or [len(letters)])   # -uc, -mvenv
        flags += letters[:cut]
        if cut < len(letters):
            inline = True
            if letters[cut] == "m":
                module = letters[cut + 1:] or (words[i + 1] if i + 1 < len(words) else "")
            break
        i += 1
    word = words[i] if i < len(words) else ""
    if not inline:
        if word == "-" or word.startswith(("<", "-<")):
            inline = True                               # python3 - …, python3 <<EOF, python3 < file
        elif piped and (not word or re.match(r"^[0-9]*[>|;&)]", word)):
            inline = True                               # … | python3
    isolated = "I" in flags or ("E" in flags and "s" in flags)
    if inline:
        if module is not None and OURS.match(module.strip("`'\"")):
            # A test runner, or one of our own modules, started from the repository root: the working
            # directory is the point, the caller's PYTHON* variables and user site are not.
            return None if isolated else "python3 -m %s without -E and -s" % module.strip("`'\"")
        if "I" in flags or (sets_path and "P" in flags and "s" in flags):
            return None
        return "a program on the command line, on standard input or by module name, without -%s" % ("P and -s" if sets_path else "I")
    if not word or re.match(r"^[0-9]*[<>|&;)]", word):
        return None
    bare = word.strip("\"'`);")
    if loose:
        script = bare.endswith(".py") or re.search(r"(?i)^\$\{?\w*py\}?$", bare)
    else:
        script = "/" in bare or bare.startswith("$") or bare.endswith(".py")
    if script:
        if sets_path:
            return None if "s" in flags else "a script by path beside an explicit PYTHONPATH, without -s"
        return None if isolated else "a script by path without -E and -s"
    return None


def findings(text, prose=False):
    """(line number, what is wrong) for each offending line of a shell script's text. `prose`: the
    text is documentation; only what an interpreter is asked to run is judged."""
    found, lines, number = [], text.split("\n"), 0
    while number < len(lines):
        start, line = number, lines[number]
        while line.rstrip().endswith("\\") and number + 1 < len(lines):   # a continued line is one line
            number += 1
            line = line.rstrip()[:-1] + " " + lines[number].lstrip()
        number += 1
        if line.lstrip().startswith("#") and not prose:
            continue
        accepted = 0
        for match in INTERP.finditer(line):
            before = line[:match.start()]
            sets_path = bool(THE_PATH.search(before))
            accepted += sets_path
            loose = match.group(0).strip("\"'}") in ("python", "python2") or (
                match.group("variable") is not None and not COMMAND.search(before))
            what = judge(line[match.end():], sets_path, bool(re.search(r"(?<!\|)\|&?\s*$", before)), loose)
            if what:
                found.append((start + 1, what))
        if not prose:
            if len(re.findall(r"\bPYTHONPATH=", line)) != accepted:
                found.append((start + 1, 'PYTHONPATH may only be set as PYTHONPATH="$HERE", directly before the interpreter'))
            if DIRECT.search(line):
                found.append((start + 1, "a Python program run through its #! line (start it as python3 -Es <path>)"))
    return found


def tracked(*patterns):
    return subprocess.run(["git", "ls-files", *patterns], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split("\n")[:-1]


def shell_scripts():
    """Every tracked *.sh, and every other tracked file whose first line is a shell "#!" line (the
    initrd's wg-boot has no extension)."""
    scripts = []
    for name in tracked():
        path = ROOT / name
        if not path.is_file():
            continue
        if name.endswith(".sh"):
            scripts.append(name)
            continue
        try:
            with open(path, "rb") as f:
                first = f.readline(200).decode("utf-8", "replace")
        except OSError:
            continue
        if SHELL.match(first):
            scripts.append(name)
    return scripts


class PythonRunsIsolated(unittest.TestCase):
    def test_every_shell_script_follows_the_rule(self):
        scripts = shell_scripts()
        self.assertGreater(len(scripts), 20, "almost no scripts were found: the check would pass by reading nothing")
        self.assertIn("deploy/baremetal/initrd/wg-boot", scripts, "a shell script without .sh was not read")
        seen = 0
        for name in scripts:
            text = (ROOT / name).read_text(encoding="utf-8", errors="replace")
            seen += len(INTERP.findall(text))
            for number, what in findings(text):
                with self.subTest(script=name, line=number):
                    self.fail("%s:%d: %s. Add -I (or -Es for a script by path, -Ps beside PYTHONPATH=\"$HERE\")" % (name, number, what))
        self.assertGreater(seen, 40, "almost no python3 invocation was seen: the pattern no longer matches how they are written")

    def test_the_commands_an_operator_is_told_to_type_follow_it_too(self):
        """The production surface is not the e2e scripts: it is `sudo python3 deploy/baremetal/host_probe.py …`
        as the runbooks and the tools' own usage text give it, typed by root on a KMS host."""
        documents = tracked("*.md") + [name for name in tracked("deploy/*.py", "tools/*.py", "e2e/*.py") if "/tests/" not in name]
        self.assertGreater(len(documents), 20)
        seen = 0
        for name in documents:
            for number, line in enumerate((ROOT / name).read_text(encoding="utf-8", errors="replace").split("\n"), 1):
                if name.endswith(".py") and not re.match(r"^\s*(?:#\s*)?(?:\$ |sudo |[A-Z_]+=\S+ )*python3 ", line):
                    continue                    # in a Python file: only usage lines of a docstring or comment
                seen += bool(INTERP.search(line))
                for _, what in findings(line, prose=True):
                    with self.subTest(document=name, line=number):
                        self.fail("%s:%d: %s: %s" % (name, number, what, line.strip()[:120]))
        self.assertGreater(seen, 15, "almost no documented command was seen")

    def test_the_rule_bites_and_does_not_cry_wolf(self):
        bad = [
            "key=\"$(python3 -c 'import secrets')\"",
            "python3 - \"$1\" <<'PY'",
            "python3 -u -c 'print(1)'",
            "x=\"$(printf '%s' \"$a\" | python3 -c \"import sys\")\"",
            "python3 \"$HERE/deploy/baremetal/firewall.py\" site.json",
            "python3 deploy/baremetal/host_probe.py",
            "python3 -m venv /opt/x",
            "PYTHONPATH=\"$HERE\" python3 -c 'from deploy.baremetal import host_probe'",
            "PYTHONPATH=\"$HERE\" python3 -P -c 'from deploy.baremetal import host_probe'",
            "env PYTHONPATH=\"$HERE\" python3 \"$T/serve.py\" \"$T\"",
            "PYTHONPATH=\"$HERE:$PYTHONPATH\" python3 -Ps -c 'from deploy.baremetal import host_probe'",
            "PYTHONPATH=\"$HERE\":\"$PYTHONPATH\" python3 -Ps -c 'from deploy.baremetal import host_probe'",
            "OLD=\"$PYTHONPATH\"; PYTHONPATH=\"$HERE:$OLD\" python3 -Ps -c 'import deploy'",
            "PYTHONPATH=\"$PWD\" python3 -Ps -c 'import deploy'",
            "PYTHONPATH=. python3 -Ps -c 'import deploy'",
            "PYTHONPATH=/tmp python3 -Ps -c 'import deploy'",
            "export PYTHONPATH=\"$HERE\"",
            "python3 -Ps -c 'import deploy'  # PYTHONPATH= is set above",
            "sudo env PYTHONPATH=\"$HERE\" python3 - > out <<'PY'",
            "python3 -X utf8 -c 'print(1)'",
            "python3 -u deploy/baremetal/firewall.py",
            "python3 /tmp/helper",
            "python3 -W ignore \"$HERE/tool.py\"",
            "python3 -Werror::ImportWarning -c 'print(1)'",
            "python3 --check-hash-based-pycs never -c 'print(1)'",
            "python3 -- \"$HERE/tool.py\"",
            "python3 -<<EOF",
            "python3 -uB - <<'PY'",
            "python3 -E \"$HERE/tool.py\"",
            "python3 -E -c 'print(1)'",
            "python3 -uc 'print(1)'",
            "/usr/bin/python3 -c 'print(1)'",
            "\"$VENV/bin/python\" \"$HERE/tool.py\"",
            "python3.13 -c 'print(1)'",
            "python -c 'print(1)'",
            "python2 -c 'print(1)'",
            "pypy3 -c 'print(1)'",
            "python3 <<'EOF'",
            "cat program.txt | python3",
            "producer |& python3",
            "python3 \\\n  -c 'print(1)'",
            "x=\"$(python3 tool.py)\"",
            "sudo \"$HERE/deploy/baremetal/host_probe.py\" --evidence e.json",
            "./deploy/baremetal/firewall.py site.json",
            "e2e/lib/sc-hsm-pty.py sc-hsm-tool",
            "schsm(){ SCHSM_SO_PIN=\"$HSM_SO_PIN\" SCHSM_DKEK_PW=\"$DKEK_PW\" \"$ROOT/e2e/lib/sc-hsm-pty.py\" sc-hsm-tool \"$@\"; }",
            "schsm(){ SCHSM_SO_PIN=\"$HSM_SO_PIN\" \\\n    \"$ROOT/e2e/lib/sc-hsm-pty.py\" sc-hsm-tool \"$@\"; }",
            "timeout 5 \"$HERE/x.py\"",
            "exec \"$HERE/x.py\"",
            "env X=1 \"$HERE/x.py\"",
            "producer | \"$HERE/x.py\"",
            "\"$HERE/x.py\";",
            "\"$PY\" \"$ROOT/e2e/cosmos_kms_tx.py\" address",
            "\"$PY\" -c 'print(1)'",
            "$PY -m venv /opt/x",
            "read -r A _ < <(\"$PY\" \"$ROOT/e2e/cosmos_kms_tx.py\" address)",
            "python3 -m unittest -v tests.test_baremetal_lease.OnSwtpm",
            "python3 -E -m unittest tests.x",
            "python3 -m deploy.baremetal.rollout transition --old A.json",
        ]
        good = [
            "key=\"$(python3 -I -c 'import secrets')\"",
            "python3 -I - \"$1\" <<'PY'",
            "python3 -Es \"$HERE/deploy/baremetal/firewall.py\" site.json",
            "python3 -E -s deploy/baremetal/firewall.py",
            "python3 -I deploy/baremetal/host_probe.py",
            "PYTHONPATH=\"$HERE\" python3 -Ps -c 'from deploy.baremetal import host_probe'",
            "env PYTHONPATH=\"$HERE\" python3 -s \"$T/serve.py\" \"$T\"",
            "sudo env PYTHONPATH=\"$HERE\" python3 -Ps - > out <<'PY'",
            "REGALIA_EXPECT_SWTPM=1 python3 -Es -m unittest -v tests.test_baremetal_lease.OnSwtpm",
            "python3 -Es -m deploy.baremetal.rollout transition --old A.json",
            "python3 -I -m json.tool api/openapi.json",
            "# python3 -c 'a comment is not code'",
            "command -v python3 >/dev/null || exit 2",
            "for t in cryptsetup python3; do command -v \"$t\"; done",
            "python3 --version",
            "python3 -X utf8 -I -c 'print(1)'",
            "python3 -Werror::ImportWarning -I -c 'print(1)'",
            "python3 -u -Es deploy/baremetal/firewall.py",
            "python3 -Es -- \"$HERE/tool.py\"",
            "python3 -IB - <<'PY'",
            "printf '%s' \"$program\" | python3 -I > out.txt",
            "make || python3 -Es \"$HERE/x.py\"",
            "\"$PY\" -Es \"$ROOT/e2e/cosmos_kms_tx.py\" address",
            "\"$PY\" -I -c 'import cosmpy' 2>/dev/null || { echo \"$PY lacks cosmpy\" >&2; exit 2; }",
            "PY=\"${REGALIA_COSMOS_PYTHON:-python3}\"",
            "imports \"$py\" \"$module\"",
            "x=\"$(python3 -Es \"$HERE/tool.py\")\"",
            "echo 'python3 is required'",
            "log \"see host_probe.py for the reason\"",
            "unset PYTHONPATH",
        ]
        for line in bad:
            with self.subTest(bad=line):
                self.assertTrue(findings(line), "not caught: %s" % line)
        for line in good:
            with self.subTest(good=line):
                self.assertEqual(findings(line), [], "refused: %s" % line)

    def test_nothing_that_reaches_the_module_path_shadows_the_standard_library(self):
        """PYTHONPATH="$HERE" puts the repository root on the module path ahead of the standard
        library; a script run by path puts its own directory first; and host_probe.py, firewall.py
        and network_probe.py insert deploy/baremetal themselves. A module in any of those named like a
        standard one (json.py, secrets.pyc, a secrets/ package, an extension module) would be imported
        instead of it. A directory WITHOUT __init__.py (cmd/, the Go commands) is a namespace portion
        and loses to the real module; that is checked by importing it."""
        places = [ROOT] + sorted({(ROOT / name).parent for name in tracked("*.py") if "/tests/" not in name and not name.startswith("tests/")})
        self.assertIn(ROOT / "deploy" / "baremetal", places)
        self.assertIn(ROOT / "e2e" / "lib", places)
        for place in places:
            shadows = [entry.name for entry in place.iterdir()
                       if entry.name.split(".")[0] in sys.stdlib_module_names
                       and (entry.suffix in (".py", ".pyc", ".so", ".pyd") or (entry.is_dir() and (entry / "__init__.py").exists()))]
            with self.subTest(place=str(place.relative_to(ROOT))):
                self.assertEqual(shadows, [], "these would be imported instead of the standard library")
        for entry in ROOT.iterdir():
            if entry.is_dir() and entry.name in sys.stdlib_module_names:
                where = subprocess.run([sys.executable, "-Ps", "-c", "import %s; print(%s.__file__)" % (entry.name, entry.name)],
                                       env=dict(os.environ, PYTHONPATH=str(ROOT)), capture_output=True, text=True, timeout=60)
                self.assertEqual(where.returncode, 0, where.stderr)
                self.assertFalse(where.stdout.strip().startswith(str(ROOT)), "%s/ shadows the standard module" % entry.name)


if __name__ == "__main__":
    unittest.main()
