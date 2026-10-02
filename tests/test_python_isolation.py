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

The rule, for every tracked *.sh; a comment line is not code, a line continued with a backslash is one:
  a program on the command line, on standard input or by module name     must carry -I
  a script run by path                                                  must carry -E and -s, or -I
  a Python program run through its "#!" line ("$HERE/x.py" as a command)  is a finding: start it as
                                                                          python3 -Es "$HERE/x.py"
  PYTHONPATH=… python3 …    a command that sets the module path ITSELF, to the repository, to import
                            deploy.baremetal: it must carry -P and -s for an inline program (the
                            working directory and the user site are dropped; -P alone still loads a
                            .pth under PYTHONUSERBASE, measured), and -s for a script by path. The
                            assignment must be outright (PYTHONPATH="$HERE"), never an appended value
  python3 -m unittest …     exempt: a test runner, started from the repository root on purpose
An interpreter is python3 or python3.N as a word, or python/python3 behind a directory.
Not covered, and said so: files that are not *.sh, eval of a command held in a variable, and Python
that starts Python.

That recovery-key.sh really is immune is run, not read: tests/test_baremetal_recovery_key.py plants a
json.py in the working directory and on PYTHONPATH and runs every mode."""
import os
import pathlib
import re
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
INTERP = re.compile(r'(?:(?<![\w./$-])python3(?:\.\d+)?(?![\w.-])["\'}]?|["\']?[\w$/{}.:-]*/python(?:3(?:\.\d+)?)?(?![\w.-])["\'}]?)')
DIRECT = re.compile(r'(?:^|[;&({!]|\|\||&&|\$\(|\bthen\b|\bdo\b|\bif\b|\belse\b|\bsudo\b)\s*(?:!\s*)?"?(?:\$[\w{(]|\.{0,2}/)[\w$/{}.-]*\.py"?(?=\s|$|\))')
TAKES_VALUE = ("-X", "-W")      # options whose value is the NEXT word


def judge(rest, sets_path, piped):
    """What follows the interpreter on the (joined) line -> what is wrong, or None."""
    words = rest.split()
    flags, i, inline = "", 0, False
    while i < len(words) and len(words[i]) > 1 and words[i].startswith("-") and not words[i].startswith("--"):
        word = words[i]
        if word in TAKES_VALUE:
            i += 2
            continue
        letters = word[1:]
        cut = min([letters.index(ch) for ch in "cm" if ch in letters] or [len(letters)])   # -uc, -mvenv
        flags += letters[:cut]
        if cut < len(letters):
            if letters[cut] == "m" and (letters[cut + 1:] == "unittest" or (i + 1 < len(words) and words[i + 1] == "unittest")):
                return None      # a test runner, started from the repository root on purpose
            inline = True
            break
        i += 1
    word = words[i] if i < len(words) else ""
    if not inline:
        if word == "-" or word.startswith("<"):
            inline = True                               # python3 - …, python3 <<EOF, python3 < file
        elif piped and (not word or re.match(r"^[0-9]*[>|;&)]", word)):
            inline = True                               # … | python3
    if inline:
        if "I" in flags or (sets_path and "P" in flags and "s" in flags):
            return None
        return "a program on the command line, on standard input or by module name, without -%s" % ("P and -s" if sets_path else "I")
    if not word or re.match(r"^[0-9]*[<>|&;)]", word):
        return None
    bare = word.strip("\"'")
    if "/" in bare or bare.startswith("$") or bare.endswith(".py"):
        if sets_path:
            return None if "s" in flags else "a script by path beside an explicit PYTHONPATH, without -s"
        return None if ("I" in flags or ("E" in flags and "s" in flags)) else "a script by path without -E and -s"
    return None


def findings(text):
    """(line number, what is wrong) for each offending line of a shell script's text."""
    found, lines, number = [], text.split("\n"), 0
    while number < len(lines):
        start, line = number, lines[number]
        while line.rstrip().endswith("\\") and number + 1 < len(lines):   # a continued line is one line
            number += 1
            line = line.rstrip()[:-1] + " " + lines[number].lstrip()
        number += 1
        if line.lstrip().startswith("#"):
            continue
        sets_path = "PYTHONPATH=" in line
        if sets_path and re.search(r'PYTHONPATH="?[^\s"]*\$\{?PYTHONPATH', line):
            found.append((start + 1, "PYTHONPATH is appended to an inherited value; assign it outright"))
        for match in INTERP.finditer(line):
            what = judge(line[match.end():], sets_path, bool(re.search(r"(?<!\|)\|\s*$", line[:match.start()])))
            if what:
                found.append((start + 1, what))
        if DIRECT.search(line):
            found.append((start + 1, "a Python program run through its #! line (start it as python3 -Es <path>)"))
    return found


class PythonRunsIsolated(unittest.TestCase):
    def test_every_shell_script_follows_the_rule(self):
        scripts = subprocess.run(["git", "ls-files", "*.sh"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split()
        self.assertGreater(len(scripts), 20, "git ls-files found almost no scripts: the check would pass by reading nothing")
        seen = 0
        for name in scripts:
            text = (ROOT / name).read_text(encoding="utf-8", errors="replace")
            seen += len(INTERP.findall(text))
            for number, what in findings(text):
                with self.subTest(script=name, line=number):
                    self.fail("%s:%d: %s. Add -I (or -Es for a script by path, -Ps beside an explicit PYTHONPATH)" % (name, number, what))
        self.assertGreater(seen, 40, "almost no python3 invocation was seen: the pattern no longer matches how they are written")

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
            "sudo env PYTHONPATH=\"$HERE\" python3 - > out <<'PY'",
            "python3 -X utf8 -c 'print(1)'",
            "python3 -u deploy/baremetal/firewall.py",
            "python3 /tmp/helper",
            "python3 -W ignore \"$HERE/tool.py\"",
            "python3 -uB - <<'PY'",
            "python3 -E \"$HERE/tool.py\"",
            "python3 -E -c 'print(1)'",
            "python3 -uc 'print(1)'",
            "/usr/bin/python3 -c 'print(1)'",
            "\"$VENV/bin/python\" \"$HERE/tool.py\"",
            "python3.13 -c 'print(1)'",
            "python3 <<'EOF'",
            "cat program.txt | python3",
            "python3 \\\n  -c 'print(1)'",
            "sudo \"$HERE/deploy/baremetal/host_probe.py\" --evidence e.json",
            "./deploy/baremetal/firewall.py site.json",
        ]
        good = [
            "key=\"$(python3 -I -c 'import secrets')\"",
            "python3 -I - \"$1\" <<'PY'",
            "python3 -Es \"$HERE/deploy/baremetal/firewall.py\" site.json",
            "python3 -E -s deploy/baremetal/firewall.py",
            "python3 -I deploy/baremetal/host_probe.py",
            "PYTHONPATH=\"$HERE\" python3 -Ps -c 'from deploy.baremetal import host_probe'",
            "env PYTHONPATH=\"$HERE\" python3 -s \"$T/serve.py\" \"$T\"",
            "python3 -m unittest -v tests.test_baremetal_lease.OnSwtpm",
            "# python3 -c 'a comment is not code'",
            "command -v python3 >/dev/null || exit 2",
            "for t in cryptsetup python3; do command -v \"$t\"; done",
            "python3 -X utf8 -I -c 'print(1)'",
            "python3 -u -Es deploy/baremetal/firewall.py",
            "python3 -IB - <<'PY'",
            "printf '%s' \"$program\" | python3 -I > out.txt",
            "echo 'python3 is required'",
            "log \"see host_probe.py for the reason\"",
        ]
        for line in bad:
            with self.subTest(bad=line):
                self.assertTrue(findings(line), "not caught: %s" % line)
        for line in good:
            with self.subTest(good=line):
                self.assertEqual(findings(line), [], "refused: %s" % line)

    def test_nothing_at_the_repository_root_shadows_the_standard_library(self):
        """The commands that set PYTHONPATH="$HERE" put the repository root on the module path, ahead
        of the standard library. A module there named like a standard one (json.py, a secrets/
        package) would be imported instead of it. A directory WITHOUT __init__.py (cmd/, the Go
        commands) is a namespace portion and loses to the real module; that is checked by importing it."""
        root = pathlib.Path(__file__).resolve().parent.parent
        shadows = [entry.name for entry in root.iterdir()
                   if entry.name.split(".")[0] in sys.stdlib_module_names
                   and (entry.suffix == ".py" or (entry.is_dir() and (entry / "__init__.py").exists()))]
        self.assertEqual(shadows, [], "these would be imported instead of the standard library")
        for entry in root.iterdir():
            if entry.is_dir() and entry.name in sys.stdlib_module_names:
                where = subprocess.run([sys.executable, "-Ps", "-c", "import %s; print(%s.__file__)" % (entry.name, entry.name)],
                                       env=dict(os.environ, PYTHONPATH=str(root)), capture_output=True, text=True, timeout=60)
                self.assertEqual(where.returncode, 0, where.stderr)
                self.assertFalse(where.stdout.strip().startswith(str(root)), "%s/ shadows the standard module" % entry.name)


if __name__ == "__main__":
    unittest.main()
