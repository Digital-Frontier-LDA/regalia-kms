"""A documented `python3 …` command for a script in this repository must run as written.

deploy/proxmox/README.md taught `python3 deploy/proxmox/verify.py …` and
`sudo python3 deploy/proxmox/install_policy_guard.py …`, and both failed with
`ModuleNotFoundError: No module named 'kms'` on a pristine checkout (#453). Running a file by path
puts the FILE'S OWN DIRECTORY on sys.path[0], not the repository root, so a script that imports a
repository package (`from deploy.proxmox.provision import …`) cannot find it. `python3 -m
deploy.proxmox.verify` works, because -m puts the working directory there instead. The second
of the two is the step that installs the continuous Proxmox policy guard, so an operator following
the commissioning procedure would stop at it.

Nothing noticed because the Python tests import these modules directly and never go through the
command a person is told to type.

THE CORPUS IS EVERY TRACKED MARKDOWN FILE, not the one README where the defect was found. When
this was written, 12 distinct invocations of repository scripts appeared across the documentation,
and exactly these two were broken.
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The packages this repository documents invocations of. `deploy` and `tools` are the two
# with runnable entry points; a name outside this list is somebody else's python3.
REPOSITORY_PACKAGES = ("deploy", "tools", "tests")
INVOCATION = re.compile(r"(?:^|[\s`$(])(?:sudo\s+(?:-\S+\s+)*)?python3\s+(-m\s+)?([A-Za-z0-9_./-]+)")
IMPORTS_REPOSITORY_PACKAGE = re.compile(
    r"^(?:from|import)\s+(?:" + "|".join(REPOSITORY_PACKAGES) + r")\b", re.M)


def documented_invocations() -> dict[tuple[str, str, str], list[str]]:
    """(form, target, script path) -> the doc:line sites that teach it, for scripts that exist."""
    tracked = subprocess.run(["git", "ls-files", "-z", "*.md"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout.split("\0")
    found: dict[tuple[str, str, str], list[str]] = {}
    for name in filter(None, tracked):
        for number, line in enumerate((ROOT / name).read_text(encoding="utf-8").splitlines(), 1):
            for match in INVOCATION.finditer(line):
                module_flag, target = match.groups()
                if module_flag:
                    if not target.startswith(tuple(package + "." for package in REPOSITORY_PACKAGES)):
                        continue
                    form, script = "module", target.replace(".", "/") + ".py"
                elif target.endswith(".py"):
                    form, script = "path", target
                else:
                    continue
                if (ROOT / script).is_file():
                    found.setdefault((form, target, script), []).append(f"{name}:{number}")
    return found


def parses_arguments_safely(script: str) -> bool:
    """True when `--help` can only ever print usage: argparse, parsed first, behind a __main__ guard.

    This is what keeps the executed arm from running a script with side effects. A script that does
    work before parsing its arguments, or has no __main__ guard, is checked statically only.
    """
    source = (ROOT / script).read_text(encoding="utf-8")
    tree = ast.parse(source)
    guarded = any(isinstance(node, ast.If) and "__main__" in ast.get_source_segment(source, node)
                  for node in tree.body)
    main = next((node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"), None)
    if not guarded or main is None or "argparse" not in source:
        return False
    for statement in main.body:
        text = ast.get_source_segment(source, statement)
        if "parse_args" in text:
            return True
        if not ("ArgumentParser" in text or "add_argument" in text):
            return False
    return False


class DocumentedPythonInvocationTests(unittest.TestCase):
    def setUp(self):
        self.invocations = documented_invocations()
        self.assertGreaterEqual(
            len(self.invocations), 4,
            f"only {len(self.invocations)} documented invocations found (expected at least 4 — the "
                f"deploy tooling documents that many): the pattern or the corpus "
            f"changed, and every check below would pass by inspecting almost nothing")

    def test_a_script_that_imports_a_repository_package_is_not_documented_by_path(self):
        for (form, target, script), sites in sorted(self.invocations.items()):
            if form != "path":
                continue
            source = (ROOT / script).read_text(encoding="utf-8")
            with self.subTest(script=script):
                self.assertIsNone(
                    IMPORTS_REPOSITORY_PACKAGE.search(source),
                    f"{', '.join(sites)} documents `python3 {target}`, but {script} imports a repository "
                    f"package, so run by path it fails with ModuleNotFoundError: Python puts the script's "
                    f"own directory on sys.path, not the repository root. Document "
                    f"`python3 -m {script[:-3].replace('/', '.')}` instead.")

    def test_every_documented_invocation_runs_as_written(self):
        """Executed, not inferred: run each documented form with --help from the repository root."""
        executed = 0
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        environment.pop("PYTHONPATH", None)  # an ambient PYTHONPATH would hide exactly this defect
        for (form, target, script), sites in sorted(self.invocations.items()):
            if not parses_arguments_safely(script):
                continue
            command = [sys.executable, "-m", target] if form == "module" else [sys.executable, target]
            result = subprocess.run(command + ["--help"], cwd=ROOT, env=environment,
                                    capture_output=True, text=True, timeout=60)
            executed += 1
            with self.subTest(script=script, form=form):
                self.assertEqual(
                    result.returncode, 0,
                    f"{', '.join(sites)} documents `python3 {'-m ' if form == 'module' else ''}{target}`, "
                    f"which does not run as written:\n{result.stderr.strip()[-400:]}")
        self.assertGreaterEqual(executed, 4, f"only {executed} invocations were executed; the safety "
                                             f"precheck may have stopped recognising argparse scripts")


if __name__ == "__main__":
    unittest.main()
