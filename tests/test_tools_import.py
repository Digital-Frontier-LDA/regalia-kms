"""Every module under tools/ must import.

WHY THIS EXISTS. `tools/secret_inventory.py` was published here while still importing
`tools.sops_inventory`, a module that deliberately stays in the private tracking repository. It was
dead on arrival — `import tools.secret_inventory` raised ModuleNotFoundError — and nothing noticed,
because the test that would have caught it was not carried over with it. A file that cannot be
imported is not tooling; it is a promise the repository does not keep.

This is deliberately the cheapest possible check: import each module and let any exception fail the
test, naming the module. It is not a substitute for a module's own tests; it is the floor beneath
them.
"""

from __future__ import annotations

import importlib
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"


def _modules():
    return sorted(p.stem for p in TOOLS.glob("*.py") if p.stem != "__init__")


class ToolsImportTests(unittest.TestCase):
    def test_there_are_tools_to_check(self):
        """An empty corpus would make the check below pass while inspecting nothing."""
        self.assertGreaterEqual(
            len(_modules()), 3,
            f"only {len(_modules())} importable tools found under {TOOLS}: the layout changed and "
            f"this check would pass by importing almost nothing")

    def test_every_tool_module_imports(self):
        for name in _modules():
            with self.subTest(module=name):
                try:
                    importlib.import_module(f"tools.{name}")
                except Exception as exc:  # noqa: BLE001 — any failure is the finding
                    self.fail(
                        f"tools/{name}.py does not import: {type(exc).__name__}: {exc}. A module "
                        f"that cannot be imported cannot be run either — either it belongs in "
                        f"another repository, or its dependency is missing here.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
