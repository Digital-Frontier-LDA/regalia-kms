"""Expose the optional tooling pin as validated CI step outputs."""
from pathlib import Path
import runpy
import sys


def main(snapshot, output):
    checker = runpy.run_path(str(Path(__file__).resolve().parents[1] / "check_openspec_references.py"))
    try:
        doc = checker["tooling_declaration"](checker["Files"](snapshot))
        lines = ["present=false"] if doc is None else [
            "present=true", f"revision={doc['sourceRevision']}", f"tree={doc['sourceTree']}",
        ]
        with Path(output).open("a", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n")
    except (checker["IntegrityError"], OSError) as exc:
        print(f"OpenSpec tooling source plan: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:]))
