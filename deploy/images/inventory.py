#!/usr/bin/env python3
"""Detect unreviewed Dockerfile/Compose image inputs; never grant release trust."""

import argparse
import fnmatch
import json
import os
from pathlib import Path
import re
import shlex
import sys

import yaml


def compose_images(value, *, ancestors=()) -> list[str]:
    if isinstance(value, (dict, list)) and id(value) in ancestors:
        raise ValueError("cyclic Compose input rejected")
    if isinstance(value, dict):
        result = []
        for name, child in value.items():
            if name == "image":
                if not isinstance(child, str) or not child:
                    raise ValueError("Compose image must be an explicit scalar reference")
                result.append(child)
            else:
                result.extend(compose_images(child, ancestors=(*ancestors, id(value))))
        return result
    if isinstance(value, list):
        return [image for child in value for image in compose_images(child, ancestors=(*ancestors, id(value)))]
    return []


def inputs(root: Path) -> list[dict]:
    found = []
    for directory, children, names in os.walk(root):
        children[:] = sorted(name for name in children if name not in
                             {".git", ".artifacts", ".venv", "node_modules", "__pycache__"})
        for name in sorted(names):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if "dockerfile" in name.lower():
                stages = set()
                for line in path.read_text().replace("\\\n", " ").splitlines():
                    if not re.match(r"\s*(FROM|COPY)\s", line, re.IGNORECASE):
                        continue
                    tokens = shlex.split(line, comments=True)
                    if tokens[0].upper() == "FROM":
                        index = 2 if tokens[1].startswith("--platform=") else 1
                        reference = tokens[index]
                        if reference.lower() not in stages and reference != "scratch":
                            found.append({"path": relative, "reference": reference, "kind": "external"})
                        if len(tokens) > index + 2 and tokens[index + 1].upper() == "AS":
                            stages.add(tokens[index + 2].lower())
                    else:
                        for token in tokens[1:]:
                            if token.startswith("--from="):
                                reference = token.partition("=")[2]
                                if reference.lower() not in stages and not reference.isdigit():
                                    found.append({"path": relative, "reference": reference, "kind": "external"})
            elif fnmatch.fnmatch(name.lower(), "*compose*.y*ml"):
                for reference in sorted(set(compose_images(yaml.safe_load(path.read_text())))):
                    found.append({"path": relative, "reference": reference, "kind": "local"})
    return found


def inventory(root: Path) -> dict:
    policy = json.loads((root / "deploy/images/development-inputs.json").read_text())
    if policy.get("schema") != "regalia.development-image-inputs/v1":
        raise ValueError("unsupported image inventory policy")
    entries = inputs(root)
    unreviewed = []
    for entry in entries:
        allowed = policy[entry["kind"]].get(entry["path"], [])
        reviewed = entry["reference"] in allowed
        if entry["kind"] == "external":
            reviewed = reviewed and bool(re.search(r"@sha256:[a-f0-9]{64}$", entry["reference"]))
        entry.update({"reviewed_development_input": reviewed,
                      "publisher_authentication": "not-established",
                      "production_approved": False})
        if not reviewed:
            unreviewed.append(entry)
    return {"schema": "regalia.image-input-inventory/v1",
            "status": "development-only" if not unreviewed else "refused",
            "production_approved": False, "inputs": entries,
            "unreviewed_inputs": unreviewed, "reason": policy["reason"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--production", action="store_true")
    args = parser.parse_args()
    try:
        report = inventory(args.root)
        print(json.dumps(report, sort_keys=True, indent=2))
        if report["unreviewed_inputs"] or args.production:
            print("REFUSED: image inputs have no production approval", file=sys.stderr)
            return 1
        print("DEVELOPMENT ONLY: image publisher signatures remain unverified", file=sys.stderr)
        return 0
    except (ValueError, OSError, IndexError, yaml.YAMLError) as error:
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
