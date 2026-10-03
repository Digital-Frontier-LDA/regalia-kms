"""Real Debian payload checks and negative source/recipe/compiler bindings."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deploy.images import source, source_package
from deploy.images.verify import VerificationError
from lab.appliance import tpm_build


class SourcePackageAdmission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.exports = self.root / "exports"
        self.exports.mkdir()
        self.bundle = self.root / "bundle"
        self.bundle.mkdir()
        self.authenticated = {"status": "fixture"}
        self.source_bytes = json.dumps(self.authenticated).encode()
        (self.bundle / "verification.json").write_bytes(self.source_bytes)
        self.recipe = {"tpm_build.py": "a" * 64, "tpm_profile.py": "b" * 64}
        self.binary = b"\x7fELF\x02\x01" + b"\0" * 12 + b"\x3e\0" + b"\0" * 44
        self.digest = hashlib.sha256(self.binary).hexdigest()
        self.dependencies = ", ".join(sorted(source_package.DEPENDENCIES))
        self.make_package()
        compiler = self.exports / "compiler-packages.tsv"
        compiler.write_text("libc6\t1.0\n")
        for name in ("first.tpm2", "second.tpm2", "installed.tpm2"):
            (self.exports / name).write_bytes(self.binary)
        build = {"binary_sha256": self.digest, "tools": ["tpm2", "tpm2_getcap"]}
        self.report = {"schema": "regalia.tpm-source-package/v1", "status": "installed",
                       "production_approved": False, "package": source.PACKAGE,
                       "version": source_package.VERSION, "source": source.PACKAGE,
                       "source_version": source_package.VERSION, "architecture": "amd64",
                       "authenticated_source": self.authenticated, "recipe_inputs": self.recipe,
                       "source_inputs": {name: value[0] for name, value in source.FILES.items()},
                       "compiler_inventory_sha256": hashlib.sha256(compiler.read_bytes()).hexdigest(),
                       "package_sha256": hashlib.sha256((self.exports / "tpm2-tools.deb").read_bytes()).hexdigest(),
                       "packages_reproduced": True, "independent_builders": False,
                       "builds": [build, copy.deepcopy(build)], "dependencies": self.dependencies}
        self.write_report(self.report)

    def write_report(self, report):
        (self.exports / "tpm-source-package.json").write_text(json.dumps(report))

    def make_package(self, attack=None):
        stage = self.root / ("stage-" + str(attack))
        (stage / "DEBIAN").mkdir(parents=True)
        (stage / "usr/bin").mkdir(parents=True)
        doc = stage / "usr/share/doc/tpm2-tools"
        doc.mkdir(parents=True)
        (doc / "regalia-source.json").write_bytes(self.source_bytes)
        (stage / "usr/bin/tpm2").write_bytes(self.binary)
        (stage / "usr/bin/tpm2").chmod(0o755)
        (stage / "usr/bin/tpm2_getcap").symlink_to("tpm2" if attack != "alias" else "/etc/shadow")
        control = (f"Package: tpm2-tools\nVersion: {source_package.VERSION}\n"
                   f"Source: tpm2-tools ({source_package.VERSION})\nArchitecture: amd64\n"
                   "Section: utils\nPriority: optional\nMaintainer: Fixture <fixture@example.invalid>\n"
                   f"Depends: {self.dependencies}\nDescription: Public admission fixture\n")
        if attack == "source":
            control = control.replace("Source: tpm2-tools", "Source: concealed-source")
        if attack == "dependency":
            control = control.replace("Depends: ", "Depends: libcurl4t64, ")
        if attack == "control":
            (stage / "DEBIAN/postinst").write_text("#!/bin/sh\nexit 0\n")
            (stage / "DEBIAN/postinst").chmod(0o755)
        if attack == "path":
            (stage / "etc").mkdir()
            (stage / "etc/shadow").write_bytes(b"not allowed")
        if attack == "architecture":
            (stage / "usr/bin/tpm2").write_bytes(self.binary[:18] + b"\xb7\0" + self.binary[20:])
        (stage / "DEBIAN/control").write_text(control)
        package = self.exports / ((attack or "tpm2-tools") + ".deb")
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(stage), str(package)],
                       capture_output=True, check=True)
        if attack is None:
            (self.exports / "second-tpm2-tools.deb").write_bytes(package.read_bytes())
        return package

    def test_exact_package_and_compiler_inputs_are_bound(self):
        with patch.object(source_package.source, "validate", return_value=self.authenticated):
            result = source_package.validate(self.exports, self.bundle,
                                             [{"Package": "libc6", "Version": "1.0"}], self.recipe)
        self.assertEqual(result["status"], "verified")
        self.assertFalse(result["production_approved"])

    def test_substituted_source_recipe_version_or_reproduction_refuses(self):
        for name, value in [("source", "concealed-source"), ("version", "5.8"),
                            ("authenticated_source", {}), ("recipe_inputs", {}),
                            ("packages_reproduced", False), ("architecture", "arm64")]:
            report = copy.deepcopy(self.report)
            report[name] = value
            self.write_report(report)
            with self.subTest(name=name), patch.object(source_package.source, "validate", return_value=self.authenticated):
                with self.assertRaises(VerificationError):
                    source_package.validate(self.exports, self.bundle,
                                            [{"Package": "libc6", "Version": "1.0"}], self.recipe)

    def test_package_cannot_install_scripts_escape_paths_or_hide_source(self):
        for attack in ("control", "alias", "path", "source", "dependency", "architecture"):
            with self.subTest(attack=attack), self.assertRaises(VerificationError):
                source_package.inspect_payload(self.make_package(attack), self.digest)

    def test_unindexed_compiler_or_changed_installed_binary_refuses(self):
        with patch.object(source_package.source, "validate", return_value=self.authenticated):
            with self.assertRaises(VerificationError):
                source_package.validate(self.exports, self.bundle,
                                        [{"Package": "libc6", "Version": "9.0"}], self.recipe)
            (self.exports / "installed.tpm2").write_bytes(b"substituted binary")
            with self.assertRaises(VerificationError):
                source_package.validate(self.exports, self.bundle,
                                        [{"Package": "libc6", "Version": "1.0"}], self.recipe)

    def test_only_the_admitted_package_can_leave_the_signed_inventory_path(self):
        path = self.root / "packages.tsv"
        admitted = {"schema": "regalia.source-package-binding/v1", "status": "verified",
                    "package": source.PACKAGE, "version": source_package.VERSION}
        path.write_text("libc6\t1.0\ntpm2-tools\t" + source_package.VERSION + "\n")
        inventory = [{"Package": "libc6", "Version": "1.0"}]
        result = source_package.installed_binding(path, inventory, admitted)
        self.assertEqual((result["archive_packages"], result["source_built_packages"]), (1, 1))
        for rows in ["libc6\t9.0\ntpm2-tools\t" + source_package.VERSION + "\n",
                     "libc6\t1.0\ntpm2-tools\t5.7-1\n"]:
            path.write_text(rows)
            with self.assertRaises(VerificationError):
                source_package.installed_binding(path, inventory, admitted)

    def test_generated_library_closure_cannot_expand_or_include_curl(self):
        good = "shlibs:Depends=" + ", ".join(sorted(source_package.DEPENDENCIES - {"libtss2-tcti-device0t64"}))
        self.assertIn("libtss2-tcti-device0t64", tpm_build.dependency_list(good))
        for bad in (good + ", libcurl4t64", good.replace("libc6", "wrong-library"), good + "\nextra=field"):
            with self.assertRaises(VerificationError):
                tpm_build.dependency_list(bad)
