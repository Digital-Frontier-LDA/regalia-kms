#!/usr/bin/env python3
"""Assert the shipped initrd, independently of the QEMU builder's installed modules (r1s.19).

Run after build-initrd.sh; no missing-artifact skip is allowed. The signed inventory verifies module bytes;
this check also follows modules.dep and requires unconditional loading before the module-free /usr takes over.
"""
import argparse
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from deploy.baremetal import uki

PRELOAD = b"vfat\nnls_cp437\nnls_ascii\nnls_iso8859-1\nnls_utf8\nbinfmt_misc\n"
MODULES = ("vfat", "fat", "nls_cp437", "nls_ascii", "nls_iso8859-1", "nls_utf8", "binfmt_misc")


class ImageESPContent(unittest.TestCase):
    def test_esp_modules_present_and_preloaded_for_image_kernel(self):
        record = json.loads((BUILD / "initrd-build.json").read_text())
        files = uki.initrd_files((BUILD / "initrd.img").read_bytes())
        kernel = record["kernel"]
        if KERNEL:
            self.assertEqual(kernel, KERNEL, "initrd modules must match the UKI's kernel")
        prefix = "usr/lib/modules/" + kernel + "/"
        versions = {p.split("/")[3] for p in files if p.startswith("usr/lib/modules/") and len(p.split("/")) > 4}
        self.assertEqual(versions, {kernel}, "only the image kernel's modules may ship")
        paths = {}
        for module in MODULES:
            matches = [p for p in files if p.startswith(prefix) and p.rsplit("/", 1)[-1].split(".ko")[0] == module]
            self.assertEqual(len(matches), 1, "ESP_MODULE_PRESENT: " + module + " for " + kernel)
            paths[module] = matches[0]
        dep = files[prefix + "modules.dep"][1].decode()
        dependencies = dict(line.split(":", 1) for line in dep.splitlines())
        for module, path in paths.items():
            relative = path[len(prefix):]
            self.assertIn(relative, dependencies, "modules.dep must index " + module)
            for needed in dependencies[relative].split():
                self.assertTrue(prefix + needed in files, "ESP_MODULE_DEPENDENCY_PRESENT: " + needed)
        path = "usr/lib/modules-load.d/regalia-filesystems.conf"
        self.assertTrue(path in files, "ESP_MODULES_PRELOADED: every boot, including before genesis")
        self.assertEqual(files[path][1], PRELOAD, "ESP_MODULES_PRELOADED: exact reviewed set")
        print("image ESP content: kernel=" + kernel + " modules=" + ",".join(MODULES) + " dependencies and preload verified")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build", type=Path)
    parser.add_argument("--kernel", help="UKI kernel version (boot harness)")
    args = parser.parse_args()
    BUILD, KERNEL = args.build, args.kernel
    unittest.main(argv=[sys.argv[0]], verbosity=2)
