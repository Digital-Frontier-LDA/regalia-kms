import json
from pathlib import Path
import tempfile
import unittest

from deploy.images import inventory


class ImageInventoryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "deploy/images").mkdir(parents=True)
        (self.root / "deploy/images/development-inputs.json").write_text(json.dumps({
            "schema": "regalia.development-image-inputs/v1", "external": {}, "local": {}, "reason": "fixture"}))

    def test_new_external_tag_is_rejected(self):
        (self.root / "Dockerfile").write_text("FROM debian:trixie-slim\n")
        report = inventory.inventory(self.root)
        self.assertEqual(report["status"], "refused")
        self.assertFalse(report["production_approved"])

    def test_external_copy_is_detected_and_local_stages_are_not_inputs(self):
        (self.root / "Dockerfile").write_text(
            "FROM scratch AS build\nFROM build AS export\n"
            "COPY --from=build /output /output\nCOPY --from=unreviewed:latest /bad /bad\n")
        entries = inventory.inputs(self.root)
        self.assertEqual([entry["reference"] for entry in entries], ["unreviewed:latest"])

    def test_json_yaml_and_anchors_do_not_hide_compose_images(self):
        (self.root / "compose.yaml").write_text(
            'x-base: &base {"image": "unreviewed:latest"}\nservices: {one: {<<: *base}}\n')
        self.assertEqual(inventory.inventory(self.root)["status"], "refused")
        self.assertEqual(len(inventory.inputs(self.root)), 1)

    def test_cyclic_yaml_and_non_scalar_images_fail_closed(self):
        for contents in ("loop: &loop {loop: *loop}\n", "services: {one: {image: [bad]}}\n"):
            (self.root / "compose.yaml").write_text(contents)
            with self.assertRaises(ValueError):
                inventory.inventory(self.root)

    def test_repository_fixtures_cannot_become_production_approved(self):
        report = inventory.inventory(Path(__file__).resolve().parents[1])
        self.assertEqual(report["status"], "development-only")
        self.assertGreater(len(report["inputs"]), 0)
        self.assertTrue(all(not entry["production_approved"] for entry in report["inputs"]))
