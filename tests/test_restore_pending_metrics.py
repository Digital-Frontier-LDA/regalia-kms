"""deploy/baremetal/node.py's restore_pending_metrics (regalia-kms-dx7.9, watched by RegaliaRestorePending):
the /etc/regalia/restore-pending boot guard (regalia-kms-dx7.26) as a textfile gauge. The held host reads
"skipped", not failed, and serves nothing; the gauge is the only thing that says why. Written at every boot
by the node and at mark/clear by restore.py, never raising: a metric does not change the run's outcome."""
import os
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from deploy.baremetal import etcdconf, metrics, node

ROOT = Path(__file__).resolve().parents[1]


class RestorePendingMetric(unittest.TestCase):
    def test_the_marker_is_published_as_one(self):
        published = []
        with tempfile.TemporaryDirectory() as directory, \
                unittest.mock.patch.object(etcdconf, "STORED_RESTORE_PENDING", os.path.join(directory, "restore-pending")):
            Path(etcdconf.STORED_RESTORE_PENDING).touch()
            node.restore_pending_metrics(published.append)
            self.assertEqual(published, [[("regalia_restore_pending", {}, 1)]])
            # it renders as a registered series, whole, in the restore writer's own file
            self.assertIn("regalia_restore_pending 1\n", metrics.render("restore", published[0]))

    def test_the_restore_writer_holds_the_file_and_publishes_to_it(self):
        """The gauge lands in the restore writer's own file under the run root, as node_exporter reads it:
        the registry's writer, the file's name, and the render-and-write whole."""
        self.assertEqual(metrics.path("restore"), "/run/regalia-metrics/restore/pending.prom")
        with tempfile.TemporaryDirectory() as directory:
            self.assertTrue(metrics.publish("restore", [("regalia_restore_pending", {}, 1)],
                                            target=os.path.join(directory, "pending.prom")))
            self.assertIn("regalia_restore_pending 1\n", Path(os.path.join(directory, "pending.prom")).read_text())

    def test_no_marker_is_published_as_zero(self):
        published = []
        with tempfile.TemporaryDirectory() as directory, \
                unittest.mock.patch.object(etcdconf, "STORED_RESTORE_PENDING", os.path.join(directory, "restore-pending")), \
                unittest.mock.patch.object(metrics, "RUN_DIR", directory), \
                unittest.mock.patch.object(node, "metrics", metrics):
            node.restore_pending_metrics(published.append)
            self.assertEqual(published, [[("regalia_restore_pending", {}, 0)]])
            self.assertIn("regalia_restore_pending 0\n", metrics.render("restore", published[0]))

    def test_a_marker_that_is_a_link_is_published_as_one(self):
        """The guard itself lexists: a link to a real marker holds the boot as surely as the marker does, so the
        gauge must not disagree with the guard."""
        published = []
        with tempfile.TemporaryDirectory() as directory, \
                unittest.mock.patch.object(etcdconf, "STORED_RESTORE_PENDING", os.path.join(directory, "restore-pending")), \
                unittest.mock.patch.object(metrics, "RUN_DIR", directory), \
                unittest.mock.patch.object(node, "metrics", metrics):
            Path(os.path.join(directory, "real-marker")).touch()
            os.symlink(os.path.join(directory, "real-marker"), etcdconf.STORED_RESTORE_PENDING)
            node.restore_pending_metrics(published.append)
            self.assertEqual(published, [[("regalia_restore_pending", {}, 1)]])

    def test_a_metric_that_cannot_be_written_does_not_change_the_outcome(self):
        """A dead /run is not a reason the boot guard's state stops being the truth; the file's age raises the
        alert instead (RegaliaRestoreMetricsMissing)."""
        with tempfile.TemporaryDirectory() as directory, \
                unittest.mock.patch.object(etcdconf, "STORED_RESTORE_PENDING", os.path.join(directory, "restore-pending")), \
                unittest.mock.patch.object(metrics, "RUN_DIR", os.path.join(directory, "gone")), \
                unittest.mock.patch.object(node, "metrics", metrics):
            self.assertIsNone(node.restore_pending_metrics())

    def test_the_boot_writes_the_guard_state_from_the_start(self):
        """node.py publishes it at boot (the node unit's first metrics write), so a held host carries the gauge
        from its first run of the day, not from the next mark or clear."""
        source = (ROOT / "deploy" / "baremetal" / "node.py").read_text()
        self.assertIn("restore_pending_metrics()", source)


if __name__ == "__main__":
    unittest.main()
