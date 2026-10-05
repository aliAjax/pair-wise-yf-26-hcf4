import base64
import hashlib
import tempfile
import threading
import time
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, PreservationStore


class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PreservationStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.archive = self.store.create_archive("owner", "城市测绘档案", (date.today() + timedelta(days=3650)).isoformat())
        self.raw = b"<record><id>1</id></record>"
        self.version = self.store.ingest_version("owner", self.archive["id"], [
            {"path": "records/one.xml", "content_b64": base64.b64encode(self.raw).decode()},
            {"path": "README.txt", "content_b64": base64.b64encode(b"archive readme").decode()},
        ])
        self.copy1 = self.store.add_copy("owner", self.version["id"], "offline-disk-a")["id"]
        self.copy2 = self.store.add_copy("owner", self.version["id"], "offline-disk-b")["id"]

    def tearDown(self):
        self.tmp.cleanup()

    def test_integrity_repair_and_format_migration(self):
        self.store.simulate_corruption("owner", self.copy1, "records/one.xml")
        result = self.store.verify_copy("owner", self.copy1)
        self.assertEqual(result["state"], "healthy")
        self.assertTrue(result["repaired"])
        self.assertEqual(result["corrupt_paths"], ["records/one.xml"])
        migrated = self.store.migrate(
            "owner", self.version["id"], "records/one.xml", "records/one.html", "html",
            base64.b64encode(b"<html><body><p>1</p></body></html>").decode(),
        )
        detail = self.store.get_version("owner", migrated["id"])
        self.assertEqual(detail["version"]["version"], 2)
        self.assertTrue(any(f["path"] == "records/one.html" for f in detail["files"]))
        status = self.store.archive_status("owner", self.archive["id"])
        self.assertGreater(status["days_remaining"], 3000)

    def test_restricted_access_and_invalid_manifest_are_rejected(self):
        with self.assertRaises(BusinessError) as ctx:
            self.store.get_version("outsider", self.version["id"])
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.ingest_version("owner", self.archive["id"], [{"path": "../escape.txt", "content_b64": "eA=="}])
        self.assertEqual(ctx.exception.code, "unsafe_path")
        with self.assertRaises(BusinessError) as ctx:
            self.store.add_copy("owner", self.version["id"], "offline-disk-a")
        self.assertEqual(ctx.exception.code, "copy_exists")


class DestructionTests(unittest.TestCase):
    """销毁 saga：三点一起待销毁、逐点提交、失败停在待处理、恢复只重试未完成、账目对账不重复执行。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PreservationStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.archive = self.store.create_archive("owner", "销毁测试档案", (date.today() + timedelta(days=3650)).isoformat())
        self.version = self.store.ingest_version("owner", self.archive["id"], [
            {"path": "records/one.xml", "content_b64": base64.b64encode(b"<record><id>1</id></record>").decode()},
        ])
        self.copy1 = self.store.add_copy("owner", self.version["id"], "offline-disk-a")["id"]
        self.copy2 = self.store.add_copy("owner", self.version["id"], "offline-disk-b")["id"]

    def tearDown(self):
        self.tmp.cleanup()

    def _points(self, detail):
        return {p["node_key"]: p for p in detail["points"]}

    def test_failure_stops_at_pending_and_recovery_retries_only_unfinished(self):
        # 第一个离线副本介质故障 -> 服务端成功后停在待处理，后续副本不执行
        self.store.set_storage_fault("owner", f"copy:{self.copy1}", True)
        detail = self.store.request_destruction("owner", self.version["id"])
        points = self._points(detail)
        self.assertEqual(detail["destruction"]["status"], "partial")
        self.assertEqual(points["server"]["state"], "destroyed")
        self.assertEqual(points[f"copy:{self.copy1}"]["state"], "pending")
        self.assertEqual(points[f"copy:{self.copy2}"]["state"], "pending")
        self.assertEqual(points[f"copy:{self.copy2}"]["attempts"], 0)
        self.assertTrue(points[f"copy:{self.copy1}"]["last_error"])

        # 恢复：只重试仍处于待处理的副本，已成功的服务端不重复执行
        self.store.set_storage_fault("owner", f"copy:{self.copy1}", False)
        detail = self.store.reconcile_destruction("owner", detail["destruction"]["id"])
        points = self._points(detail)
        self.assertEqual(detail["destruction"]["status"], "completed")
        self.assertTrue(all(p["state"] == "destroyed" for p in points.values()))
        self.assertEqual(points["server"]["attempts"], 1)
        self.assertEqual(points[f"copy:{self.copy1}"]["attempts"], 2)
        self.assertTrue(all(p["consistent"] and p["actual"] == "gone" for p in points.values()))

    def test_reconcile_is_idempotent_and_double_destroy_rejected(self):
        detail = self.store.request_destruction("owner", self.version["id"])
        self.assertEqual(detail["destruction"]["status"], "completed")
        # 再次对账不重复执行任何已成功的存储点
        again = self.store.reconcile_destruction("owner", detail["destruction"]["id"])
        points = self._points(again)
        self.assertTrue(all(p["state"] == "destroyed" for p in points.values()))
        self.assertEqual(points["server"]["attempts"], 1)
        # 同一版本不能重复发起销毁
        with self.assertRaises(BusinessError) as ctx:
            self.store.request_destruction("owner", self.version["id"])
        self.assertEqual(ctx.exception.code, "already_destroyed")

    def test_destruction_serializes_simultaneous_uploads(self):
        # 销毁执行期间持有写锁，同时上传必须被串行挡住
        started = threading.Event()
        proceed = threading.Event()

        def slow_execute(conn, point):
            started.set()
            proceed.wait(timeout=5)

        original = self.store._execute_point
        self.store._execute_point = slow_execute
        try:
            t = threading.Thread(target=self.store.request_destruction, args=("owner", self.version["id"]))
            t.start()
            self.assertTrue(started.wait(timeout=5))
            # 销毁执行中，上传被挡住
            ingest_done = threading.Event()

            def do_ingest():
                self.store.ingest_version("owner", self.archive["id"], [{"path": "b.txt", "content_b64": "Yg=="}])
                ingest_done.set()

            it = threading.Thread(target=do_ingest)
            it.start()
            time.sleep(0.2)
            self.assertFalse(ingest_done.is_set())
            proceed.set()
            t.join(timeout=5)
            it.join(timeout=5)
            self.assertTrue(ingest_done.is_set())
        finally:
            self.store._execute_point = original

    def test_destruction_requires_write_permission(self):
        with self.assertRaises(BusinessError) as ctx:
            self.store.request_destruction("outsider", self.version["id"])
        self.assertEqual(ctx.exception.status, 403)


if __name__ == "__main__":
    unittest.main()
