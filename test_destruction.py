import base64
import hashlib
import tempfile
import threading
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import PRIMARY_LOCATION, BusinessError, PreservationStore


class DestructionTests(unittest.TestCase):
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
        self.vid = self.version["id"]
        self.copy1 = self.store.add_copy("owner", self.vid, "offline-disk-a")
        self.copy2 = self.store.add_copy("owner", self.vid, "offline-disk-b")

    def tearDown(self):
        self.tmp.cleanup()

    def _request(self, reason="保留期满销毁"):
        return self.store.request_destruction("owner", self.vid, reason)

    def test_all_three_points_must_succeed_before_record(self):
        req = self._request()
        job_id = req["job_id"]
        self.assertEqual(req["state"], "in_progress")
        self.assertEqual(set(req["points"]), {"offline-disk-a", "offline-disk-b", PRIMARY_LOCATION})

        # 第二个离线库故障：只销毁了 disk-a，任务停在待处理，没有销毁账目。
        self.store.set_storage_fault("owner", "offline-disk-b", "磁头损坏")
        with self.assertRaises(BusinessError) as ctx:
            self.store.run_destruction("owner", job_id)
        self.assertEqual(ctx.exception.code, "destruction_point_failed")
        self.assertEqual(ctx.exception.payload["failed"]["location"], "offline-disk-b")
        progress = self.store.get_destruction_job("owner", job_id)
        states = {i["location"]: i["state"] for i in progress["items"]}
        self.assertEqual(states, {"offline-disk-a": "done", "offline-disk-b": "failed", PRIMARY_LOCATION: "pending"})
        self.assertIsNone(progress["record"])
        recon = self.store.reconcile_destruction("owner", job_id)
        self.assertTrue(recon["balanced"], recon["mismatches"])

        # 销毁申请期间，上传 / 新建副本 / 迁移都被串行挡住。
        with self.assertRaises(BusinessError) as c:
            self.store.ingest_version("owner", self.archive["id"],
                                      [{"path": "new.txt", "content_b64": base64.b64encode(b"x").decode()}])
        self.assertEqual(c.exception.code, "destruction_in_progress")
        with self.assertRaises(BusinessError) as c:
            self.store.add_copy("owner", self.vid, "offline-disk-c")
        self.assertEqual(c.exception.code, "destruction_in_progress")
        with self.assertRaises(BusinessError) as c:
            self.store.migrate("owner", self.vid, "README.txt", "README.md", "md",
                               base64.b64encode(b"# readme").decode())
        self.assertEqual(c.exception.code, "destruction_in_progress")

        # 介质未恢复时重试：disk-a 不重跑，disk-b 仍失败，尝试次数累加。
        with self.assertRaises(BusinessError):
            self.store.run_destruction("owner", job_id)
        again = self.store.get_destruction_job("owner", job_id)
        disk_a = next(i for i in again["items"] if i["location"] == "offline-disk-a")
        disk_b = next(i for i in again["items"] if i["location"] == "offline-disk-b")
        self.assertEqual(disk_a["state"], "done")
        self.assertEqual(disk_a["attempts"], 1)  # 已成功的点绝不重复执行
        self.assertEqual(disk_b["attempts"], 2)

        # 恢复介质：只继续 disk-b 和主副本；disk-a 依然不重跑。
        self.store.clear_storage_fault("owner", "offline-disk-b")
        result = self.store.run_destruction("owner", job_id)
        self.assertEqual(result["state"], "completed")
        self.assertEqual({e["location"] for e in result["executed"]}, {"offline-disk-b", PRIMARY_LOCATION})
        final = self.store.get_destruction_job("owner", job_id)
        self.assertTrue(all(i["state"] == "done" for i in final["items"]))
        self.assertEqual(final["record"]["record_no"], f"DR-{job_id:06d}")
        self.assertEqual(final["record"]["point_count"], 3)
        self.assertEqual({f["path"] for f in final["record"]["manifest"]}, {"records/one.xml", "README.txt"})

        detail = self.store.get_version("owner", self.vid)
        self.assertEqual(detail["version"]["state"], "destroyed")
        self.assertEqual({c["state"] for c in detail["copies"]}, {"destroyed"})
        self.assertEqual(detail["files"], [])

        # 完成后再次执行是幂等的，不会重复销毁任何存储点。
        rerun = self.store.run_destruction("owner", job_id)
        self.assertTrue(rerun["already"])
        self.assertEqual(rerun["executed"], [])

        # 对账页：账目与三个存储点一致。
        recon = self.store.reconcile_destruction("owner", job_id)
        self.assertTrue(recon["balanced"])
        self.assertEqual(recon["mismatches"], [])

        # 已销毁版本不能再申请、不能再写。
        with self.assertRaises(BusinessError) as c:
            self.store.request_destruction("owner", self.vid, "再来一次")
        self.assertEqual(c.exception.code, "version_destroyed")

    def test_reconcile_detects_state_drift(self):
        job_id = self._request()["job_id"]
        self.store.set_storage_fault("owner", "offline-disk-b", "坏道")
        with self.assertRaises(BusinessError):
            self.store.run_destruction("owner", job_id)
        # 人为把已成功销毁的 disk-a 状态改回 healthy，对账必须发现账目与实物不符。
        with self.store.connect() as conn:
            conn.execute("UPDATE copies SET state='healthy' WHERE location='offline-disk-a'")
            conn.commit()
        recon = self.store.reconcile_destruction("owner", job_id)
        self.assertFalse(recon["balanced"])
        self.assertTrue(any("offline-disk-a" in m.get("location", "") for m in recon["mismatches"]))

    def test_requires_three_storage_points(self):
        version2 = self.store.ingest_version("owner", self.archive["id"], [
            {"path": "only.txt", "content_b64": base64.b64encode(b"y").decode()},
        ])
        with self.assertRaises(BusinessError) as ctx:
            self.store.request_destruction("owner", version2["id"], "副本不齐")
        self.assertEqual(ctx.exception.code, "storage_topology_invalid")

    def test_destruction_execution_is_serialized(self):
        job_id = self._request()["job_id"]
        results, errors = [], []

        def run():
            try:
                results.append(self.store.run_destruction("owner", job_id))
            except BusinessError as exc:
                errors.append(exc)

        threads = [threading.Thread(target=run) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 只有一次真实执行完成；其它调用都拿到同一个已完成结果，没有任何点被销毁两次。
        self.assertFalse(errors)
        completed = [r for r in results if r["state"] == "completed"]
        self.assertEqual(len(completed), 4)
        total_executed = sum(len(r["executed"]) for r in results)
        self.assertEqual(total_executed, 3)  # 三个点各只执行一次
        job = self.store.get_destruction_job("owner", job_id)
        self.assertEqual({i["location"]: (i["state"], i["attempts"]) for i in job["items"]},
                         {"offline-disk-a": ("done", 1), "offline-disk-b": ("done", 1), PRIMARY_LOCATION: ("done", 1)})


if __name__ == "__main__":
    unittest.main()
