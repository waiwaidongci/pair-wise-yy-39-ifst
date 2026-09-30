import threading
import tempfile, unittest
from pathlib import Path
from src.domain import ConflictError, PermissionDenied, ValidationError
from src.repository import Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES

OFFICE_A = "office_a"
OFFICE_B = "office_b"


class IsolationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        # 坝段映射：DS-1→A处，DS-2→B处
        self.service.set_mapping("DS-1", OFFICE_A, "admin", "admin")
        self.service.set_mapping("DS-2", OFFICE_B, "admin", "admin")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _item(self, section="DS-1", office=OFFICE_A, ref=None):
        payload = {"title": "crack", "description": "isolation check",
                   "severity": "major", "quantity": 5, "threshold": 10,
                   "dam_section": section}
        if ref:
            payload["external_ref"] = ref
        return self.service.create_item(payload, "creator", "inspector", office)

    # ---------- 列表/详情/记录/审计 只认本处 ----------
    def test_list_only_own_office(self):
        a = self._item("DS-1", OFFICE_A, "REF-A")
        b = self._item("DS-2", OFFICE_B, "REF-B")
        list_a = self.service.list_items("viewer", OFFICE_A)
        list_b = self.service.list_items("viewer", OFFICE_B)
        ids_a = [i["id"] for i in list_a]
        ids_b = [i["id"] for i in list_b]
        self.assertIn(a["id"], ids_a)
        self.assertNotIn(b["id"], ids_a)
        self.assertIn(b["id"], ids_b)
        self.assertNotIn(a["id"], ids_b)

    def test_cross_office_read_and_modify_rejected(self):
        item = self._item("DS-1", OFFICE_A)
        # 跨处读取
        with self.assertRaises(PermissionDenied):
            self.service.get_item(item["id"], "viewer", OFFICE_B)
        with self.assertRaises(PermissionDenied):
            self.service.list_records(item["id"], "viewer", OFFICE_B)
        with self.assertRaises(PermissionDenied):
            self.service.audit("viewer", OFFICE_B, item["id"])
        # 跨处审批/修改
        with self.assertRaises(PermissionDenied):
            self.service.transition(item["id"], STATES[1], 1,
                                    "reviewer", "inspector", OFFICE_B)
        with self.assertRaises(PermissionDenied):
            self.service.add_record(item["id"], {"kind": "note", "detail": "x"},
                                    "recorder", "inspector", OFFICE_B)
        # 本处可正常访问
        self.assertIsNotNone(self.service.get_item(item["id"], "viewer", OFFICE_A))

    def test_missing_office_rejected(self):
        with self.assertRaises(PermissionDenied):
            self.service.list_items("viewer", "")

    # ---------- 回填 ----------
    def test_backfill_uses_mapping(self):
        # 创建时坝段未映射 → 无归属
        item1 = self.service.create_item(
            {"title": "old-1", "description": "x", "severity": "minor",
             "quantity": 1, "threshold": 2, "dam_section": "DS-OLD1"},
            "creator", "inspector", OFFICE_A)
        item2 = self.service.create_item(
            {"title": "old-2", "description": "x", "severity": "minor",
             "quantity": 1, "threshold": 2, "dam_section": "DS-OLD2"},
            "creator", "inspector", OFFICE_A)
        self.assertIsNone(item1["office"])
        self.assertIsNone(item2["office"])
        # 补充映射后回填
        self.service.set_mapping("DS-OLD1", OFFICE_A, "admin", "admin")
        self.service.set_mapping("DS-OLD2", OFFICE_B, "admin", "admin")
        result = self.service.backfill("admin", "admin")
        self.assertEqual(len(result["backfilled"]), 2)
        self.assertEqual(result["remaining"], 0)
        self.assertEqual(self.repo.get_item(item1["id"])["office"], OFFICE_A)
        self.assertEqual(self.repo.get_item(item2["id"])["office"], OFFICE_B)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_backfill_unmappable_keeps_unclaimed(self):
        item = self.service.create_item(
            {"title": "old-unknown", "description": "x", "severity": "minor",
             "quantity": 1, "threshold": 2, "dam_section": "DS-UNKNOWN"},
            "creator", "inspector", OFFICE_A)
        result = self.service.backfill("admin", "admin")
        self.assertEqual(len(result["backfilled"]), 0)
        self.assertEqual(result["remaining"], 1)
        self.assertIsNone(self.repo.get_item(item["id"])["office"])

    # ---------- 无法映射：仅原创建人所在处指定负责人 ----------
    def test_unmappable_designated_by_creator_office(self):
        item = self.service.create_item(
            {"title": "unmappable", "description": "x", "severity": "minor",
             "quantity": 1, "threshold": 2, "dam_section": "DS-UNKNOWN"},
            "creator", "inspector", OFFICE_A)
        # 原创建人所在处可见并可指定负责人
        updated = self.service.designate_assignee(item["id"], "张三",
                                                   "creator", "inspector", OFFICE_A)
        self.assertEqual(updated["assignee"], "张三")
        # 未认领条目在认领前保持原状态，不得流转
        with self.assertRaises(PermissionDenied):
            self.service.transition(item["id"], STATES[1], 1,
                                    "reviewer", "inspector", OFFICE_A)
        # 其他处不可见、不可指定
        with self.assertRaises(PermissionDenied):
            self.service.get_item(item["id"], "viewer", OFFICE_B)
        with self.assertRaises(PermissionDenied):
            self.service.designate_assignee(item["id"], "李四",
                                             "other", "inspector", OFFICE_B)
        list_b = self.service.list_items("viewer", OFFICE_B)
        self.assertNotIn(item["id"], [i["id"] for i in list_b])

    # ---------- 并发认领：只接受先到的一次 ----------
    def test_concurrent_claim_only_first_wins(self):
        item = self.service.create_item(
            {"title": "historical", "description": "x", "severity": "major",
             "quantity": 3, "threshold": 6, "dam_section": "DS-OLD"},
            "creator", "inspector", OFFICE_A)
        self.service.set_mapping("DS-OLD", OFFICE_B, "admin", "admin")
        results, errors = [], []

        def do_claim(actor):
            try:
                results.append(self.service.claim_item(item["id"], actor, "admin"))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        t1 = threading.Thread(target=do_claim, args=("admin1",))
        t2 = threading.Thread(target=do_claim, args=("admin2",))
        t1.start(); t2.start()
        t1.join(); t2.join()
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ConflictError)
        # 认领归属取自映射结果(DS-OLD→B处)，与认领人所在处无关
        claimed = self.repo.get_item(item["id"])
        self.assertEqual(claimed["office"], OFFICE_B)
        # 未认领缺陷保持原状态
        self.assertEqual(claimed["status"], STATES[0])
        self.assertEqual(claimed["version"], 1)
        self.assertIsNone(claimed["assignee"])
        self.assertTrue(self.repo.verify_audit_chain())

    def test_repo_claim_atomicity(self):
        item = self.service.create_item(
            {"title": "historical-2", "description": "x", "severity": "major",
             "quantity": 3, "threshold": 6, "dam_section": "DS-OLD2"},
            "creator", "inspector", OFFICE_A)
        self.service.set_mapping("DS-OLD2", OFFICE_A, "admin", "admin")
        barrier = threading.Barrier(2)
        outcomes = []

        def attempt():
            barrier.wait()
            outcomes.append(self.repo.claim_with_audit(
                item["id"], OFFICE_A, "admin", {"via": "test"}))

        t1 = threading.Thread(target=attempt)
        t2 = threading.Thread(target=attempt)
        t1.start(); t2.start()
        t1.join(); t2.join()
        self.assertEqual(sorted(outcomes), [False, True])

    def test_claim_retry_uses_mapping_result(self):
        item = self.service.create_item(
            {"title": "historical-3", "description": "x", "severity": "major",
             "quantity": 3, "threshold": 6, "dam_section": "DS-OLD3"},
            "creator", "inspector", OFFICE_A)
        self.service.set_mapping("DS-OLD3", OFFICE_B, "admin", "admin")
        # 先到的认领成功
        first = self.service.claim_item(item["id"], "admin1", "admin")
        self.assertEqual(first["office"], OFFICE_B)
        # 后到的认领失败；重试仍沿用同一映射结果(DS-OLD3→B处)，不会改成别处
        with self.assertRaises(ConflictError):
            self.service.claim_item(item["id"], "admin2", "admin")
        self.assertEqual(self.repo.get_item(item["id"])["office"], OFFICE_B)

    # ---------- 负责人变更与审计同事务 ----------
    def test_designate_atomic_and_audited(self):
        item = self._item("DS-1", OFFICE_A)
        updated = self.service.designate_assignee(item["id"], "张三",
                                                   "creator", "inspector", OFFICE_A)
        self.assertEqual(updated["assignee"], "张三")
        events = self.service.audit("viewer", OFFICE_A, item["id"])
        designate_events = [e for e in events if e["action"] == "designate"]
        self.assertEqual(len(designate_events), 1)
        self.assertEqual(designate_events[0]["detail"]["assignee"], "张三")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_admin_cannot_designate(self):
        item = self._item("DS-1", OFFICE_A)
        with self.assertRaises(PermissionDenied):
            self.service.designate_assignee(item["id"], "张三", "admin", "admin", "")


if __name__ == "__main__":
    unittest.main()
