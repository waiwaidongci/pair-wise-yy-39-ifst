import http.client
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from src.domain import ConflictError, PermissionDenied, ValidationError
from src.http_api import make_handler
from src.repository import Repository
from src.service import Service
from src.rules import STATES

A = "office-a"
B = "office-b"


class TenancyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        # 两名巡检员分别归属两处
        self.repo.upsert_actor_office("ins-a", A, "admin-a")
        self.repo.upsert_actor_office("ins-b", B, "admin-b")
        self.item = self.service.create_item(
            {"title": "A处坝段裂缝", "description": "d", "severity": "major",
             "quantity": 3, "threshold": 1, "section": "A-10",
             "external_ref": "X-1"},
            "ins-a", "inspector", A)

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    # ---------- 列表/详情/记录/状态流转/审计只认本处 ----------

    def test_list_detail_records_records_are_office_scoped(self):
        self.assertEqual([i["id"] for i in self.service.list_items("viewer", A)], [self.item["id"]])
        self.assertEqual(self.service.list_items("viewer", B), [])
        self.service.get_item(self.item["id"], "viewer", A)
        with self.assertRaises(PermissionDenied):
            self.service.get_item(self.item["id"], "viewer", B)
        self.service.add_record(self.item["id"], {"kind": "repair", "detail": "x"},
                                "ins-a", "inspector", A)
        with self.assertRaises(PermissionDenied):
            self.service.list_records(self.item["id"], "viewer", B)
        with self.assertRaises(PermissionDenied):
            self.service.add_record(self.item["id"], {"kind": "repair", "detail": "y"},
                                    "ins-b", "inspector", B)
        with self.assertRaises(PermissionDenied):
            self.service.transition(self.item["id"], STATES[1], 1,
                                    "ins-b", "inspector", B)
        with self.assertRaises(PermissionDenied):
            self.service.audit("viewer", B, self.item["id"])
        self.assertEqual(self.service.audit("viewer", A, self.item["id"])[0]["office_id"], A)
        # 全量审计也不会串处
        self.assertEqual(len(self.service.audit("viewer", B)), 0)

    def test_missing_office_header_is_rejected(self):
        with self.assertRaises(PermissionDenied):
            self.service.list_items("viewer", "")

    def test_actor_cannot_create_under_foreign_office(self):
        with self.assertRaises(PermissionDenied):
            self.service.create_item(
                {"title": "越权", "description": "d", "severity": "minor",
                 "section": "B-1"}, "ins-a", "inspector", B)

    # ---------- 历史未认领数据：不默认开放 ----------

    def _seed_legacy(self, section, creator):
        # 直接写入一条旧数据：无归属、无坝段映射依据
        with self.repo._lock, self.repo.conn:
            cur = self.repo.conn.execute(
                """INSERT INTO items(title, description, severity, quantity, threshold,
                   status, version, created_by, created_at, updated_at,
                   office_id, section, owner)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                ("旧缺陷", "d", "major", 1, 1, STATES[0], 1, creator,
                 "2020-01-01T00:00:00+00:00", "2020-01-01T00:00:00+00:00",
                 None, section, None))
            legacy_id = int(cur.lastrowid)
            self.repo._append_audit_locked(
                "create", "大坝缺陷", legacy_id, creator, {"legacy": True}, None)
        return legacy_id

    def test_unclaimed_legacy_invisible_to_business_roles(self):
        legacy_id = self._seed_legacy("A-99", "old-hand")
        for office in (A, B):
            with self.assertRaises(PermissionDenied):
                self.service.get_item(legacy_id, "viewer", office)
        self.assertEqual(self.service.list_items("viewer", A), [self.service.enrich(self.item)])
        with self.assertRaises(PermissionDenied):
            self.service.transition(legacy_id, STATES[1], 1,
                                    "ins-a", "inspector", A)
        # 管理员可见未认领列表，业务角色不可见
        with self.assertRaises(PermissionDenied):
            self.service.list_unclaimed("ins-a", "inspector", A)
        unclaimed = self.service.list_unclaimed("admin-a", "admin", A)
        self.assertEqual([u["id"] for u in unclaimed], [legacy_id])

    def test_unclaimed_preview_survives_foreign_mapping(self):
        legacy_b = self._seed_legacy("B-77", "old-hand-2")
        legacy_none = self._seed_legacy("Z-00", "old-hand-3")
        self.service.register_section({"section": "B-77"}, "admin-b", "admin", B)
        # A处管理员仍能看到完整未认领清单及解析指向
        preview = {u["id"]: u["claim_resolution"]
                   for u in self.service.list_unclaimed("admin-a", "admin", A)}
        self.assertEqual(preview[legacy_b]["mapped_office"], B)
        self.assertFalse(preview[legacy_b]["claimable_here"])
        self.assertIsNone(preview[legacy_none]["source"])
        # 但真正跨处认领仍被拒绝
        with self.assertRaises(PermissionDenied):
            self.service.claim_legacy(legacy_b, {"owner": "intruder"},
                                      "admin-a", "admin", A)

    def test_admin_mapping_backfill_assigns_only_own_office(self):
        legacy_a = self._seed_legacy("A-99", "old-hand")
        legacy_b = self._seed_legacy("B-77", "old-hand-2")
        legacy_none = self._seed_legacy("Z-00", "old-hand-3")
        self.service.register_section({"section": "A-99"}, "admin-a", "admin", A)
        self.service.register_section({"section": "B-77"}, "admin-b", "admin", B)
        result = self.service.backfill({}, "admin-a", "admin", A)
        self.assertEqual(result["assigned"], [
            {"id": legacy_a, "office": A, "section": "A-99"}])
        self.assertEqual({s["id"] for s in result["skipped"]}, {legacy_b, legacy_none})
        # 回填是幂等的：第二次没有任何新指派
        again = self.service.backfill({}, "admin-a", "admin", A)
        self.assertEqual(again["assigned"], [])
        claimed = self.service.get_item(legacy_a, "viewer", A)
        self.assertEqual(claimed["office_id"], A)
        # 未认领缺陷保持原状态
        unclaimed = self.repo.get_item(legacy_none)
        self.assertIsNone(unclaimed["office_id"])
        self.assertEqual(unclaimed["status"], STATES[0])
        self.assertEqual(unclaimed["version"], 1)
        # 回填后历史审计归属本处，审计链不断
        events = self.service.audit("viewer", A, legacy_a)
        self.assertTrue(events)
        self.assertTrue(all(e["office_id"] == A for e in events))
        self.assertTrue(self.repo.verify_audit_chain())

    def test_section_mapping_is_immutable(self):
        self.service.register_section({"section": "A-99"}, "admin-a", "admin", A)
        # 重复登记到本处幂等
        self.service.register_section({"section": "A-99"}, "admin-a", "admin", A)
        with self.assertRaises(ConflictError):
            self.service.register_section({"section": "A-99"}, "admin-b", "admin", B)

    # ---------- 无法映射：只由创建人所在处认领并指定负责人 ----------

    def test_unmappable_claimed_by_creator_office_with_owner(self):
        legacy_id = self._seed_legacy("Z-00", "ins-a")
        # 无映射时，创建人在 A 处花名册，只有 A 处可认领
        with self.assertRaises(PermissionDenied):
            self.service.claim_legacy(legacy_id, {"owner": "lead-b"},
                                      "admin-b", "admin", B)
        # 必须指定负责人
        with self.assertRaises(ValidationError):
            self.service.claim_legacy(legacy_id, {}, "admin-a", "admin", A)
        claimed = self.service.claim_legacy(
            legacy_id, {"owner": "lead-a"}, "admin-a", "admin", A)
        self.assertEqual(claimed["office_id"], A)
        self.assertEqual(claimed["owner"], "lead-a")
        self.assertEqual(claimed["status"], STATES[0])  # 认领不改状态
        events = self.service.audit("viewer", A, legacy_id)
        self.assertTrue(any(e["action"] == "claim" for e in events))

    def test_unmappable_without_creator_roster_cannot_be_claimed(self):
        legacy_id = self._seed_legacy("Z-00", "stranger-no-roster")
        with self.assertRaises(ValidationError):
            self.service.claim_legacy(legacy_id, {"owner": "lead-a"},
                                      "admin-a", "admin", A)
        # 仍处于未认领、原状态
        row = self.repo.get_item(legacy_id)
        self.assertIsNone(row["office_id"])
        self.assertEqual(row["status"], STATES[0])

    def test_section_mapping_takes_precedence_and_retry_reuses_resolution(self):
        # 坝段映射存在但创建人花名册在别处：以映射为准
        legacy_id = self._seed_legacy("A-99", "ins-b")
        self.service.register_section({"section": "A-99"}, "admin-a", "admin", A)
        # B 处（创建人所在处）尝试认领 -> 映射要求 A 处，拒绝跨处
        with self.assertRaises(PermissionDenied):
            self.service.claim_legacy(legacy_id, {"owner": "lead-b"},
                                      "admin-b", "admin", B)
        # 认领失败后重试沿用同一映射结果：A 处可认领
        claimed = self.service.claim_legacy(
            legacy_id, {"owner": "lead-a"}, "admin-a", "admin", A)
        self.assertEqual(claimed["office_id"], A)

    def test_double_claim_first_writer_wins_even_with_same_office(self):
        legacy_id = self._seed_legacy("Z-00", "ins-a")
        self.service.claim_legacy(legacy_id, {"owner": "lead-a-1"},
                                  "admin-a", "admin", A)
        with self.assertRaises(ConflictError):
            self.service.claim_legacy(legacy_id, {"owner": "lead-a-2"},
                                      "admin-a2", "admin", A)
        row = self.repo.get_item(legacy_id)
        self.assertEqual(row["owner"], "lead-a-1")

    def test_concurrent_claims_only_one_succeeds(self):
        legacy_id = self._seed_legacy("Z-00", "ins-a")
        outcomes = []

        def claim(owner):
            try:
                self.service.claim_legacy(legacy_id, {"owner": owner},
                                          "admin-a", "admin", A)
                outcomes.append(("ok", owner))
            except ConflictError:
                outcomes.append(("conflict", owner))

        threads = [threading.Thread(target=claim, args=(o,))
                   for o in ("lead-1", "lead-2", "lead-3")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(o[0] for o in outcomes).count("ok"), 1)
        self.assertEqual(sorted(o[0] for o in outcomes).count("conflict"), 2)
        row = self.repo.get_item(legacy_id)
        self.assertIn(row["owner"], {"lead-1", "lead-2", "lead-3"})
        # 只有一条认领审计
        claims = [e for e in self.service.audit("viewer", A, legacy_id)
                  if e["action"] == "claim"]
        self.assertEqual(len(claims), 1)

    # ---------- 负责人变更与审计原子性 ----------

    def test_assign_owner_writes_change_and_audit_together(self):
        self.service.assign_owner(self.item["id"], {"owner": "new-lead"},
                                  "admin-a", "admin", A)
        self.assertEqual(self.repo.get_item(self.item["id"])["owner"], "new-lead")
        events = self.service.audit("viewer", A, self.item["id"])
        self.assertTrue(any(e["action"] == "assign_owner" for e in events))
        self.assertTrue(self.repo.verify_audit_chain())

    def test_assign_owner_foreign_office_denied(self):
        with self.assertRaises(PermissionDenied):
            self.service.assign_owner(self.item["id"], {"owner": "intruder"},
                                      "admin-b", "admin", B)
        self.assertIsNone(self.repo.get_item(self.item["id"])["owner"])

    def test_claim_is_atomic_when_audit_write_fails(self):
        legacy_id = self._seed_legacy("Z-00", "ins-a")
        original = Repository._append_audit_locked

        def boom(self, *a, **kw):
            raise RuntimeError("audit disk failure")

        Repository._append_audit_locked = boom
        try:
            with self.assertRaises(RuntimeError):
                self.service.claim_legacy(legacy_id, {"owner": "lead-a"},
                                          "admin-a", "admin", A)
        finally:
            Repository._append_audit_locked = original
        # 归属和审计都没有写一半
        row = self.repo.get_item(legacy_id)
        self.assertIsNone(row["office_id"])
        self.assertIsNone(row["owner"])
        self.assertEqual(row["status"], STATES[0])
        self.assertEqual(len(self.repo.list_audit(A, legacy_id)), 0)
        self.assertTrue(self.repo.verify_audit_chain())
        # 回滚后同一管理员仍可用同一映射结果重试成功
        claimed = self.service.claim_legacy(
            legacy_id, {"owner": "lead-a"}, "admin-a", "admin", A)
        self.assertEqual(claimed["office_id"], A)

    def test_assign_owner_is_atomic_when_audit_write_fails(self):
        original = Repository._append_audit_locked

        def boom(self, *a, **kw):
            raise RuntimeError("audit disk failure")

        Repository._append_audit_locked = boom
        try:
            with self.assertRaises(RuntimeError):
                self.service.assign_owner(self.item["id"], {"owner": "half-lead"},
                                          "admin-a", "admin", A)
        finally:
            Repository._append_audit_locked = original
        self.assertIsNone(self.repo.get_item(self.item["id"])["owner"])
        self.assertFalse(any(e["action"] == "assign_owner"
                             for e in self.repo.list_audit(A)))
        self.assertTrue(self.repo.verify_audit_chain())

    def test_non_admin_cannot_touch_admin_routes(self):
        with self.assertRaises(PermissionDenied):
            self.service.register_section({"section": "A-99"},
                                          "ins-a", "inspector", A)
        with self.assertRaises(PermissionDenied):
            self.service.backfill({}, "ins-a", "inspector", A)
        with self.assertRaises(PermissionDenied):
            self.service.register_actor_office(
                {"actor": "x", "office_id": B}, "ins-b", "inspector", B)


class HttpTenancyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "http.db"))
        service = Service(self.repo)
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(
            service, str(Path(__file__).resolve().parent.parent / "static")))
        self.port = server.server_address[1]
        self.thread = threading.Thread(target=server.serve_forever, daemon=True)
        self.thread.start()
        self.server = server

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.repo.close()
        self.tmp.cleanup()

    def _request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        data = None
        hdrs = dict(headers or {})
        if body is not None:
            data = body if isinstance(body, str) else None
            import json
            data = json.dumps(body)
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        payload = resp.read().decode("utf-8")
        conn.close()
        import json
        return resp.status, json.loads(payload)

    def test_http_office_headers_and_cross_office_reject(self):
        status, item = self._request("POST", "/api/items", {
            "title": "http裂缝", "description": "d", "severity": "major",
            "section": "A-1"},
            {"X-Actor": "ins-a", "X-Role": "inspector", "X-Office": A})
        self.assertEqual(status, 201)
        item_id = item["id"]
        # 缺少 X-Office -> 403
        status, _ = self._request("GET", "/api/items",
                                  headers={"X-Actor": "v", "X-Role": "viewer"})
        self.assertEqual(status, 403)
        # 跨处详情 -> 403
        status, _ = self._request(
            "GET", f"/api/items/{item_id}",
            headers={"X-Actor": "v", "X-Role": "viewer", "X-Office": B})
        self.assertEqual(status, 403)
        # 跨处加记录 -> 403
        status, _ = self._request(
            "POST", f"/api/items/{item_id}/records", {"kind": "r", "detail": "x"},
            {"X-Actor": "ins-b", "X-Role": "inspector", "X-Office": B})
        self.assertEqual(status, 403)
        # 本处可看
        status, body = self._request(
            "GET", "/api/items",
            headers={"X-Actor": "v", "X-Role": "viewer", "X-Office": A})
        self.assertEqual(status, 200)
        self.assertEqual(len(body["items"]), 1)
        # 坝段映射登记接口需要 admin
        status, _ = self._request(
            "POST", "/api/admin/sections", {"section": "A-9"},
            {"X-Actor": "admin-a", "X-Role": "admin", "X-Office": A})
        self.assertEqual(status, 201)


if __name__ == "__main__":
    unittest.main()
