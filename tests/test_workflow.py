import tempfile, unittest
from pathlib import Path
from src.repository import Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES

OFFICE = "office_a"
SECTION = "DS-1"


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        # 坝段映射：本处坝段归属本处
        self.service.set_mapping(SECTION, OFFICE, "admin", "admin")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def test_complete_workflow_and_audit(self):
        item = self.service.create_item(
            {"title": "workflow item", "description": "complete business flow",
             "severity": 'major', "quantity": 12, "threshold": 6,
             "external_ref": "WF-1", "dam_section": SECTION},
            "creator", 'inspector', OFFICE)
        self.assertEqual(item["status"], STATES[0])
        self.assertEqual(item["office"], OFFICE)
        self.service.add_record(
            item["id"],
            {"kind": "evidence", "detail": "evidence registered",
             "status": "closed", "external_ref": "EV-1"},
            "recorder", 'inspector', OFFICE)
        current = item
        for target in STATES[1:]:
            current = self.service.transition(
                current["id"], target, current["version"],
                "reviewer", TRANSITION_ROLES[target][0], OFFICE)
        self.assertEqual(current["status"], STATES[-1])
        self.assertEqual(len(self.service.list_records(current["id"], "viewer", OFFICE)), 1)
        events = self.service.audit("viewer", OFFICE, current["id"])
        self.assertGreaterEqual(len(events), len(STATES) + 1)
        self.assertTrue(self.repo.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
