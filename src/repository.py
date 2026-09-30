from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ENTITY, ID_PREFIX, STATES


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()
        self._migrate()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    dam_section TEXT,
                    office TEXT,
                    created_office TEXT,
                    assignee TEXT,
                    claimed_by TEXT,
                    claimed_at TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE INDEX IF NOT EXISTS idx_items_office ON items(office);
                CREATE INDEX IF NOT EXISTS idx_items_created_office ON items(created_office);
                CREATE TABLE IF NOT EXISTS section_office_map (
                    dam_section TEXT PRIMARY KEY,
                    office TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
            """)

    def _migrate(self) -> None:
        """为旧库补充归属相关列（幂等）。"""
        with self._lock, self.conn:
            existing = {row[1] for row in self.conn.execute("PRAGMA table_info(items)").fetchall()}
            additions = {
                "dam_section": "ALTER TABLE items ADD COLUMN dam_section TEXT",
                "office": "ALTER TABLE items ADD COLUMN office TEXT",
                "created_office": "ALTER TABLE items ADD COLUMN created_office TEXT",
                "assignee": "ALTER TABLE items ADD COLUMN assignee TEXT",
                "claimed_by": "ALTER TABLE items ADD COLUMN claimed_by TEXT",
                "claimed_at": "ALTER TABLE items ADD COLUMN claimed_at TEXT",
            }
            for name, ddl in additions.items():
                if name not in existing:
                    self.conn.execute(ddl)
            self.conn.execute("""CREATE TABLE IF NOT EXISTS section_office_map (
                dam_section TEXT PRIMARY KEY, office TEXT NOT NULL)""")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str, dam_section: str, office: Optional[str],
                    created_office: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at,
                       dam_section, office, created_office)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now, dam_section, office, created_office),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None,
                   office: Optional[str] = None,
                   unclaimed_only: bool = False) -> List[Dict[str, Any]]:
        """按管理处隔离列出条目。

        - unclaimed_only=True：仅未认领（office IS NULL），供管理员回填/认领。
        - office 给定：返回本处条目 + 本处创建但尚未认领的条目（原创建人所在处可见）。
        """
        sql = "SELECT * FROM items WHERE 1=1"
        params: List[Any] = []
        if unclaimed_only:
            sql += " AND office IS NULL"
        elif office is not None:
            sql += " AND (office = ? OR (office IS NULL AND created_office = ?))"
            params.extend([office, office])
        if status:
            sql += " AND status=?"
            params.append(status)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    # ---------- 坝段映射表 ----------
    def get_mapping(self, dam_section: str) -> Optional[str]:
        with self._lock:
            row = self.conn.execute(
                "SELECT office FROM section_office_map WHERE dam_section=?",
                (dam_section,),
            ).fetchone()
        return row["office"] if row else None

    def set_mapping(self, dam_section: str, office: str) -> None:
        with self._lock, self.conn:
            self.conn.execute(
                """INSERT INTO section_office_map(dam_section, office) VALUES(?,?)
                   ON CONFLICT(dam_section) DO UPDATE SET office=excluded.office""",
                (dam_section, office),
            )

    def list_mappings(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT dam_section, office FROM section_office_map ORDER BY dam_section"
            ).fetchall()
        return [dict(row) for row in rows]

    # ---------- 认领 / 负责人变更（与审计同事务） ----------
    def _append_audit(self, action: str, entity_type: str, entity_id: int,
                       actor: str, detail: Dict[str, Any]) -> Dict[str, Any]:
        """在已有的 self._lock 与事务内追加审计事件，不单独提交。"""
        row = self.conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = row["entry_hash"] if row else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous)
        cur = self.conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"]),
        )
        event["id"] = int(cur.lastrowid)
        return event

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock, self.conn:
            return self._append_audit(action, entity_type, entity_id, actor, detail)

    def claim_with_audit(self, item_id: int, office: str, actor: str,
                         detail: Dict[str, Any]) -> bool:
        """原子认领：仅当仍无归属(office IS NULL)时写入归属并追加审计。

        返回 False 表示已被他人认领（调用方应拒绝），条目状态/版本不变。
        """
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET office=?, claimed_by=?, claimed_at=?, updated_at=?
                   WHERE id=? AND office IS NULL""",
                (office, actor, now, now, item_id),
            )
            if cur.rowcount == 0:
                return False
            self._append_audit("claim", ENTITY, item_id, actor, detail)
        return True

    def designate_with_audit(self, item_id: int, assignee: str, actor: str,
                             detail: Dict[str, Any]) -> bool:
        """原子变更负责人：更新负责人与追加审计在同一事务，不能只写一半。"""
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                "UPDATE items SET assignee=?, updated_at=? WHERE id=?",
                (assignee, now, item_id),
            )
            if cur.rowcount == 0:
                return False
            self._append_audit("designate", ENTITY, item_id, actor, detail)
        return True

    def list_audit(self, entity_id: Optional[int] = None,
                   entity_ids: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: List[Any] = []
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params.append(entity_id)
        elif entity_ids is not None:
            if not entity_ids:
                return []
            placeholders = ",".join("?" for _ in entity_ids)
            sql += f" WHERE entity_id IN ({placeholders})"
            params.extend(entity_ids)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    def close(self) -> None:
        with self._lock:
            self.conn.close()
