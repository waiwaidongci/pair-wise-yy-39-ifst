from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ENTITY, STATES


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
                    office_id TEXT,
                    section TEXT,
                    owner TEXT
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
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
                    created_at TEXT NOT NULL,
                    office_id TEXT
                );
                CREATE TABLE IF NOT EXISTS section_mappings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    section TEXT NOT NULL UNIQUE,
                    office_id TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS actor_offices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor TEXT NOT NULL UNIQUE,
                    office_id TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            self._migrate_columns()

    def _migrate_columns(self) -> None:
        # 旧库回填：历史数据 office_id 保持 NULL，即未认领，不默认开放
        existing = {
            row["name"] for row in self.conn.execute("PRAGMA table_info(items)")
        }
        for column, declaration in (
            ("office_id", "TEXT"),
            ("section", "TEXT"),
            ("owner", "TEXT"),
        ):
            if column not in existing:
                self.conn.execute(f"ALTER TABLE items ADD COLUMN {column} {declaration}")
        audit_columns = {
            row["name"] for row in self.conn.execute("PRAGMA table_info(audit_events)")
        }
        if "office_id" not in audit_columns:
            self.conn.execute("ALTER TABLE audit_events ADD COLUMN office_id TEXT")
        # 归属列就绪后再建索引（兼容旧库升级）
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_items_office ON items(office_id)")
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS ix_audit_office ON audit_events(office_id, entity_id)")

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ---------- 坝段映射与人员归属花名册 ----------

    def upsert_section_mapping(self, section: str, office: str, actor: str) -> Dict[str, Any]:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT * FROM section_mappings WHERE section=?", (section,)
            ).fetchone()
            if row is not None:
                if row["office_id"] != office:
                    raise ConflictError("坝段已映射到其他管理处，映射不可修改")
                return dict(row)
            now = utc_now()
            try:
                cur = self.conn.execute(
                    """INSERT INTO section_mappings(section, office_id, created_by, created_at)
                       VALUES(?,?,?,?)""",
                    (section, office, actor, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("坝段已映射到其他管理处，映射不可修改") from exc
            row = self.conn.execute(
                "SELECT * FROM section_mappings WHERE id=?", (int(cur.lastrowid),)
            ).fetchone()
            return dict(row)

    def get_section_mapping(self, section: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM section_mappings WHERE section=?", (section,)
            ).fetchone()
        return dict(row) if row else None

    def list_section_mappings(self, office: str) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM section_mappings WHERE office_id=? ORDER BY section",
                (office,),
            ).fetchall()
        return [dict(row) for row in rows]

    def upsert_actor_office(self, actor: str, office: str, registrar: str) -> Dict[str, Any]:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT * FROM actor_offices WHERE actor=?", (actor,)
            ).fetchone()
            if row is not None:
                if row["office_id"] != office:
                    raise ConflictError("该人员已归属其他管理处")
                return dict(row)
            now = utc_now()
            try:
                cur = self.conn.execute(
                    """INSERT INTO actor_offices(actor, office_id, created_by, created_at)
                       VALUES(?,?,?,?)""",
                    (actor, office, registrar, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("该人员已归属其他管理处") from exc
            row = self.conn.execute(
                "SELECT * FROM actor_offices WHERE id=?", (int(cur.lastrowid),)
            ).fetchone()
            return dict(row)

    def get_actor_office(self, actor: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM actor_offices WHERE actor=?", (actor,)
            ).fetchone()
        return dict(row) if row else None

    # ---------- 缺陷 ----------

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str, office: str, section: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at,
                       office_id, section, owner)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now, office, section, None),
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

    def list_items(self, office: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items WHERE office_id=?"
        params: tuple = (office,)
        if status:
            sql += " AND status=?"
            params = (office, status)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def list_unclaimed_items(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM items WHERE office_id IS NULL ORDER BY id"
            ).fetchall()
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

    # ---------- 历史缺陷认领：归属变更与审计同一事务 ----------

    def _append_audit_locked(self, action: str, entity_type: str, entity_id: int,
                             actor: str, detail: dict,
                             office: Optional[str]) -> int:
        # 调用方必须已持有 self._lock 并处于 self.conn 事务中
        row = self.conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = row["entry_hash"] if row else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous)
        cur = self.conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at, office_id)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"], office),
        )
        return int(cur.lastrowid)

    def claim_item(self, item_id: int, office: str, owner: Optional[str],
                   actor: str, source: str, mapped_section: Optional[str]) -> Dict[str, Any]:
        """条件更新认领历史缺陷。只接受先到的一次；status/version 不动。

        归属写入、该缺陷历史审计归属补齐、认领审计在同一事务中提交。
        """
        now = utc_now()
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT id, office_id FROM items WHERE id=?", (item_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("项目不存在")
            if row["office_id"] is not None:
                raise ConflictError("该历史缺陷已被认领")
            if owner is not None:
                cur = self.conn.execute(
                    """UPDATE items SET office_id=?, owner=?, updated_at=?
                       WHERE id=? AND office_id IS NULL""",
                    (office, owner, now, item_id),
                )
            else:
                cur = self.conn.execute(
                    """UPDATE items SET office_id=?, updated_at=?
                       WHERE id=? AND office_id IS NULL""",
                    (office, now, item_id),
                )
            if cur.rowcount == 0:
                # 并发下另一名管理员先到
                raise ConflictError("该历史缺陷已被认领")
            self._append_audit_locked("claim", ENTITY, item_id, actor, {
                "office": office, "owner": owner, "source": source,
                "mapped_section": mapped_section,
            }, office)
            self.conn.execute(
                """UPDATE audit_events SET office_id=?
                   WHERE entity_type=? AND entity_id=? AND office_id IS NULL""",
                (office, ENTITY, item_id),
            )
        return self.get_item(item_id)

    def change_owner(self, item_id: int, owner: str, actor: str, office: str,
                     previous_owner: Optional[str]) -> None:
        """负责人变更与审计必须同事务，绝不只写一半。"""
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE items SET owner=?, updated_at=? WHERE id=? AND office_id=?",
                (owner, utc_now(), item_id, office),
            )
            self._append_audit_locked("assign_owner", ENTITY, item_id, actor, {
                "previous_owner": previous_owner, "owner": owner, "office": office,
            }, office)

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

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict, office: str) -> Dict[str, Any]:
        with self._lock, self.conn:
            event_id = self._append_audit_locked(
                action, entity_type, entity_id, actor, detail, office)
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM audit_events WHERE id=?", (event_id,)).fetchone()
        event = dict(row)
        event["detail"] = json.loads(event["detail"])
        return event

    def list_audit(self, office: str, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events WHERE office_id=?"
        params: tuple = (office,)
        if entity_id is not None:
            sql += " AND entity_id=?"
            params = (office, entity_id)
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
