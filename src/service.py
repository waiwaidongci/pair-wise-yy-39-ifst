from __future__ import annotations

from typing import Any, Dict, List, Optional

from .domain import (ConflictError, PermissionDenied, ValidationError,
                     ensure_role, normalize_severity, require_number,
                     require_office, require_text)
from .repository import Repository
from .rules import (ADMIN_ROLE, AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES,
                    VIEW_ROLES, completion_blockers, escalation_required,
                    priority_score, response_deadline_hours, role_for_transition,
                    validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    # ---------- 基础校验 ----------

    @staticmethod
    def _admin(role: str) -> None:
        ensure_role(role, {ADMIN_ROLE})

    def _scoped_item(self, item_id: int, office: str) -> Dict[str, Any]:
        """只认本处数据：跨处或未认领缺陷对业务角色一律拒绝。"""
        item = self.repository.get_item(item_id)
        if item["office_id"] is None or item["office_id"] != office:
            raise PermissionDenied("拒绝访问非本处数据")
        return item

    def _view_item(self, item_id: int, office: str, role: str) -> Dict[str, Any]:
        ensure_role(role, VIEW_ROLES)
        return self._scoped_item(item_id, office)

    # ---------- 缺陷业务 ----------

    def create_item(self, payload: Dict[str, Any], actor: str, role: str,
                    office: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        office = require_office(office)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        section = require_text(payload.get("section"), "section", 100)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        # 巡检员归属其请求所在处；已登记到别处的身份不能在本处建档
        known = self.repository.get_actor_office(actor)
        if known is not None and known["office_id"] != office:
            raise PermissionDenied("该巡检员已归属其他管理处")
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor, office, section)
        self.repository.upsert_actor_office(actor, office, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "section": section, "office": office,
            "priority": priority_score(severity, quantity, threshold),
        }, office)
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str, office: str) -> Dict[str, Any]:
        office = require_office(office)
        item = self._scoped_item(item_id, office)
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValidationError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        }, office)
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str, office: str) -> Dict[str, Any]:
        office = require_office(office)
        actor = require_text(actor, "actor", 100)
        item = self._scoped_item(item_id, office)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or isinstance(expected_version, bool) \
                or expected_version < 1:
            raise ValidationError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        }, office)
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str, office: str) -> Dict[str, Any]:
        office = require_office(office)
        item = self._view_item(item_id, office, role)
        return self.enrich(item)

    def list_items(self, role: str, office: str,
                   status: Optional[str] = None) -> list:
        office = require_office(office)
        ensure_role(role, VIEW_ROLES)
        return [self.enrich(item)
                for item in self.repository.list_items(office, status)]

    def list_records(self, item_id: int, role: str, office: str) -> list:
        office = require_office(office)
        self._view_item(item_id, office, role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, office: str, item_id: Optional[int] = None) -> list:
        office = require_office(office)
        ensure_role(role, AUDIT_ROLES)
        if item_id is not None:
            # 不允许借审计接口读别处缺陷：先验归属再出审计
            self._scoped_item(item_id, office)
        return self.repository.list_audit(office, item_id)

    # ---------- 管理员：映射、花名册、回填、认领 ----------

    def register_section(self, payload: Dict[str, Any], actor: str, role: str,
                         office: str) -> Dict[str, Any]:
        office = require_office(office)
        self._admin(role)
        actor = require_text(actor, "actor", 100)
        section = require_text(payload.get("section"), "section", 100)
        return self.repository.upsert_section_mapping(section, office, actor)

    def list_sections(self, actor: str, role: str, office: str) -> list:
        office = require_office(office)
        self._admin(role)
        del actor
        return self.repository.list_section_mappings(office)

    def register_actor_office(self, payload: Dict[str, Any], actor: str, role: str,
                              office: str) -> Dict[str, Any]:
        office = require_office(office)
        self._admin(role)
        actor = require_text(actor, "actor", 100)
        target_actor = require_text(payload.get("actor"), "actor", 100)
        target_office = require_text(payload.get("office_id"), "office_id", 100)
        if target_office != office:
            raise PermissionDenied("只能登记巡检员到本管理处")
        return self.repository.upsert_actor_office(target_actor, target_office, actor)

    def list_unclaimed(self, actor: str, role: str, office: str) -> list:
        """未认领历史缺陷只对管理员可见，并给出可沿用的归属解析结果。

        预览只提示解析指向的管理处，不在这里拦截；真正认领时再强制拒绝跨处。
        """
        office = require_office(office)
        self._admin(role)
        del actor
        result = []
        for item in self.repository.list_unclaimed_items():
            enriched = self.enrich(item)
            enriched["claim_resolution"] = self._resolve_claim(item, office)
            result.append(enriched)
        return result

    def backfill(self, payload: Dict[str, Any], actor: str, role: str,
                 office: str) -> Dict[str, Any]:
        """按坝段映射表批量回填；只能把缺陷回填到本处，无法映射的保持未认领。"""
        office = require_office(office)
        self._admin(role)
        actor = require_text(actor, "actor", 100)
        wanted = payload.get("item_ids")
        if wanted is not None and not isinstance(wanted, list):
            raise ValidationError("item_ids必须是数组")
        assigned: List[Dict[str, Any]] = []
        skipped: List[Dict[str, Any]] = []
        for item in self.repository.list_unclaimed_items():
            if wanted is not None and item["id"] not in wanted:
                continue
            section = item["section"]
            mapping = None
            if section:
                mapping = self.repository.get_section_mapping(section)
            if mapping is None:
                skipped.append({"id": item["id"],
                                "reason": "坝段无映射，保持未认领"})
                continue
            if mapping["office_id"] != office:
                skipped.append({"id": item["id"],
                                "reason": "坝段映射归属其他管理处"})
                continue
            try:
                claimed = self.repository.claim_item(
                    item["id"], office, None, actor, "section_mapping", section)
            except ConflictError:
                # 并发回填/认领下先到者为准
                skipped.append({"id": item["id"], "reason": "已被认领"})
                continue
            assigned.append({"id": claimed["id"], "office": office,
                             "section": section})
        return {"assigned": assigned, "skipped": skipped}

    def claim_legacy(self, item_id: int, payload: Dict[str, Any], actor: str,
                     role: str, office: str) -> Dict[str, Any]:
        """认领无法回填的历史缺陷并指定负责人，只接受先到的一次。"""
        office = require_office(office)
        self._admin(role)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        if item["office_id"] is not None:
            if item["office_id"] != office:
                raise PermissionDenied("拒绝访问非本处数据")
            raise ConflictError("该历史缺陷已被认领")
        resolution = self._authorize_claim(item, office)
        owner = require_text(payload.get("owner"), "owner", 100)
        claimed = self.repository.claim_item(
            item_id, office, owner, actor,
            resolution["source"], resolution.get("mapped_section"))
        return self.enrich(claimed)

    def assign_owner(self, item_id: int, payload: Dict[str, Any], actor: str,
                     role: str, office: str) -> Dict[str, Any]:
        """本处内负责人变更：归属校验后，负责人写入与审计同事务提交。"""
        office = require_office(office)
        self._admin(role)
        actor = require_text(actor, "actor", 100)
        item = self._scoped_item(item_id, office)
        owner = require_text(payload.get("owner"), "owner", 100)
        self.repository.change_owner(item_id, owner, actor, office,
                                     item.get("owner"))
        return self.enrich(self.repository.get_item(item_id))

    def _resolve_claim(self, item: Dict[str, Any], office: str) -> Dict[str, Any]:
        """归属解析（纯查询，不拦截）：坝段映射优先，其次创建人花名册所在处。

        映射与花名册均不可变，故认领失败后重试沿用同一解析结果。
        """
        section = item["section"]
        mapping = self.repository.get_section_mapping(section) if section else None
        if mapping is not None:
            return {"source": "section_mapping", "mapped_section": section,
                    "mapped_office": mapping["office_id"],
                    "claimable_here": mapping["office_id"] == office,
                    "owner_required": False}
        roster = self.repository.get_actor_office(item["created_by"])
        if roster is not None:
            return {"source": "creator_office", "mapped_section": None,
                    "mapped_office": roster["office_id"],
                    "claimable_here": roster["office_id"] == office,
                    "owner_required": True}
        return {"source": None, "mapped_section": None, "mapped_office": None,
                "claimable_here": False, "owner_required": True}

    def _authorize_claim(self, item: Dict[str, Any], office: str) -> Dict[str, Any]:
        """认领时强制授权：跨处一律拒绝；无映射且创建人无归属处则无法指定负责人。"""
        resolution = self._resolve_claim(item, office)
        if resolution["source"] is None:
            raise ValidationError("坝段无映射且创建人未登记归属处，无法指定负责人")
        if not resolution["claimable_here"]:
            if resolution["source"] == "section_mapping":
                raise PermissionDenied("该坝段映射归属其他管理处，拒绝跨处认领")
            raise PermissionDenied("只能由原创建人所在管理处认领")
        return resolution

    # ---------- 视图增强 ----------

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        result["claimed"] = item["office_id"] is not None
        return result
