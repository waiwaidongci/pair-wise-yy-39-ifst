from __future__ import annotations

from typing import Any, Dict, List, Optional

from .domain import (ConflictError, NotFoundError, PermissionDenied,
                     ValidationError, ensure_role, normalize_severity,
                     require_number, require_text)
from .repository import Repository
from .rules import (ADMIN_ROLE, AUDIT_ROLES, CREATE_ROLES, ENTITY, RECORD_ROLES,
                    VIEW_ROLES, completion_blockers, escalation_required,
                    priority_score, response_deadline_hours, role_for_transition,
                    validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    # ---------- 身份与归属 ----------
    @staticmethod
    def _is_admin(role: str) -> bool:
        return role == ADMIN_ROLE

    def _require_office(self, role: str, office: str) -> str:
        """非管理员必须带管理处标识；管理员不归属具体管理处。"""
        office = (office or "").strip()
        if self._is_admin(role):
            return office
        if not office:
            raise PermissionDenied("缺少管理处标识(X-Office)")
        return office

    def _can_access(self, item: Dict[str, Any], role: str, office: str) -> bool:
        """读权限：本处条目；或本处创建但尚未认领的条目（原创建人所在处可见）。"""
        if self._is_admin(role):
            return item["office"] is None
        return item["office"] == office or (
            item["office"] is None and item["created_office"] == office
        )

    def _get_accessible(self, item_id: int, role: str, office: str) -> Dict[str, Any]:
        item = self.repository.get_item(item_id)
        if not self._can_access(item, role, office):
            raise PermissionDenied("无权访问其他管理处的数据")
        return item

    def _require_owner(self, item: Dict[str, Any], role: str, office: str) -> None:
        """写/审批权限：仅归属管理处；未认领条目在认领前保持原状态，不得流转或追加记录。"""
        if self._is_admin(role) or item["office"] != office:
            raise PermissionDenied("仅归属管理处可执行该操作")

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES | {ADMIN_ROLE})

    # ---------- 用例 ----------
    def create_item(self, payload: Dict[str, Any], actor: str, role: str,
                    office: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        office = self._require_office(role, office)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        dam_section = require_text(payload.get("dam_section"), "dam_section", 100)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        # 归属由坝段映射表决定；映射不到则暂未认领，仅原创建人所在处可指定负责人。
        mapped_office = self.repository.get_mapping(dam_section)
        item = self.repository.create_item(
            title, description, severity, quantity, threshold, external_ref, actor,
            dam_section, mapped_office, office,
        )
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "dam_section": dam_section, "office": mapped_office,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str, office: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        office = self._require_office(role, office)
        actor = require_text(actor, "actor", 100)
        item = self._get_accessible(item_id, role, office)
        self._require_owner(item, role, office)
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
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str, office: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        office = self._require_office(role, office)
        item = self._get_accessible(item_id, role, office)
        self._require_owner(item, role, office)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValidationError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str, office: str) -> Dict[str, Any]:
        self._view(role)
        office = self._require_office(role, office)
        item = self._get_accessible(item_id, role, office)
        return self.enrich(item)

    def list_items(self, role: str, office: str,
                   status: Optional[str] = None) -> List[Dict[str, Any]]:
        self._view(role)
        office = self._require_office(role, office)
        if self._is_admin(role):
            items = self.repository.list_items(status=status, unclaimed_only=True)
        else:
            items = self.repository.list_items(status=status, office=office)
        return [self.enrich(item) for item in items]

    def list_records(self, item_id: int, role: str, office: str) -> List[Dict[str, Any]]:
        self._view(role)
        office = self._require_office(role, office)
        self._get_accessible(item_id, role, office)
        return self.repository.list_records(item_id)

    def audit(self, role: str, office: str,
              item_id: Optional[int] = None) -> List[Dict[str, Any]]:
        ensure_role(role, AUDIT_ROLES | {ADMIN_ROLE})
        office = self._require_office(role, office)
        if item_id is not None:
            self._get_accessible(item_id, role, office)
            return self.repository.list_audit(entity_id=item_id)
        if self._is_admin(role):
            scope = self.repository.list_items(unclaimed_only=True)
        else:
            scope = self.repository.list_items(office=office)
        accessible_ids = [item["id"] for item in scope]
        return self.repository.list_audit(entity_ids=accessible_ids)

    # ---------- 管理员：坝段映射表 ----------
    def set_mapping(self, dam_section: str, mapped_office: str,
                    actor: str, role: str) -> Dict[str, str]:
        ensure_role(role, {ADMIN_ROLE})
        actor = require_text(actor, "actor", 100)
        dam_section = require_text(dam_section, "dam_section", 100)
        mapped_office = require_text(mapped_office, "office", 100)
        self.repository.set_mapping(dam_section, mapped_office)
        return {"dam_section": dam_section, "office": mapped_office}

    def list_mappings(self, actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, {ADMIN_ROLE})
        return {"mappings": self.repository.list_mappings()}

    # ---------- 管理员：回填与认领 ----------
    def backfill(self, actor: str, role: str) -> Dict[str, Any]:
        """用坝段映射表为历史无归属缺陷回填管理处。

        仅处理仍无归属(office IS NULL)的条目；映射不到的保持未认领，
        不默认对所有人开放。每条认领与审计同事务。
        """
        ensure_role(role, {ADMIN_ROLE})
        actor = require_text(actor, "actor", 100)
        unclaimed = self.repository.list_items(unclaimed_only=True)
        backfilled: List[Dict[str, Any]] = []
        remaining = 0
        for item in unclaimed:
            mapped = self.repository.get_mapping(item["dam_section"])
            if mapped is None:
                remaining += 1
                continue
            ok = self.repository.claim_with_audit(
                item["id"], mapped, actor,
                {"dam_section": item["dam_section"], "office": mapped, "via": "backfill"},
            )
            if ok:
                backfilled.append({"item_id": item["id"], "office": mapped})
            else:
                remaining += 1  # 已被他人认领，下一轮再处理
        return {"backfilled": backfilled, "remaining": remaining}

    def claim_item(self, item_id: int, actor: str, role: str) -> Dict[str, Any]:
        """认领单个历史缺陷。并发认领只接受先到的一次；认领失败不改变条目状态。

        归属一律取自坝段映射表（与认领人所在处无关），重试沿用同一映射结果。
        """
        ensure_role(role, {ADMIN_ROLE})
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        if item["office"] is not None:
            raise ConflictError("该缺陷已被认领")
        mapped = self.repository.get_mapping(item["dam_section"])
        if mapped is None:
            raise ValidationError("该坝段无法映射到管理处，无法认领")
        ok = self.repository.claim_with_audit(
            item_id, mapped, actor,
            {"dam_section": item["dam_section"], "office": mapped, "via": "claim"},
        )
        if not ok:
            raise ConflictError("认领失败，该缺陷已被其他管理员认领")
        return self.enrich(self.repository.get_item(item_id))

    # ---------- 指定负责人 ----------
    def designate_assignee(self, item_id: int, assignee: str, actor: str,
                           role: str, office: str) -> Dict[str, Any]:
        """指定负责人：归属管理处可指定；无法映射的未认领条目仅原创建人所在处可指定。"""
        office = self._require_office(role, office)
        actor = require_text(actor, "actor", 100)
        assignee = require_text(assignee, "assignee", 100)
        item = self._get_accessible(item_id, role, office)
        if self._is_admin(role):
            raise PermissionDenied("管理员不能指定负责人")
        is_owner = item["office"] == office
        is_creator_office = item["office"] is None and item["created_office"] == office
        if not (is_owner or is_creator_office):
            raise PermissionDenied("仅归属管理处或原创建人所在处可指定负责人")
        ok = self.repository.designate_with_audit(
            item_id, assignee, actor, {"assignee": assignee},
        )
        if not ok:
            raise NotFoundError("项目不存在")
        return self.enrich(self.repository.get_item(item_id))

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
