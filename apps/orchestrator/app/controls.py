"""Control Registry API (Giai đoạn 1, mục 3/6/7 architecture-proposal.md).

Vai trò:
  - rule-editor/admin: tạo Control, thêm StandardMapping/RemediationVariant
    ("soạn/đề xuất control, không tự deploy").
  - approver/admin: chuyển maturity draft -> reviewed -> production
    ("duyệt thay đổi, không tự thực thi") — KHÔNG được là người đã tạo
    chính Control đó (four-eyes, xem ràng buộc role "admin" trong
    infra/keycloak/realm-export.json).
  - Mọi role đã đăng nhập: đọc (list/get).

CHƯA làm ở lần này (để sau, không phải thiếu sót): sửa/xoá Control, workflow
approval nhiều bước/nhiều người duyệt, versioning lịch sử thay đổi.
"""
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.audit import write_audit_event
from app.auth import CurrentUser, require_roles
from app.db import SessionLocal
from app.models import Control, ControlVersion, RemediationVariant, StandardMapping
from app.schemas import (
    MATURITY_LEVELS,
    RISK_GROUPS,
    ControlCreate,
    ControlDetailOut,
    ControlMaturityUpdate,
    ControlOut,
    ControlRiskGroupUpdate,
    ControlVersionOut,
    RemediationVariantCreate,
    RemediationVariantOut,
    StandardMappingCreate,
    StandardMappingOut,
)

router = APIRouter(prefix="/controls", tags=["control-registry"])

_ALL_ROLES = ("viewer", "auditor", "rule-editor", "approver", "operator", "admin")
_EDITOR_ROLES = ("rule-editor", "admin")
_APPROVER_ROLES = ("approver", "admin")

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _slugify(title: str) -> str:
    slug = _SLUG_RE.sub("-", title.strip().lower()).strip("-")
    if not slug:
        raise HTTPException(status_code=422, detail="title không tạo được id hợp lệ")
    return slug


def _unique_control_id(db: Session, base_slug: str) -> str:
    candidate = base_slug
    suffix = 2
    while db.get(Control, candidate) is not None:
        candidate = f"{base_slug}-{suffix}"
        suffix += 1
    return candidate


def _demote_if_production(control: Control, db: Session, actor: str) -> None:
    """Thêm/sửa StandardMapping hay RemediationVariant của 1 control đã
    maturity="production" mà không đưa control về "draft" nghĩa là người tạo
    ban đầu (chỉ cần role rule-editor, không cần approver) có thể tự ý đổi
    nội dung kỹ thuật thật (remediation_ref — thứ Agent Active Response tin
    tưởng thực thi) SAU KHI đã được approver duyệt, mà maturity vẫn hiển thị
    "production" như thể nội dung đó đã được review — bypass hoàn toàn ý
    nghĩa four-eyes của maturity (phát hiện qua review, không phải test
    thật). Tự động đưa về draft buộc phải qua lại `update_control_maturity`
    (đã có four-eyes) để production phản ánh đúng nội dung đã duyệt.
    """
    if control.maturity != "production":
        return
    previous = control.maturity
    control.maturity = "draft"
    control.updated_at = datetime.now(timezone.utc)
    detail = {"reason": "content_changed_after_production"}
    payload = {"from": previous, "to": "draft", "reason": "content_changed_after_production"}
    # risk_group="A" chỉ hợp lệ khi maturity="production" (xem
    # update_control_risk_group) — control vừa bị demote về "draft" ở đây thì
    # risk_group="A" (nếu có) phải reset theo, giữ trong CÙNG ControlVersion/
    # audit event thay vì bắn thêm 1 event song song (theo quyết định thiết
    # kế: 1 lần content-change-after-production chỉ nên là 1 sự kiện lịch sử).
    if control.risk_group == "A":
        control.risk_group = "B"
        detail["risk_group_reset"] = True
        payload["risk_group_reset"] = True
    db.add(
        ControlVersion(
            control_id=control.id,
            event_type="maturity_changed",
            actor=actor,
            from_maturity=previous,
            to_maturity="draft",
            detail=detail,
        )
    )
    db.commit()
    write_audit_event(
        actor=actor,
        action="control_maturity_updated",
        resource=control.id,
        payload=payload,
    )


@router.post("", response_model=ControlOut, status_code=status.HTTP_201_CREATED)
def create_control(
    body: ControlCreate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_EDITOR_ROLES)),
) -> Control:
    control_id = _unique_control_id(db, _slugify(body.title))
    control = Control(
        id=control_id,
        title=body.title,
        description=body.description,
        category=body.category,
        maturity="draft",
        created_by=user.username,
    )
    db.add(control)
    db.add(
        ControlVersion(
            control_id=control_id,
            event_type="created",
            actor=user.username,
            to_maturity="draft",
            detail={"title": body.title, "category": body.category},
        )
    )
    db.commit()
    db.refresh(control)

    write_audit_event(
        actor=user.username,
        action="control_created",
        resource=control_id,
        payload={"title": body.title, "category": body.category},
    )
    return control


@router.get("", response_model=list[ControlOut])
def list_controls(
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(require_roles(*_ALL_ROLES)),
) -> list[Control]:
    return db.query(Control).order_by(Control.created_at.desc()).all()


@router.get("/{control_id}", response_model=ControlDetailOut)
def get_control(
    control_id: str,
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(require_roles(*_ALL_ROLES)),
) -> Control:
    control = db.get(
        Control,
        control_id,
        options=[joinedload(Control.standard_mappings), joinedload(Control.remediation_variants)],
    )
    if control is None:
        raise HTTPException(status_code=404, detail="control không tồn tại")
    return control


@router.get("/{control_id}/history", response_model=list[ControlVersionOut])
def get_control_history(
    control_id: str,
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(require_roles(*_ALL_ROLES)),
) -> list[ControlVersion]:
    if db.get(Control, control_id) is None:
        raise HTTPException(status_code=404, detail="control không tồn tại")
    return (
        db.query(ControlVersion)
        .filter(ControlVersion.control_id == control_id)
        .order_by(ControlVersion.id.asc())
        .all()
    )


@router.patch("/{control_id}/maturity", response_model=ControlOut)
def update_control_maturity(
    control_id: str,
    body: ControlMaturityUpdate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_APPROVER_ROLES)),
) -> Control:
    if body.maturity not in MATURITY_LEVELS:
        raise HTTPException(status_code=422, detail=f"maturity phải là 1 trong {MATURITY_LEVELS}")

    control = db.get(Control, control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="control không tồn tại")

    # Four-eyes: người duyệt không được là người đã tạo/đề xuất chính control này
    # (ràng buộc nêu ở mô tả role "admin" trong realm-export.json — enforce ở
    # tầng application vì Keycloak không tự kiểm tra được điều này).
    if control.created_by == user.username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="không được tự duyệt thay đổi của chính mình (four-eyes)",
        )

    previous_maturity = control.maturity
    control.maturity = body.maturity
    control.updated_at = datetime.now(timezone.utc)
    detail = None
    payload = {"from": previous_maturity, "to": body.maturity}
    # risk_group="A" chỉ hợp lệ khi maturity="production" — approver đổi
    # maturity ra khỏi "production" theo BẤT KỲ hướng nào (hàm này không
    # enforce forward-only, có thể nhảy thẳng production -> draft) thì
    # risk_group="A" (nếu có) phải tự reset về "B" theo, ghi trong CÙNG
    # ControlVersion/audit event này thay vì bắn thêm 1 event song song.
    if control.risk_group == "A" and body.maturity != "production":
        control.risk_group = "B"
        detail = {"risk_group_reset": True}
        payload["risk_group_reset"] = True
    db.add(
        ControlVersion(
            control_id=control_id,
            event_type="maturity_changed",
            actor=user.username,
            from_maturity=previous_maturity,
            to_maturity=body.maturity,
            detail=detail,
        )
    )
    db.commit()
    db.refresh(control)

    write_audit_event(
        actor=user.username,
        action="control_maturity_updated",
        resource=control_id,
        payload=payload,
    )
    return control


@router.patch("/{control_id}/risk-group", response_model=ControlOut)
def update_control_risk_group(
    control_id: str,
    body: ControlRiskGroupUpdate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_APPROVER_ROLES)),
) -> Control:
    if body.risk_group not in RISK_GROUPS:
        raise HTTPException(status_code=422, detail=f"risk_group phải là 1 trong {RISK_GROUPS}")

    control = db.get(Control, control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="control không tồn tại")

    # Four-eyes: giống hệt update_control_maturity — người phân loại
    # risk_group không được là người đã tạo/đề xuất chính control này.
    if control.created_by == user.username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="không được tự duyệt thay đổi của chính mình (four-eyes)",
        )

    # risk_group="A" (đủ điều kiện canary rollout tự động) chỉ có ý nghĩa cho
    # control đã qua đủ vòng duyệt production — chặn gán "A" sớm cho control
    # draft/reviewed (xem app/canary.py: canary rollout yêu cầu đúng risk_group
    # "A" + maturity "production").
    if body.risk_group == "A" and control.maturity != "production":
        raise HTTPException(
            status_code=422,
            detail="phải đưa control lên maturity production trước khi phân loại Nhóm A",
        )

    previous_risk_group = control.risk_group
    control.risk_group = body.risk_group
    control.updated_at = datetime.now(timezone.utc)
    db.add(
        ControlVersion(
            control_id=control_id,
            event_type="risk_group_changed",
            actor=user.username,
            detail={"from": previous_risk_group, "to": body.risk_group},
        )
    )
    db.commit()
    db.refresh(control)

    write_audit_event(
        actor=user.username,
        action="control_risk_group_updated",
        resource=control_id,
        payload={"from": previous_risk_group, "to": body.risk_group},
    )
    return control


@router.post(
    "/{control_id}/standard-mappings",
    response_model=StandardMappingOut,
    status_code=status.HTTP_201_CREATED,
)
def add_standard_mapping(
    control_id: str,
    body: StandardMappingCreate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_EDITOR_ROLES)),
) -> StandardMapping:
    control = db.get(Control, control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="control không tồn tại")
    mapping = StandardMapping(control_id=control_id, **body.model_dump())
    db.add(mapping)
    db.add(
        ControlVersion(
            control_id=control_id,
            event_type="standard_mapping_added",
            actor=user.username,
            detail={
                "standard": body.standard,
                "standard_version": body.standard_version,
                "section_id": body.section_id,
            },
        )
    )
    try:
        db.commit()
    except IntegrityError:
        # uq_standard_mapping (control_id, standard, standard_version,
        # section_id) trước đây không được bắt -> lộ nguyên IntegrityError
        # thành 500 thay vì 409 (phát hiện qua test thật, không phải chỉ đọc
        # code — xem README).
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="standard mapping này (standard/standard_version/section_id) đã tồn tại cho control này",
        )
    db.refresh(mapping)

    write_audit_event(
        actor=user.username,
        action="standard_mapping_added",
        resource=control_id,
        payload={
            "standard": body.standard,
            "standard_version": body.standard_version,
            "section_id": body.section_id,
        },
    )
    _demote_if_production(control, db, user.username)
    return mapping


@router.post(
    "/{control_id}/remediation-variants",
    response_model=RemediationVariantOut,
    status_code=status.HTTP_201_CREATED,
)
def add_remediation_variant(
    control_id: str,
    body: RemediationVariantCreate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_EDITOR_ROLES)),
) -> RemediationVariant:
    control = db.get(Control, control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="control không tồn tại")
    variant = RemediationVariant(control_id=control_id, **body.model_dump())
    db.add(variant)
    db.add(
        ControlVersion(
            control_id=control_id,
            event_type="remediation_variant_added",
            actor=user.username,
            detail={
                "os_family": body.os_family,
                "os_version": body.os_version,
                "remediation_ref": body.remediation_ref,
            },
        )
    )
    try:
        db.commit()
    except IntegrityError:
        # uq_remediation_variant (control_id, os_family, os_version) trước
        # đây không được bắt -> lộ nguyên IntegrityError thành 500 thay vì
        # 409 (phát hiện qua test thật, không phải chỉ đọc code — xem README).
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="remediation variant này (os_family/os_version) đã tồn tại cho control này",
        )
    db.refresh(variant)

    write_audit_event(
        actor=user.username,
        action="remediation_variant_added",
        resource=control_id,
        payload={
            "os_family": body.os_family,
            "os_version": body.os_version,
            "remediation_ref": body.remediation_ref,
        },
    )
    _demote_if_production(control, db, user.username)
    return variant
