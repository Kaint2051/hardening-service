"""Control Registry API (Giai đoạn 1, mục 3/6/7 architecture-proposal.md).

Vai trò:
  - rule-editor/admin: tạo Control, thêm StandardMapping/RemediationVariant
    ("soạn/đề xuất control, không tự deploy").
  - approver/admin: chuyển maturity draft -> reviewed -> production
    ("duyệt thay đổi, không tự thực thi") — KHÔNG còn ràng buộc four-eyes
    (đã bị bỏ theo yêu cầu người dùng), có thể là người đã tạo chính
    Control đó.
  - Mọi role đã đăng nhập: đọc (list/get).

CHƯA làm ở lần này (để sau, không phải thiếu sót): sửa/xoá Control, workflow
approval nhiều bước/nhiều người duyệt, versioning lịch sử thay đổi.
"""
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.audit import write_audit_event
from app.auth import CurrentUser
from app.db import SessionLocal
from app.models import Control, ControlVersion, RemediationVariant, StandardMapping
from app.permissions import CONTROLS_EDIT, CONTROLS_PROMOTE, CONTROLS_VIEW
from app.rbac import require_permission
from app.schemas import (
    MATURITY_LEVELS,
    RISK_GROUPS,
    ControlCreate,
    ControlDetailOut,
    ControlLookupItem,
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

_SLUG_RE = re.compile(r"[^a-z0-9]+")

# Tiền tố cố định ComplianceAsCode/SSG gắn vào MỌI rule_id lúc xuất kết quả
# quét XCCDF (xem apps/execution-env/scan.sh — rule_id = rr.get("idref")) —
# rule_id lưu trong StandardMapping.cis_rule_id (từ tab "Template", xem
# app/control_templates.py) là phần SAU tiền tố này. Bóc tiền tố là bước
# chuẩn hoá DUY NHẤT cần để nối 2 định dạng — xem lookup_controls_by_rule.
_XCCDF_RULE_PREFIX = "xccdf_org.ssgproject.content_rule_"


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
    nghĩa "production" (phát hiện qua review, không phải test thật). Tự động
    đưa về draft buộc phải qua lại `update_control_maturity` để production
    phản ánh đúng nội dung đã duyệt.
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
    user: CurrentUser = Depends(require_permission(CONTROLS_EDIT)),
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
    _user: CurrentUser = Depends(require_permission(CONTROLS_VIEW)),
) -> list[Control]:
    return db.query(Control).order_by(Control.created_at.desc()).all()


def _has_matching_remediation_variant(
    db: Session, control_id: str, os_family: str, os_version: str | None
) -> bool:
    """Cùng logic khớp distro/version với app/jobs.py:_find_remediation_variant
    (không import thẳng — hàm đó private của module khác, và ở đây chỉ cần
    biết CÓ tồn tại hay không, không cần cả object) — ưu tiên khớp đúng
    os_version cụ thể, nếu không có thì thử bản "mọi version" (os_version
    IS NULL), và khớp os_family KHÔNG phân biệt hoa/thường.

    PHẢI khớp y hệt _find_remediation_variant: hàm này quyết định UI có hiện
    nút "Sửa lỗi này" hay không, hàm kia quyết định remediate có chạy được
    hay không. Lệch nhau = UI hứa sửa được rồi backend từ chối (hoặc ngược
    lại, giấu mất bản vá thật sự dùng được). Sửa 1 bên thì sửa cả 2.
    """
    os_family_lower = (os_family or "").lower()
    exact = (
        db.query(RemediationVariant)
        .filter(
            RemediationVariant.control_id == control_id,
            func.lower(RemediationVariant.os_family) == os_family_lower,
            RemediationVariant.os_version == os_version,
        )
        .first()
    )
    if exact is not None or os_version is None:
        return exact is not None
    return (
        db.query(RemediationVariant)
        .filter(
            RemediationVariant.control_id == control_id,
            func.lower(RemediationVariant.os_family) == os_family_lower,
            RemediationVariant.os_version.is_(None),
        )
        .first()
        is not None
    )


@router.get("/lookup", response_model=list[ControlLookupItem])
def lookup_controls_by_rule(
    rule_ids: str,
    os_family: str,
    os_version: str | None = None,
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(require_permission(CONTROLS_VIEW)),
) -> list[ControlLookupItem]:
    """Cầu nối rule_id lúc QUÉT (SCAP, dạng đầy đủ XCCDF idref) tới Control
    dùng để SỬA lỗi đó — dùng bởi trang "Kiểm tra & Khắc phục" để biết rule
    thất bại nào đã có bản vá sẵn sàng qua giao diện ("fixable"). Đọc-only,
    KHÔNG đổi gì luồng remediate hiện có — chỉ tra cứu qua
    StandardMapping.cis_rule_id (field này CHỈ được set khi tạo Control từ
    tab "Template", xem app/control_templates.py:create_control_from_template).

    `rule_ids` — chuỗi nhiều rule_id cách nhau dấu phẩy (chấp nhận CẢ 2 dạng:
    idref đầy đủ từ kết quả quét lẫn rule_id ngắn của template — bóc tiền tố
    _XCCDF_RULE_PREFIX nếu có, không có thì dùng nguyên).

    `fixable=true` CHỈ khi Control tương ứng có maturity="production" (nội
    dung đã qua duyệt approver) VÀ có RemediationVariant khớp
    os_family/os_version của host — cùng đúng 2 điều kiện
    app/jobs.py:run_remediate_apply đã enforce, tránh báo "fixable" nhầm
    cho 1 Control còn draft hoặc chưa có nội dung remediate thật nào.
    """
    requested_ids = [r.strip() for r in rule_ids.split(",") if r.strip()]
    if not requested_ids:
        raise HTTPException(status_code=422, detail="rule_ids không được rỗng")

    results: list[ControlLookupItem] = []
    for rule_id in requested_ids:
        cis_rule_id = rule_id
        if cis_rule_id.startswith(_XCCDF_RULE_PREFIX):
            cis_rule_id = cis_rule_id[len(_XCCDF_RULE_PREFIX):]

        mapping = (
            db.query(StandardMapping)
            .join(Control, Control.id == StandardMapping.control_id)
            .filter(StandardMapping.cis_rule_id == cis_rule_id, Control.maturity == "production")
            .first()
        )
        if mapping is None or not _has_matching_remediation_variant(
            db, mapping.control_id, os_family, os_version
        ):
            results.append(ControlLookupItem(rule_id=rule_id, fixable=False))
            continue

        results.append(
            ControlLookupItem(
                rule_id=rule_id,
                fixable=True,
                control_id=mapping.control_id,
                control_title=mapping.control.title,
            )
        )
    return results


@router.get("/{control_id}", response_model=ControlDetailOut)
def get_control(
    control_id: str,
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(require_permission(CONTROLS_VIEW)),
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
    _user: CurrentUser = Depends(require_permission(CONTROLS_VIEW)),
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
    user: CurrentUser = Depends(require_permission(CONTROLS_PROMOTE)),
) -> Control:
    if body.maturity not in MATURITY_LEVELS:
        raise HTTPException(status_code=422, detail=f"maturity phải là 1 trong {MATURITY_LEVELS}")

    control = db.get(Control, control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="control không tồn tại")

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
    user: CurrentUser = Depends(require_permission(CONTROLS_PROMOTE)),
) -> Control:
    if body.risk_group not in RISK_GROUPS:
        raise HTTPException(status_code=422, detail=f"risk_group phải là 1 trong {RISK_GROUPS}")

    control = db.get(Control, control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="control không tồn tại")

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
    user: CurrentUser = Depends(require_permission(CONTROLS_EDIT)),
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
    user: CurrentUser = Depends(require_permission(CONTROLS_EDIT)),
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
