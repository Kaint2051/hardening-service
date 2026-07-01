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
from sqlalchemy.orm import Session, joinedload

from app.auth import CurrentUser, require_roles
from app.db import SessionLocal
from app.models import Control, RemediationVariant, StandardMapping
from app.schemas import (
    MATURITY_LEVELS,
    ControlCreate,
    ControlDetailOut,
    ControlMaturityUpdate,
    ControlOut,
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
    db.commit()
    db.refresh(control)
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

    control.maturity = body.maturity
    control.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(control)
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
    _user: CurrentUser = Depends(require_roles(*_EDITOR_ROLES)),
) -> StandardMapping:
    if db.get(Control, control_id) is None:
        raise HTTPException(status_code=404, detail="control không tồn tại")
    mapping = StandardMapping(control_id=control_id, **body.model_dump())
    db.add(mapping)
    db.commit()
    db.refresh(mapping)
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
    _user: CurrentUser = Depends(require_roles(*_EDITOR_ROLES)),
) -> RemediationVariant:
    if db.get(Control, control_id) is None:
        raise HTTPException(status_code=404, detail="control không tồn tại")
    variant = RemediationVariant(control_id=control_id, **body.model_dump())
    db.add(variant)
    db.commit()
    db.refresh(variant)
    return variant
