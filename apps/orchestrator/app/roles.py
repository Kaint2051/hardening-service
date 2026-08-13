"""Quản lý RBAC tuỳ biến — tạo/sửa/xoá vai trò + ma trận quyền. Toàn bộ
admin-only qua require_permission(RBAC_MANAGE), TRỪ GET /me/permissions (mở
cho mọi user đã đăng nhập — xem docstring riêng bên dưới).

Permission tự nó luôn cố định trong code (app/permissions.py) — router này
CHỈ cho sửa MA TRẬN role -> permission và tạo/xoá role, không cho "phát
minh" permission mới qua API.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.audit import write_audit_event
from app.auth import CurrentUser, get_current_user
from app.db import SessionLocal
from app.models import AppRole, RolePermission, UserRoleAssignment
from app.permissions import ALL_PERMISSIONS, PERMISSION_DESCRIPTIONS, RBAC_MANAGE
from app.rbac import (
    RbacInvariantError,
    check_admin_keeps_rbac_manage,
    check_caller_keeps_permission,
    require_permission,
    resolve_permissions,
)
from app.schemas import PermissionOut, RoleCreate, RoleOut, RolePermissionsUpdate

router = APIRouter(tags=["rbac"])


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _role_out(role: AppRole, permissions: list[str]) -> dict:
    return {
        "name": role.name,
        "is_builtin": role.is_builtin,
        "description": role.description,
        "permissions": sorted(permissions),
    }


@router.get("/permissions", response_model=list[PermissionOut])
def list_permissions(_user: CurrentUser = Depends(require_permission(RBAC_MANAGE))) -> list[dict]:
    return [{"permission": p, "description": PERMISSION_DESCRIPTIONS[p]} for p in sorted(ALL_PERMISSIONS)]


@router.get("/roles", response_model=list[RoleOut])
def list_roles(
    db: Session = Depends(_get_db), _user: CurrentUser = Depends(require_permission(RBAC_MANAGE))
) -> list[dict]:
    roles = db.query(AppRole).order_by(AppRole.name).all()
    perms_by_role: dict[str, list[str]] = {r.name: [] for r in roles}
    for rp in db.query(RolePermission).all():
        perms_by_role.setdefault(rp.role_name, []).append(rp.permission)
    return [_role_out(r, perms_by_role.get(r.name, [])) for r in roles]


@router.post("/roles", response_model=RoleOut, status_code=status.HTTP_201_CREATED)
def create_role(
    body: RoleCreate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(RBAC_MANAGE)),
) -> dict:
    if db.get(AppRole, body.name) is not None:
        raise HTTPException(status_code=422, detail=f'vai trò "{body.name}" đã tồn tại')
    role = AppRole(name=body.name, is_builtin=False, description=body.description, created_by=user.username)
    db.add(role)
    db.commit()
    write_audit_event(
        actor=user.username, action="role_created", resource=body.name, payload={"description": body.description}
    )
    return _role_out(role, [])


@router.patch("/roles/{name}/permissions", response_model=RoleOut)
def update_role_permissions(
    name: str,
    body: RolePermissionsUpdate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(RBAC_MANAGE)),
) -> dict:
    role = db.get(AppRole, name)
    if role is None:
        raise HTTPException(status_code=404, detail="vai trò không tồn tại")

    desired = set(body.permissions)
    unknown = desired - ALL_PERMISSIONS
    if unknown:
        raise HTTPException(status_code=422, detail=f"permission không hợp lệ: {sorted(unknown)}")

    try:
        check_admin_keeps_rbac_manage(name, frozenset(desired))
    except RbacInvariantError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    previous = {rp.permission for rp in db.query(RolePermission).filter(RolePermission.role_name == name).all()}
    db.query(RolePermission).filter(RolePermission.role_name == name).delete()
    for permission in desired:
        db.add(RolePermission(role_name=name, permission=permission))
    db.flush()

    try:
        check_caller_keeps_permission(db, user, None, RBAC_MANAGE)
    except RbacInvariantError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    db.commit()
    write_audit_event(
        actor=user.username,
        action="role_permissions_updated",
        resource=name,
        payload={"from": sorted(previous), "to": sorted(desired)},
    )
    return _role_out(role, sorted(desired))


@router.delete("/roles/{name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_role(
    name: str,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(RBAC_MANAGE)),
) -> None:
    role = db.get(AppRole, name)
    if role is None:
        raise HTTPException(status_code=404, detail="vai trò không tồn tại")
    if role.is_builtin:
        raise HTTPException(status_code=422, detail="không thể xoá vai trò builtin")
    still_assigned = db.query(UserRoleAssignment).filter(UserRoleAssignment.role_name == name).first()
    if still_assigned is not None:
        raise HTTPException(
            status_code=422, detail="vai trò này vẫn đang được gán cho ít nhất 1 user — bỏ gán trước khi xoá"
        )
    db.delete(role)
    db.commit()
    write_audit_event(actor=user.username, action="role_deleted", resource=name, payload={})


@router.get("/me/permissions")
def my_permissions(db: Session = Depends(_get_db), user: CurrentUser = Depends(get_current_user)) -> dict:
    """Mở cho MỌI user đã đăng nhập (không cần rbac.manage) — frontend dùng
    để quyết định hiện/ẩn tab/nút. Đây CHỈ là gợi ý hiển thị, KHÔNG phải
    enforcement thật — enforcement luôn ở require_permission phía backend,
    cùng triết lý "UI không được tin để enforce" đã áp dụng xuyên suốt app
    này (trước đây ghi rõ ở Layout.tsx cho role, giờ áp dụng y hệt cho
    permission)."""
    return {"permissions": sorted(resolve_permissions(db, user.roles))}
