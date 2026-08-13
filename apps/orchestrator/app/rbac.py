"""RBAC tuỳ biến — permission-based authorization, thay require_roles(...)
cứng cũ (đã xoá khỏi app/auth.py). Vai trò/quyền của user 100% nằm ở DB app
(app/models.py: AppRole/RolePermission/UserRoleAssignment) — Keycloak chỉ
còn xác thực danh tính (app/auth.py:get_current_user), không còn quyết định
user được làm gì.

Taxonomy permission cố định trong code — xem app/permissions.py. File này
chỉ chứa MÁY THỰC THI (require_permission) + 2 bất biến an toàn dùng chung
bởi app/roles.py và app/users.py.
"""
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, status

from app.auth import CurrentUser, get_current_user
from app.db import SessionLocal
from app.models import AppRole, RolePermission
from app.permissions import BUILTIN_ROLE_PERMISSIONS, RBAC_MANAGE


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def resolve_permissions(db: Session, roles: frozenset[str]) -> frozenset[str]:
    """Hợp toàn bộ permission của các role trong `roles` — dùng bởi
    require_permission VÀ GET /me/permissions (app/roles.py)."""
    if not roles:
        return frozenset()
    rows = db.query(RolePermission.permission).filter(RolePermission.role_name.in_(roles)).all()
    return frozenset(r[0] for r in rows)


def require_permission(permission: str):
    """Dependency factory — 403 nếu user hiện tại không có `permission` (qua
    hợp permission của mọi role đang gán). Thay require_roles(...) cũ, cùng
    khuôn (đóng `permission` tại thời điểm decorate, checker thật thi ở
    request-time), khác ở việc checker cần thêm 1 query DB (role_permissions)
    — app/auth.py đã tự query DB riêng để resolve `user.roles`."""

    def _checker(
        user: CurrentUser = Depends(get_current_user), db: Session = Depends(_get_db)
    ) -> CurrentUser:
        granted = resolve_permissions(db, user.roles)
        if permission not in granted:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"thiếu quyền: {permission}",
            )
        return user

    return _checker


def seed_builtin_roles(db: Session) -> None:
    """Insert 6 role builtin + role_permissions từ BUILTIN_ROLE_PERMISSIONS
    (app/permissions.py) — dùng bởi fixture test (SQLite in-memory mỗi file
    test), TÁI HIỆN đúng dữ liệu migration 0026 seed cho Postgres thật (cùng
    đọc app/permissions.py nên không lệch nhau)."""
    for role_name, permissions in BUILTIN_ROLE_PERMISSIONS.items():
        db.add(AppRole(name=role_name, is_builtin=True))
        for permission in permissions:
            db.add(RolePermission(role_name=role_name, permission=permission))
    db.commit()


class RbacInvariantError(ValueError):
    """1 trong 2 bất biến an toàn RBAC bị vi phạm (xem docstring các hàm
    check_* dưới đây) — caller (app/roles.py, app/users.py) bắt lỗi này để
    trả 422 rõ lý do, KHÔNG để lộ thành 500."""


def check_admin_keeps_rbac_manage(role_name: str, new_permissions: frozenset[str]) -> None:
    """Bất biến #1: role "admin" LUÔN phải giữ "rbac.manage" — không có
    Keycloak console nào cứu được nếu lỡ tay tự khoá hết đường quản lý RBAC
    của chính app này (khác lúc còn dùng Keycloak role, giờ RBAC 100% tự
    quản). 5 role builtin khác không bị ràng buộc này — xoá hết quyền của
    "operator" chẳng hạn vẫn luôn sửa lại được vì "admin" còn rbac.manage."""
    if role_name == "admin" and RBAC_MANAGE not in new_permissions:
        raise RbacInvariantError(
            'vai trò "admin" phải luôn giữ quyền "rbac.manage" — nếu không sẽ '
            "không còn cách nào tự sửa lại RBAC của hệ thống"
        )


def check_caller_keeps_permission(
    db: Session,
    caller: CurrentUser,
    caller_new_roles: frozenset[str] | None,
    required_permission: str,
) -> None:
    """Bất biến #2 (tổng quát hoá guard "không tự rút vai trò admin của
    chính mình" cũ ở app/users.py — trước đây so tên role "admin", giờ so
    permission cho đúng bản chất "đừng tự khoá đường quay lại"): sau khi áp
    thay đổi, quyền CỦA CHÍNH NGƯỜI GỌI không được mất `required_permission`.

    `caller_new_roles=None`: đang sửa role_permissions (app/roles.py), KHÔNG
    đổi role của caller — gọi hàm này SAU khi đã `db.flush()` thay đổi vào
    session (chưa commit), để resolve_permissions đọc đúng dữ liệu MỚI.
    `caller_new_roles` khác None: đang sửa CHÍNH role-assignment của caller
    (app/users.py) — dùng tập role MỚI đó thay vì query DB.
    """
    roles = caller_new_roles if caller_new_roles is not None else caller.roles
    if required_permission not in resolve_permissions(db, roles):
        raise RbacInvariantError(
            f'thao tác này sẽ làm chính bạn mất quyền "{required_permission}" '
            "— không thể tự khoá đường quay lại, nhờ 1 admin khác thực hiện"
        )
