"""Quản lý người dùng (tab "Cài đặt") — XEM danh sách user (từ Keycloak, xem
app/keycloak_admin.py) + ĐỔI vai trò. Tạo user mới/đặt lại mật khẩu/xoá user
vẫn qua Keycloak admin console như trước (không có endpoint nào ở đây làm
việc đó, dù service account "orchestrator-admin" về mặt kỹ thuật vẫn có thể
mở rộng — phạm vi CỐ Ý giới hạn).

Vai trò ĐỔI ở đây ghi TRỰC TIẾP vào `user_role_assignments` (DB app, xem
app/rbac.py) — KHÔNG còn gọi Keycloak Admin API cho việc gán role (khác bản
cũ) vì RBAC tuỳ biến đã chuyển hẳn "user được làm gì" ra khỏi Keycloak.
"""
import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.audit import write_audit_event
from app.auth import CurrentUser
from app.db import SessionLocal
from app.keycloak_admin import list_users
from app.models import AppRole, UserRoleAssignment
from app.permissions import USERS_MANAGE
from app.rbac import RbacInvariantError, check_caller_keeps_permission, require_permission
from app.schemas import UserOut, UserRolesOut, UserRolesUpdate

router = APIRouter(prefix="/users", tags=["users"])


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("", response_model=list[UserOut])
def list_all_users(
    db: Session = Depends(_get_db), _user: CurrentUser = Depends(require_permission(USERS_MANAGE))
) -> list[dict]:
    try:
        users = list_users()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"không gọi được Keycloak Admin API: {exc}") from exc

    roles_by_user: dict[str, list[str]] = {}
    for row in db.query(UserRoleAssignment).all():
        roles_by_user.setdefault(row.user_id, []).append(row.role_name)
    for u in users:
        u["roles"] = sorted(roles_by_user.get(u["id"], []))
    return users


@router.patch("/{user_id}/roles", response_model=UserRolesOut)
def update_user_roles(
    user_id: str,
    body: UserRolesUpdate,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(USERS_MANAGE)),
) -> dict:
    desired = frozenset(body.roles)
    known_role_names = {r[0] for r in db.query(AppRole.name).all()}
    unknown = desired - known_role_names
    if unknown:
        raise HTTPException(status_code=422, detail=f"vai trò không hợp lệ: {sorted(unknown)} — xem GET /roles")

    # Tự-khoá-quyền: chặn user tự sửa vai trò của CHÍNH MÌNH nếu kết quả làm
    # mất quyền "users.manage" — không có đường phục hồi trong app nếu lỡ
    # tay (Keycloak console không cứu được, RBAC 100% nằm ở DB app từ nay).
    # Chỉ chặn tự-sửa, KHÔNG chặn rút quyền của NGƯỜI KHÁC.
    if user_id == user.subject:
        try:
            check_caller_keeps_permission(db, user, desired, USERS_MANAGE)
        except RbacInvariantError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    previous = frozenset(
        row.role_name for row in db.query(UserRoleAssignment).filter(UserRoleAssignment.user_id == user_id).all()
    )
    to_remove = previous - desired
    to_add = desired - previous

    # Xoá-trước-thêm-sau, giữ nguyên nguyên tắc cũ (app/keycloak_admin.py
    # trước khi đổi kiến trúc): nếu có lỗi giữa chừng, kết quả còn lại là tập
    # giao — THIẾU quyền, an toàn hơn dư quyền. Khác bản cũ (gọi Keycloak qua
    # HTTP, có thể fail nửa đường): đây là 1 transaction DB local duy nhất,
    # commit atomic — không còn cần bước "đọc lại xác nhận" như
    # KeycloakRoleSyncError cũ, không còn ý nghĩa khi không gọi mạng nữa.
    if to_remove:
        db.query(UserRoleAssignment).filter(
            UserRoleAssignment.user_id == user_id, UserRoleAssignment.role_name.in_(to_remove)
        ).delete(synchronize_session=False)
    for role_name in to_add:
        db.add(UserRoleAssignment(user_id=user_id, role_name=role_name, assigned_by=user.username))
    db.commit()

    write_audit_event(
        actor=user.username,
        action="user_roles_updated",
        resource=user_id,
        payload={"user_id": user_id, "from": sorted(previous), "to": sorted(desired)},
    )
    return {"user_id": user_id, "roles": sorted(desired)}
