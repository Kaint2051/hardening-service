"""Unit test cho app/rbac.py — require_permission mechanics + 2 bất biến an
toàn tự-khoá-quyền RBAC (check_admin_keeps_rbac_manage/
check_caller_keeps_permission), cùng seed_builtin_roles. Gọi checker/hàm
TRỰC TIẾP như hàm Python thường (bypass FastAPI Depends hoàn toàn) — cùng
khuôn test require_roles cũ trước khi bị xoá (xem git history test_auth.py).

Engine SQLite riêng của CHÍNH FILE NÀY (không dùng chung
tests/_rbac_test_engine.py — file đó phục vụ test HTTP thật qua TestClient
nhiều router khác nhau, ở đây chỉ cần gọi hàm Python trực tiếp, tự kiểm soát
session, không qua Depends/dependency_overrides gì cả)."""
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import CurrentUser
from app.db import Base
from app.models import AppRole, RolePermission
from app.permissions import BUILTIN_ROLE_PERMISSIONS, RBAC_MANAGE
from app.rbac import (
    RbacInvariantError,
    check_admin_keeps_rbac_manage,
    check_caller_keeps_permission,
    require_permission,
    resolve_permissions,
    seed_builtin_roles,
)

_engine = create_engine(
    "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
)
_TestSessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)


@pytest.fixture(autouse=True)
def _fresh_schema():
    Base.metadata.create_all(
        bind=_engine, tables=[Base.metadata.tables["app_roles"], Base.metadata.tables["role_permissions"]]
    )
    yield
    Base.metadata.drop_all(bind=_engine)


def _user(*roles: str) -> CurrentUser:
    return CurrentUser(subject="u-1", username="tester", roles=frozenset(roles))


class TestSeedBuiltinRoles:
    def test_seeds_exactly_6_roles_matching_taxonomy(self):
        db = _TestSessionLocal()
        try:
            seed_builtin_roles(db)
            names = {r.name for r in db.query(AppRole).all()}
            assert names == set(BUILTIN_ROLE_PERMISSIONS)
            assert all(r.is_builtin for r in db.query(AppRole).all())

            for role_name, expected in BUILTIN_ROLE_PERMISSIONS.items():
                actual = {
                    rp.permission
                    for rp in db.query(RolePermission).filter(RolePermission.role_name == role_name).all()
                }
                assert actual == set(expected)
        finally:
            db.close()


class TestResolvePermissions:
    def test_unions_permissions_across_multiple_roles(self):
        db = _TestSessionLocal()
        try:
            seed_builtin_roles(db)
            result = resolve_permissions(db, frozenset({"viewer", "operator"}))
            assert result == BUILTIN_ROLE_PERMISSIONS["viewer"] | BUILTIN_ROLE_PERMISSIONS["operator"]
        finally:
            db.close()

    def test_empty_roles_returns_empty_set_without_query(self):
        db = _TestSessionLocal()
        try:
            assert resolve_permissions(db, frozenset()) == frozenset()
        finally:
            db.close()


class TestRequirePermission:
    def test_allows_when_permission_granted(self):
        db = _TestSessionLocal()
        try:
            seed_builtin_roles(db)
            checker = require_permission("hosts.view")
            result = checker(user=_user("viewer"), db=db)
            assert result.username == "tester"
        finally:
            db.close()

    def test_blocks_when_permission_missing(self):
        db = _TestSessionLocal()
        try:
            seed_builtin_roles(db)
            checker = require_permission("hosts.delete")
            with pytest.raises(HTTPException) as exc_info:
                checker(user=_user("viewer"), db=db)
            assert exc_info.value.status_code == 403
        finally:
            db.close()

    def test_blocks_when_user_has_no_roles(self):
        db = _TestSessionLocal()
        try:
            seed_builtin_roles(db)
            checker = require_permission("hosts.view")
            with pytest.raises(HTTPException) as exc_info:
                checker(user=_user(), db=db)
            assert exc_info.value.status_code == 403
        finally:
            db.close()


class TestCheckAdminKeepsRbacManage:
    def test_raises_when_admin_role_loses_rbac_manage(self):
        with pytest.raises(RbacInvariantError):
            check_admin_keeps_rbac_manage("admin", frozenset({"hosts.view"}))

    def test_noop_when_admin_keeps_rbac_manage(self):
        check_admin_keeps_rbac_manage("admin", frozenset({RBAC_MANAGE, "hosts.view"}))

    def test_noop_for_non_admin_role_missing_rbac_manage(self):
        # Bất biến CHỈ áp cho role "admin" — role builtin khác (operator...)
        # không bị ràng buộc này, có thể mất mọi quyền.
        check_admin_keeps_rbac_manage("operator", frozenset())


class TestCheckCallerKeepsPermission:
    def test_raises_when_explicit_new_roles_lose_permission(self):
        db = _TestSessionLocal()
        try:
            seed_builtin_roles(db)
            caller = _user("admin")
            with pytest.raises(RbacInvariantError):
                check_caller_keeps_permission(db, caller, frozenset({"viewer"}), RBAC_MANAGE)
        finally:
            db.close()

    def test_noop_when_explicit_new_roles_keep_permission(self):
        db = _TestSessionLocal()
        try:
            seed_builtin_roles(db)
            caller = _user("admin")
            check_caller_keeps_permission(db, caller, frozenset({"admin", "operator"}), RBAC_MANAGE)
        finally:
            db.close()

    def test_uses_callers_current_roles_when_new_roles_is_none(self):
        db = _TestSessionLocal()
        try:
            seed_builtin_roles(db)
            # role_permissions của "admin" đã bị sửa TRƯỚC lúc gọi (mô phỏng
            # app/roles.py:update_role_permissions gọi hàm này SAU khi đã
            # flush thay đổi vào session, chưa commit) — caller_new_roles=None
            # nghĩa là dùng caller.roles (không đổi) + dữ liệu role_permissions
            # MỚI NHẤT trong DB.
            db.query(RolePermission).filter(RolePermission.role_name == "admin").delete()
            caller = _user("admin")
            with pytest.raises(RbacInvariantError):
                check_caller_keeps_permission(db, caller, None, RBAC_MANAGE)
        finally:
            db.close()
