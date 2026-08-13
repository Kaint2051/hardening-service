"""Unit test cho app/auth.py:_resolve_user_roles — tách riêng khỏi
get_current_user để test được mà không cần dựng JWT/JWKS thật (Keycloak giờ
CHỈ còn xác thực danh tính, vai trò đọc từ user_role_assignments — DB app).

`require_roles(...)` cũ đã bị xoá cùng lúc RBAC chuyển sang permission-based
(app/rbac.py:require_permission, xem tests/test_rbac.py) — không còn gì để
test ở module auth.py ngoài helper resolve-role này."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth import _resolve_user_roles
from app.db import Base
from app.models import UserRoleAssignment

_engine = create_engine(
    "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
)
_TestSessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)


@pytest.fixture(autouse=True)
def _fresh_schema():
    Base.metadata.create_all(bind=_engine, tables=[Base.metadata.tables["user_role_assignments"]])
    yield
    Base.metadata.drop_all(bind=_engine)


def test_resolve_user_roles_returns_assigned_roles():
    db = _TestSessionLocal()
    try:
        db.add(UserRoleAssignment(user_id="u-1", role_name="operator", assigned_by="test"))
        db.add(UserRoleAssignment(user_id="u-1", role_name="approver", assigned_by="test"))
        db.add(UserRoleAssignment(user_id="u-2", role_name="admin", assigned_by="test"))
        db.commit()

        assert _resolve_user_roles(db, "u-1") == frozenset({"operator", "approver"})
        assert _resolve_user_roles(db, "u-2") == frozenset({"admin"})
    finally:
        db.close()


def test_resolve_user_roles_empty_for_user_with_no_assignment():
    db = _TestSessionLocal()
    try:
        assert _resolve_user_roles(db, "no-such-user") == frozenset()
    finally:
        db.close()
