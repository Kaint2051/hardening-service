"""Integration test cho app/users.py qua HTTP thật (TestClient) — mock
app.users.list_users (không gọi Keycloak Admin API thật, cùng cách
test_jobs.py mock jobs_module.mint_ssh_certificate: patch tại namespace
IMPORT trong module đang test). Vai trò/quyền giờ đọc/ghi TRỰC TIẾP DB app
(user_role_assignments) — dùng chung engine SQLite của
tests/_rbac_test_engine.py (cùng dữ liệu với app.rbac._get_db dùng bởi
require_permission, xem conftest.py) — router này giờ CÓ _get_db (khác bản
cũ trước khi RBAC chuyển hẳn về DB app)."""
import httpx
import pytest
from fastapi.testclient import TestClient

from app import users as users_module
from app.auth import CurrentUser, get_current_user
from app.main import app

from _rbac_test_engine import RbacSessionLocal, override_rbac_db

app.dependency_overrides[users_module._get_db] = override_rbac_db
client = TestClient(app)


def _as(username: str, *roles: str):
    def _fake_user():
        return CurrentUser(subject=username, username=username, roles=frozenset(roles))

    return _fake_user


def _clear_user_override():
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture(autouse=True)
def _mock_audit(monkeypatch):
    calls = []
    monkeypatch.setattr(users_module, "write_audit_event", lambda **kwargs: calls.append(kwargs))
    return calls


def _assign_role(user_id: str, role_name: str) -> None:
    from app.models import UserRoleAssignment

    db = RbacSessionLocal()
    try:
        db.add(UserRoleAssignment(user_id=user_id, role_name=role_name, assigned_by="test"))
        db.commit()
    finally:
        db.close()


def _create_custom_role(name: str) -> None:
    # Insert TRỰC TIẾP (không gọi POST /roles) — tránh phụ thuộc thứ tự
    # collect pytest giữa test_users.py/test_roles.py cho override
    # roles_module._get_db (2 file khác nhau, xem CLAUDE.md gotcha).
    from app.models import AppRole

    db = RbacSessionLocal()
    try:
        db.add(AppRole(name=name, is_builtin=False))
        db.commit()
    finally:
        db.close()


def _current_roles(user_id: str) -> set[str]:
    from app.models import UserRoleAssignment

    db = RbacSessionLocal()
    try:
        return {
            row.role_name
            for row in db.query(UserRoleAssignment).filter(UserRoleAssignment.user_id == user_id).all()
        }
    finally:
        db.close()


def test_non_admin_cannot_list_users():
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.get("/users")
    _clear_user_override()
    assert resp.status_code == 403


def test_non_admin_cannot_update_roles():
    app.dependency_overrides[get_current_user] = _as("alice", "viewer")
    resp = client.patch("/users/u1/roles", json={"roles": ["operator"]})
    _clear_user_override()
    assert resp.status_code == 403


def test_list_users_merges_roles_from_db(monkeypatch):
    monkeypatch.setattr(
        users_module,
        "list_users",
        lambda: [{"id": "u1", "username": "bob", "email": "bob@x", "enabled": True}],
    )
    _assign_role("u1", "operator")
    app.dependency_overrides[get_current_user] = _as("admin1", "admin")
    resp = client.get("/users")
    _clear_user_override()

    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["username"] == "bob"
    assert body[0]["roles"] == ["operator"]


def test_list_users_with_no_roles_assigned_returns_empty_list(monkeypatch):
    monkeypatch.setattr(
        users_module,
        "list_users",
        lambda: [{"id": "u2", "username": "carol", "email": None, "enabled": True}],
    )
    app.dependency_overrides[get_current_user] = _as("admin1", "admin")
    resp = client.get("/users")
    _clear_user_override()

    assert resp.status_code == 200
    assert resp.json()[0]["roles"] == []


def test_list_users_keycloak_error_returns_502(monkeypatch):
    def _raise():
        raise httpx.ConnectError("keycloak không phản hồi")

    monkeypatch.setattr(users_module, "list_users", _raise)
    app.dependency_overrides[get_current_user] = _as("admin1", "admin")
    resp = client.get("/users")
    _clear_user_override()
    assert resp.status_code == 502


def test_update_roles_success_writes_db_and_one_audit_event(_mock_audit):
    _assign_role("target-user", "operator")
    app.dependency_overrides[get_current_user] = _as("admin1", "admin")
    resp = client.patch("/users/target-user/roles", json={"roles": ["admin"]})
    _clear_user_override()

    assert resp.status_code == 200
    assert resp.json() == {"user_id": "target-user", "roles": ["admin"]}
    assert _current_roles("target-user") == {"admin"}
    assert len(_mock_audit) == 1
    assert _mock_audit[0]["action"] == "user_roles_updated"
    assert _mock_audit[0]["resource"] == "target-user"
    assert _mock_audit[0]["payload"] == {"user_id": "target-user", "from": ["operator"], "to": ["admin"]}


def test_update_roles_can_assign_custom_role(_mock_audit):
    _create_custom_role("scan-only")
    app.dependency_overrides[get_current_user] = _as("admin1", "admin")
    resp = client.patch("/users/target-user/roles", json={"roles": ["scan-only"]})
    _clear_user_override()
    assert resp.status_code == 200
    assert _current_roles("target-user") == {"scan-only"}


def test_update_roles_unknown_role_rejected_without_db_write(_mock_audit):
    app.dependency_overrides[get_current_user] = _as("admin1", "admin")
    resp = client.patch("/users/target-user/roles", json={"roles": ["superuser"]})
    _clear_user_override()
    assert resp.status_code == 422
    assert _current_roles("target-user") == set()
    assert len(_mock_audit) == 0


def test_self_removal_of_only_admin_role_blocked(_mock_audit):
    _assign_role("admin1", "admin")
    app.dependency_overrides[get_current_user] = _as("admin1", "admin")
    resp = client.patch("/users/admin1/roles", json={"roles": ["viewer"]})
    _clear_user_override()
    assert resp.status_code == 422
    # KHÔNG có gì bị đổi — vẫn giữ nguyên "admin", không rơi xuống "viewer".
    assert _current_roles("admin1") == {"admin"}
    assert len(_mock_audit) == 0


def test_removing_admin_from_someone_else_is_allowed():
    _assign_role("other-admin", "admin")
    app.dependency_overrides[get_current_user] = _as("admin1", "admin")
    resp = client.patch("/users/other-admin/roles", json={"roles": ["viewer"]})
    _clear_user_override()
    assert resp.status_code == 200
    assert _current_roles("other-admin") == {"viewer"}


def test_self_edit_keeping_users_manage_permission_is_allowed():
    _assign_role("admin1", "admin")
    app.dependency_overrides[get_current_user] = _as("admin1", "admin")
    resp = client.patch("/users/admin1/roles", json={"roles": ["admin", "operator"]})
    _clear_user_override()
    assert resp.status_code == 200
    assert _current_roles("admin1") == {"admin", "operator"}
