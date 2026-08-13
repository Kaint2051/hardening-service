"""Integration test cho RBAC tuỳ biến (app/roles.py) — dùng chung engine
SQLite của tests/_rbac_test_engine.py (cùng dữ liệu với app.rbac._get_db,
xem conftest.py), verify RBAC qua HTTP thật (TestClient). KHÔNG mock DB
riêng — router này không gọi Keycloak, chỉ đọc/ghi app_roles/
role_permissions/user_role_assignments."""
import pytest
from fastapi.testclient import TestClient

from app import roles as roles_module
from app.auth import CurrentUser, get_current_user
from app.main import app
from app.models import UserRoleAssignment

from _rbac_test_engine import RbacSessionLocal, override_rbac_db

app.dependency_overrides[roles_module._get_db] = override_rbac_db
client = TestClient(app)


def _as(username: str, *roles: str):
    def _fake_user():
        return CurrentUser(subject=username, username=username, roles=frozenset(roles))

    return _fake_user


@pytest.fixture(autouse=True)
def _mock_audit(monkeypatch):
    calls = []
    monkeypatch.setattr(roles_module, "write_audit_event", lambda **kwargs: calls.append(kwargs))
    return calls


def _override_user(fake):
    app.dependency_overrides[get_current_user] = fake


def _clear_user_override():
    app.dependency_overrides.pop(get_current_user, None)


def _assign_role(user_id: str, role_name: str) -> None:
    db = RbacSessionLocal()
    try:
        db.add(UserRoleAssignment(user_id=user_id, role_name=role_name, assigned_by="test"))
        db.commit()
    finally:
        db.close()


class TestPermissionCheck:
    def test_non_rbac_manage_blocked_on_every_endpoint(self):
        _override_user(_as("viewer1", "viewer"))
        try:
            assert client.get("/roles").status_code == 403
            assert client.get("/permissions").status_code == 403
            assert client.post("/roles", json={"name": "x"}).status_code == 403
            assert client.patch("/roles/viewer/permissions", json={"permissions": []}).status_code == 403
            assert client.delete("/roles/viewer").status_code == 403
        finally:
            _clear_user_override()

    def test_me_permissions_open_to_any_authenticated_user(self):
        _override_user(_as("viewer1", "viewer"))
        try:
            resp = client.get("/me/permissions")
            assert resp.status_code == 200
            assert "hosts.view" in resp.json()["permissions"]
            assert "hosts.manage" not in resp.json()["permissions"]
        finally:
            _clear_user_override()


class TestListRolesAndPermissions:
    def test_list_roles_returns_6_builtin(self):
        _override_user(_as("admin1", "admin"))
        try:
            resp = client.get("/roles")
            assert resp.status_code == 200
            names = {r["name"] for r in resp.json()}
            assert names == {"viewer", "auditor", "rule-editor", "approver", "operator", "admin"}
            assert all(r["is_builtin"] for r in resp.json())
            admin_role = next(r for r in resp.json() if r["name"] == "admin")
            assert "rbac.manage" in admin_role["permissions"]
        finally:
            _clear_user_override()

    def test_list_permissions_returns_full_taxonomy(self):
        _override_user(_as("admin1", "admin"))
        try:
            resp = client.get("/permissions")
            assert resp.status_code == 200
            perms = {p["permission"] for p in resp.json()}
            assert "hosts.view" in perms
            assert "rbac.manage" in perms
            assert all(p["description"] for p in resp.json())
        finally:
            _clear_user_override()


class TestCreateRole:
    def test_create_role_starts_with_no_permissions(self):
        _override_user(_as("admin1", "admin"))
        try:
            resp = client.post("/roles", json={"name": "scan-only", "description": "chỉ scan"})
            assert resp.status_code == 201
            assert resp.json() == {
                "name": "scan-only", "is_builtin": False, "description": "chỉ scan", "permissions": []
            }
        finally:
            _clear_user_override()

    def test_create_role_duplicate_name_rejected(self):
        _override_user(_as("admin1", "admin"))
        try:
            assert client.post("/roles", json={"name": "dup"}).status_code == 201
            resp = client.post("/roles", json={"name": "dup"})
            assert resp.status_code == 422
        finally:
            _clear_user_override()

    def test_create_role_duplicate_of_builtin_rejected(self):
        _override_user(_as("admin1", "admin"))
        try:
            resp = client.post("/roles", json={"name": "admin"})
            assert resp.status_code == 422
        finally:
            _clear_user_override()


class TestUpdateRolePermissions:
    def test_grant_permissions_to_custom_role(self):
        _override_user(_as("admin1", "admin"))
        try:
            client.post("/roles", json={"name": "scan-only"})
            resp = client.patch(
                "/roles/scan-only/permissions",
                json={"permissions": ["hosts.view", "jobs.view", "jobs.scan"]},
            )
            assert resp.status_code == 200
            assert sorted(resp.json()["permissions"]) == ["hosts.view", "jobs.scan", "jobs.view"]

            listed = client.get("/roles").json()
            scan_only = next(r for r in listed if r["name"] == "scan-only")
            assert sorted(scan_only["permissions"]) == ["hosts.view", "jobs.scan", "jobs.view"]
        finally:
            _clear_user_override()

    def test_unknown_permission_rejected(self):
        _override_user(_as("admin1", "admin"))
        try:
            client.post("/roles", json={"name": "scan-only"})
            resp = client.patch("/roles/scan-only/permissions", json={"permissions": ["not.a.real.permission"]})
            assert resp.status_code == 422
        finally:
            _clear_user_override()

    def test_role_not_found(self):
        _override_user(_as("admin1", "admin"))
        try:
            resp = client.patch("/roles/does-not-exist/permissions", json={"permissions": []})
            assert resp.status_code == 404
        finally:
            _clear_user_override()

    def test_admin_role_cannot_lose_rbac_manage(self):
        _override_user(_as("admin1", "admin"))
        try:
            resp = client.patch("/roles/admin/permissions", json={"permissions": ["hosts.view"]})
            assert resp.status_code == 422
            # KHÔNG có gì bị đổi — verify lại admin vẫn còn nguyên rbac.manage.
            admin_role = next(r for r in client.get("/roles").json() if r["name"] == "admin")
            assert "rbac.manage" in admin_role["permissions"]
        finally:
            _clear_user_override()

    def test_caller_cannot_strip_own_last_rbac_manage_grant(self):
        # Caller CHỈ giữ 1 vai trò tuỳ biến "temp-admin" (không phải "admin"
        # builtin) đang có rbac.manage — tự rút quyền đó khỏi CHÍNH vai trò
        # đang giữ sẽ khoá luôn đường quay lại của chính mình.
        _override_user(_as("boss", "admin"))
        try:
            client.post("/roles", json={"name": "temp-admin"})
            client.patch("/roles/temp-admin/permissions", json={"permissions": ["rbac.manage"]})
        finally:
            _clear_user_override()

        _override_user(_as("boss", "temp-admin"))
        try:
            resp = client.patch("/roles/temp-admin/permissions", json={"permissions": []})
            assert resp.status_code == 422
        finally:
            _clear_user_override()

    def test_caller_can_edit_other_roles_permissions_freely(self):
        # Guard tự-khoá-quyền CHỈ áp dụng khi ảnh hưởng tới quyền CỦA CHÍNH
        # caller — admin sửa quyền "operator" (không phải role của chính họ)
        # không bị chặn dù operator mất hết quyền.
        _override_user(_as("admin1", "admin"))
        try:
            resp = client.patch("/roles/operator/permissions", json={"permissions": []})
            assert resp.status_code == 200
            assert resp.json()["permissions"] == []
        finally:
            _clear_user_override()


class TestDeleteRole:
    def test_cannot_delete_builtin_role(self):
        _override_user(_as("admin1", "admin"))
        try:
            resp = client.delete("/roles/viewer")
            assert resp.status_code == 422
        finally:
            _clear_user_override()

    def test_cannot_delete_role_still_assigned(self):
        _override_user(_as("admin1", "admin"))
        try:
            client.post("/roles", json={"name": "scan-only"})
        finally:
            _clear_user_override()
        _assign_role("some-user-id", "scan-only")
        _override_user(_as("admin1", "admin"))
        try:
            resp = client.delete("/roles/scan-only")
            assert resp.status_code == 422
        finally:
            _clear_user_override()

    def test_delete_unassigned_custom_role(self):
        _override_user(_as("admin1", "admin"))
        try:
            client.post("/roles", json={"name": "scan-only"})
            resp = client.delete("/roles/scan-only")
            assert resp.status_code == 204
            names = {r["name"] for r in client.get("/roles").json()}
            assert "scan-only" not in names
        finally:
            _clear_user_override()

    def test_delete_role_not_found(self):
        _override_user(_as("admin1", "admin"))
        try:
            resp = client.delete("/roles/does-not-exist")
            assert resp.status_code == 404
        finally:
            _clear_user_override()
