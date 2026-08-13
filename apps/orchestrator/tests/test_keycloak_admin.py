"""Unit test cho app/keycloak_admin.py — mock httpx.get/post (module-level,
KHÔNG dùng httpx.Client() instance trong code thật để còn mock được theo
đúng cách app/jobs.py's test đã dùng cho _call_job_dispatcher). Không gọi
Keycloak thật ở đâu cả.

Sau khi RBAC tuỳ biến chuyển hẳn vai trò/quyền vào DB app (app/rbac.py),
module này CHỈ còn get_admin_token/_get_paginated/list_users — không còn
role-mapping API nào (list_users_with_roles/set_user_realm_roles/
KeycloakRoleSyncError cũ đã xoá cùng lúc, xem app/keycloak_admin.py)."""
from app import keycloak_admin


class _FakeResponse:
    def __init__(self, json_body):
        self._json = json_body

    def raise_for_status(self):
        pass

    def json(self):
        return self._json


def test_get_admin_token_posts_client_credentials_grant(monkeypatch):
    import httpx

    captured = {}

    def _fake_post(url, data=None, **kwargs):
        captured["url"] = url
        captured["data"] = data
        return _FakeResponse({"access_token": "tok-123"})

    monkeypatch.setattr(httpx, "post", _fake_post)
    token = keycloak_admin.get_admin_token()

    assert token == "tok-123"
    assert captured["data"]["grant_type"] == "client_credentials"
    assert captured["data"]["client_id"] == "orchestrator-admin"


def test_get_paginated_merges_multiple_pages(monkeypatch):
    import httpx

    page1 = [{"id": f"u{i}"} for i in range(keycloak_admin._PAGE_SIZE)]
    page2 = [{"id": "u-last"}]

    def _fake_get(url, headers=None, params=None, **kwargs):
        first = (params or {}).get("first", 0)
        return _FakeResponse(page1 if first == 0 else page2)

    monkeypatch.setattr(httpx, "get", _fake_get)
    result = keycloak_admin._get_paginated("tok", "/users")

    assert len(result) == keycloak_admin._PAGE_SIZE + 1
    assert result[-1]["id"] == "u-last"


def test_list_users_filters_service_accounts_and_drops_roles(monkeypatch):
    import httpx

    monkeypatch.setattr(keycloak_admin, "get_admin_token", lambda: "tok")

    users_page = [
        {"id": "u1", "username": "alice", "email": "alice@x", "enabled": True},
        {
            "id": "svc1",
            "username": "service-account-orchestrator-admin",
            "enabled": True,
            "serviceAccountClientId": "orchestrator-admin",
        },
    ]

    def _fake_get(url, headers=None, params=None, **kwargs):
        assert url.endswith("/users")
        return _FakeResponse(users_page)

    monkeypatch.setattr(httpx, "get", _fake_get)
    result = keycloak_admin.list_users()

    assert len(result) == 1  # user ảo của service account bị loại
    assert result[0] == {"id": "u1", "username": "alice", "email": "alice@x", "enabled": True}
