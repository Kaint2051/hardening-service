"""Gọi Keycloak Admin REST API bằng client "orchestrator-admin" (service
account riêng, xem infra/keycloak/bootstrap-admin-client.sh) — module lá DUY
NHẤT giữ `settings.keycloak_admin_client_secret`, cùng lý do app/ca_client.py
là nơi duy nhất giữ provisioner password của step-ca: 1 credential nhạy cảm,
1 module chịu trách nhiệm, mọi router khác gọi vào đây chứ không tự cầm secret.

Sau khi RBAC tuỳ biến chuyển hẳn "vai trò/quyền user được làm gì" vào DB app
(app/rbac.py, app/permissions.py) — Keycloak chỉ còn xác thực danh tính,
module này CHỈ còn 1 việc: liệt kê user thật (username/email/enabled) để
app/users.py JOIN thêm role từ user_role_assignments. Không còn gọi
role-mapping API nào cả (bản cũ có `list_users_with_roles`/
`set_user_realm_roles`/`KeycloakRoleSyncError` — đã xoá, không còn nơi gọi).
Nhờ vậy service account "orchestrator-admin" có thể RÚT quyền Keycloak về
tối thiểu hơn trước (chỉ còn cần view-users+query-users — xem
infra/keycloak/bootstrap-admin-client.sh, đã xác nhận qua test thật trước
khi rút).
"""
import httpx

from app.config import settings

_ADMIN_CLIENT_ID = "orchestrator-admin"
_PAGE_SIZE = 100
_TIMEOUT = 10.0

# settings.keycloak_jwks_base_url dạng "https://keycloak:8443/realms/hardening-console"
# (đã có sẵn, dùng chung với JWKS fetch trong app/auth.py) — tách phần gốc
# server + tên realm để tự dựng URL Admin API ("/admin/realms/{realm}/...",
# khác hẳn "/realms/{realm}/..." dùng cho JWKS/token endpoint).
_KC_BASE = settings.keycloak_jwks_base_url
_KC_ROOT, _, _KC_REALM = _KC_BASE.rpartition("/realms/")
_TOKEN_URL = f"{_KC_BASE}/protocol/openid-connect/token"
_ADMIN_BASE = f"{_KC_ROOT}/admin/realms/{_KC_REALM}"


def get_admin_token() -> str:
    """Client credentials grant — access token ngắn hạn cho service account
    "orchestrator-admin". KHÔNG cache giữa các lần gọi (mint mới mỗi lần
    `list_users()` được gọi) — cùng triết lý "no standing privilege" của
    `app/jobs.py:_call_job_dispatcher` (mint mTLS cert mới mỗi job thay vì
    cache/renew)."""
    resp = httpx.post(
        _TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "client_id": _ADMIN_CLIENT_ID,
            "client_secret": settings.keycloak_admin_client_secret,
        },
        verify=settings.stepca_root_cert_path,
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def _get_paginated(token: str, path: str) -> list[dict]:
    """Keycloak mặc định trả tối đa 100 phần tử/lần cho GET /users — bỏ qua
    phân trang là điểm mù bảo mật thật (danh sách user hiển thị thiếu) nếu
    tổ chức có hơn 100 user. Quy mô hiện tại (<50 user) không chạm ngưỡng
    này nhưng vẫn xử lý đúng ngay từ đầu."""
    results: list[dict] = []
    first = 0
    while True:
        resp = httpx.get(
            f"{_ADMIN_BASE}{path}",
            headers={"Authorization": f"Bearer {token}"},
            params={"first": first, "max": _PAGE_SIZE},
            verify=settings.stepca_root_cert_path,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        page = resp.json()
        if not page:
            break
        results.extend(page)
        if len(page) < _PAGE_SIZE:
            break
        first += _PAGE_SIZE
    return results


def list_users() -> list[dict]:
    """Danh sách user THẬT từ Keycloak (id/username/email/enabled) — KHÔNG
    kèm role (role JOIN từ user_role_assignments, xem app/users.py). Tự loại
    user ảo của service account (kể cả chính "orchestrator-admin") — user
    thật có `serviceAccountClientId is None`, user ảo của 1 client thì không.
    """
    token = get_admin_token()
    users = _get_paginated(token, "/users")
    return [
        {
            "id": u["id"],
            "username": u["username"],
            "email": u.get("email"),
            "enabled": u.get("enabled", True),
        }
        for u in users
        if not u.get("serviceAccountClientId")
    ]
