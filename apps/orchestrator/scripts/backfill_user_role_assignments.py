"""Backfill 1 LẦN DUY NHẤT: nạp `user_role_assignments` (RBAC tuỳ biến, xem
app/rbac.py) từ role-mapping THẬT hiện có trong Keycloak.

BẮT BUỘC chạy đúng theo thứ tự cutover (xem plan RBAC mục 8):
  1. docker compose build orchestrator
  2. docker compose run --rm orchestrator alembic upgrade head   (tạo 3 bảng
     RBAC + seed role_permissions cho 6 role builtin — user_role_assignments
     còn TRỐNG sau bước này)
  3. docker compose exec -T orchestrator python3 scripts/backfill_user_role_assignments.py
     (CHÍNH LÀ SCRIPT NÀY — đọc role-mapping cũ từ Keycloak, nạp vào
     user_role_assignments)
  3.5. XÁC NHẬN bằng mắt output dưới đây khớp đúng user/role THẬT trước khi
       qua bước 4 — cổng chặn thủ công, không tự động next step.
  4. docker compose up -d orchestrator   (code mới đọc role từ DB, không
     còn đọc claim JWT)

Nếu chạy BƯỚC 4 TRƯỚC bước này: mọi user tạm mất hết quyền (get_current_user
đọc user_role_assignments rỗng) cho tới khi script này chạy xong — không mất
dữ liệu, chỉ tạm gián đoạn, tự khắc phục ngay sau khi script chạy (không cần
restart lại orchestrator — lần gọi API kế tiếp của user đó tự đọc đúng).

Gọi TRỰC TIẾP Keycloak Admin API (GET /roles/{role}/users cho từng role
builtin) — CỐ Ý không dùng app/keycloak_admin.py:list_users() (bản đã rút
gọn sau khi RBAC chuyển hẳn về DB app, không còn biết role nào) vì đây là
lần DUY NHẤT cần đọc lại role-mapping cũ trước khi rời bỏ hẳn cơ chế đó — chỉ
mượn `get_admin_token()` (giữ đúng nguyên tắc "1 credential nhạy cảm, 1 module
chịu trách nhiệm" của app/keycloak_admin.py), tự dựng lại phần gọi HTTP còn
lại ở đây để không phụ thuộc cấu trúc nội bộ của module đó về sau.

Idempotent — chạy lại nhiều lần an toàn (bỏ qua row đã tồn tại).

Chạy: docker compose exec -T orchestrator python3 scripts/backfill_user_role_assignments.py
"""
import httpx

from app.config import settings
from app.db import SessionLocal
from app.keycloak_admin import get_admin_token
from app.models import UserRoleAssignment
from app.permissions import BUILTIN_ROLE_NAMES

_KC_BASE = settings.keycloak_jwks_base_url
_KC_ROOT, _, _KC_REALM = _KC_BASE.rpartition("/realms/")
_ADMIN_BASE = f"{_KC_ROOT}/admin/realms/{_KC_REALM}"
_PAGE_SIZE = 100
_TIMEOUT = 10.0


def _get_paginated(token: str, path: str) -> list[dict]:
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


def main() -> None:
    token = get_admin_token()
    roles_by_user: dict[str, set[str]] = {}
    for role in BUILTIN_ROLE_NAMES:
        for u in _get_paginated(token, f"/roles/{role}/users"):
            roles_by_user.setdefault(u["id"], set()).add(role)

    db = SessionLocal()
    try:
        inserted = 0
        for user_id, roles in roles_by_user.items():
            for role_name in roles:
                if db.get(UserRoleAssignment, (user_id, role_name)) is not None:
                    continue
                db.add(UserRoleAssignment(user_id=user_id, role_name=role_name, assigned_by="backfill_script"))
                inserted += 1
        db.commit()

        print(f"=== Backfill xong: {len(roles_by_user)} user, {inserted} role-assignment mới ghi vào DB ===")
        for user_id, roles in sorted(roles_by_user.items()):
            print(f"  user_id={user_id} -> {sorted(roles)}")
        if not roles_by_user:
            print("  (KHÔNG tìm thấy user nào có role builtin nào trong Keycloak — kiểm tra lại trước khi tiếp tục)")
    finally:
        db.close()


if __name__ == "__main__":
    main()
