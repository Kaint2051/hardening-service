"""Xác thực qua Keycloak (Giai đoạn 1, mục 4.7 architecture-proposal.md).

Verify access token bằng JWKS thật lấy từ Keycloak (RS256) — không tự ký/tự
kiểm tra token nội bộ. Keycloak CHỈ còn xác thực DANH TÍNH (bạn là ai, qua
claim "sub") — vai trò/quyền (bạn được làm gì) 100% chuyển sang DB app từ
RBAC tuỳ biến (app/rbac.py, app/permissions.py), KHÔNG còn đọc claim
"realm_access.roles" trong JWT nữa (đây là 1 thay đổi kiến trúc thật, không
phải chỉ đổi tên biến — trước đây roles đọc thẳng từ JWT, stateless hoàn
toàn; giờ cần 1 query DB mỗi request để biết user hiện có vai trò gì, đổi
lại là vai trò có hiệu lực NGAY lần gọi API kế tiếp, không cần đăng nhập lại
như trước). `require_roles()` cũ đã bị xoá — dùng
`app/rbac.py:require_permission()` thay thế.
"""
import ssl
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import settings
from app.db import SessionLocal
from app.models import UserRoleAssignment

_bearer_scheme = HTTPBearer(auto_error=True)


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# PyJWKClient tự cache JWKS theo thời gian — không cần tự implement cache.
# Dùng keycloak_jwks_base_url (nội bộ container), KHÔNG dùng keycloak_issuer_url
# (URL công khai cho browser) — xem giải thích trong app/config.py.
#
# Mục "Dựng TLS thật": keycloak_jwks_base_url giờ là https (cert do CHÍNH
# step-ca nội bộ ký, không phải CA công khai) — urllib (PyJWKClient dùng nội
# bộ, không phải httpx) sẽ từ chối bằng lỗi CERTIFICATE_VERIFY_FAILED nếu
# không trỏ đúng root CA tin cậy. `ssl_context=None` (giữ nguyên default hệ
# thống) vẫn hoạt động khi URL còn là http (tham số bị bỏ qua), nên không
# cần rẽ nhánh theo scheme.
_jwks_client = jwt.PyJWKClient(
    f"{settings.keycloak_jwks_base_url}/protocol/openid-connect/certs",
    ssl_context=ssl.create_default_context(cafile=settings.stepca_root_cert_path),
)


@dataclass(frozen=True)
class CurrentUser:
    subject: str
    username: str
    roles: frozenset[str]


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
    db: Session = Depends(_get_db),
) -> CurrentUser:
    token = credentials.credentials
    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=settings.keycloak_issuer_url,
            # Keycloak mặc định để "aud": "account" trừ khi cấu hình audience
            # mapper riêng — dùng "azp" (authorized party) để xác nhận token
            # được cấp cho đúng client "orchestrator" thay vì verify "aud".
            options={"verify_aud": False},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"token không hợp lệ: {exc}",
        ) from exc

    if claims.get("azp") not in settings.keycloak_client_ids_set:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="token không được cấp cho client hợp lệ (orchestrator/web)",
        )

    # Keycloak ID token và access token dùng chung issuer/azp, chỉ khác claim
    # "typ" ("ID" vs "Bearer") — không kiểm tra riêng thì 1 ID token (vốn chỉ
    # để xác thực đăng nhập ở SPA, KHÔNG phải để gọi API) vẫn qua được hết các
    # bước verify ở trên rồi được cấp NGUYÊN vai trò thật của user (giờ đọc
    # từ DB theo "sub", không còn phụ thuộc claim gì trong token — khác trước
    # đây khi ID token của realm này tình cờ có realm_access rỗng nên vẫn bị
    # require_roles() chặn; giờ không còn "tấm lưới an toàn" tình cờ đó nữa,
    # bước kiểm tra typ dưới đây là chặn DUY NHẤT, không phải phòng hờ).
    if claims.get("typ") != "Bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="token không phải access token hợp lệ",
        )

    subject = claims["sub"]
    return CurrentUser(
        subject=subject,
        username=claims.get("preferred_username", subject),
        roles=_resolve_user_roles(db, subject),
    )


def _resolve_user_roles(db: Session, subject: str) -> frozenset[str]:
    """Đọc vai trò THẬT của user từ DB app (user_role_assignments), KHÔNG
    còn đọc claim JWT — tách riêng khỏi get_current_user để test được mà
    không cần dựng JWT/JWKS thật (xem tests/test_auth.py)."""
    rows = db.query(UserRoleAssignment.role_name).filter(UserRoleAssignment.user_id == subject).all()
    return frozenset(r[0] for r in rows)
