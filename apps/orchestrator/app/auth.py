"""Xác thực/RBAC thật qua Keycloak (Giai đoạn 1, mục 4.7 architecture-proposal.md).

Verify access token bằng JWKS thật lấy từ Keycloak (RS256) — không tự ký/tự
kiểm tra token nội bộ. `require_roles()` là dependency factory dùng để chặn
endpoint theo 1 trong 6 vai trò realm (viewer/auditor/rule-editor/approver/
operator/admin) đã định nghĩa trong infra/keycloak/realm-export.json.
"""
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings

_bearer_scheme = HTTPBearer(auto_error=True)

# PyJWKClient tự cache JWKS theo thời gian — không cần tự implement cache.
# Dùng keycloak_jwks_base_url (nội bộ container), KHÔNG dùng keycloak_issuer_url
# (URL công khai cho browser) — xem giải thích trong app/config.py.
_jwks_client = jwt.PyJWKClient(
    f"{settings.keycloak_jwks_base_url}/protocol/openid-connect/certs"
)


@dataclass(frozen=True)
class CurrentUser:
    subject: str
    username: str
    roles: frozenset[str]


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
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

    if claims.get("azp") != settings.keycloak_client_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="token không được cấp cho client orchestrator",
        )

    roles = frozenset(claims.get("realm_access", {}).get("roles", []))
    return CurrentUser(
        subject=claims["sub"],
        username=claims.get("preferred_username", claims["sub"]),
        roles=roles,
    )


def require_roles(*allowed_roles: str):
    """Dependency factory: chặn 403 nếu user không có ít nhất 1 role trong danh sách."""
    allowed = frozenset(allowed_roles)

    def _checker(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not (user.roles & allowed):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"cần 1 trong các vai trò: {sorted(allowed)}",
            )
        return user

    return _checker
