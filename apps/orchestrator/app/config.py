from typing import Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Kết nối bằng role app thông thường (CRUD nghiệp vụ ở các giai đoạn sau).
    database_url: str
    # Kết nối bằng role bị giới hạn quyền INSERT/SELECT-only trên audit_log
    # (nguyên tắc "audit log append-only" — xem docs/architecture-proposal.md mục 1.4).
    audit_database_url: str
    # URL Keycloak mà TRÌNH DUYỆT/client dùng để lấy token — phải khớp CHÍNH XÁC
    # với claim "iss" trong token thật (Keycloak set "iss" theo URL công khai
    # dùng để gọi token endpoint, không phải theo config nội bộ).
    keycloak_issuer_url: str
    # URL Keycloak mà Orchestrator (chạy trong container riêng) dùng để tự fetch
    # JWKS — thường là hostname nội bộ trong docker network (vd "http://keycloak:8080/...").
    # "localhost" trong keycloak_issuer_url (dùng cho browser) KHÔNG resolve được
    # tới container Keycloak từ bên trong container Orchestrator — phát hiện qua
    # test thật trên lab server (connection refused). Nếu không set, dùng chung
    # keycloak_issuer_url (trường hợp Keycloak/Orchestrator cùng network namespace).
    keycloak_internal_url: Optional[str] = None
    # clientId trong realm-export.json — dùng để kiểm tra claim "azp" (authorized
    # party) của access token, chặn token phát hành cho client khác bị dùng sai chỗ.
    keycloak_client_id: str = "orchestrator"
    secret_key: str

    class Config:
        env_file = ".env"

    @property
    def keycloak_jwks_base_url(self) -> str:
        return self.keycloak_internal_url or self.keycloak_issuer_url


settings = Settings()
