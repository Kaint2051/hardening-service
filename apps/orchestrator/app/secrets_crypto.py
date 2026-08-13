"""Mã hoá/giải mã secret lưu trên Host (ssh_password_encrypted, static_ssh_
private_key_encrypted) — tách riêng module này (KHÔNG đặt trong app/hosts.py)
để app/jobs.py dùng lại được mà không tạo circular import: app/hosts.py đã
`from app.jobs import _call_job_dispatcher`, nên app/jobs.py không thể
`from app.hosts import ...` ngược lại.
"""
from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


def encrypt_host_secret(plaintext: str) -> str:
    # Fernet (AES-CBC + HMAC, xử lý nonce/xác thực nội bộ) — khoá lấy từ
    # settings.host_credential_encryption_key (chỉ ở .env, KHÔNG lưu DB).
    # LƯU Ý đã ghi rõ ở app/config.py: không chặn được kịch bản Orchestrator
    # tự nó bị chiếm, chỉ chặn được lộ riêng bản backup DB.
    return Fernet(settings.host_credential_encryption_key.encode()).encrypt(plaintext.encode()).decode()


def decrypt_host_secret(ciphertext: str, secret_name: str) -> str:
    try:
        return Fernet(settings.host_credential_encryption_key.encode()).decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        # Xảy ra nếu host_credential_encryption_key bị đổi SAU khi đã mã hoá
        # dữ liệu cũ (vd xoay khoá không di trú lại dữ liệu) — báo lỗi rõ
        # ràng thay vì để lộ traceback thô qua API. secret_name chỉ để thông
        # báo lỗi đúng tên field (ssh_password/static_ssh_private_key).
        raise RuntimeError(
            f"không giải mã được {secret_name} đã lưu — host_credential_encryption_key "
            "có thể đã đổi kể từ lúc lưu"
        ) from exc
