"""Cert mTLS SERVER của chính job-dispatcher (Giai đoạn 2 — mTLS giữa
Orchestrator/job-dispatcher, xem README.md thư mục này mục "Chưa làm" cũ).

job-dispatcher KHÔNG nối `ca-net` (chỉ Orchestrator được gọi CA trực tiếp,
xem docs/architecture-proposal.md) — xin cert server qua
`POST /internal/job-dispatcher/server-cert` (Orchestrator, shared secret),
tự renew định kỳ, cùng pattern hệt `apps/agent-manager/main.go`
(`serverIdentity`/`renewalLoop`) nhưng viết lại bằng Python vì job-dispatcher
là FastAPI/uvicorn.

Tách hẳn khỏi `app/main.py` (ASGI app) — main.py test qua
`fastapi.testclient.TestClient` gọi handler trực tiếp, KHÔNG chạy uvicorn
thật nên không đụng gì tới TLS; mọi logic ở đây chỉ chạy qua `app/serve.py`
(entrypoint thật, xem Dockerfile), giữ `app/main.py` sạch để test không cần
mock Orchestrator.
"""
import os
import ssl
import time

import httpx

CERT_PATH = "/tmp/job-dispatcher-tls/server.crt"
KEY_PATH = "/tmp/job-dispatcher-tls/server.key"
CA_ROOT_PATH = "/tmp/job-dispatcher-tls/ca-root.crt"


def _write_atomic(path: str, content: str) -> None:
    # Ghi vào file tạm CÙNG thư mục rồi os.replace (atomic trên cùng
    # filesystem) — tránh cert/key nửa vời nếu crash giữa chừng ghi, cùng
    # nguyên tắc writeFileAtomic đã áp dụng cho apps/agent/pki.go.
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp_path, path)


class TLSIdentity:
    """Giữ đường dẫn file cert/key/ca-root hiện hành + logic xin/renew."""

    def __init__(self, orchestrator_url: str, shared_secret: str, subject: str = "job-dispatcher"):
        self.orchestrator_url = orchestrator_url
        self.shared_secret = shared_secret
        self.subject = subject
        os.makedirs(os.path.dirname(CERT_PATH), exist_ok=True)

    def _fetch(self) -> tuple[str, str, str]:
        resp = httpx.post(
            f"{self.orchestrator_url}/internal/job-dispatcher/server-cert",
            headers={"Authorization": f"Bearer {self.shared_secret}"},
            timeout=15,
        )
        resp.raise_for_status()
        body = resp.json()
        return body["cert_pem"], body["key_pem"], body["ca_root_pem"]

    def bootstrap_blocking(self, interval: float = 2.0, deadline: float = 60.0) -> None:
        """Lấy cert lần đầu — blocking, retry cách nhau `interval` cho tới
        khi thành công hoặc vượt quá `deadline` tổng. job-dispatcher vô nghĩa
        nếu không có cert để mTLS nên đây PHẢI thành công trước khi uvicorn
        khởi động — retry với backoff cố định (không Fatal ngay lần đầu) vì
        `depends_on: orchestrator: condition: service_started` chỉ đảm bảo
        container Orchestrator đã start, KHÔNG đảm bảo alembic migrate +
        uvicorn đã sẵn sàng nhận request (phát hiện thật khi deploy
        agent-manager trước đây, lặp lại đúng bài học đó ở đây).
        """
        give_up_at = time.monotonic() + deadline
        while True:
            try:
                cert_pem, key_pem, ca_root_pem = self._fetch()
                _write_atomic(CERT_PATH, cert_pem)
                _write_atomic(KEY_PATH, key_pem)
                _write_atomic(CA_ROOT_PATH, ca_root_pem)
                return
            except (httpx.HTTPError, KeyError) as exc:
                if time.monotonic() > give_up_at:
                    raise RuntimeError(
                        f"không lấy được server cert sau nhiều lần thử: {exc}"
                    ) from exc
                print(
                    f"chưa lấy được server cert (Orchestrator có thể đang khởi động), "
                    f"thử lại sau {interval}s: {exc}",
                    flush=True,
                )
                time.sleep(interval)

    def refresh_and_reload(self, ssl_context: ssl.SSLContext) -> None:
        """Xin cert MỚI rồi hot-swap vào `ssl_context` ĐANG DÙNG cho server
        thật, không restart process. Validate bằng cách load vào 1
        SSLContext TẠM trước — nếu cert/key hỏng, `load_cert_chain` raise
        NGAY, KHÔNG chạm gì tới `ssl_context` thật (giữ nguyên cert cũ đang
        chạy tốt), cùng nguyên tắc "validate trước khi commit" của
        `serverIdentity.refresh` bên agent-manager.
        """
        cert_pem, key_pem, ca_root_pem = self._fetch()

        probe = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tmp_cert, tmp_key = f"{CERT_PATH}.probe", f"{KEY_PATH}.probe"
        _write_atomic(tmp_cert, cert_pem)
        _write_atomic(tmp_key, key_pem)
        probe.load_cert_chain(tmp_cert, tmp_key)  # raise ngay nếu cert/key hỏng
        os.remove(tmp_cert)
        os.remove(tmp_key)

        _write_atomic(CERT_PATH, cert_pem)
        _write_atomic(KEY_PATH, key_pem)
        _write_atomic(CA_ROOT_PATH, ca_root_pem)
        # Gọi lại load_cert_chain trên CHÍNH context server đang dùng — các
        # kết nối TLS MỚI sau dòng này dùng cert mới ngay, kết nối đang mở
        # (nếu có) giữ nguyên cert cũ tới hết đời kết nối đó (hành vi chuẩn
        # của OpenSSL/Python ssl module, không cần restart server).
        ssl_context.load_cert_chain(CERT_PATH, KEY_PATH)

    def renewal_loop(self, ssl_context: ssl.SSLContext, interval: float) -> None:
        """Chạy trong thread nền suốt vòng đời process — lỗi 1 lần renew
        KHÔNG được dừng loop hay làm sập job-dispatcher (giữ cert cũ, thử
        lại ở chu kỳ tiếp theo), cùng triết lý renewalLoop bên agent-manager."""
        while True:
            time.sleep(interval)
            try:
                self.refresh_and_reload(ssl_context)
                print("renew server cert thành công", flush=True)
            except Exception as exc:  # noqa: BLE001 — loop nền, phải nuốt MỌI lỗi
                print(f"renew server cert thất bại, tiếp tục dùng cert cũ: {exc}", flush=True)
