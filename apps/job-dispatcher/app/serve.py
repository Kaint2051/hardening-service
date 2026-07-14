"""Entrypoint THẬT của job-dispatcher (Dockerfile CMD gọi file này thay vì
`uvicorn app.main:app` trực tiếp) — bootstrap + tự renew cert mTLS server
TRƯỚC khi phục vụ request nào (xem app/tls_identity.py).

`app/main.py` (ASGI app) giữ NGUYÊN không đổi, không import gì từ file này —
test qua `fastapi.testclient.TestClient` gọi thẳng app object, không chạy
qua uvicorn.Server thật nên không đụng gì tới TLS/Orchestrator.
"""
import os
import ssl
import threading

import uvicorn

from app.main import app
from app.tls_identity import CA_ROOT_PATH, CERT_PATH, KEY_PATH, TLSIdentity

# Provisioner "agent-enrollment" cấp x509 mặc định 8h (xem
# infra/step-ca/setup-provisioners.sh) — renew ở nửa chu kỳ, cùng giá trị
# apps/agent-manager/main.go dùng cho chính nó.
RENEWAL_INTERVAL_SECONDS = 4 * 60 * 60


def main() -> None:
    orchestrator_url = os.environ.get("ORCHESTRATOR_URL", "http://orchestrator:8000")
    shared_secret = os.environ["JOB_DISPATCHER_SHARED_SECRET"]

    identity = TLSIdentity(orchestrator_url, shared_secret)
    identity.bootstrap_blocking()

    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=9100,
        ssl_certfile=CERT_PATH,
        ssl_keyfile=KEY_PATH,
        ssl_ca_certs=CA_ROOT_PATH,
        # BẮT BUỘC client cert — job-dispatcher chỉ có ĐÚNG 1 client hợp lệ
        # (Orchestrator), khác agent-manager (có /enroll phải hoạt động
        # TRƯỚC khi agent có cert nên dùng optional) nên không cần optional.
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )
    # config.ssl chỉ được gán BÊN TRONG config.load() (xem uvicorn source —
    # Config.__init__ KHÔNG tự gọi load(), chỉ Server._serve() gọi lúc THẬT
    # SỰ serve, bên trong asyncio.run() của server.run()) — phát hiện qua
    # đọc trực tiếp source code sau khi chạy thử bị AttributeError, không
    # phải suy đoán từ tài liệu. Gọi load() tường minh ở đây để config.ssl
    # sẵn sàng TRƯỚC khi server.run(); Server._serve() có check
    # `if not config.loaded: config.load()` nên gọi trước như này không bị
    # gọi lại/lỗi assert.
    config.load()
    server = uvicorn.Server(config)

    # renewal_loop chạy trong thread nền, hot-swap cert vào CHÍNH
    # config.ssl (SSLContext instance) mà server thật đang dùng cho mọi
    # handshake TLS — xem app/tls_identity.py:refresh_and_reload.
    renewal_thread = threading.Thread(
        target=identity.renewal_loop, args=(config.ssl, RENEWAL_INTERVAL_SECONDS), daemon=True,
    )
    renewal_thread.start()

    server.run()


if __name__ == "__main__":
    main()
