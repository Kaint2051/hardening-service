"""Entrypoint THẬT của Orchestrator (Dockerfile CMD gọi file này thay vì
`uvicorn app.main:app` trực tiếp) — mục "Dựng TLS thật cho Keycloak/
Orchestrator/Web" (sslRequired="none" trước đây chỉ chấp nhận được vì chưa
có TLS ở đâu cả).

Chạy ĐỒNG THỜI 2 listener trên CÙNG 1 FastAPI app (`app.main.app`, không đổi
gì bên trong nó — test qua `fastapi.testclient.TestClient` vẫn không đụng
gì tới TLS, đúng quy ước `serve.py` tách riêng đã dùng cho job-dispatcher):

  - Cổng HTTPS chính (8000, publish ra host, KHÔNG đổi so với trước) —
    browser/SPA dùng. Cert tự mint TRỰC TIẾP (Orchestrator có `ca-net`, là
    thành phần DUY NHẤT được gọi CA — không cần xin qua ai như job-
    dispatcher/agent-manager).
  - Cổng HTTP nội bộ (8001, KHÔNG publish ra host) — CHỈ dùng cho
    job-dispatcher/agent-manager/keycloak/web tới xin cert TLS của CHÍNH HỌ
    (`POST /internal/*/server-cert`, xem app/jobs.py). Tách riêng khỏi cổng
    HTTPS chính vì 2 lý do: (1) wrapper của Keycloak/Web là bash thuần
    (không có curl/openssl trong image gốc, xem infra/keycloak/README) chỉ
    gọi được HTTP thường, không tự làm TLS client được; (2) tránh vòng lặp
    con-gà-quả-trứng — không thể đòi 1 service PHẢI có cert TLS hợp lệ rồi
    mới gọi được đúng endpoint XIN cert TLS đó. Cổng 8001 không publish ra
    host nên không lộ ra ngoài LAN, chỉ service cùng docker network (job-net/
    mgmt-net/ca-net) gọi được — vẫn qua đúng shared secret riêng từng
    service như trước, cổng nội bộ chỉ giảm 1 lớp rào (network), không thay
    thế lớp xác thực.
"""
import asyncio
import os
import threading
import time

import uvicorn

from app.ca_client import mint_agent_manager_server_cert
from app.config import settings
from app.main import app

CERT_PATH = "/tmp/orchestrator-tls/server.crt"
KEY_PATH = "/tmp/orchestrator-tls/server.key"

# Cùng chu kỳ renew 4h các service khác đang dùng (TTL provisioner
# "agent-enrollment" 8h — xem infra/step-ca/setup-provisioners.sh).
RENEWAL_INTERVAL_SECONDS = 4 * 60 * 60


def _write_atomic(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp_path, path)


def _mint_own_cert() -> None:
    cert_pem, key_pem = mint_agent_manager_server_cert("orchestrator", extra_sans=[settings.public_host])
    _write_atomic(CERT_PATH, cert_pem)
    _write_atomic(KEY_PATH, key_pem)


def _renewal_loop(ssl_context) -> None:
    """Cùng triết lý renewal_loop của job-dispatcher/agent-manager: lỗi 1
    lần renew KHÔNG dừng loop hay làm sập Orchestrator, giữ cert cũ tới hết
    hạn thay vì crash."""
    while True:
        time.sleep(RENEWAL_INTERVAL_SECONDS)
        try:
            _mint_own_cert()
            ssl_context.load_cert_chain(CERT_PATH, KEY_PATH)
            print("renew server cert (orchestrator) thanh cong", flush=True)
        except Exception as exc:  # noqa: BLE001 — loop nền, phải nuốt MỌI lỗi
            print(f"renew server cert (orchestrator) that bai, giu cert cu: {exc}", flush=True)


async def _serve_both() -> None:
    # Blocking — Orchestrator vô nghĩa nếu không tự mint được cert của
    # chính nó (khác job-dispatcher/agent-manager, không có "chờ Orchestrator
    # sẵn sàng" ở đây vì chính step-ca là phụ thuộc duy nhất, đã có
    # depends_on: step-ca: condition: service_healthy trong docker-compose.yml).
    _mint_own_cert()

    https_config = uvicorn.Config(app, host="0.0.0.0", port=8000, ssl_certfile=CERT_PATH, ssl_keyfile=KEY_PATH)
    # config.ssl chỉ được gán BÊN TRONG config.load() (đã verify qua sự cố
    # thật lúc làm mTLS Orchestrator/job-dispatcher — xem
    # apps/job-dispatcher/app/serve.py cùng comment) — gọi tường minh ở đây
    # để lấy được config.ssl (SSLContext) truyền cho renewal thread TRƯỚC
    # khi server.run() tự gọi lại (Server._serve() tự kiểm tra
    # `if not config.loaded` nên không lỗi khi gọi trước như này).
    https_config.load()
    https_server = uvicorn.Server(https_config)

    internal_config = uvicorn.Config(app, host="0.0.0.0", port=8001)
    internal_server = uvicorn.Server(internal_config)

    renewal_thread = threading.Thread(target=_renewal_loop, args=(https_config.ssl,), daemon=True)
    renewal_thread.start()

    await asyncio.gather(https_server.serve(), internal_server.serve())


def main() -> None:
    asyncio.run(_serve_both())


if __name__ == "__main__":
    main()
