FROM python:3.12-slim

# Không có -u/PYTHONUNBUFFERED trước đây khiến print() ra stdout bị block-
# buffer khi không gắn TTY (bình thường trong Docker) — phát hiện qua verify
# E2E thật: log reconciliation lúc khởi động (app/main.py) không hiện trong
# `docker compose logs` dù code đã chạy, vì tiến trình còn sống lâu (server
# HTTP) nên buffer chưa bao giờ được flush.
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/

EXPOSE 9100

# app/serve.py (không phải uvicorn CLI trực tiếp) — tự bootstrap + renew cert
# mTLS server qua Orchestrator trước khi phục vụ request nào (Giai đoạn 2 —
# xem app/tls_identity.py).
CMD ["python", "-m", "app.serve"]
