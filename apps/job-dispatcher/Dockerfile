FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/

EXPOSE 9100

# app/serve.py (không phải uvicorn CLI trực tiếp) — tự bootstrap + renew cert
# mTLS server qua Orchestrator trước khi phục vụ request nào (Giai đoạn 2 —
# xem app/tls_identity.py).
CMD ["python", "-m", "app.serve"]
