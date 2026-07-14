FROM python:3.12-slim

# step CLI — dùng để tự cấp SSH cert ngắn hạn cho mỗi job (app/ca_client.py),
# KHÔNG tái sử dụng cert của toán tử con người. Cài qua apt repo chính thức
# của Smallstep (GPG-signed) thay vì tự tải binary + tự ghim checksum thủ công.
RUN apt-get update && apt-get install -y --no-install-recommends curl gnupg ca-certificates \
    && curl -fsSL https://packages.smallstep.com/keys/apt/repo-signing-key.gpg -o /etc/apt/trusted.gpg.d/smallstep.asc \
    && echo 'deb [signed-by=/etc/apt/trusted.gpg.d/smallstep.asc] https://packages.smallstep.com/stable/debian debs main' > /etc/apt/sources.list.d/smallstep.list \
    && apt-get update && apt-get install -y --no-install-recommends step-cli \
    && apt-get purge -y curl gnupg && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
