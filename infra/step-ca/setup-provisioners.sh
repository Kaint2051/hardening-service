#!/usr/bin/env bash
# Chạy 1 lần sau khi step-ca đã lên (docker compose up -d step-ca) để:
#   1. Siết TTL của provisioner mặc định (orchestrator) xuống 5-15 phút cho SSH cert.
#   2. Thêm provisioner "agent-enrollment" riêng cho bootstrap token của agent (mục 4.3/4.4).
#
# Yêu cầu: STEPCA_PROVISIONER_PASSWORD trong .env khớp với password đã dùng để init.
set -euo pipefail

COMPOSE="docker compose"
SVC="step-ca"

echo "==> Siết TTL provisioner 'orchestrator' xuống 5-15 phút (mục 4.1)"
# Lưu ý: --x509-*-dur chỉ áp dụng cho x509 leaf cert. SSH user cert (loại thực
# sự dùng để cấp quyền đăng nhập không thường trực) phải siết riêng bằng
# --ssh-user-*-dur, nếu không step-ca sẽ dùng default rất dài (16h khi test
# thực tế trên lab server) — vi phạm nguyên tắc "no standing privilege".
$COMPOSE exec -T "$SVC" step ca provisioner update orchestrator \
  --ssh \
  --x509-min-dur=5m --x509-max-dur=15m --x509-default-dur=10m \
  --ssh-user-min-dur=5m --ssh-user-max-dur=15m --ssh-user-default-dur=10m

echo "==> Thêm provisioner 'agent-enrollment' cho bootstrap token agent (mục 4.3/4.4)"
# --password-file thay vì prompt tương tác (không có /dev/tty khi chạy qua
# `docker compose exec` từ một phiên non-interactive như CI/SSH exec_command).
# Bên trong container, biến này tên là DOCKER_STEPCA_INIT_PASSWORD (đặt bởi
# docker-compose.yml), KHÔNG phải STEPCA_PROVISIONER_PASSWORD (tên biến đó chỉ
# tồn tại ở phía host/.env).
$COMPOSE exec -T "$SVC" sh -c "echo \"\$DOCKER_STEPCA_INIT_PASSWORD\" > /tmp/provisioner-pw"
$COMPOSE exec -T "$SVC" step ca provisioner add agent-enrollment \
  --type JWK \
  --create \
  --password-file /tmp/provisioner-pw \
  --ssh \
  --x509-min-dur=1h --x509-max-dur=24h --x509-default-dur=8h
$COMPOSE exec -T "$SVC" rm -f /tmp/provisioner-pw

echo "==> Restart step-ca để áp dụng ca.json vừa cập nhật"
$COMPOSE restart "$SVC"

echo "==> Xong. Kiểm tra danh sách provisioner:"
$COMPOSE exec -T "$SVC" step ca provisioner list
