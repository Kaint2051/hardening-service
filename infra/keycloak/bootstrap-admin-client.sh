#!/usr/bin/env bash
# Chạy 1 lần để tạo client "orchestrator-admin" (service account Orchestrator
# dùng để tự gọi Keycloak Admin REST API cho tính năng Quản lý người dùng —
# xem app/keycloak_admin.py) trên Keycloak ĐANG CHẠY trên lab server.
#
# KHÔNG đủ để chỉ sửa infra/keycloak/realm-export.json rồi
# "docker compose up -d keycloak" — realm chỉ được import lúc container khởi
# động LẦN ĐẦU (xem infra/keycloak/README.md), state thật (client/user) nằm
# trong volume "keycloak-data" (H2 nhúng), không phải file JSON này. Phải tạo
# client trực tiếp vào realm đang sống bằng kcadm.sh, y hệt cách
# infra/step-ca/setup-provisioners.sh tạo provisioner trực tiếp vào step-ca
# đang chạy.
#
# Idempotent — chạy lại nhiều lần an toàn (bỏ qua bước tạo nếu client đã có).
#
# Yêu cầu: KEYCLOAK_ADMIN/KEYCLOAK_ADMIN_PASSWORD trong .env khớp với admin
# Keycloak thật (2 biến này ĐÃ có sẵn trong environment của container
# keycloak — không cần thêm biến mới).
set -euo pipefail

COMPOSE="docker compose"
SVC="keycloak"
REALM="hardening-console"
CLIENT_ID="orchestrator-admin"
KCADM="/opt/keycloak/bin/kcadm.sh"

# Cổng 8080 (HTTP nội bộ, KHÔNG publish ra host) — start-dev LUÔN tự bật lại
# HTTP dù có --http-enabled=false (xem comment thật trong docker-compose.yml,
# đã verify trên lab: log khởi động in "Listening on: http://0.0.0.0:8080").
# Gọi thẳng localhost từ TRONG container keycloak, không cần cert TLS gì cho
# 1 script vận hành chạy 1 lần thế này.
KC_URL="http://localhost:8080"

# kcadm.sh's format JSON mặc định (pretty-print) cho `get ... --fields X` là
# 1 object hoặc 1 mảng đúng 1 object dạng {"X" : "gia-tri"} — trích giá trị
# bằng grep/sed thay vì --format csv (chưa verify được cú pháp CSV thật của
# kcadm.sh, tránh đoán bừa lần 2 sau khi lần đầu đoán sai định dạng "create"
# trả về "Created new client with id '<uuid>'" thay vì UUID trần).
_kc_field() {
  local field="$1"
  grep -oE "\"$field\" : \"[^\"]*\"" | head -1 | sed -E "s/.*: \"([^\"]*)\"/\1/"
}

echo "==> Đăng nhập master realm bằng KEYCLOAK_ADMIN"
# KEYCLOAK_ADMIN/KEYCLOAK_ADMIN_PASSWORD KHÔNG có trong environment của
# chính script này (chạy trên shell lab server) — chỉ có trong environment
# CỦA CONTAINER keycloak (do docker-compose.yml đặt) — nên phải \$-escape để
# 2 biến này được CONTAINER tự expand, không phải shell lab server (nếu
# không sẽ lỗi "unbound variable"). Cùng kỹ thuật
# infra/step-ca/setup-provisioners.sh dùng cho DOCKER_STEPCA_INIT_PASSWORD.
$COMPOSE exec -T "$SVC" sh -c \
  "$KCADM config credentials --server '$KC_URL' --realm master --user \"\$KEYCLOAK_ADMIN\" --password \"\$KEYCLOAK_ADMIN_PASSWORD\""

echo "==> Kiểm tra client '$CLIENT_ID' đã tồn tại chưa"
EXISTING_ID=$($COMPOSE exec -T "$SVC" $KCADM get clients -r "$REALM" \
  -q clientId="$CLIENT_ID" --fields id | _kc_field id)

if [ -n "$EXISTING_ID" ]; then
  echo "==> Đã tồn tại (id=$EXISTING_ID), bỏ qua bước tạo"
  CLIENT_UUID="$EXISTING_ID"
else
  echo "==> Tạo client '$CLIENT_ID' (confidential, serviceAccountsEnabled=true, không flow tương tác nào khác)"
  CREATE_OUTPUT=$($COMPOSE exec -T "$SVC" $KCADM create clients -r "$REALM" \
    -s clientId="$CLIENT_ID" \
    -s name="Orchestrator Admin API (Keycloak service account)" \
    -s enabled=true \
    -s protocol=openid-connect \
    -s publicClient=false \
    -s standardFlowEnabled=false \
    -s implicitFlowEnabled=false \
    -s directAccessGrantsEnabled=false \
    -s serviceAccountsEnabled=true)
  # kcadm.sh in ra "Created new client with id '<uuid>'" (đã verify thật trên
  # lab — KHÔNG in UUID trần như lúc đầu đoán).
  CLIENT_UUID=$(echo "$CREATE_OUTPUT" | sed -n "s/.*id '\([^']*\)'.*/\1/p")
  if [ -z "$CLIENT_UUID" ]; then
    echo "LỖI: không trích được client UUID từ output: $CREATE_OUTPUT" >&2
    exit 1
  fi
fi

echo "==> Cấp role manage-users + view-users + query-users + view-realm (client realm-management) cho service account"
# view-realm PHÁT HIỆN QUA TEST THẬT trên lab — thiếu nó, GET
# /roles/{role}/users (dùng bởi keycloak_admin.py:list_users_with_roles để
# tránh N+1) trả 403 dù đã có manage-users+view-users+query-users. Endpoint
# liệt-kê-user-theo-role bị Keycloak coi là 1 phần của "xem cấu trúc realm"
# (roles thuộc phạm vi realm), không chỉ "xem user". Không chặn script nếu
# role đã được gán từ lần chạy trước (idempotent) — add-roles không phải lúc
# nào cũng no-op sạch khi role đã có, nhưng đây không phải lỗi cần dừng
# script, các bước sau (lấy secret) vẫn cần chạy.
$COMPOSE exec -T "$SVC" $KCADM add-roles -r "$REALM" \
  --uusername "service-account-$CLIENT_ID" \
  --cclientid realm-management \
  --rolename manage-users \
  --rolename view-users \
  --rolename query-users \
  --rolename view-realm \
  || echo "    (add-roles báo lỗi — có thể role đã được gán từ lần chạy trước, kiểm tra lại qua Keycloak console nếu nghi ngờ)"

echo "==> Lấy client secret"
SECRET=$($COMPOSE exec -T "$SVC" $KCADM get "clients/$CLIENT_UUID/client-secret" -r "$REALM" | _kc_field value)

if [ -z "$SECRET" ]; then
  echo "LỖI: không lấy được secret cho client uuid=$CLIENT_UUID" >&2
  exit 1
fi

echo ""
echo "==> XONG. Dán dòng dưới vào .env trên lab server (KHÔNG commit vào git):"
echo "KEYCLOAK_ADMIN_CLIENT_SECRET=$SECRET"
