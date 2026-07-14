#!/usr/bin/env bash
# Rehearsal + verify khôi phục PITR thật bằng chính repo backup pgBackRest
# đang dùng — dùng: ./infra/postgres/restore-drill.sh
#
# Quy trình: dựng service `postgres-restore-drill` (profile riêng, KHÔNG
# chạy cùng `docker compose up` mặc định — xem docker-compose.yml) trên
# volume HOÀN TOÀN RIÊNG, chạy `pgbackrest --delta restore` đọc-chỉ từ repo
# backup thật, khởi động Postgres trên dữ liệu vừa phục hồi, kiểm tra dữ
# liệu, rồi dọn sạch — KHÔNG đụng `postgres-data` (volume Postgres thật) ở
# bất kỳ bước nào.
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

# Nạp .env để lấy đúng POSTGRES_USER/POSTGRES_DB thật (không hardcode) —
# cùng cách các script vận hành khác trong repo tự nạp .env.
if [[ -f .env ]]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi
PG_USER="${POSTGRES_USER:?thiếu POSTGRES_USER trong .env}"
PG_DB="${POSTGRES_DB:?thiếu POSTGRES_DB trong .env}"

echo "==> [1/4] Build lại image restore-drill (đảm bảo dùng đúng pgbackrest.conf/backup.sh hiện tại)"
docker compose build postgres-restore-drill

echo "==> [2/4] Khởi động container restore-drill (pgbackrest --delta restore, rồi start Postgres trên dữ liệu vừa phục hồi)"
docker compose --profile restore-drill up -d postgres-restore-drill

echo "==> Chờ Postgres tạm sẵn sàng (tối đa ~150s — thời gian này CHÍNH LÀ RTO tham khảo, ghi vào README)"
START_TS=$(date +%s)
READY=0
for _ in $(seq 1 30); do
    if docker compose --profile restore-drill exec -T postgres-restore-drill pg_isready -U "$PG_USER" >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 5
done
END_TS=$(date +%s)

if [[ "$READY" -ne 1 ]]; then
    echo "LỖI: Postgres restore-drill không sẵn sàng sau 150s — xem log:" >&2
    docker compose --profile restore-drill logs postgres-restore-drill >&2
    docker compose --profile restore-drill rm -sf postgres-restore-drill || true
    exit 1
fi
echo "    Sẵn sàng sau $((END_TS - START_TS))s."

echo "==> [3/4] Verify dữ liệu đã phục hồi (audit_log — bảng append-only, có ở mọi lần chạy thật)"
docker compose --profile restore-drill exec -T postgres-restore-drill \
    psql -U "$PG_USER" -d "$PG_DB" -c "SELECT count(*) AS audit_log_rows, max(id) AS max_id FROM audit_log;"

echo "==> [4/4] Dọn sạch (container + volume RIÊNG của restore-drill — KHÔNG đụng postgres-data thật)"
docker compose --profile restore-drill rm -sf postgres-restore-drill
VOL_ID=$(docker volume ls -q --filter "label=com.docker.compose.volume=postgres-restore-drill-data")
if [[ -n "$VOL_ID" ]]; then
    docker volume rm $VOL_ID >/dev/null
fi

echo "==> XONG. Đối chiếu số dòng/max_id ở trên với dữ liệu thật lúc chạy drill để xác nhận PITR đúng."
