#!/bin/sh
# Chạy full backup Postgres qua pgBackRest — dùng: cron hàng ngày (chạy dưới
# user "postgres", vd `docker compose exec -u postgres postgres
# pgbackrest-backup.sh`) hoặc thủ công lúc cần backup ngay.
#
# Dùng: pgbackrest-backup.sh [full|diff]  (mặc định "full" — xem
# infra/postgres/README.md mục lịch backup lý do MVP chỉ dùng full, chưa
# cần diff/incr ở quy mô hiện tại).
set -eu
STANZA=hardening-console
TYPE="${1:-full}"

# `stanza-create` tự idempotent (an toàn gọi lại nếu đã tồn tại, chỉ verify)
# — gọi luôn mỗi lần thay vì tự đoán qua `info` (lệnh `info` vẫn exit 0 dù
# stanza chưa tồn tại, chỉ in "no stanzas found", không dùng được để check).
echo "==> Đảm bảo stanza '$STANZA' đã sẵn sàng (idempotent)."
pgbackrest --stanza="$STANZA" --log-level-console=info stanza-create

echo "==> Chạy backup type=$TYPE cho stanza '$STANZA'..."
pgbackrest --stanza="$STANZA" --type="$TYPE" --log-level-console=info backup
echo "==> Xong."
