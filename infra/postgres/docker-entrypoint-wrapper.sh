#!/bin/sh
# Wrapper chạy TRƯỚC entrypoint gốc của image postgres — volume Docker mới
# `pgbackrest-repo` (mount /var/lib/pgbackrest) được tạo mặc định owner root,
# nhưng archive_command/backup.sh chạy dưới user "postgres" (do
# docker-entrypoint.sh gốc tự gosu xuống) — chown 1 lần ở đây trước khi
# entrypoint gốc hạ quyền, không đụng gì tới logic init PGDATA đã có sẵn của
# image chính thức.
set -e
mkdir -p /var/lib/pgbackrest /var/log/pgbackrest 2>/dev/null || true
# `|| true`: container restore-drill (docker-compose.yml) mount
# /var/lib/pgbackrest DẠNG READ-ONLY (chỉ đọc repo backup thật, không được
# ghi) — chown trên mount `:ro` luôn lỗi ("Read-only file system"), CHẤP
# NHẬN ĐƯỢC vì mount đó chỉ cần đọc được (mode mặc định đã world-readable),
# không cần đổi owner. Ở service postgres chính (mount ghi được), chown vẫn
# chạy đúng như thường — `|| true` không che lỗi thật nào ở đó vì thao tác
# này luôn thành công trên filesystem ghi được.
chown -R postgres:postgres /var/lib/pgbackrest /var/log/pgbackrest 2>/dev/null || true
exec docker-entrypoint.sh "$@"
