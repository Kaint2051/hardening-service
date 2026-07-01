#!/bin/bash
# Chạy tự động bởi image postgres khi khởi tạo DB lần đầu (docker-entrypoint-initdb.d).
# Tạo role bị giới hạn quyền cho audit log — chỉ được INSERT/SELECT, KHÔNG có
# UPDATE/DELETE trên bảng audit_log (nguyên tắc 4 mục "audit log append-only").
#
# Lưu ý: GRANT cụ thể trên bảng audit_log được áp trong migration Alembic
# (0001_create_audit_log.py) vì bảng đó chưa tồn tại ở bước này — script này
# chỉ tạo role và quyền CONNECT tối thiểu.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${POSTGRES_AUDIT_USER}') THEN
            CREATE ROLE ${POSTGRES_AUDIT_USER} LOGIN PASSWORD '${POSTGRES_AUDIT_PASSWORD}';
        END IF;
    END
    \$\$;

    GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO ${POSTGRES_AUDIT_USER};
    -- Không GRANT gì trên schema/table ở đây — audit role hoàn toàn không có
    -- quyền gì cho tới khi migration tạo bảng audit_log và GRANT tường minh.
EOSQL
