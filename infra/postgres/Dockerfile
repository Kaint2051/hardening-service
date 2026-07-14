FROM postgres:16-alpine

# pgBackRest chạy CÙNG filesystem với PGDATA (archive_command gọi trực tiếp
# `pgbackrest archive-push`) — cài thêm layer vào chính image Postgres, không
# tách container riêng, để tránh phức tạp chia sẻ PGDATA giữa 2 container ở
# quy mô 1 VM hiện tại (xem infra/postgres/README.md mục "Vì sao không sidecar").
RUN apk add --no-cache pgbackrest

COPY pgbackrest.conf /etc/pgbackrest/pgbackrest.conf
COPY backup.sh /usr/local/bin/pgbackrest-backup.sh
COPY docker-entrypoint-wrapper.sh /usr/local/bin/docker-entrypoint-wrapper.sh
RUN chmod +x /usr/local/bin/pgbackrest-backup.sh /usr/local/bin/docker-entrypoint-wrapper.sh

ENTRYPOINT ["docker-entrypoint-wrapper.sh"]
CMD ["postgres"]
