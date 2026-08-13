# Mục "Dựng TLS thật cho Keycloak/Orchestrator/Web" — trước đây dùng thẳng
# image gốc (image: quay.io/keycloak/keycloak:24.0 trong docker-compose.yml),
# giờ cần build riêng để thêm entrypoint wrapper tự lấy cert TLS qua
# Orchestrator lúc khởi động (xem fetch-cert.sh/entrypoint-wrapper.sh cùng
# thư mục — image gốc KHÔNG có curl/microdnf/python3/openssl để tự viết
# HTTP client kiểu thông thường, xem README.md).
FROM quay.io/keycloak/keycloak:24.0

# Ghi đè ENTRYPOINT gốc (/opt/keycloak/bin/kc.sh, xem README.md) — wrapper
# gọi lại đúng kc.sh đó ở dòng cuối, giữ nguyên mọi args/command hiện có
# trong docker-compose.yml (start-dev --import-realm), chỉ thêm 2 flag
# https + bootstrap cert trước đó.
#
# Image gốc tự khai USER keycloak (uid 1000, không phải root, kế thừa sang
# Dockerfile này) — RUN chmod sau COPY sẽ lỗi "Operation not permitted" vì
# user đó không sở hữu file ở "/" (build thật xác nhận, không phải suy
# đoán). COPY --chmod tự set quyền NGAY lúc copy (buildkit thực thi COPY với
# quyền root nội bộ, không phụ thuộc USER hiện hành) — tránh cần RUN riêng.
COPY --chmod=755 fetch-cert.sh /fetch-cert.sh
COPY --chmod=755 entrypoint-wrapper.sh /entrypoint-wrapper.sh

ENTRYPOINT ["/entrypoint-wrapper.sh"]
