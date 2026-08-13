#!/usr/bin/env bash
# ENTRYPOINT thật (thay /opt/keycloak/bin/kc.sh gốc — xem Dockerfile cùng
# thư mục) — lấy cert TLS TRƯỚC khi Keycloak thật khởi động, rồi exec sang
# kc.sh gốc kèm 2 flag https, giữ NGUYÊN mọi args docker-compose truyền vào
# (command: start-dev --import-realm).
set -e

/fetch-cert.sh bootstrap

CERT_DIR="${KEYCLOAK_CERT_DIR:-/opt/keycloak/certs}"

# Renew bằng cách RESTART container, KHÔNG hot-reload — Keycloak (Quarkus/
# Java) không có cách nào nạp lại cert TLS mà không khởi động lại process
# (khác job-dispatcher/agent-manager, nơi code Python/Go tự viết có thể
# hot-swap SSLContext). TTL provisioner 8h (setup-provisioners.sh) đủ dài để
# vài giây downtime mỗi lần renew (docker-compose `restart: unless-stopped`
# tự đưa container lên lại, entrypoint này chạy lại từ đầu và lấy cert mới)
# là đánh đổi hợp lý — đúng tinh thần "không over-engineer" xuyên suốt dự án,
# rẻ hơn nhiều so với tự viết cơ chế reload cho 1 binary không hỗ trợ sẵn.
# Chạy nền TRƯỚC dòng exec bên dưới — subshell này giữ PID riêng, không bị
# thay bởi exec (exec chỉ thay process ĐANG GỌI nó, không đụng con đã fork),
# nên `kill -TERM 1` vẫn gửi đúng tới tiến trình PID 1 hiện hành lúc đó
# (kc.sh, sau khi exec đã thay thế đúng script này ở CÙNG PID).
(
    sleep "${KEYCLOAK_CERT_RENEWAL_SECONDS:-14400}"
    echo "cert TLS sap den han renew - thoat de Docker restart tu lay cert moi"
    kill -TERM 1
) &

exec /opt/keycloak/bin/kc.sh "$@" \
    --https-certificate-file="${CERT_DIR}/tls.crt" \
    --https-certificate-key-file="${CERT_DIR}/tls.key"
