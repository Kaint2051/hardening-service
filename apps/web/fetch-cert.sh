#!/usr/bin/env bash
# Xin cert TLS server cho Web (nginx) qua Orchestrator — mục "Dựng TLS thật".
# KHÁC Keycloak (infra/keycloak/fetch-cert.sh, phải tự viết HTTP client bằng
# /dev/tcp vì image gốc không có gì) — image nginx:alpine có apk, nên cài
# thẳng curl+jq (Dockerfile) cho gọn/chắc hơn thay vì tự parse JSON tay.
set -euo pipefail

ORCH_HOST="${ORCHESTRATOR_INTERNAL_HOST:-orchestrator}"
ORCH_PORT="${ORCHESTRATOR_INTERNAL_PORT:-8001}"
SECRET="${WEB_TLS_SHARED_SECRET:?thieu WEB_TLS_SHARED_SECRET}"
CERT_DIR="${WEB_CERT_DIR:-/etc/nginx/certs}"

fetch_once() {
    local response
    if ! response="$(curl -fsS -X POST "http://${ORCH_HOST}:${ORCH_PORT}/internal/web/server-cert" \
        -H "Authorization: Bearer ${SECRET}")"; then
        return 1
    fi

    local cert key ca_root
    cert="$(printf '%s' "$response" | jq -r '.cert_pem')"
    key="$(printf '%s' "$response" | jq -r '.key_pem')"
    ca_root="$(printf '%s' "$response" | jq -r '.ca_root_pem')"
    if [ -z "$cert" ] || [ "$cert" = "null" ] || [ -z "$key" ] || [ "$key" = "null" ]; then
        echo "response khong co cert_pem/key_pem hop le" >&2
        return 1
    fi

    mkdir -p "$CERT_DIR"
    printf '%s' "$cert" > "${CERT_DIR}/tls.crt.tmp"
    printf '%s' "$key" > "${CERT_DIR}/tls.key.tmp"
    mv "${CERT_DIR}/tls.crt.tmp" "${CERT_DIR}/tls.crt"
    mv "${CERT_DIR}/tls.key.tmp" "${CERT_DIR}/tls.key"
    chmod 600 "${CERT_DIR}/tls.key"

    # Mục "thống nhất 1 port" — nginx.conf giờ reverse-proxy /api và
    # /realms|/resources sang chính orchestrator/keycloak, cần trust root CA
    # đó để "proxy_ssl_verify on" xác minh được cert của 2 service này (cùng
    # root CA đã ký cert cho chính web, response mint cert trả sẵn từ trước).
    if [ -n "$ca_root" ] && [ "$ca_root" != "null" ]; then
        printf '%s' "$ca_root" > "${CERT_DIR}/ca-root.crt.tmp"
        mv "${CERT_DIR}/ca-root.crt.tmp" "${CERT_DIR}/ca-root.crt"
    fi
}

bootstrap() {
    local attempt
    for attempt in $(seq 1 30); do
        if fetch_once; then
            echo "da lay cert TLS thanh cong (lan thu ${attempt})"
            return 0
        fi
        echo "chua lay duoc cert (lan ${attempt}/30), thu lai sau 2s..." >&2
        sleep 2
    done
    echo "KHONG lay duoc cert TLS sau 30 lan thu - dung lai" >&2
    return 1
}

renew_loop() {
    # KHÁC Keycloak (không hot-reload được, phải restart cả container) —
    # nginx -s reload nạp lại cert MỚI mà không rớt connection đang mở
    # (chuẩn nginx graceful reload), nên vòng lặp này KHÔNG cần thoát process.
    while true; do
        sleep "${WEB_CERT_RENEWAL_SECONDS:-14400}"
        if fetch_once; then
            nginx -s reload && echo "renew cert TLS + reload nginx thanh cong"
        else
            echo "renew cert TLS that bai, giu cert cu, thu lai o chu ky sau" >&2
        fi
    done
}

case "${1:-}" in
    bootstrap) bootstrap ;;
    renew-loop) renew_loop ;;
    *)
        echo "dung: $0 bootstrap|renew-loop" >&2
        exit 1
        ;;
esac
