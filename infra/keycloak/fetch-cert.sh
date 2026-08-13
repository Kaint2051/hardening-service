#!/usr/bin/env bash
# Xin cert TLS server cho Keycloak qua Orchestrator — image gốc
# (quay.io/keycloak/keycloak:24.0, RHEL9 UBI tối giản) KHÔNG có curl/
# microdnf/python3/openssl/jq (đã verify thật, xem README.md thư mục này),
# chỉ có bash + coreutils cơ bản. Dùng `/dev/tcp` (giả file có sẵn trong
# bash, không cần cài gì thêm) tự viết 1 HTTP client tối giản CHỈ đủ cho
# đúng nhu cầu này — response JSON PHẲNG, đúng 3 field (cert_pem/key_pem/
# ca_root_pem, xem app/schemas.py:AgentVerifyEnrollResponse), không mảng/
# không lồng nhau, nên không cần jq.
set -u

ORCH_HOST="${ORCHESTRATOR_INTERNAL_HOST:-orchestrator}"
ORCH_PORT="${ORCHESTRATOR_INTERNAL_PORT:-8001}"
CERT_DIR="${KEYCLOAK_CERT_DIR:-/opt/keycloak/certs}"

_fetch_once() {
    local secret="$1"
    exec 3<>"/dev/tcp/${ORCH_HOST}/${ORCH_PORT}" || return 1
    printf 'POST /internal/keycloak/server-cert HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' \
        "$ORCH_HOST" "$secret" >&3

    local response
    response="$(cat <&3)"
    exec 3>&- 2>/dev/null
    # đóng luôn phía ghi (dù đã đóng cả fd 3 ở dòng trên, no-op an toàn nếu
    # hệ thống đã tự đóng) — không có gì phải làm thêm, giữ dòng này để rõ ý.

    local status_line
    status_line="$(printf '%s\n' "$response" | head -n1)"
    case "$status_line" in
        *" 200 "*) ;;
        *)
            echo "loi xin cert (HTTP): ${status_line:-khong co response}" >&2
            return 1
            ;;
    esac

    # Body nằm sau dòng trống đầu tiên (CRLF CRLF) — cách tách chuẩn của
    # HTTP/1.1, response ở đây luôn Content-Length (JSON nhỏ, không chunked).
    local body cert_esc key_esc
    body="${response#*$'\r\n\r\n'}"
    cert_esc="$(printf '%s' "$body" | sed -n 's/.*"cert_pem":"\([^"]*\)".*/\1/p')"
    key_esc="$(printf '%s' "$body" | sed -n 's/.*"key_pem":"\([^"]*\)".*/\1/p')"
    if [ -z "$cert_esc" ] || [ -z "$key_esc" ]; then
        echo "khong parse duoc cert_pem/key_pem tu response JSON" >&2
        return 1
    fi

    mkdir -p "$CERT_DIR"
    # printf '%b' tự unescape "\n" (2 ký tự backslash+n trong JSON) thành
    # dòng mới thật — PEM base64 không chứa backslash nào khác nên an toàn,
    # không cần sed/tr xử lý newline riêng.
    printf '%b' "$cert_esc" > "${CERT_DIR}/tls.crt.tmp"
    printf '%b' "$key_esc" > "${CERT_DIR}/tls.key.tmp"
    mv "${CERT_DIR}/tls.crt.tmp" "${CERT_DIR}/tls.crt"
    mv "${CERT_DIR}/tls.key.tmp" "${CERT_DIR}/tls.key"
    chmod 600 "${CERT_DIR}/tls.key"
}

bootstrap() {
    local secret="${KEYCLOAK_TLS_SHARED_SECRET:?thieu KEYCLOAK_TLS_SHARED_SECRET}"
    local attempt=1
    # 30 lần x 2s = tối đa 60s — cùng deadline job-dispatcher/agent-manager
    # đang dùng cho bootstrap_blocking (Orchestrator có thể chưa kịp
    # alembic-migrate + tự mint cert của chính nó xong).
    while [ "$attempt" -le 30 ]; do
        if _fetch_once "$secret"; then
            echo "da lay cert TLS thanh cong (lan thu ${attempt})"
            return 0
        fi
        echo "chua lay duoc cert (lan ${attempt}/30), thu lai sau 2s..." >&2
        attempt=$((attempt + 1))
        sleep 2
    done
    echo "KHONG lay duoc cert TLS sau 30 lan thu - dung lai" >&2
    return 1
}

case "${1:-}" in
    bootstrap) bootstrap ;;
    *)
        echo "dung: $0 bootstrap" >&2
        exit 1
        ;;
esac
