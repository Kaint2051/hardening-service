#!/usr/bin/env bash
# ENTRYPOINT thật (thay entrypoint gốc của image nginx:alpine) — lấy cert
# TLS TRƯỚC khi nginx thật khởi động, rồi chạy vòng lặp renew nền (hot-reload
# qua "nginx -s reload", không như Keycloak phải restart cả container — xem
# fetch-cert.sh), cuối cùng exec sang nginx thật ở foreground.
set -e

/fetch-cert.sh bootstrap
/fetch-cert.sh renew-loop &

exec nginx -g "daemon off;"
