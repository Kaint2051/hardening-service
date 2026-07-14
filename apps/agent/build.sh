#!/usr/bin/env bash
# Biên dịch agent thành 1 binary tĩnh cho linux/amd64 — chạy trong container
# golang:1.22-alpine (không cần cài Go trên host, đúng cách đã dùng cho mọi
# service khác trong dự án: build qua Docker, không build trên máy local).
#
# Ra binary tĩnh để scp lên máy đích rồi chạy qua systemd (xem
# hardening-agent.service + provision.sh + README.md mục "Triển khai qua
# systemd") — không có Dockerfile runtime riêng, agent không chạy trong
# container ở môi trường thật.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

docker run --rm \
  -v "$(pwd):/src" -w /src \
  -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 \
  golang:1.22-alpine \
  go build -o agent .

echo "==> Đã build xong: $(pwd)/agent"
