#!/usr/bin/env bash
# Biên dịch Executor thành 1 binary tĩnh RIÊNG với Reporter (../build.sh) —
# 2 tiến trình tách biệt đúng thiết kế mục 4.3 architecture-proposal.md, dù
# cùng module Go. Build qua container golang:1.22-alpine (không cần Go trên
# host), giống mọi service Go khác trong dự án.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

docker run --rm \
  -v "$(pwd)/..:/src" -w /src \
  -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 \
  golang:1.22-alpine \
  go build -o executor/executor ./executor

echo "==> Đã build xong: $(pwd)/executor"
