#!/usr/bin/env bash
# Dispatcher: job-dispatcher gọi container này với 1 subcommand ("scan",
# "remediate" hoặc "restore" — xem README.md). Container bị huỷ ngay sau khi
# lệnh kết thúc (--rm phía job-dispatcher) — không có state nào tồn tại lại.
set -euo pipefail

case "${1:-}" in
  scan)
    exec /usr/local/bin/scan.sh
    ;;
  remediate)
    exec /usr/local/bin/remediate.sh
    ;;
  restore)
    exec /usr/local/bin/restore.sh
    ;;
  *)
    echo "Dùng: docker run <image> {scan|remediate|restore}" >&2
    exit 2
    ;;
esac
