#!/usr/bin/env bash
# Dispatcher: job-dispatcher gọi container này với 1 subcommand ("scan",
# "remediate", "restore", "ssh-check", "ca-bootstrap" hoặc "agent-install" —
# xem README.md). Container bị huỷ ngay sau khi lệnh kết thúc (--rm phía
# job-dispatcher) — không có state nào tồn tại lại.
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
  ssh-check)
    exec /usr/local/bin/ssh-check.sh
    ;;
  ca-bootstrap)
    exec /usr/local/bin/ca-bootstrap.sh
    ;;
  agent-install)
    exec /usr/local/bin/agent-install.sh
    ;;
  *)
    echo "Dùng: docker run <image> {scan|remediate|restore|ssh-check|ca-bootstrap|agent-install}" >&2
    exit 2
    ;;
esac
