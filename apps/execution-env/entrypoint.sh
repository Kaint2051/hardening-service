#!/usr/bin/env bash
# Dispatcher: job-dispatcher gọi container này với 1 subcommand ("scan",
# "remediate", "restore", "ssh-check", "ca-bootstrap", "static-ssh-key-
# bootstrap", "agent-install", "agent-uninstall" hoặc "ssh-port-change" —
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
  static-ssh-key-bootstrap)
    exec /usr/local/bin/static-ssh-key-bootstrap.sh
    ;;
  agent-install)
    exec /usr/local/bin/agent-install.sh
    ;;
  agent-uninstall)
    exec /usr/local/bin/agent-uninstall.sh
    ;;
  ssh-port-change)
    exec /usr/local/bin/ssh-port-change.sh
    ;;
  *)
    echo "Dùng: docker run <image> {scan|remediate|restore|ssh-check|ca-bootstrap|static-ssh-key-bootstrap|agent-install|agent-uninstall|ssh-port-change}" >&2
    exit 2
    ;;
esac
