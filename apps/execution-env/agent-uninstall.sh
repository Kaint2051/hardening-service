#!/usr/bin/env bash
# Gỡ Agent (Reporter + Executor) khỏi máy đích bằng cert SSH ngắn hạn — chạy
# trước khi hard-delete Host record (xem app/hosts.py:delete_host). BEST-
# EFFORT: script này chỉ dừng/tắt/xoá tiến trình + file trên máy thật, KHÔNG
# revoke cert mTLS agent đang cầm (hệ thống không có CRL/OCSP) — cert cũ tự
# hết hiệu lực theo TTL tự nhiên nếu vì lý do gì đó service vẫn còn sống.
#
# Input qua biến môi trường (giống ssh-check.sh):
#   TARGET_HOST, SSH_USER, SSH_KEY_B64 — luôn có
#   SSH_CERT_B64 — TUỲ CHỌN (thiếu nếu host dùng static SSH key — xem
#     app/jobs.py:_get_ssh_dispatch_environment)
#   TARGET_PORT
set -euo pipefail
: "${TARGET_HOST:?thiếu TARGET_HOST}"
: "${SSH_USER:?thiếu SSH_USER}"
: "${SSH_KEY_B64:?thiếu SSH_KEY_B64}"
SSH_CERT_B64="${SSH_CERT_B64:-}"
: "${TARGET_PORT:?thiếu TARGET_PORT}"

mkdir -p /tmp/ssh
echo "$SSH_KEY_B64" | base64 -d > /tmp/ssh/job_key
chmod 600 /tmp/ssh/job_key
SSH_OPTS="-i /tmp/ssh/job_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes"
if [ -n "$SSH_CERT_B64" ]; then
  echo "$SSH_CERT_B64" | base64 -d > /tmp/ssh/job_key-cert.pub
  chmod 644 /tmp/ssh/job_key-cert.pub
  SSH_OPTS="$SSH_OPTS -o CertificateFile=/tmp/ssh/job_key-cert.pub"
fi

set +e
REMOTE_OUTPUT=$(ssh $SSH_OPTS -p "$TARGET_PORT" "${SSH_USER}@${TARGET_HOST}" 'bash -s' 2>/tmp/step_stderr.log <<'REMOTE_UNINSTALL_EOF'
set -uo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo "LOI: phai chay bang root." >&2
  exit 1
fi
# "|| true" tung buoc -- may co the chi cai Reporter (chua bao gio enable
# Executor, xem agent-install.sh) hoac dich vu da chet tu truoc, khong coi
# la loi neu 1 buoc khong co gi de dung/xoa.
systemctl disable --now hardening-agent.service 2>/dev/null || true
systemctl disable --now hardening-executor.service 2>/dev/null || true
rm -f /etc/systemd/system/hardening-agent.service /etc/systemd/system/hardening-executor.service
systemctl daemon-reload
rm -rf /etc/hardening-agent /var/cache/hardening-agent /run/hardening-agent
rm -f /opt/hardening-agent/agent /opt/hardening-agent/executor/executor
rmdir /opt/hardening-agent/executor /opt/hardening-agent 2>/dev/null || true
echo "Da go Reporter + Executor (service/file/state) khoi may nay."
exit 0
REMOTE_UNINSTALL_EOF
)
RC=$?
set -e

echo "$REMOTE_OUTPUT"
if [ "$RC" -ne 0 ]; then
  echo "AGENT_UNINSTALL_STATUS=failed"
  echo "--- stderr ---"
  cat /tmp/step_stderr.log
  exit 1
fi

echo "AGENT_UNINSTALL_STATUS=ok"
exit 0
