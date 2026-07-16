#!/usr/bin/env bash
# Kiểm tra khả năng SSH tới host đích bằng cert ngắn hạn cấp riêng cho lần
# kiểm tra này — KHÔNG chạy scan/remediate gì, chỉ xác nhận kết nối được
# trước khi operator trigger scan/remediate thật (xem app/jobs.py:trigger_ssh_check).
#
# Input qua biến môi trường (giống scan.sh):
#   TARGET_HOST, SSH_USER, SSH_KEY_B64, SSH_CERT_B64
set -euo pipefail
: "${TARGET_HOST:?thiếu TARGET_HOST}"
: "${SSH_USER:?thiếu SSH_USER}"
: "${SSH_KEY_B64:?thiếu SSH_KEY_B64}"
: "${SSH_CERT_B64:?thiếu SSH_CERT_B64}"

mkdir -p /tmp/ssh
echo "$SSH_KEY_B64" | base64 -d > /tmp/ssh/job_key
echo "$SSH_CERT_B64" | base64 -d > /tmp/ssh/job_key-cert.pub
chmod 600 /tmp/ssh/job_key
chmod 644 /tmp/ssh/job_key-cert.pub

set +e
UNAME_OUTPUT=$(ssh \
  -i /tmp/ssh/job_key -o CertificateFile=/tmp/ssh/job_key-cert.pub \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=10 -o BatchMode=yes \
  "${SSH_USER}@${TARGET_HOST}" 'uname -a' 2>/tmp/ssh_stderr.log)
SSH_RC=$?
set -e

if [ "$SSH_RC" -eq 0 ]; then
  echo "SSH_CHECK_STATUS=ok"
  echo "SSH_CHECK_UNAME=$UNAME_OUTPUT"
  exit 0
fi

echo "SSH_CHECK_STATUS=failed"
echo "--- stderr ---"
cat /tmp/ssh_stderr.log
exit 1
