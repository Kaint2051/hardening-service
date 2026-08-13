#!/usr/bin/env bash
# Khôi phục cấu hình từ backup đã chụp lúc 1 remediate-apply trước đó (mục
# "1-click restore", xem app/jobs.py:run_restore + BACKUP_MAX_BYTES).
#
# Input qua biến môi trường (do job-dispatcher truyền vào lúc `docker run`,
# xem apps/orchestrator/app/jobs.py):
#   TARGET_HOST, SSH_USER, SSH_KEY_B64 — luôn có
#   SSH_CERT_B64 — TUỲ CHỌN (thiếu nếu host dùng static SSH key — xem
#     app/jobs.py:_get_ssh_dispatch_environment)
#   TARGET_PORT — cổng SSH của host (Host.ssh_port, mặc định 22)
#   BACKUP_TAR_B64_CHUNKS, BACKUP_TAR_B64_0..N — nội dung tar.gz (base64) chụp
#     bởi remediate.sh lúc apply, CHIA NHỎ thành nhiều biến (xem
#     app/jobs.py:_chunk_backup_env) — 1 biến env duy nhất chứa toàn bộ backup
#     (tới 2 MiB) sẽ vượt MAX_ARG_STRLEN (131072 byte/biến) của kernel Linux,
#     xác nhận qua thử thật, không phải suy đoán. Orchestrator đã từ chối
#     dispatch job này nếu backup bị truncate (BACKUP_MAX_BYTES) TRƯỚC khi
#     tới đây.
set -euo pipefail
: "${TARGET_HOST:?thiếu TARGET_HOST}"
: "${SSH_USER:?thiếu SSH_USER}"
: "${SSH_KEY_B64:?thiếu SSH_KEY_B64}"
SSH_CERT_B64="${SSH_CERT_B64:-}"
: "${TARGET_PORT:?thiếu TARGET_PORT}"
: "${BACKUP_TAR_B64_CHUNKS:?thiếu BACKUP_TAR_B64_CHUNKS}"

# set -u tự báo lỗi rõ ràng ("unbound variable") nếu BACKUP_TAR_B64_{i} nào
# đó thiếu so với BACKUP_TAR_B64_CHUNKS đã khai — không cần tự kiểm tra thêm
# (Orchestrator luôn sinh đủ số biến khớp count, xem app/jobs.py:_chunk_backup_env).
BACKUP_B64=""
for ((i = 0; i < BACKUP_TAR_B64_CHUNKS; i++)); do
  var="BACKUP_TAR_B64_${i}"
  BACKUP_B64="${BACKUP_B64}${!var}"
done

mkdir -p /tmp/ssh
echo "$SSH_KEY_B64" | base64 -d > /tmp/ssh/job_key
chmod 600 /tmp/ssh/job_key
SSH_OPTS="-i /tmp/ssh/job_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -p ${TARGET_PORT}"
if [ -n "$SSH_CERT_B64" ]; then
  echo "$SSH_CERT_B64" | base64 -d > /tmp/ssh/job_key-cert.pub
  chmod 644 /tmp/ssh/job_key-cert.pub
  SSH_OPTS="$SSH_OPTS -o CertificateFile=/tmp/ssh/job_key-cert.pub"
fi

echo "=== Giải nén backup lên host đích (ghi đè đúng các path đã backup lúc remediate-apply) ==="
set +e
echo "$BACKUP_B64" | base64 -d | ssh $SSH_OPTS "${SSH_USER}@${TARGET_HOST}" "tar xzf - -C /"
RESTORE_RC=$?
set -e
if [ "$RESTORE_RC" -ne 0 ]; then
  echo "SCAN_JOB_STATUS=error"
  echo "Giải nén backup lên host đích thất bại (rc=$RESTORE_RC)" >&2
  exit 1
fi

# sshd_config nằm trong phạm vi backup (/etc/ssh) — kiểm tra hợp lệ TRƯỚC khi
# reload, tránh tự khoá SSH nếu backup vì lý do nào đó không toàn vẹn. KHÔNG
# reload nếu test lỗi — để nguyên file đã ghi trên đĩa, báo lỗi rõ ràng cho
# operator tự kiểm tra tay thay vì reload mù rồi mất kết nối.
echo "=== Kiểm tra sshd_config sau restore trước khi reload ==="
set +e
SSHD_TEST=$(ssh $SSH_OPTS "${SSH_USER}@${TARGET_HOST}" "sshd -t" 2>&1)
SSHD_TEST_RC=$?
set -e
if [ "$SSHD_TEST_RC" -ne 0 ]; then
  echo "SCAN_JOB_STATUS=error"
  echo "sshd_config sau restore KHÔNG hợp lệ (sshd -t thất bại) — ĐÃ giải nén" >&2
  echo "backup lên đĩa nhưng KHÔNG reload sshd để tránh tự khoá SSH. Cần vào" >&2
  echo "tay kiểm tra. Chi tiết: $SSHD_TEST" >&2
  exit 1
fi
ssh $SSH_OPTS "${SSH_USER}@${TARGET_HOST}" "systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true"

echo "SCAN_JOB_STATUS=completed"
exit 0
