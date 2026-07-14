#!/usr/bin/env bash
# Remediation qua Ansible (agentless, mục 7 roadmap: job_type="remediate-*").
#
# Nội dung remediation (playbook) đến từ scripts/content-signing/signed/,
# mount read-only bởi job-dispatcher tại /content (xem
# apps/job-dispatcher/app/main.py) — KHÔNG bake trong image này (khác các
# role dev-sec cài qua requirements.yml lúc build: đó là thư viện chung,
# playbook.yml trong bundle có thể include_role tới các role đó).
#
# Verify chữ ký bundle TRƯỚC khi chạy bất cứ gì — đúng nguyên tắc "verify
# hash script khớp bản đã ký trước khi chạy" (mục 4.3 architecture-proposal.md,
# áp dụng cùng tinh thần với Executor của Agent tự phát triển nhưng cho
# đường agentless). KHÔNG tự chế crypto — chỉ gọi gpg đã cài sẵn.
#
# Input qua biến môi trường (do job-dispatcher truyền vào lúc `docker run`,
# xem apps/orchestrator/app/jobs.py):
#   TARGET_HOST, SSH_USER, SSH_KEY_B64, SSH_CERT_B64 — giống scan.sh
#   REMEDIATION_REF — tên thư mục bundle trong /content/
#   DRY_RUN — "true" (ansible-playbook --check --diff, KHÔNG đổi gì) hoặc
#     "false" (apply thật — backup trước, xem bên dưới)
#   CONTENT_SIGNING_TRUSTED_FINGERPRINT — fingerprint GPG tin cậy; KHÔNG đọc
#     fingerprint tin cậy từ chính bundle đang verify, cùng nguyên tắc
#     scripts/content-signing/verify.sh
set -euo pipefail
: "${TARGET_HOST:?thiếu TARGET_HOST}"
: "${SSH_USER:?thiếu SSH_USER}"
: "${SSH_KEY_B64:?thiếu SSH_KEY_B64}"
: "${SSH_CERT_B64:?thiếu SSH_CERT_B64}"
: "${REMEDIATION_REF:?thiếu REMEDIATION_REF}"
: "${DRY_RUN:?thiếu DRY_RUN}"
: "${CONTENT_SIGNING_TRUSTED_FINGERPRINT:?thiếu CONTENT_SIGNING_TRUSTED_FINGERPRINT}"

BUNDLE_DIR="/content/${REMEDIATION_REF}"
DATA_FILE="${BUNDLE_DIR}/content.tar.gz"
SIG_FILE="${BUNDLE_DIR}/content.tar.gz.sig"
PLAYBOOK="${BUNDLE_DIR}/playbook.yml"

echo "=== Verify chữ ký bundle ${REMEDIATION_REF} ==="
if [ ! -f "$DATA_FILE" ] || [ ! -f "$SIG_FILE" ]; then
  echo "SCAN_JOB_STATUS=error"
  echo "Bundle ${REMEDIATION_REF} thiếu content.tar.gz hoặc content.tar.gz.sig tại ${BUNDLE_DIR}" >&2
  exit 1
fi

# --status-fd 1 in ra output máy đọc được, parse dòng VALIDSIG thay vì grep
# chuỗi text tiếng Anh dễ vỡ khi đổi ngôn ngữ/version gpg — cùng cơ chế
# scripts/content-signing/lib-gpg-fingerprint.sh:verified_signer_fingerprint.
GPG_STATUS=$(gpg --status-fd 1 --verify "$SIG_FILE" "$DATA_FILE" 2>/dev/null || true)
ACTUAL_FPR=$(echo "$GPG_STATUS" | awk '/^\[GNUPG:\] VALIDSIG/ {print $3; exit}')
if [ -z "$ACTUAL_FPR" ]; then
  echo "SCAN_JOB_STATUS=error"
  echo "Chữ ký bundle ${REMEDIATION_REF} không hợp lệ hoặc không verify được — TỪ CHỐI chạy." >&2
  exit 1
fi
if [ "$ACTUAL_FPR" != "$CONTENT_SIGNING_TRUSTED_FINGERPRINT" ]; then
  echo "SCAN_JOB_STATUS=error"
  echo "Bundle ${REMEDIATION_REF} được ký bởi ${ACTUAL_FPR}, không khớp fingerprint tin cậy — TỪ CHỐI chạy." >&2
  exit 1
fi
echo "Chữ ký hợp lệ, ký bởi ${ACTUAL_FPR}."

if [ ! -f "$PLAYBOOK" ]; then
  echo "SCAN_JOB_STATUS=error"
  echo "Bundle ${REMEDIATION_REF} không có playbook.yml" >&2
  exit 1
fi

mkdir -p /tmp/ssh
echo "$SSH_KEY_B64" | base64 -d > /tmp/ssh/job_key
echo "$SSH_CERT_B64" | base64 -d > /tmp/ssh/job_key-cert.pub
chmod 600 /tmp/ssh/job_key
chmod 644 /tmp/ssh/job_key-cert.pub

SSH_OPTS="-i /tmp/ssh/job_key -o CertificateFile=/tmp/ssh/job_key-cert.pub -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"
# Dùng biến môi trường ansible-core hỗ trợ sẵn thay vì nhúng option vào cú
# pháp inventory INI (dễ vỡ vì quoting) — cùng tinh thần dùng
# SSH_ADDITIONAL_OPTIONS của scan.sh cho oscap-ssh.
export ANSIBLE_HOST_KEY_CHECKING=False
export ANSIBLE_SSH_COMMON_ARGS="-o CertificateFile=/tmp/ssh/job_key-cert.pub -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"
export ANSIBLE_PRIVATE_KEY_FILE="/tmp/ssh/job_key"
export ANSIBLE_REMOTE_USER="${SSH_USER}"
echo "${TARGET_HOST}" > /tmp/inventory

set +e
if [ "$DRY_RUN" = "true" ]; then
  echo "=== Dry-run (--check --diff) — KHÔNG đổi gì trên host đích ==="
  DIFF_OUTPUT=$(ansible-playbook -i /tmp/inventory --check --diff "$PLAYBOOK" 2>&1)
  ANSIBLE_RC=$?
  echo "$DIFF_OUTPUT"
  echo "DIFF_OUTPUT_BEGIN"
  echo "$DIFF_OUTPUT"
  echo "DIFF_OUTPUT_END"
else
  echo "=== Backup cấu hình liên quan TRƯỚC khi remediate thật (nguyên tắc cốt lõi #7 architecture-proposal.md) ==="
  # Danh sách path cố định — đúng phạm vi 2 role dev-sec os-hardening/
  # ssh-hardening (requirements.yml) hay đụng chạm. MVP: chỉ đóng gói backup
  # vào result_summary, CHƯA có "1-click restore" tự động — xem README.
  BACKUP_B64=$(ssh $SSH_OPTS "${SSH_USER}@${TARGET_HOST}" \
    "tar czf - /etc/ssh /etc/pam.d /etc/sysctl.conf /etc/sysctl.d /etc/security /etc/login.defs 2>/dev/null" \
    | base64 -w0)
  echo "BACKUP_TAR_B64_BEGIN"
  echo "$BACKUP_B64"
  echo "BACKUP_TAR_B64_END"

  echo "=== Apply thật ==="
  ansible-playbook -i /tmp/inventory "$PLAYBOOK"
  ANSIBLE_RC=$?
fi
set -e

if [ "$ANSIBLE_RC" -ne 0 ]; then
  echo "SCAN_JOB_STATUS=error"
  exit 1
fi

echo "SCAN_JOB_STATUS=completed"
exit 0
