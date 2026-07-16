#!/usr/bin/env bash
# Remote-deploy Agent tự động (mục "sao ko remote deploy" — xem
# app/agents.py:trigger_agent_install) — verify chữ ký bundle TRƯỚC khi đẩy
# bất cứ gì lên máy đích (cùng nguyên tắc remediate.sh), scp binary +
# provision.sh + 2 systemd unit qua cert SSH ngắn hạn, SSH vào chạy cài đặt.
# KHÔNG cần operator tự SSH/paste tay (khác _build_agent_install_script cũ,
# vẫn giữ làm phương án dự phòng). Chỉ khả thi cho host ĐÃ
# trust_deployed/migrated — dùng cert ephemeral, KHÔNG cần legacy credential
# nào (khác ca-bootstrap.sh, vốn chạy TRƯỚC khi CA trust tồn tại).
#
# Input qua biến môi trường:
#   TARGET_HOST, SSH_USER, SSH_KEY_B64, SSH_CERT_B64 — giống ssh-check.sh
#   AGENT_HOSTNAME — hostname trong Host Registry (KHÁC TARGET_HOST — đó là
#     ip_address; agent tự ghi vào agent.env để không phụ thuộc hostname hệ
#     điều hành thật của máy đích có khớp registry hay không)
#   AGENT_BUNDLE_REF — tên thư mục bundle trong /content/
#   AGENT_BUNDLE_TRUSTED_FINGERPRINT — fingerprint GPG tin cậy, cùng
#     nguyên tắc remediate.sh (KHÔNG đọc fingerprint tin cậy từ chính bundle)
#   AGENT_ENROLL_TOKEN_B64 — bootstrap token OTT (base64), xem app/agents.py
#   CA_ROOT_PEM_B64 — root cert step-ca (base64, không bí mật)
#   AGENT_MANAGER_PUBLIC_URL — địa chỉ Agent Manager THẬT (settings.
#     agent_manager_public_url) — hardening-agent.service mặc định
#     "https://localhost:8443" (chỉ đúng khi Agent Manager chạy CÙNG máy),
#     PHẢI ghi đè qua agent.env cho MỌI host thật khác — thiếu bước này agent
#     "cài xong" nhưng KHÔNG BAO GIỜ enroll được (lỗi âm thầm đã gặp thật khi
#     cài lên host khác máy chạy Agent Manager).
#
# Bundle content.tar.gz PHẢI chứa đúng 5 file ở gốc: agent, executor,
# provision.sh, hardening-agent.service, hardening-executor.service — xem
# apps/agent/README.md mục "Đóng gói bundle cho remote-deploy".
#
# Chỉ enable hardening-agent.service (Reporter) — KHÔNG tự bật
# hardening-executor.service (Active Response), cùng hành vi
# _build_agent_install_script cũ: Executor cần executor.env
# (EXECUTOR_TRUSTED_SIGNER_FINGERPRINT) tạo tay trước, tránh bật nhầm trước
# khi pentest riêng (mục 4.3 architecture-proposal.md).
set -euo pipefail
: "${TARGET_HOST:?thiếu TARGET_HOST}"
: "${SSH_USER:?thiếu SSH_USER}"
: "${SSH_KEY_B64:?thiếu SSH_KEY_B64}"
: "${SSH_CERT_B64:?thiếu SSH_CERT_B64}"
: "${AGENT_BUNDLE_REF:?thiếu AGENT_BUNDLE_REF}"
: "${AGENT_BUNDLE_TRUSTED_FINGERPRINT:?thiếu AGENT_BUNDLE_TRUSTED_FINGERPRINT}"
: "${AGENT_ENROLL_TOKEN_B64:?thiếu AGENT_ENROLL_TOKEN_B64}"
: "${CA_ROOT_PEM_B64:?thiếu CA_ROOT_PEM_B64}"
: "${AGENT_HOSTNAME:?thiếu AGENT_HOSTNAME}"
: "${AGENT_MANAGER_PUBLIC_URL:?thiếu AGENT_MANAGER_PUBLIC_URL}"

BUNDLE_DIR="/content/${AGENT_BUNDLE_REF}"
DATA_FILE="${BUNDLE_DIR}/content.tar.gz"
SIG_FILE="${BUNDLE_DIR}/content.tar.gz.sig"

echo "=== Verify chữ ký bundle ${AGENT_BUNDLE_REF} ==="
if [ ! -f "$DATA_FILE" ] || [ ! -f "$SIG_FILE" ]; then
  echo "AGENT_INSTALL_STATUS=failed"
  echo "Bundle ${AGENT_BUNDLE_REF} thiếu content.tar.gz hoặc content.tar.gz.sig tại ${BUNDLE_DIR}" >&2
  exit 1
fi

GPG_STATUS=$(gpg --status-fd 1 --verify "$SIG_FILE" "$DATA_FILE" 2>/dev/null || true)
ACTUAL_FPR=$(echo "$GPG_STATUS" | awk '/^\[GNUPG:\] VALIDSIG/ {print $3; exit}')
if [ -z "$ACTUAL_FPR" ]; then
  echo "AGENT_INSTALL_STATUS=failed"
  echo "Chữ ký bundle ${AGENT_BUNDLE_REF} không hợp lệ hoặc không verify được — TỪ CHỐI cài." >&2
  exit 1
fi
if [ "$ACTUAL_FPR" != "$AGENT_BUNDLE_TRUSTED_FINGERPRINT" ]; then
  echo "AGENT_INSTALL_STATUS=failed"
  echo "Bundle ${AGENT_BUNDLE_REF} được ký bởi ${ACTUAL_FPR}, không khớp fingerprint tin cậy — TỪ CHỐI cài." >&2
  exit 1
fi
echo "Chữ ký hợp lệ, ký bởi ${ACTUAL_FPR}."

echo "=== Giải nén bundle ==="
mkdir -p /tmp/agent-bundle
tar xzf "$DATA_FILE" -C /tmp/agent-bundle
for f in agent executor provision.sh hardening-agent.service hardening-executor.service; do
  if [ ! -f "/tmp/agent-bundle/$f" ]; then
    echo "AGENT_INSTALL_STATUS=failed"
    echo "Bundle ${AGENT_BUNDLE_REF} thiếu file '$f' sau khi giải nén — xem apps/agent/README.md mục đóng gói." >&2
    exit 1
  fi
done
chmod +x /tmp/agent-bundle/agent /tmp/agent-bundle/executor /tmp/agent-bundle/provision.sh

mkdir -p /tmp/ssh
echo "$SSH_KEY_B64" | base64 -d > /tmp/ssh/job_key
echo "$SSH_CERT_B64" | base64 -d > /tmp/ssh/job_key-cert.pub
chmod 600 /tmp/ssh/job_key
chmod 644 /tmp/ssh/job_key-cert.pub
echo "$AGENT_ENROLL_TOKEN_B64" | base64 -d > /tmp/agent-bundle/enroll-token
echo "$CA_ROOT_PEM_B64" | base64 -d > /tmp/agent-bundle/ca-root.crt
cat > /tmp/agent-bundle/agent.env <<EOF
AGENT_MANAGER_URL=${AGENT_MANAGER_PUBLIC_URL}
AGENT_HOSTNAME=${AGENT_HOSTNAME}
EOF

SSH_OPTS="-i /tmp/ssh/job_key -o CertificateFile=/tmp/ssh/job_key-cert.pub -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes"

set +e

echo "=== Tạo thư mục tạm trên máy đích ==="
ssh $SSH_OPTS "${SSH_USER}@${TARGET_HOST}" 'mkdir -p /tmp/agent-install' 2>/tmp/step_stderr.log
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "AGENT_INSTALL_STATUS=failed"
  echo "--- stderr (mkdir máy đích) ---"
  cat /tmp/step_stderr.log
  exit 1
fi

echo "=== Copy binary + provision.sh + unit + token/ca-root ==="
scp $SSH_OPTS \
  /tmp/agent-bundle/agent /tmp/agent-bundle/executor /tmp/agent-bundle/provision.sh \
  /tmp/agent-bundle/hardening-agent.service /tmp/agent-bundle/hardening-executor.service \
  /tmp/agent-bundle/enroll-token /tmp/agent-bundle/ca-root.crt /tmp/agent-bundle/agent.env \
  "${SSH_USER}@${TARGET_HOST}:/tmp/agent-install/" 2>/tmp/step_stderr.log
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "AGENT_INSTALL_STATUS=failed"
  echo "--- stderr (scp) ---"
  cat /tmp/step_stderr.log
  exit 1
fi

echo "=== Chạy cài đặt trên máy đích ==="
REMOTE_OUTPUT=$(ssh $SSH_OPTS "${SSH_USER}@${TARGET_HOST}" 'bash -s' 2>/tmp/step_stderr.log <<'REMOTE_SETUP_EOF'
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo "LOI: phai chay bang root." >&2
  exit 1
fi
mkdir -p /opt/hardening-agent/executor
install -m 0755 /tmp/agent-install/agent /opt/hardening-agent/agent
install -m 0755 /tmp/agent-install/executor /opt/hardening-agent/executor/executor
bash /tmp/agent-install/provision.sh
umask 077
install -m 0600 /tmp/agent-install/enroll-token /etc/hardening-agent/enroll-token
install -m 0644 /tmp/agent-install/ca-root.crt /etc/hardening-agent/ca-root.crt
install -m 0644 /tmp/agent-install/agent.env /etc/hardening-agent/agent.env
chown hardening-agent:hardening-agent /etc/hardening-agent/enroll-token /etc/hardening-agent/ca-root.crt /etc/hardening-agent/agent.env
install -m 0644 /tmp/agent-install/hardening-agent.service /etc/systemd/system/hardening-agent.service
install -m 0644 /tmp/agent-install/hardening-executor.service /etc/systemd/system/hardening-executor.service
systemctl daemon-reload
systemctl enable hardening-agent.service
# restart (không phải "enable --now") -- neu service dang chay tu lan cai
# truoc, "enable --now" KHONG lam gi vi da active, binary/agent.env moi ghi
# se KHONG duoc ap dung cho toi khi restart/reboot thu cong -- phat hien
# thuc te khi cai lai tren host da co Agent chay tu lan truoc (agent.env
# moi khong co hieu luc, Agent van dung config cu).
systemctl restart hardening-agent.service
rm -rf /tmp/agent-install
echo "Reporter da chay -- xem: journalctl -u hardening-agent -f"
echo "Executor (Active Response) CHUA duoc bat tu dong -- tao truoc"
echo "/etc/hardening-agent/executor.env (EXECUTOR_TRUSTED_SIGNER_FINGERPRINT=...)"
echo "roi chay tay: systemctl enable --now hardening-executor.service"
REMOTE_SETUP_EOF
)
RC=$?
set -e

echo "$REMOTE_OUTPUT"
if [ "$RC" -ne 0 ]; then
  echo "AGENT_INSTALL_STATUS=failed"
  echo "--- stderr (cài đặt trên máy đích) ---"
  cat /tmp/step_stderr.log
  exit 1
fi

echo "AGENT_INSTALL_STATUS=ok"
exit 0
