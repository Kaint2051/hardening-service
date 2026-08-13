#!/usr/bin/env bash
# Bootstrap CA trust bằng credential CŨ (password/private key) — tương đương
# 3 bước đầu của ansible/playbooks/zero-to-ca-migration.yml (đẩy public key
# SSH User CA + bật TrustedUserCAKeys + reload sshd), chạy 1 LẦN DUY NHẤT
# lúc thêm host mới — xem app/jobs.py:trigger_ca_bootstrap.
#
# Credential CŨ CHỈ tồn tại trong bộ nhớ/đĩa tạm (/tmp) của CHÍNH container
# này, đúng thời gian chạy job — KHÔNG được Orchestrator lưu lại ở bất kỳ
# đâu (không DB, không log, không result_summary) trước/sau khi gọi job này.
#
# GIẢ ĐỊNH BẮT BUỘC: LEGACY_SSH_USER đăng nhập là root, HOẶC có sudo KHÔNG
# cần mật khẩu (NOPASSWD) — cùng giả định mặc định của `become: true` trong
# Ansible khi không truyền --ask-become-pass. Script TỪ CHỐI chạy tiếp nếu
# không (lỗi rõ ràng), KHÔNG cố truyền thêm 1 mật khẩu sudo riêng qua đường
# khác — giảm bề mặt phải xử lý bí mật thêm trong 1 tác vụ vốn đã rủi ro cao.
#
# Input qua biến môi trường:
#   TARGET_HOST, LEGACY_SSH_USER, CA_SSH_USER_PUBKEY (public key, KHÔNG bí mật)
#   TARGET_PORT — cổng SSH của host (Host.ssh_port, mặc định 22)
#   ĐÚNG 1 TRONG 2: LEGACY_SSH_PASSWORD_B64 hoặc LEGACY_SSH_PRIVATE_KEY_B64
set -euo pipefail
: "${TARGET_HOST:?thiếu TARGET_HOST}"
: "${LEGACY_SSH_USER:?thiếu LEGACY_SSH_USER}"
: "${CA_SSH_USER_PUBKEY:?thiếu CA_SSH_USER_PUBKEY}"
: "${TARGET_PORT:?thiếu TARGET_PORT}"

mkdir -p /tmp/legacy-ssh
chmod 700 /tmp/legacy-ssh
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -p "${TARGET_PORT}")

if [ -n "${LEGACY_SSH_PRIVATE_KEY_B64:-}" ]; then
  echo "$LEGACY_SSH_PRIVATE_KEY_B64" | base64 -d > /tmp/legacy-ssh/key
  chmod 600 /tmp/legacy-ssh/key
  SSH_OPTS+=(-i /tmp/legacy-ssh/key -o BatchMode=yes)
  run_ssh() { ssh "${SSH_OPTS[@]}" "$@"; }
elif [ -n "${LEGACY_SSH_PASSWORD_B64:-}" ]; then
  echo "$LEGACY_SSH_PASSWORD_B64" | base64 -d > /tmp/legacy-ssh/pass
  chmod 600 /tmp/legacy-ssh/pass
  # KHÔNG dùng BatchMode=yes ở nhánh này — nó tắt luôn cả việc ssh chấp nhận
  # trả lời password (không chỉ tắt prompt tương tác treo), sshpass sẽ không
  # bao giờ có cơ hội cấp password nếu bật cờ này.
  run_ssh() { sshpass -f /tmp/legacy-ssh/pass ssh "${SSH_OPTS[@]}" "$@"; }
else
  echo "CA_BOOTSTRAP_STATUS=failed"
  echo "LOI: can dung 1 trong LEGACY_SSH_PRIVATE_KEY_B64 hoac LEGACY_SSH_PASSWORD_B64" >&2
  exit 1
fi

TARGET="${LEGACY_SSH_USER}@${TARGET_HOST}"

set +e

echo "==> Buoc 1/4: kiem tra sudo khong-mat-khau (hoac dang nhap thang bang root)"
run_ssh "$TARGET" 'sudo -n true' 2>/tmp/legacy-ssh/step.log
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "CA_BOOTSTRAP_STATUS=failed"
  echo "LOI: LEGACY_SSH_USER khong co sudo khong-mat-khau tren may dich (hoac khong dang nhap duoc bang credential da cung cap)." >&2
  cat /tmp/legacy-ssh/step.log >&2
  exit 1
fi

echo "==> Buoc 2/4: day public key SSH User CA len may dich"
printf '%s\n' "$CA_SSH_USER_PUBKEY" | run_ssh "$TARGET" \
  'sudo tee /etc/ssh/user_ca.pub > /dev/null && sudo chown root:root /etc/ssh/user_ca.pub && sudo chmod 644 /etc/ssh/user_ca.pub' \
  2>/tmp/legacy-ssh/step.log
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "CA_BOOTSTRAP_STATUS=failed"
  echo "LOI: khong day duoc public key CA len may dich." >&2
  cat /tmp/legacy-ssh/step.log >&2
  exit 1
fi

echo "==> Buoc 3/4: bat TrustedUserCAKeys + validate + reload sshd"
run_ssh "$TARGET" '
  set -e
  if sudo grep -qE "^#?TrustedUserCAKeys[[:space:]]" /etc/ssh/sshd_config; then
    sudo sed -i -E "s|^#?TrustedUserCAKeys[[:space:]].*|TrustedUserCAKeys /etc/ssh/user_ca.pub|" /etc/ssh/sshd_config
  else
    echo "TrustedUserCAKeys /etc/ssh/user_ca.pub" | sudo tee -a /etc/ssh/sshd_config > /dev/null
  fi
  sudo sshd -t
  SSHD_SVC=sshd
  [ -f /etc/debian_version ] && SSHD_SVC=ssh
  sudo systemctl reload "$SSHD_SVC"
' 2>/tmp/legacy-ssh/step.log
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "CA_BOOTSTRAP_STATUS=failed"
  echo "LOI: khong bat duoc TrustedUserCAKeys hoac reload sshd that bai." >&2
  cat /tmp/legacy-ssh/step.log >&2
  exit 1
fi

echo "==> Buoc 4/4: hoan tat"
echo "CA_BOOTSTRAP_STATUS=trust_deployed"
exit 0
