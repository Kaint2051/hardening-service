#!/usr/bin/env bash
# Đổi cổng SSH thật của 1 host, có TỰ XÁC MINH kết nối trước khi coi thành
# công — xem app/jobs.py:run_ssh_port_change. Hạng mục rủi ro cao nhất còn
# lại của dự án (docs/architecture-proposal.md mục 8, rủi ro #5: không phải
# host nào cũng có phương án khôi phục ngoài băng thông nếu bị khoá mất SSH).
#
# MỖI bước là 1 kết nối SSH RIÊNG (không tái dùng session "coi như còn sống"
# từ bước trước) — nếu container/job chết giữa chừng, host luôn ở 1 trong 2
# trạng thái AN TOÀN:
#   (a) CHƯA đổi gì (chết ở bước 1-3: kết nối cổng cũ/backup/ghi file+reload
#       thất bại), hoặc
#   (b) đang nghe CẢ 2 cổng (chết ở bước 4: xác minh cổng mới thất bại) —
#       KHÔNG BAO GIỜ chỉ còn nghe đúng 1 cổng MÀ CHƯA được xác minh kết nối
#       được trước.
# Chỉ sau khi bước 4 xác minh cổng mới THÀNH CÔNG mới gỡ cổng cũ (bước 5).
#
# Input qua biến môi trường (TARGET_HOST/SSH_USER/SSH_KEY_B64 luôn có;
# SSH_CERT_B64 TUỲ CHỌN — thiếu nếu host dùng static SSH key, xem
# app/jobs.py:_get_ssh_dispatch_environment; giống scan.sh — dùng cert
# ephemeral cấp riêng cho job này, KHÔNG phải credential cũ như ca-bootstrap.sh):
#   CURRENT_PORT — cổng SSH hiện tại (Host.ssh_port trước khi đổi)
#   NEW_PORT — cổng muốn đổi sang
#
# Output: dòng PORT_CHANGE_STATUS=... — app/jobs.py CHỈ cập nhật
# Host.ssh_port khi thấy đúng "cutover_complete", never dựa exit code.
set -euo pipefail
: "${TARGET_HOST:?thiếu TARGET_HOST}"
: "${SSH_USER:?thiếu SSH_USER}"
: "${SSH_KEY_B64:?thiếu SSH_KEY_B64}"
SSH_CERT_B64="${SSH_CERT_B64:-}"
: "${CURRENT_PORT:?thiếu CURRENT_PORT}"
: "${NEW_PORT:?thiếu NEW_PORT}"

mkdir -p /tmp/ssh
echo "$SSH_KEY_B64" | base64 -d > /tmp/ssh/job_key
chmod 600 /tmp/ssh/job_key

TARGET="${SSH_USER}@${TARGET_HOST}"
SSH_BASE_OPTS=(-i /tmp/ssh/job_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes)
if [ -n "$SSH_CERT_B64" ]; then
  echo "$SSH_CERT_B64" | base64 -d > /tmp/ssh/job_key-cert.pub
  chmod 644 /tmp/ssh/job_key-cert.pub
  SSH_BASE_OPTS+=(-o CertificateFile=/tmp/ssh/job_key-cert.pub)
fi

# ssh_at PORT CMD... — 1 kết nối RIÊNG mỗi lần gọi, đúng tinh thần "mỗi bước
# tự đứng độc lập" ở trên.
ssh_at() {
  local port="$1"; shift
  ssh "${SSH_BASE_OPTS[@]}" -p "$port" "$TARGET" "$@"
}

# Ghi CẢ 2 dòng Port (cũ + mới) — directive Port CỘNG DỒN (sshd nghe TẤT CẢ
# cổng được khai), nhưng mặc định ngầm 22 NGỪNG áp dụng ngay khi có bất kỳ
# dòng Port nào xuất hiện ở bất kỳ file nào trong sshd_config.d — bỏ sót
# dòng cổng cũ ở đây sẽ tự ngắt cổng cũ TRƯỚC KHI kịp xác minh cổng mới (xem
# docstring app/jobs.py:run_ssh_port_change).
#
# restart (KHÔNG PHẢI reload) sshd — SIGHUP (điều "reload" gửi) chỉ khiến
# sshd re-đọc config cho hành vi RUNTIME (auth, ciphers...), KHÔNG mở thêm
# listening socket mới cho 1 dòng Port vừa thêm.
#
# PHÁT HIỆN systemd socket activation (ssh.socket) — XÁC NHẬN THẬT qua lần
# chạy đầu tiên trên host thật: nhiều bản Ubuntu 22.04+ (kể cả host lab dùng
# ở đây) dùng ssh.socket (ListenStream=22 TĨNH trong unit file riêng,
# Accept=no) để mở cổng lắng nghe, sshd chỉ NHẬN LẠI socket đã mở sẵn qua
# activation — sửa Port trong sshd_config lúc đó vô nghĩa với cổng THẬT SỰ
# đang nghe (sshd -T báo đúng cổng mới trong effective config, nhưng `ss
# -tlnp` sau restart vẫn chỉ thấy cổng cũ, vì ssh.socket mới là thứ thật sự
# giữ cổng). Khi phát hiện ssh.socket đang active: ghi đè ListenStream= qua
# drop-in (rỗng trước để XOÁ giá trị 22 kế thừa từ unit gốc — quy ước
# systemd cho directive dạng danh sách, thiếu dòng rỗng này sẽ cộng dồn
# nhầm thay vì thay thế), daemon-reload, restart ssh.socket (kéo theo
# ssh.service). Không có ssh.socket (hệ thống cũ hơn/không dùng socket
# activation): restart thẳng ssh.service như bình thường.
_run_stage_or_finalize_remote() {
  local port="$1" cur="$2" new="$3" mode="$4"  # mode: "stage" (2 cổng) | "finalize" (1 cổng)
  ssh_at "$port" "CUR='${cur}' NEW='${new}' MODE='${mode}' bash -s" <<'REMOTE_EOF'
set -e
if [ "$MODE" = "stage" ]; then
  printf 'Port %s\nPort %s\n' "$CUR" "$NEW" | sudo tee /etc/ssh/sshd_config.d/00-hardening-console-port.conf > /dev/null
else
  printf 'Port %s\n' "$NEW" | sudo tee /etc/ssh/sshd_config.d/00-hardening-console-port.conf > /dev/null
fi
sudo sshd -t
if systemctl is-active --quiet ssh.socket 2>/dev/null; then
  sudo mkdir -p /etc/systemd/system/ssh.socket.d
  if [ "$MODE" = "stage" ]; then
    printf '[Socket]\nListenStream=\nListenStream=%s\nListenStream=%s\n' "$CUR" "$NEW"
  else
    printf '[Socket]\nListenStream=\nListenStream=%s\n' "$NEW"
  fi | sudo tee /etc/systemd/system/ssh.socket.d/00-hardening-console-port.conf > /dev/null
  sudo systemctl daemon-reload
  sudo systemctl restart ssh.socket
elif [ -f /etc/debian_version ]; then
  sudo systemctl restart ssh
else
  sudo systemctl restart sshd
fi
REMOTE_EOF
}

set +e

echo "=== Buoc 1/6: ket noi cong HIEN TAI ($CURRENT_PORT) ==="
ssh_at "$CURRENT_PORT" 'true' 2>/tmp/step.log
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "PORT_CHANGE_STATUS=current_port_unreachable"
  cat /tmp/step.log >&2
  exit 1
fi

echo "=== Buoc 2/6: backup /etc/ssh TRUOC khi doi gi (nguyen tac cot loi #7) ==="
BACKUP_B64=$(ssh_at "$CURRENT_PORT" "tar czf - /etc/ssh 2>/dev/null" | base64 -w0)
RC=$?
if [ "$RC" -ne 0 ] || [ -z "$BACKUP_B64" ]; then
  echo "PORT_CHANGE_STATUS=backup_failed"
  exit 1
fi
echo "BACKUP_TAR_B64_BEGIN"
echo "$BACKUP_B64"
echo "BACKUP_TAR_B64_END"

echo "=== Buoc 3/6: ghi cau hinh nghe CA 2 cong (cu + moi), reload ==="
_run_stage_or_finalize_remote "$CURRENT_PORT" "$CURRENT_PORT" "$NEW_PORT" "stage" 2>/tmp/step.log
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "PORT_CHANGE_STATUS=stage_failed"
  cat /tmp/step.log >&2
  exit 1
fi

echo "=== Buoc 4/6: xac minh ket noi CONG MOI ($NEW_PORT) — cua an toan that su ==="
VERIFIED=1
for attempt in 1 2 3 4 5; do
  ssh_at "$NEW_PORT" 'true' 2>/tmp/step.log
  RC=$?
  if [ "$RC" -eq 0 ]; then
    VERIFIED=0
    break
  fi
  sleep 2
done
if [ "$VERIFIED" -ne 0 ]; then
  echo "PORT_CHANGE_STATUS=verify_failed"
  echo "Cong moi $NEW_PORT KHONG ket noi duoc sau 5 lan thu (~10s) — host VAN dang nghe CA 2 cong ($CURRENT_PORT va $NEW_PORT), KHONG mat ket noi. Khong go cong cu." >&2
  cat /tmp/step.log >&2
  exit 1
fi

echo "=== Buoc 5/6: da xac minh cong moi, go cong cu (finalize cutover) ==="
_run_stage_or_finalize_remote "$NEW_PORT" "$CURRENT_PORT" "$NEW_PORT" "finalize" 2>/tmp/step.log
RC=$?
if [ "$RC" -ne 0 ]; then
  # That bai SAU KHI da xac minh cong moi ket noi duoc o buoc 4 — khong tu
  # doan host dang o trang thai nao (co the cong cu da bi go mot phan truoc
  # khi reload loi), bao loi ro de operator tu kiem tra qua log job nay.
  echo "PORT_CHANGE_STATUS=finalize_failed"
  cat /tmp/step.log >&2
  exit 1
fi

echo "=== Buoc 6/6: xac minh lan cuoi cong moi SAU KHI finalize ==="
ssh_at "$NEW_PORT" 'true' 2>/tmp/step.log
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "PORT_CHANGE_STATUS=finalize_verify_failed"
  cat /tmp/step.log >&2
  exit 1
fi

echo "PORT_CHANGE_STATUS=cutover_complete"
exit 0
