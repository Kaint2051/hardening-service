#!/usr/bin/env bash
# Kiểm tra khả năng SSH tới host đích bằng cert ngắn hạn cấp riêng cho lần
# kiểm tra này — KHÔNG chạy scan/remediate gì, chỉ xác nhận kết nối được
# trước khi operator trigger scan/remediate thật (xem app/jobs.py:trigger_ssh_check).
#
# Input qua biến môi trường (giống scan.sh):
#   TARGET_HOST, SSH_USER, SSH_KEY_B64 — luôn có
#   SSH_CERT_B64 — TUỲ CHỌN (thiếu nếu host dùng static SSH key — xem
#     app/jobs.py:_get_ssh_dispatch_environment)
#   TARGET_PORT — cổng SSH của host (Host.ssh_port, mặc định 22)
set -euo pipefail
echo "##PROGRESS## 10 preparing"
: "${TARGET_HOST:?thiếu TARGET_HOST}"
: "${SSH_USER:?thiếu SSH_USER}"
: "${SSH_KEY_B64:?thiếu SSH_KEY_B64}"
SSH_CERT_B64="${SSH_CERT_B64:-}"
: "${TARGET_PORT:?thiếu TARGET_PORT}"

mkdir -p /tmp/ssh
echo "$SSH_KEY_B64" | base64 -d > /tmp/ssh/job_key
chmod 600 /tmp/ssh/job_key
SSH_OPTS=(-i /tmp/ssh/job_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes)
if [ -n "$SSH_CERT_B64" ]; then
  echo "$SSH_CERT_B64" | base64 -d > /tmp/ssh/job_key-cert.pub
  chmod 644 /tmp/ssh/job_key-cert.pub
  SSH_OPTS+=(-o CertificateFile=/tmp/ssh/job_key-cert.pub)
fi

echo "##PROGRESS## 40 connecting"

# Lấy LUÔN thông tin OS/kernel/phần cứng trong CÙNG 1 phiên SSH (không mở
# thêm kết nối riêng) — mục "sau khi test SSH thành công thì lấy thông tin
# máy". Mỗi giá trị in ra 1 dòng "SSH_CHECK_<KEY>=<value>", đúng quy ước
# app/jobs.py:_parse_ssh_check_summary tự nhặt mọi dòng có tiền tố đó.
#
# Nguyên tắc khi soạn đoạn remote này:
#   - CHỈ ĐỌC (cat/uname/df/nproc) — test SSH không được đổi gì trên máy đích.
#   - Mọi lệnh đều `|| true` / có giá trị mặc định: máy thiếu 1 file/tool
#     (container tối giản, distro lạ) KHÔNG được làm cả job fail — phần kết
#     nối được mới là thứ job này kiểm tra.
#   - `tr -d '\n'` + cắt độ dài từng giá trị: 1 host bị chiếm có thể trả
#     chuỗi khổng lồ/nhiều dòng để bơm phồng result_summary hoặc chèn thêm
#     dòng "SSH_CHECK_..." giả — cắt ở đây và parser phía Orchestrator chỉ
#     nhận key nằm trong allowlist (xem _SSH_CHECK_SYSTEM_KEYS).
REMOTE_PROBE='
set -u
say() { printf "SSH_CHECK_%s=%s\n" "$1" "$(printf "%s" "$2" | tr -d "\n" | cut -c1-200)"; }
. /etc/os-release 2>/dev/null || true
say OS_ID "${ID:-}"
say OS_VERSION_ID "${VERSION_ID:-}"
say OS_PRETTY "${PRETTY_NAME:-}"
say KERNEL "$(uname -r 2>/dev/null || echo unknown)"
say ARCH "$(uname -m 2>/dev/null || echo unknown)"
say CPU_MODEL "$(grep -m1 "^model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed "s/^ *//" || echo unknown)"
say CPU_CORES "$(nproc 2>/dev/null || echo unknown)"
# CỐ Ý không dùng awk ở 2 dòng dưới: chuỗi này đi qua 3 lớp shell (bash local
# -> ssh -> shell máy đích), mà "$2" của awk phải escape khác nhau ở mỗi lớp
# — đã thử và vỡ thật ("backslash not last character on line", cả 2 giá trị
# thành "unknown"). tr -s + cut không có ký tự nào cần escape nên qua bao
# nhiêu lớp cũng nguyên vẹn.
say MEM_TOTAL_KB "$(grep -m1 "^MemTotal:" /proc/meminfo 2>/dev/null | tr -s " " | cut -d" " -f2 || echo unknown)"
say DISK_ROOT "$(df -h / 2>/dev/null | tail -1 | tr -s " " | cut -d" " -f2,4 | tr " " "/" || echo unknown)"
say VIRT "$(systemd-detect-virt 2>/dev/null || echo unknown)"
say UPTIME_SEC "$(cut -d. -f1 /proc/uptime 2>/dev/null || echo unknown)"
uname -a 2>/dev/null | sed "s/^/SSH_CHECK_UNAME=/" || true
'

set +e
PROBE_OUTPUT=$(ssh "${SSH_OPTS[@]}" -p "$TARGET_PORT" \
  "${SSH_USER}@${TARGET_HOST}" "$REMOTE_PROBE" 2>/tmp/ssh_stderr.log)
SSH_RC=$?
set -e

if [ "$SSH_RC" -eq 0 ]; then
  echo "SSH_CHECK_STATUS=ok"
  # In nguyên khối đã thu — từng dòng đã đúng định dạng SSH_CHECK_<KEY>=...
  echo "$PROBE_OUTPUT"
  exit 0
fi

echo "SSH_CHECK_STATUS=failed"
echo "--- stderr ---"
cat /tmp/ssh_stderr.log
exit 1
