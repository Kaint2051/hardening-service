#!/usr/bin/env bash
# Provisioning 1 lần/máy đích, chạy bằng root, TRƯỚC lần khởi động đầu tiên
# của hardening-agent.service / hardening-executor.service (mục 4.3
# docs/architecture-proposal.md: Reporter và Executor PHẢI là 2 user hệ
# thống khác nhau để giảm blast radius, nhưng dùng chung 1 group để Executor
# tự chown được socket cho Reporter kết nối vào mà không cần thêm capability
# nào — xem apps/agent/executor/README.md mục "Mô hình quyền socket").
#
# Idempotent — chạy lại nhiều lần trên cùng 1 máy KHÔNG lỗi, KHÔNG xoá dữ
# liệu đã có (đặc biệt /etc/hardening-agent có thể đã chứa cert/key/token từ
# trước nếu máy này từng chạy Agent như process trần trước khi có systemd
# unit — chỉ chỉnh lại owner/permission, không đụng nội dung bên trong).
#
# Dùng: sudo ./provision.sh
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "LỖI: phải chạy bằng root (sudo ./provision.sh)." >&2
    exit 1
fi

GROUP_NAME="hardening-agent"
REPORTER_USER="hardening-agent"
EXECUTOR_USER="hardening-executor"
STATE_DIR="/etc/hardening-agent"

echo "==> Group hệ thống '${GROUP_NAME}' (dùng chung giữa Reporter và Executor)"
if getent group "${GROUP_NAME}" >/dev/null 2>&1; then
    echo "    đã tồn tại, bỏ qua."
else
    groupadd --system "${GROUP_NAME}"
    echo "    đã tạo."
fi

echo "==> User hệ thống '${REPORTER_USER}' (Reporter — quyền tối thiểu, không login, không home)"
if id "${REPORTER_USER}" >/dev/null 2>&1; then
    echo "    đã tồn tại, bỏ qua."
else
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --gid "${GROUP_NAME}" "${REPORTER_USER}"
    echo "    đã tạo (primary group: ${GROUP_NAME})."
fi

echo "==> User hệ thống '${EXECUTOR_USER}' (VESTIGIAL — Executor giờ chạy User=root"
echo "    trong hardening-executor.service, xem executor/README.md mục 'Chạy quyền"
echo "    root'; user này không còn được dùng, giữ lại tạo cho máy cũ không lỗi,"
echo "    không gây hại)"
if id "${EXECUTOR_USER}" >/dev/null 2>&1; then
    echo "    đã tồn tại — đảm bảo có group phụ ${GROUP_NAME} (idempotent, không xoá group phụ khác đã có)."
    usermod --append --groups "${GROUP_NAME}" "${EXECUTOR_USER}"
else
    # Primary group để mặc định (useradd tự tạo group riêng trùng tên user) —
    # chỉ CẦN group phụ ${GROUP_NAME} để tự chown được socket, không cần là
    # primary group (xem giải thích trong hardening-executor.service).
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --groups "${GROUP_NAME}" "${EXECUTOR_USER}"
    echo "    đã tạo (group phụ: ${GROUP_NAME})."
fi

echo "==> Thư mục state '${STATE_DIR}' (AGENT_STATE_DIR — cert/key/token của Reporter, executor.env của Executor)"
if [[ -d "${STATE_DIR}" ]]; then
    echo "    đã tồn tại — CHỈ chỉnh lại owner/permission, KHÔNG đụng nội dung bên trong."
else
    mkdir "${STATE_DIR}"
    echo "    đã tạo."
fi
chown "${REPORTER_USER}:${GROUP_NAME}" "${STATE_DIR}"
chmod 0700 "${STATE_DIR}"

# Cache bundle remediation dùng CHUNG giữa Reporter (ghi — tải bundle đã ký về
# đây qua AGENT_CONTENT_CACHE_DIR) và Executor (đọc — EXECUTOR_SIGNED_CONTENT_DIR
# PHẢI trỏ CÙNG path vật lý này, xem apps/agent/executor/README.md). 0770 (chủ
# sở hữu + group đọc/ghi được, không phải mode 0700 như STATE_DIR ở trên) vì
# Reporter cần GHI được qua tư cách group viên (không phải chủ sở hữu duy
# nhất) — Executor giờ chạy root nên đọc được vô điều kiện dù không cùng
# group.
CONTENT_CACHE_DIR="/var/cache/hardening-agent/content"
echo "==> Thư mục cache bundle remediation '${CONTENT_CACHE_DIR}' (Reporter ghi, Executor đọc)"
if [[ -d "${CONTENT_CACHE_DIR}" ]]; then
    echo "    đã tồn tại — CHỈ chỉnh lại owner/permission, KHÔNG đụng nội dung bên trong."
else
    mkdir -p "${CONTENT_CACHE_DIR}"
    echo "    đã tạo."
fi
chown "${REPORTER_USER}:${GROUP_NAME}" "${CONTENT_CACHE_DIR}"
chmod 0770 "${CONTENT_CACHE_DIR}"

echo "==> Kiểm tra ansible-core (bắt buộc để bật Active Response — Executor tự LookPath lúc khởi động)"
if command -v ansible-playbook >/dev/null 2>&1; then
    echo "    đã tìm thấy ansible-playbook: $(command -v ansible-playbook)"
else
    echo "    CẢNH BÁO: không tìm thấy ansible-playbook trong PATH — cài ansible-core" >&2
    echo "    TRƯỚC KHI khởi động hardening-executor.service, nếu không Executor sẽ" >&2
    echo "    Fatal ngay lúc khởi động (không phải lỗi script provision.sh này)." >&2
fi

echo "==> Xong. Các bước còn lại (thủ công, out-of-band — xem README.md từng thư mục):"
echo "    1. Reporter: đặt enroll-token + ca-root.crt vào ${STATE_DIR} (nếu chưa enroll)."
echo "    2. Executor: tạo ${STATE_DIR}/executor.env (KHÔNG commit git) chứa ít nhất"
echo "       EXECUTOR_TRUSTED_SIGNER_FINGERPRINT=<fingerprint GPG tin cậy>."
echo "    3. Copy binary agent/executor + 2 file *.service vào đúng chỗ, rồi:"
echo "         systemctl daemon-reload"
echo "         systemctl enable --now hardening-agent.service"
echo "         systemctl enable --now hardening-executor.service"
