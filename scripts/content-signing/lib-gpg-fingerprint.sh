#!/usr/bin/env bash
# Helper dùng chung: lấy fingerprint chữ ký hợp lệ từ 1 file .asc/.sig bằng
# --status-fd (output máy đọc được), thay vì grep chuỗi text tiếng Anh của gpg
# (dễ vỡ khi đổi ngôn ngữ/version gpg).
#
# Dùng: fingerprint=$(verified_signer_fingerprint <file-đã-ký> [<file-gốc-nếu-detached>])
verified_signer_fingerprint() {
    local signed_file="$1"
    local data_file="${2:-}"
    local status
    if [[ -n "$data_file" ]]; then
        status=$(gpg --status-fd 1 --verify "$signed_file" "$data_file" 2>/dev/null)
    else
        status=$(gpg --status-fd 1 --verify "$signed_file" 2>/dev/null)
    fi
    echo "$status" | awk '/^\[GNUPG:\] VALIDSIG/ {print $3; exit}'
}

# Lấy fingerprint đầy đủ của secret key đầu tiên trong keyring hiện tại
# (dùng để xác định "tôi đang là ai" khi chạy review.sh/sign.sh).
current_signer_fingerprint() {
    gpg --list-secret-keys --with-colons --fingerprint \
        | awk -F: '/^fpr:/ {print $10; exit}'
}
