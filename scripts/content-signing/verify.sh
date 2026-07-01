#!/usr/bin/env bash
# Dùng bởi Execution Env / pipeline nạp nội dung — verify chữ ký trước khi
# tin dùng bất kỳ bundle nào từ signed/. Chỉ định rõ fingerprint tin cậy
# (--trusted-signer) để tránh vô tình chấp nhận chữ ký của một key lạ đã lọt
# vào keyring.
#
# Dùng: ./verify.sh <signed/<name>-<timestamp>> <trusted-signer-fingerprint>
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${ROOT_DIR}/lib-gpg-fingerprint.sh"

SIGNED_DIR="${1:?thiếu đường dẫn thư mục trong signed/}"
TRUSTED_FPR="${2:?thiếu trusted-signer-fingerprint}"

ACTUAL_FPR=$(verified_signer_fingerprint "${SIGNED_DIR}/content.tar.gz.sig" "${SIGNED_DIR}/content.tar.gz")

if [[ -z "$ACTUAL_FPR" ]]; then
    echo "TỪ CHỐI: chữ ký không hợp lệ hoặc không verify được." >&2
    exit 1
fi
if [[ "$ACTUAL_FPR" != "$TRUSTED_FPR" ]]; then
    echo "TỪ CHỐI: nội dung được ký bởi ${ACTUAL_FPR}, không khớp fingerprint tin cậy ${TRUSTED_FPR}." >&2
    exit 1
fi

echo "OK: chữ ký hợp lệ, ký bởi ${ACTUAL_FPR} — nội dung tin cậy để nạp vào production."
