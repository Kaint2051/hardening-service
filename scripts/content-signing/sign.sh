#!/usr/bin/env bash
# Vai trò: SIGNER — kiểm tra đủ 2 chữ ký hợp lệ (Puller + Reviewer), cả 3 GPG
# fingerprint (Puller/Reviewer/Signer) phải khác nhau hoàn toàn, rồi mới ký
# bundle cuối cùng bằng GPG key của tổ chức. Đây là bước duy nhất tạo ra nội
# dung mà Execution Env / Agent được phép tin dùng (mục 3, 4.5 architecture-proposal.md).
#
# Dùng: ./sign.sh <reviewed/<name>-<timestamp>>
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${ROOT_DIR}/lib-gpg-fingerprint.sh"

REVIEWED_DIR="${1:?thiếu đường dẫn thư mục trong reviewed/}"

echo "==> [SIGNER] Verify chữ ký Puller (manifest.json.asc)"
PULLER_FPR=$(verified_signer_fingerprint "${REVIEWED_DIR}/manifest.json.asc")
echo "==> [SIGNER] Verify chữ ký Reviewer (review-record.json.asc)"
REVIEWER_FPR=$(verified_signer_fingerprint "${REVIEWED_DIR}/review-record.json.asc")

if [[ -z "$PULLER_FPR" || -z "$REVIEWER_FPR" ]]; then
    echo "LỖI: thiếu hoặc không verify được chữ ký Puller/Reviewer." >&2
    exit 1
fi

SIGNER_FPR=$(current_signer_fingerprint)
if [[ -z "$SIGNER_FPR" ]]; then
    echo "LỖI: không tìm thấy GPG secret key nào của Signer trong keyring hiện tại." >&2
    exit 1
fi

if [[ "$SIGNER_FPR" == "$PULLER_FPR" || "$SIGNER_FPR" == "$REVIEWER_FPR" || "$PULLER_FPR" == "$REVIEWER_FPR" ]]; then
    echo "LỖI: 3 vai trò Puller/Reviewer/Signer phải dùng 3 GPG key khác nhau hoàn toàn." >&2
    echo "     puller=${PULLER_FPR} reviewer=${REVIEWER_FPR} signer=${SIGNER_FPR}" >&2
    exit 1
fi

echo "==> Verify sha256 content.tar.gz vẫn khớp manifest (chống thay đổi nội dung giữa các bước)"
EXPECTED_SHA=$(python3 -c "import json; print(json.load(open('${REVIEWED_DIR}/manifest.json'))['sha256'])")
ACTUAL_SHA=$(sha256sum "${REVIEWED_DIR}/content.tar.gz" | awk '{print $1}')
if [[ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]]; then
    echo "LỖI: sha256 không khớp — nội dung có thể đã bị thay đổi sau khi Puller tải." >&2
    exit 1
fi

echo "==> Tất cả kiểm tra pass (3 fingerprint khác nhau, sha256 khớp). Ký bundle cuối cùng."
gpg --detach-sign --armor --output "${REVIEWED_DIR}/content.tar.gz.sig" "${REVIEWED_DIR}/content.tar.gz"

cat > "${REVIEWED_DIR}/signing-record.json" <<EOF
{
  "signed_by": "$(git config user.email 2>/dev/null || whoami)",
  "signer_gpg_fingerprint": "${SIGNER_FPR}",
  "puller_gpg_fingerprint": "${PULLER_FPR}",
  "reviewer_gpg_fingerprint": "${REVIEWER_FPR}",
  "signed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

SIGNED_DIR="${ROOT_DIR}/signed/$(basename "${REVIEWED_DIR}")"
mv "${REVIEWED_DIR}" "${SIGNED_DIR}"
echo "==> Đã ký và chuyển sang: ${SIGNED_DIR}"
echo "    Execution Env / Agent chỉ được nạp nội dung từ signed/ — verify bằng verify.sh trước khi dùng."
