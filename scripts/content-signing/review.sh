#!/usr/bin/env bash
# Vai trò: REVIEWER — kiểm diff nội dung so với bản đã ký gần nhất, ký duyệt
# bằng GPG key CÁ NHÂN của mình. Script từ chối chạy nếu Reviewer dùng cùng
# GPG key với Puller (thực thi tách vai trò bằng mật mã học, không chỉ quy ước).
#
# Dùng: ./review.sh <staging/<name>-<timestamp>>
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${ROOT_DIR}/lib-gpg-fingerprint.sh"

STAGED_DIR="${1:?thiếu đường dẫn thư mục trong staging/}"
NAME=$(python3 -c "import json; print(json.load(open('${STAGED_DIR}/manifest.json'))['name'])")

echo "==> [REVIEWER] Verify chữ ký của Puller trên manifest.json"
PULLER_FPR=$(verified_signer_fingerprint "${STAGED_DIR}/manifest.json.asc")
if [[ -z "$PULLER_FPR" ]]; then
    echo "LỖI: chữ ký Puller không hợp lệ hoặc không verify được." >&2
    exit 1
fi

REVIEWER_FPR=$(current_signer_fingerprint)
if [[ -z "$REVIEWER_FPR" ]]; then
    echo "LỖI: không tìm thấy GPG secret key nào của Reviewer trong keyring hiện tại." >&2
    exit 1
fi
if [[ "$REVIEWER_FPR" == "$PULLER_FPR" ]]; then
    echo "LỖI: Reviewer đang dùng CÙNG GPG key với Puller — vi phạm tách vai trò bắt buộc (mục 3, architecture-proposal.md)." >&2
    exit 1
fi

LATEST_SIGNED=$(ls -td "${ROOT_DIR}"/signed/"${NAME}"-* 2>/dev/null | head -1 || true)
if [[ -n "$LATEST_SIGNED" ]]; then
    echo "==> So sánh danh sách file với bản đã ký gần nhất: $(basename "$LATEST_SIGNED")"
    diff <(tar -tzf "${LATEST_SIGNED}/content.tar.gz" | sort) \
         <(tar -tzf "${STAGED_DIR}/content.tar.gz" | sort) || true
else
    echo "==> Không có bản đã ký trước đó cho '${NAME}' — đây là lần nạp đầu tiên, cần rà soát kỹ hơn."
fi

echo ""
read -rp "Reviewer (fingerprint ${REVIEWER_FPR}) đã kiểm tra diff ở trên — gõ APPROVE để duyệt: " CONFIRM
if [[ "$CONFIRM" != "APPROVE" ]]; then
    echo "Huỷ — không duyệt nội dung này." >&2
    exit 1
fi

# --local-user "$REVIEWER_FPR": pin đúng key ĐÃ kiểm tra ở trên (khác Puller)
# cho lệnh ký thật — không truyền cờ này, gpg tự chọn key mặc định của máy,
# có thể KHÁC key đã dùng để tính REVIEWER_FPR nếu keyring có nhiều secret
# key (vd Reviewer lỡ import thêm key người khác) — khi đó check "khác
# Puller" ở trên không còn phản ánh đúng key thực sự tạo ra chữ ký (phát
# hiện qua review, không phải test thật).
cat > "${STAGED_DIR}/review-record.json" <<EOF
{
  "reviewed_by": "$(git config user.email 2>/dev/null || whoami)",
  "reviewer_gpg_fingerprint": "${REVIEWER_FPR}",
  "puller_gpg_fingerprint": "${PULLER_FPR}",
  "reviewed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "decision": "APPROVE"
}
EOF
gpg --local-user "$REVIEWER_FPR" --clearsign --output "${STAGED_DIR}/review-record.json.asc" "${STAGED_DIR}/review-record.json"

REVIEWED_DIR="${ROOT_DIR}/reviewed/$(basename "${STAGED_DIR}")"
mv "${STAGED_DIR}" "${REVIEWED_DIR}"
echo "==> Đã chuyển sang: ${REVIEWED_DIR}"
echo "    Bước tiếp theo: một SIGNER thứ 3 (GPG key thứ 3, khác cả Puller lẫn Reviewer) chạy sign.sh."
