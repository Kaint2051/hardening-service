#!/usr/bin/env bash
# BƯỚC 2/4 — CHẠY TRÊN MÁY ONLINE (máy sẽ chạy container step-ca thật, hoặc
# bất kỳ máy có Docker nào dùng tạm để sinh khoá rồi copy kết quả sang).
# Có thể chạy TRƯỚC hoặc SAU bước 1, không phụ thuộc gì vào máy air-gapped.
# Xem quy trình đầy đủ ở ../root-ca-airgap-runbook.md.
#
# Sinh cặp khoá Intermediate CA + CSR. Mật khẩu bảo vệ intermediate_ca_key
# PHẢI khác mật khẩu root (bước 1) — máy online sẽ phải tự lưu mật khẩu này
# dạng plaintext cạnh file key (để container tự mở khoá lúc khởi động, xem
# bước 4) nên không được để lộ mật khẩu root dù chỉ suy đoán.
#
# Sau bước này: intermediate_ca_key (private) Ở LẠI máy này, không đưa qua
# USB. Chỉ có intermediate_ca.csr (public — chỉ chứa thông tin định danh +
# public key, KHÔNG chứa private key) được copy sang USB mang tới máy
# air-gapped để ký ở bước 3.
set -euo pipefail

INTERMEDIATE_NAME="${STEPCA_NAME:-hardening-console-ca} Intermediate"
OUT_DIR="${1:-./out}"

if command -v step >/dev/null 2>&1; then
  STEP=(step)
else
  echo "==> Không thấy lệnh 'step' cài sẵn, dùng image smallstep/step-ca qua Docker"
  STEP=(docker run --rm -it -v "$(pwd)/${OUT_DIR}:/work" -w /work --entrypoint step smallstep/step-ca:latest)
fi

mkdir -p "$OUT_DIR"

echo "==> Sinh cặp khoá + CSR cho Intermediate CA (EC P-256) — sẽ hỏi mật khẩu,"
echo "    PHẢI khác mật khẩu đã đặt cho root ở bước 1"
# Không truyền --profile ở đây: step CLI từ chối kết hợp --profile với --csr
# (profile/extension của intermediate-ca được áp dụng ở bước KÝ, xem
# 03-sign-intermediate.sh --profile intermediate-ca — không phải ở bước sinh
# CSR này). Xác nhận qua chạy thử thật, không phải suy đoán.
"${STEP[@]}" certificate create "$INTERMEDIATE_NAME" \
  "${OUT_DIR}/intermediate_ca.csr" "${OUT_DIR}/intermediate_ca_key" \
  --csr \
  --kty EC --curve P-256

echo
echo "==> XONG. Trong thư mục ${OUT_DIR}:"
echo "    intermediate_ca.csr  — CÔNG KHAI, copy ra USB mang sang máy air-gapped"
echo "                           để ký ở bước 3 (03-sign-intermediate.sh)."
echo "    intermediate_ca_key  — Ở LẠI máy này. Giữ nguyên trong thư mục này,"
echo "                           sẽ dùng trực tiếp ở bước 4 (không copy đi đâu)."
