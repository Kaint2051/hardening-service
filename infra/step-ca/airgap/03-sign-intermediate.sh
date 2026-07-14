#!/usr/bin/env bash
# BƯỚC 3/4 — CHẠY TRÊN MÁY AIR-GAPPED, SAU bước 1, sau khi đã mang
# intermediate_ca.csr (từ bước 2, qua USB) sang máy này. Xem quy trình đầy đủ
# ở ../root-ca-airgap-runbook.md.
#
# Ký CSR bằng Root CA. Sẽ hỏi lại mật khẩu root đã đặt ở bước 1 để mở khoá
# root_ca.key tạm thời trong bộ nhớ tiến trình (không ghi khoá đã giải mã ra
# đĩa).
#
# --path-len 0: intermediate này CHỈ được ký cert lá (leaf, vd mTLS agent, SSH
# host/user), KHÔNG được ký thêm intermediate con nào khác — đúng mô hình 2
# tầng root/intermediate của kiến trúc, không có tầng thứ 3.
set -euo pipefail

OUT_DIR="${1:-./out}"
INTERMEDIATE_VALIDITY="${INTERMEDIATE_CA_VALIDITY:-43800h}"  # 5 năm

if [ ! -f "${OUT_DIR}/root_ca.crt" ] || [ ! -f "${OUT_DIR}/root_ca.key" ]; then
  echo "!!! Không thấy ${OUT_DIR}/root_ca.{crt,key} — chạy 01-generate-root-ca.sh trước." >&2
  exit 1
fi
if [ ! -f "${OUT_DIR}/intermediate_ca.csr" ]; then
  echo "!!! Không thấy ${OUT_DIR}/intermediate_ca.csr — copy file này từ máy online" >&2
  echo "!!! (kết quả bước 2, 02-generate-intermediate-csr.sh) vào ${OUT_DIR}/ trước." >&2
  exit 1
fi

if command -v step >/dev/null 2>&1; then
  STEP=(step)
else
  echo "==> Không thấy lệnh 'step' cài sẵn, dùng image smallstep/step-ca qua Docker"
  STEP=(docker run --rm -it -v "$(pwd)/${OUT_DIR}:/work" -w /work --entrypoint step smallstep/step-ca:latest)
fi

echo "==> Đối chiếu fingerprint root_ca.crt với biên bản đã ghi ở bước 1 trước khi ký"
"${STEP[@]}" certificate fingerprint "${OUT_DIR}/root_ca.crt"
read -r -p "Fingerprint trên có khớp biên bản đã ghi ở bước 1 không? (yes/NO) " confirm
if [ "$confirm" != "yes" ]; then
  echo "!!! Không khớp hoặc chưa xác nhận — DỪNG. Kiểm tra lại trước khi ký." >&2
  exit 1
fi

echo "==> Ký intermediate CSR bằng root (hiệu lực ${INTERMEDIATE_VALIDITY}, path-len=0)"
"${STEP[@]}" certificate sign \
  --profile intermediate-ca --path-len 0 \
  --not-after "$INTERMEDIATE_VALIDITY" \
  "${OUT_DIR}/intermediate_ca.csr" "${OUT_DIR}/root_ca.crt" "${OUT_DIR}/root_ca.key" \
  > "${OUT_DIR}/intermediate_ca.crt"

echo
echo "==> XONG. Trong thư mục ${OUT_DIR}, mang 2 file sau ra USB trả về máy online:"
echo "    root_ca.crt          — (lại lần nữa, để máy online có bản chính thức)"
echo "    intermediate_ca.crt  — vừa ký xong"
echo
echo "    intermediate_ca.csr có thể xoá (đã dùng xong, không còn cần)."
echo "    root_ca.key VẪN Ở LẠI máy này — không copy đi đâu cả."
echo
"${STEP[@]}" certificate inspect --short "${OUT_DIR}/intermediate_ca.crt"
