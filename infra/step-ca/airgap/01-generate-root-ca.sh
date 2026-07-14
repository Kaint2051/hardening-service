#!/usr/bin/env bash
# BƯỚC 1/4 — CHẠY TRÊN MÁY AIR-GAPPED (đã rút cáp mạng / tắt Wi-Fi, không có
# đường ra Internet hay mạng nội bộ nào). Xem quy trình đầy đủ ở
# ../root-ca-airgap-runbook.md.
#
# Sinh cặp khoá Root CA. Không dùng --password-file/--insecure: lệnh dưới sẽ
# hỏi mật khẩu qua terminal (không có gì ghi ra đĩa dạng plaintext). Người
# vận hành tự chọn mật khẩu dài, ghi nhớ hoặc lưu vào nơi lưu trữ mật khẩu
# vật lý riêng (không lưu chung ổ USB mang cert đi lại giữa 2 máy).
#
# Sau bước này: root_ca.key KHÔNG BAO GIỜ rời khỏi máy air-gapped này. Chỉ có
# root_ca.crt (public) được copy sang USB để mang sang máy online.
set -euo pipefail

ROOT_NAME="${STEPCA_NAME:-hardening-console-ca} Root"
ROOT_VALIDITY="${ROOT_CA_VALIDITY:-87600h}"  # 10 năm, chỉnh qua env nếu cần
OUT_DIR="${1:-./out}"

if command -v step >/dev/null 2>&1; then
  STEP=(step)
else
  echo "==> Không thấy lệnh 'step' cài sẵn, dùng image smallstep/step-ca qua Docker"
  STEP=(docker run --rm -it -v "$(pwd)/${OUT_DIR}:/work" -w /work --entrypoint step smallstep/step-ca:latest)
fi

mkdir -p "$OUT_DIR"

echo "==> Kiểm tra máy này KHÔNG có kết nối mạng trước khi tiếp tục"
if command -v ip >/dev/null 2>&1 && ip route show default 2>/dev/null | grep -q default; then
  echo "!!! Máy này vẫn còn default route (có khả năng nối mạng). DỪNG LẠI." >&2
  echo "!!! Rút cáp mạng / tắt Wi-Fi rồi chạy lại script này." >&2
  exit 1
fi

echo "==> Sinh Root CA (EC P-256, hiệu lực ${ROOT_VALIDITY}) — sẽ hỏi mật khẩu, tự đặt và ghi nhớ"
"${STEP[@]}" certificate create "$ROOT_NAME" \
  "${OUT_DIR}/root_ca.crt" "${OUT_DIR}/root_ca.key" \
  --profile root-ca \
  --kty EC --curve P-256 \
  --not-after "$ROOT_VALIDITY"

echo
echo "==> XONG. Trong thư mục ${OUT_DIR}:"
echo "    root_ca.crt — CÔNG KHAI, copy ra USB mang sang máy online."
echo "    root_ca.key — TUYỆT ĐỐI KHÔNG rời máy này. Sao lưu ra ít nhất 1 USB"
echo "                  mã hoá riêng khác, cất ở nơi vật lý an toàn thứ 2"
echo "                  (tách khỏi USB dùng để đi lại), không cắm lại vào máy"
echo "                  có mạng. Nếu mất máy này VÀ bản sao lưu, toàn bộ chuỗi"
echo "                  tin cậy phải làm lại từ đầu (xem mục Disaster Recovery"
echo "                  trong runbook)."
echo
step certificate fingerprint "${OUT_DIR}/root_ca.crt" 2>/dev/null || \
  "${STEP[@]}" certificate fingerprint "${OUT_DIR}/root_ca.crt"
echo "    ^ Fingerprint trên — ghi lại vào biên bản nghi lễ ký root (giấy hoặc"
echo "      nơi lưu trữ tách biệt), dùng để đối chiếu sau này khi cần xác minh"
echo "      root_ca.crt mang ra không bị tráo/sửa giữa đường."
