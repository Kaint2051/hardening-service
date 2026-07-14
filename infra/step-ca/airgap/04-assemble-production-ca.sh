#!/usr/bin/env bash
# BƯỚC 4/4 — CHẠY TRÊN MÁY ONLINE (máy chạy production docker-compose), SAU
# khi đã:
#   1. `docker compose up -d step-ca` LẦN ĐẦU trên máy production để tự sinh
#      cấu trúc thư mục/ca.json/provisioner/SSH CA qua DOCKER_STEPCA_INIT_*
#      (root/intermediate tự sinh lúc này chỉ là hàng TẠM, sẽ bị thay thế ở
#      script này — xem README.md "chỉ dùng auto-init cho DEV").
#   2. Mang intermediate_ca.crt + root_ca.crt (đã ký ở bước 3, qua USB) về máy
#      này, đặt cạnh intermediate_ca_key còn lại từ bước 2, trong cùng OUT_DIR.
#
# Script thay 3 file certs/secrets TRONG VOLUME docker của step-ca bằng bộ
# root/intermediate vừa sinh qua nghi lễ air-gap, KHÔNG đụng tới ca.json/
# provisioner/SSH CA đã có (root/intermediate không liên quan mật mã tới
# provisioner hay SSH CA — xem giải thích trong runbook). Xem quy trình đầy đủ
# ở ../root-ca-airgap-runbook.md.
set -euo pipefail

OUT_DIR="${1:-./out}"
VOLUME="${STEPCA_VOLUME:-hardening-console_step-ca-data}"
COMPOSE="${COMPOSE_CMD:-docker compose}"
SVC="step-ca"

for f in root_ca.crt intermediate_ca.crt intermediate_ca_key; do
  if [ ! -f "${OUT_DIR}/${f}" ]; then
    echo "!!! Không thấy ${OUT_DIR}/${f}. Cần đủ 3 file: root_ca.crt,"
    echo "!!! intermediate_ca.crt (mang về từ máy air-gapped), intermediate_ca_key" >&2
    echo "!!! (còn lại từ bước 2 trên chính máy này)." >&2
    exit 1
  fi
done

echo "==> Kiểm tra intermediate_ca.crt thực sự được ký bởi root_ca.crt"
if ! step certificate verify --roots "${OUT_DIR}/root_ca.crt" "${OUT_DIR}/intermediate_ca.crt" >/dev/null 2>&1; then
  docker run --rm -v "$(pwd)/${OUT_DIR}:/work" -w /work --entrypoint step smallstep/step-ca:latest \
    certificate verify --roots root_ca.crt intermediate_ca.crt
fi
echo "    OK — chain hợp lệ."

echo "==> Kiểm tra intermediate_ca.crt khớp public key của intermediate_ca_key"
echo "    (crypto key public sẽ hỏi mật khẩu đã đặt cho intermediate_ca_key ở bước 2)"
CRT_PUB=$(step certificate key "${OUT_DIR}/intermediate_ca.crt" 2>/dev/null || \
  docker run --rm -v "$(pwd)/${OUT_DIR}:/work" -w /work --entrypoint step smallstep/step-ca:latest \
    certificate key intermediate_ca.crt)
KEY_PUB=$(step crypto key public "${OUT_DIR}/intermediate_ca_key" 2>/dev/null || \
  docker run --rm -it -v "$(pwd)/${OUT_DIR}:/work" -w /work --entrypoint step smallstep/step-ca:latest \
    crypto key public intermediate_ca_key)
if [ "$CRT_PUB" != "$KEY_PUB" ]; then
  echo "!!! Public key trong intermediate_ca.crt KHÔNG khớp intermediate_ca_key." >&2
  echo "!!! Sai file / lẫn lộn giữa các lần chạy bước 2-3. DỪNG." >&2
  exit 1
fi
echo "    OK — khớp."

read -r -s -p "Nhập lại mật khẩu đã đặt cho intermediate_ca_key ở bước 2 (sẽ lưu vào secrets/password để container tự mở khoá lúc khởi động): " INTERMEDIATE_PW
echo
if [ -z "$INTERMEDIATE_PW" ]; then
  echo "!!! Mật khẩu rỗng — DỪNG." >&2
  exit 1
fi
# Ghi ra file tạm thay vì truyền qua argv của `docker run` — argv của tiến
# trình đang chạy có thể bị user cục bộ khác đọc được qua `ps`/`/proc`. Chmod
# 644 (không phải 600) vì container smallstep/step-ca chạy bằng uid 1000
# (không phải root) cần đọc được file bind-mount này — xác nhận qua rehearvsal
# thật (600 gây "permission denied" khi container đọc).
PW_TMP=$(mktemp)
chmod 644 "$PW_TMP"
printf '%s' "$INTERMEDIATE_PW" > "$PW_TMP"
unset INTERMEDIATE_PW
trap 'rm -f "$PW_TMP"' EXIT

BACKUP_DIR="${OUT_DIR}/pre-swap-backup-$(date +%Y%m%dT%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "==> Dừng $SVC trước khi thay khoá"
$COMPOSE stop "$SVC"

echo "==> Sao lưu certs/secrets hiện có trong volume $VOLUME ra $BACKUP_DIR (phòng khi cần rollback)"
docker run --rm \
  -v "${VOLUME}:/home/step" \
  -v "$(pwd)/${BACKUP_DIR}:/backup" \
  alpine sh -c "cp -a /home/step/certs/root_ca.crt /home/step/certs/intermediate_ca.crt /home/step/secrets/root_ca_key /home/step/secrets/intermediate_ca_key /home/step/secrets/password /home/step/secrets/ssh_host_ca_key /home/step/secrets/ssh_user_ca_key /backup/ 2>/dev/null || true"

# secrets/password là 1 mật khẩu DÙNG CHUNG để step-ca tự mở khoá MỌI key nó
# cần lúc khởi động — không chỉ intermediate_ca_key, mà cả ssh_host_ca_key và
# ssh_user_ca_key (cả 2 đều do DOCKER_STEPCA_INIT_* sinh cùng lúc, cùng mật
# khẩu init ban đầu). Xác nhận qua rehearsal thật: chỉ thay secrets/password
# mà không re-key 2 SSH key này làm step-ca crash lúc khởi động lại với lỗi
# "x509: decryption password incorrect" trên ssh_host_ca_key. Vì SSH CA không
# nằm trong phạm vi nghi lễ air-gap (chỉ x509 root/intermediate mới cần offline
# theo mục 4.1 kiến trúc), cách xử lý đúng là GIỮ NGUYÊN khoá SSH CA, chỉ đổi
# mật khẩu bảo vệ chúng cho khớp mật khẩu intermediate mới — không tạo mới.
OLD_PW_TMP=$(mktemp)
docker run --rm -v "${VOLUME}:/home/step:ro" alpine cat /home/step/secrets/password > "$OLD_PW_TMP"
chmod 644 "$OLD_PW_TMP"
trap 'rm -f "$PW_TMP" "$OLD_PW_TMP"' EXIT

echo "==> Đổi mật khẩu ssh_host_ca_key + ssh_user_ca_key sang mật khẩu intermediate mới"
echo "    (giữ nguyên bản thân 2 khoá SSH CA — SSH CA không thuộc phạm vi nghi lễ"
echo "    air-gap này, chỉ re-key cho khớp secrets/password mới)"
docker run --rm \
  -v "${VOLUME}:/home/step" \
  -v "${OLD_PW_TMP}:/old-pw.txt:ro" \
  -v "${PW_TMP}:/new-pw.txt:ro" \
  --entrypoint sh smallstep/step-ca:latest \
  -c '
    set -e
    for k in ssh_host_ca_key ssh_user_ca_key; do
      step crypto change-pass "/home/step/secrets/$k" \
        --password-file /old-pw.txt --new-password-file /new-pw.txt -f
    done
  '

echo "==> Ghi root_ca.crt + intermediate_ca.crt + intermediate_ca_key + password mới vào volume"
echo "    (và xoá root_ca_key TẠM do DOCKER_STEPCA_INIT_* tự sinh lúc auto-init"
echo "    lần đầu — key đó không còn ai tin cậy, nhưng để sót lại trong volume"
echo "    online sẽ vi phạm đúng bất biến 'root key không bao giờ ở máy online'"
echo "    mà toàn bộ quy trình này đang thiết lập)"
docker run --rm \
  -v "${VOLUME}:/home/step" \
  -v "$(pwd)/${OUT_DIR}:/incoming:ro" \
  -v "${PW_TMP}:/incoming-password:ro" \
  alpine sh -c '
    set -e
    cp /incoming/root_ca.crt /home/step/certs/root_ca.crt
    cp /incoming/intermediate_ca.crt /home/step/certs/intermediate_ca.crt
    cp /incoming/intermediate_ca_key /home/step/secrets/intermediate_ca_key
    cp /incoming-password /home/step/secrets/password
    chown 1000:1000 /home/step/certs/root_ca.crt /home/step/certs/intermediate_ca.crt /home/step/secrets/intermediate_ca_key /home/step/secrets/password /home/step/secrets/ssh_host_ca_key /home/step/secrets/ssh_user_ca_key
    chmod 600 /home/step/certs/root_ca.crt /home/step/certs/intermediate_ca.crt /home/step/secrets/intermediate_ca_key /home/step/secrets/password /home/step/secrets/ssh_host_ca_key /home/step/secrets/ssh_user_ca_key
    rm -f /home/step/secrets/root_ca_key
  '
rm -f "$PW_TMP" "$OLD_PW_TMP"

echo "==> Xác nhận root_ca.key KHÔNG tồn tại trong volume online (phải luôn đúng)"
if docker run --rm -v "${VOLUME}:/home/step" alpine sh -c 'test -f /home/step/secrets/root_ca_key'; then
  echo "!!! CẢNH BÁO NGHIÊM TRỌNG: /home/step/secrets/root_ca_key tồn tại trong volume online." >&2
  echo "!!! Root key KHÔNG được phép ở máy online. Kiểm tra lại ngay." >&2
  exit 1
fi
echo "    OK — không có root_ca_key trong volume online."

echo "==> Khởi động lại $SVC"
$COMPOSE start "$SVC"

echo "==> Đợi health check..."
for i in $(seq 1 30); do
  status=$($COMPOSE ps --format json "$SVC" 2>/dev/null | grep -o '"Health":"[a-z]*"' | cut -d'"' -f4 || true)
  [ "$status" = "healthy" ] && break
  sleep 2
done
$COMPOSE ps "$SVC"

echo
echo "==> XONG. Kiểm tra thêm thủ công trước khi coi là hoàn tất:"
echo "    - $COMPOSE exec $SVC step ca health"
echo "    - Cấp thử 1 cert qua provisioner hiện có, xác nhận chain dẫn về root mới"
echo "      (step certificate verify --roots root_ca.crt <cert-vừa-cấp>)."
echo "    - Phân phối root_ca.crt (${OUT_DIR}/root_ca.crt) mới tới mọi nơi cần"
echo "      tin cậy CA này (trust store của Agent, known_hosts SSH CA, v.v.) —"
echo "      NẾU đây là root MỚI thay cho root cũ đang được tin cậy, phải chạy"
echo "      qua Zero-to-CA Migration playbook (xem README.md mục tương ứng),"
echo "      KHÔNG thay trực tiếp như script này (script này dành cho triển"
echo "      khai production LẦN ĐẦU, chưa có ai tin cậy root cũ)."
echo "    - Xoá sạch $OUT_DIR khỏi máy online sau khi xác nhận ổn định (không"
echo "      cần giữ intermediate_ca_key dạng file rời nữa, đã nằm trong volume)."
