#!/usr/bin/env bash
# Tạo 1 SSH keypair MỚI + cài public key lên host bằng credential CŨ (dùng
# đúng 1 lần) — LỰA CHỌN THAY THẾ cho ca-bootstrap.sh (KHÔNG đụng
# sshd_config/TrustedUserCAKeys ở đây, chỉ ghi authorized_keys), theo yêu
# cầu người dùng chấp nhận đánh đổi bảo mật (secret sống mãi, không revoke)
# — xem app/jobs.py:trigger_static_ssh_key_bootstrap.
#
# Keypair sinh TẠI ĐÂY (đại diện "server quản lý"), KHÔNG sinh trên host
# đích — private key không bao giờ chạm đĩa host đích, chỉ public key được
# đẩy lên qua session credential cũ (kiểu ssh-copy-id).
#
# Credential CŨ và các bước kiểm tra sudo giống HỆT ca-bootstrap.sh (tách
# riêng file, không import lẫn — execution-env không có cơ chế "include 1
# script khác" ngoài copy nguyên văn phần dùng chung).
#
# Input qua biến môi trường:
#   TARGET_HOST, LEGACY_SSH_USER, TARGET_PORT — giống ca-bootstrap.sh
#   ĐÚNG 1 TRONG 2: LEGACY_SSH_PASSWORD_B64 hoặc LEGACY_SSH_PRIVATE_KEY_B64
#   STATIC_KEY_TARGET_USERS — CSV các user cần cài public key (vd "root" hoặc
#     "root,deploy") — Orchestrator tính sẵn dựa trên MỌI principal thực sự
#     dùng qua 7 điểm dispatch SSH (root hardcode cho remediate/restore/
#     ssh-port-change, Host.ssh_user cho scan/ssh-check/agent-install/
#     agent-uninstall) — thiếu 1 user ở đây sẽ khiến nhóm job dùng principal
#     đó auth fail âm thầm sau này.
#   TRANSPORT_PASSPHRASE — passphrase CHỈ DÙNG CHO LẦN GỌI NÀY (Orchestrator
#     sinh mới mỗi lần, không lưu lại) — mã hoá private key TRƯỚC KHI in ra
#     stdout, vì Docker's json-file log driver ghi nguyên văn log của
#     container xuống đĩa máy chạy job-dispatcher TRƯỚC KHI container bị xoá
#     — in plaintext sẽ lộ ra ngoài tầm kiểm soát của Orchestrator (khác
#     legacy_ssh_password — credential đó sắp bị revoke, key MỚI này thì
#     sống mãi, không có bước revoke nào). Truyền qua `openssl -pass env:`
#     (KHÔNG phải `-K`/`-iv` CLI argument trần) để không lộ qua `ps aux`,
#     cùng lý do sshpass ở đây dùng `-f <file>` thay vì `-p <chuỗi>`.
set -euo pipefail
: "${TARGET_HOST:?thiếu TARGET_HOST}"
: "${LEGACY_SSH_USER:?thiếu LEGACY_SSH_USER}"
: "${TARGET_PORT:?thiếu TARGET_PORT}"
: "${STATIC_KEY_TARGET_USERS:?thiếu STATIC_KEY_TARGET_USERS}"
: "${TRANSPORT_PASSPHRASE:?thiếu TRANSPORT_PASSPHRASE}"

mkdir -p /tmp/legacy-ssh
chmod 700 /tmp/legacy-ssh
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -p "${TARGET_PORT}")

if [ -n "${LEGACY_SSH_PRIVATE_KEY_B64:-}" ]; then
  echo "$LEGACY_SSH_PRIVATE_KEY_B64" | base64 -d > /tmp/legacy-ssh/key
  chmod 600 /tmp/legacy-ssh/key
  SSH_OPTS+=(-i /tmp/legacy-ssh/key -o BatchMode=yes)
  run_ssh() { ssh "${SSH_OPTS[@]}" "$@"; }
elif [ -n "${LEGACY_SSH_PASSWORD_B64:-}" ]; then
  echo "$LEGACY_SSH_PASSWORD_B64" | base64 -d > /tmp/legacy-ssh/pass
  chmod 600 /tmp/legacy-ssh/pass
  # KHÔNG dùng BatchMode=yes ở nhánh này — cùng lý do ca-bootstrap.sh.
  run_ssh() { sshpass -f /tmp/legacy-ssh/pass ssh "${SSH_OPTS[@]}" "$@"; }
else
  echo "STATIC_KEY_BOOTSTRAP_STATUS=failed"
  echo "LOI: can dung 1 trong LEGACY_SSH_PRIVATE_KEY_B64 hoac LEGACY_SSH_PASSWORD_B64" >&2
  exit 1
fi

TARGET="${LEGACY_SSH_USER}@${TARGET_HOST}"

set +e

echo "==> Buoc 1: kiem tra sudo khong-mat-khau (hoac dang nhap thang bang root)"
run_ssh "$TARGET" 'sudo -n true' 2>/tmp/legacy-ssh/step.log
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "STATIC_KEY_BOOTSTRAP_STATUS=failed"
  echo "LOI: LEGACY_SSH_USER khong co sudo khong-mat-khau tren may dich (hoac khong dang nhap duoc bang credential da cung cap)." >&2
  cat /tmp/legacy-ssh/step.log >&2
  exit 1
fi

echo "==> Buoc 2: sinh SSH keypair moi (ed25519) tai day, KHONG tren may dich"
ssh-keygen -q -t ed25519 -N '' -f /tmp/hc_static_key -C hardening-console-managed
PUBKEY=$(cat /tmp/hc_static_key.pub)

echo "==> Buoc 3: cai public key vao authorized_keys cua tung user dich"
IFS=',' read -ra TARGET_USERS <<< "$STATIC_KEY_TARGET_USERS"
for user in "${TARGET_USERS[@]}"; do
  echo "  -> user: $user"
  # getent passwd doc duoc (khong can quyen) tren MOI he Linux -- dung de
  # tra dung $HOME thuc su cua user do, KHONG doan "/home/<user>" (co the
  # khac, vd home tuy bien). Kiem tra ton tai truoc -- thieu buoc nay,
  # user khong ton tai se khien lenh mkdir phia duoi chay voi duong dan
  # trong/sai (rong -> ghi nham vao "/.ssh") thay vi bao loi ro rang.
  #
  # Idempotent: xoa dong co marker cu truoc khi ghi dong moi -- bam lai (do
  # loi giua duong, hoac double-click) tu don dep thay vi tich rac nhieu
  # key mo coi khong ai con giu private key.
  run_ssh "$TARGET" "
    set -e
    USER_HOME=\$(getent passwd '$user' | cut -d: -f6)
    if [ -z \"\$USER_HOME\" ]; then
      echo \"user $user khong ton tai tren may dich\" >&2
      exit 1
    fi
    sudo mkdir -p \"\$USER_HOME/.ssh\"
    sudo chmod 700 \"\$USER_HOME/.ssh\"
    sudo chown '$user' \"\$USER_HOME/.ssh\"
    AUTH_KEYS=\"\$USER_HOME/.ssh/authorized_keys\"
    sudo touch \"\$AUTH_KEYS\"
    sudo sed -i '/# hardening-console-static-key\$/d' \"\$AUTH_KEYS\"
    echo '$PUBKEY # hardening-console-static-key' | sudo tee -a \"\$AUTH_KEYS\" > /dev/null
    sudo chmod 600 \"\$AUTH_KEYS\"
    sudo chown '$user' \"\$AUTH_KEYS\"
  " 2>/tmp/legacy-ssh/step.log
  RC=$?
  if [ "$RC" -ne 0 ]; then
    echo "STATIC_KEY_BOOTSTRAP_STATUS=failed"
    echo "LOI: khong cai duoc public key vao authorized_keys cua user '$user'." >&2
    cat /tmp/legacy-ssh/step.log >&2
    exit 1
  fi
done

echo "==> Buoc 4: ma hoa private key truoc khi in ra stdout"
# -pass env: (KHONG phai -K/-iv CLI argument tran) de passphrase khong lo
# qua `ps aux`. -iter/-md PIN CUNG (khong dung default cua openssl) de
# Orchestrator giai ma lai dung, khong le thuoc phien ban openssl cua image
# nay co default KDF khac hay khong -- xem app/jobs.py:_decrypt_transport_payload.
export TRANSPORT_PASSPHRASE
openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -md sha256 -pass env:TRANSPORT_PASSPHRASE \
  -in /tmp/hc_static_key -out /tmp/hc_static_key.enc
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "STATIC_KEY_BOOTSTRAP_STATUS=failed"
  echo "LOI: ma hoa private key that bai." >&2
  exit 1
fi

echo "STATIC_SSH_PUBLIC_KEY=$PUBKEY"
echo "STATIC_SSH_PRIVATE_KEY_ENC_B64=$(base64 -w0 /tmp/hc_static_key.enc)"

# Don dep dia cuc bo cua container nay ngay (du sap bi huy sau khi job xong)
# -- khong de private key plaintext ton tai lau hon can thiet.
shred -u /tmp/hc_static_key /tmp/hc_static_key.enc 2>/dev/null || rm -f /tmp/hc_static_key /tmp/hc_static_key.enc

echo "==> Hoan tat"
echo "STATIC_KEY_BOOTSTRAP_STATUS=ok"
exit 0
