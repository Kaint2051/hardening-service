#!/usr/bin/env bash
# Remote-deploy Agent tự động (mục "sao ko remote deploy" — xem
# app/agents.py:trigger_agent_install) — verify chữ ký bundle TRƯỚC khi đẩy
# bất cứ gì lên máy đích (cùng nguyên tắc remediate.sh), scp binary +
# provision.sh + 2 systemd unit qua cert SSH ngắn hạn, SSH vào chạy cài đặt.
# KHÔNG cần operator tự SSH/paste tay (khác _build_agent_install_script cũ,
# vẫn giữ làm phương án dự phòng). Chỉ khả thi cho host ĐÃ
# trust_deployed/migrated — dùng cert ephemeral, KHÔNG cần legacy credential
# nào (khác ca-bootstrap.sh, vốn chạy TRƯỚC khi CA trust tồn tại).
#
# Input qua biến môi trường:
#   TARGET_HOST, SSH_USER, SSH_KEY_B64 — luôn có, giống ssh-check.sh
#   SSH_CERT_B64 — TUỲ CHỌN (thiếu nếu host dùng static SSH key — xem
#     app/jobs.py:_get_ssh_dispatch_environment)
#   TARGET_PORT — cổng SSH của host (Host.ssh_port, mặc định 22)
#   AGENT_HOSTNAME — hostname trong Host Registry (KHÁC TARGET_HOST — đó là
#     ip_address; agent tự ghi vào agent.env để không phụ thuộc hostname hệ
#     điều hành thật của máy đích có khớp registry hay không)
#   AGENT_BUNDLE_REF — tên thư mục bundle trong /content/
#   AGENT_BUNDLE_TRUSTED_FINGERPRINT — fingerprint GPG tin cậy, cùng
#     nguyên tắc remediate.sh (KHÔNG đọc fingerprint tin cậy từ chính bundle)
#   AGENT_ENROLL_TOKEN_B64 — bootstrap token OTT (base64), xem app/agents.py
#   CA_ROOT_PEM_B64 — root cert step-ca (base64, không bí mật)
#   AGENT_MANAGER_PUBLIC_URL — địa chỉ Agent Manager THẬT (settings.
#     agent_manager_public_url) — hardening-agent.service mặc định
#     "https://localhost:8443" (chỉ đúng khi Agent Manager chạy CÙNG máy),
#     PHẢI ghi đè qua agent.env cho MỌI host thật khác — thiếu bước này agent
#     "cài xong" nhưng KHÔNG BAO GIỜ enroll được (lỗi âm thầm đã gặp thật khi
#     cài lên host khác máy chạy Agent Manager).
#
# Bundle content.tar.gz PHẢI chứa đúng 5 file ở gốc: agent, executor,
# provision.sh, hardening-agent.service, hardening-executor.service — xem
# apps/agent/README.md mục "Đóng gói bundle cho remote-deploy".
#
# Cũng copy kèm datastream SSG (ssg-*-ds.xml, khớp danh sách
# app/jobs.py:SCAP_PROFILES) từ CHÍNH image execution-env này (đã có sẵn qua
# ssg-debderived/ssg-debian, cùng file scan.sh đang dùng) lên
# /usr/share/xml/scap/ssg/content/ của máy đích — apps/agent/scan.go chạy
# `oscap` NGAY trên máy đích nên cần file này tồn tại VẬT LÝ ở đó, KHÁC hẳn
# scan qua SSH (chỉ cần datastream phía execution-env, scp file qua lúc chạy
# job). Thiếu bước này Agent cài xong nhưng agent-scan luôn lỗi "Unable to
# open file" — phát hiện thật lúc kiểm tra agent-scan trên vps1 (job báo
# "succeeded" nhưng result_summary rỗng, xem thêm fix agent_scan_result ở
# app/agents.py không tin cậy status hardcode nữa).
#
# Chỉ enable hardening-agent.service (Reporter) — KHÔNG tự bật
# hardening-executor.service (Active Response), cùng hành vi
# _build_agent_install_script cũ: Executor cần executor.env
# (EXECUTOR_TRUSTED_SIGNER_FINGERPRINT) tạo tay trước, tránh bật nhầm trước
# khi pentest riêng (mục 4.3 architecture-proposal.md).
set -euo pipefail
: "${TARGET_HOST:?thiếu TARGET_HOST}"
: "${SSH_USER:?thiếu SSH_USER}"
: "${SSH_KEY_B64:?thiếu SSH_KEY_B64}"
SSH_CERT_B64="${SSH_CERT_B64:-}"
: "${TARGET_PORT:?thiếu TARGET_PORT}"
: "${AGENT_BUNDLE_REF:?thiếu AGENT_BUNDLE_REF}"
: "${AGENT_BUNDLE_TRUSTED_FINGERPRINT:?thiếu AGENT_BUNDLE_TRUSTED_FINGERPRINT}"
: "${AGENT_ENROLL_TOKEN_B64:?thiếu AGENT_ENROLL_TOKEN_B64}"
: "${CA_ROOT_PEM_B64:?thiếu CA_ROOT_PEM_B64}"
: "${AGENT_HOSTNAME:?thiếu AGENT_HOSTNAME}"
: "${AGENT_MANAGER_PUBLIC_URL:?thiếu AGENT_MANAGER_PUBLIC_URL}"
# Fingerprint nội dung remediation (KHÁC AGENT_BUNDLE_TRUSTED_FINGERPRINT ở
# trên — cái đó verify bundle CÀI ĐẶT agent, cái này verify bundle
# REMEDIATION mà Executor sẽ chạy về sau; 2 khoá tách riêng có chủ đích, xem
# app/config.py). Dùng để ghi executor.env + xuất public key cho máy đích.
: "${CONTENT_SIGNING_TRUSTED_FINGERPRINT:?thiếu CONTENT_SIGNING_TRUSTED_FINGERPRINT}"

BUNDLE_DIR="/content/${AGENT_BUNDLE_REF}"
DATA_FILE="${BUNDLE_DIR}/content.tar.gz"
SIG_FILE="${BUNDLE_DIR}/content.tar.gz.sig"

echo "=== Verify chữ ký bundle ${AGENT_BUNDLE_REF} ==="
echo "##PROGRESS## 5 verify_signature"
if [ ! -f "$DATA_FILE" ] || [ ! -f "$SIG_FILE" ]; then
  echo "AGENT_INSTALL_STATUS=failed"
  echo "Bundle ${AGENT_BUNDLE_REF} thiếu content.tar.gz hoặc content.tar.gz.sig tại ${BUNDLE_DIR}" >&2
  exit 1
fi

GPG_STATUS=$(gpg --status-fd 1 --verify "$SIG_FILE" "$DATA_FILE" 2>/dev/null || true)
ACTUAL_FPR=$(echo "$GPG_STATUS" | awk '/^\[GNUPG:\] VALIDSIG/ {print $3; exit}')
if [ -z "$ACTUAL_FPR" ]; then
  echo "AGENT_INSTALL_STATUS=failed"
  echo "Chữ ký bundle ${AGENT_BUNDLE_REF} không hợp lệ hoặc không verify được — TỪ CHỐI cài." >&2
  exit 1
fi
if [ "$ACTUAL_FPR" != "$AGENT_BUNDLE_TRUSTED_FINGERPRINT" ]; then
  echo "AGENT_INSTALL_STATUS=failed"
  echo "Bundle ${AGENT_BUNDLE_REF} được ký bởi ${ACTUAL_FPR}, không khớp fingerprint tin cậy — TỪ CHỐI cài." >&2
  exit 1
fi
echo "Chữ ký hợp lệ, ký bởi ${ACTUAL_FPR}."

echo "=== Giải nén bundle ==="
echo "##PROGRESS## 20 extract_bundle"
mkdir -p /tmp/agent-bundle
tar xzf "$DATA_FILE" -C /tmp/agent-bundle
for f in agent executor provision.sh hardening-agent.service hardening-executor.service; do
  if [ ! -f "/tmp/agent-bundle/$f" ]; then
    echo "AGENT_INSTALL_STATUS=failed"
    echo "Bundle ${AGENT_BUNDLE_REF} thiếu file '$f' sau khi giải nén — xem apps/agent/README.md mục đóng gói." >&2
    exit 1
  fi
done
chmod +x /tmp/agent-bundle/agent /tmp/agent-bundle/executor /tmp/agent-bundle/provision.sh

mkdir -p /tmp/ssh
echo "$SSH_KEY_B64" | base64 -d > /tmp/ssh/job_key
chmod 600 /tmp/ssh/job_key
echo "$AGENT_ENROLL_TOKEN_B64" | base64 -d > /tmp/agent-bundle/enroll-token
echo "$CA_ROOT_PEM_B64" | base64 -d > /tmp/agent-bundle/ca-root.crt
cat > /tmp/agent-bundle/agent.env <<EOF
AGENT_MANAGER_URL=${AGENT_MANAGER_PUBLIC_URL}
AGENT_HOSTNAME=${AGENT_HOSTNAME}
EOF

SSH_OPTS="-i /tmp/ssh/job_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes"
if [ -n "$SSH_CERT_B64" ]; then
  echo "$SSH_CERT_B64" | base64 -d > /tmp/ssh/job_key-cert.pub
  chmod 644 /tmp/ssh/job_key-cert.pub
  SSH_OPTS="$SSH_OPTS -o CertificateFile=/tmp/ssh/job_key-cert.pub"
fi

set +e

echo "=== Tạo thư mục tạm trên máy đích ==="
echo "##PROGRESS## 35 mkdir_remote"
ssh $SSH_OPTS -p "$TARGET_PORT" "${SSH_USER}@${TARGET_HOST}" 'mkdir -p /tmp/agent-install' 2>/tmp/step_stderr.log
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "AGENT_INSTALL_STATUS=failed"
  echo "--- stderr (mkdir máy đích) ---"
  cat /tmp/step_stderr.log
  exit 1
fi

# === Chuẩn bị sẵn cấu hình cho Executor (Active Response) ===
# Executor chạy TRÊN MÁY ĐÍCH nên tự nó phải verify được chữ ký bundle
# remediation — khác hoàn toàn đường SSH agentless (gpg chạy trong chính
# container này, keyring đã có key nhúng lúc build image, xem Dockerfile).
# Thiếu 2 file dưới đây thì Executor khởi động là Fatal ("thiếu
# EXECUTOR_TRUSTED_SIGNER_FINGERPRINT") hoặc từ chối MỌI bundle ("chữ ký
# không hợp lệ hoặc không verify được") — cả 2 đều đã xảy ra thật trên host
# đầu tiên bật Active Response, và thông báo lỗi không hề chỉ ra thiếu cái gì.
#
# CHỈ CHUẨN BỊ SẴN, KHÔNG tự bật service: Executor chạy quyền root và thực
# thi playbook tuỳ ý trong bundle, việc bật nó là quyết định có chủ đích của
# operator (xem apps/agent/executor/hardening-executor.service) — script này
# chỉ lo phần không có lý do gì bắt người ta làm tay.
echo "=== Chuẩn bị cấu hình Executor (fingerprint + public key) ==="
printf 'EXECUTOR_TRUSTED_SIGNER_FINGERPRINT=%s\n' "$CONTENT_SIGNING_TRUSTED_FINGERPRINT" \
  > /tmp/agent-bundle/executor.env
# Xuất ĐÚNG public key ứng với fingerprint tin cậy từ keyring của chính image
# này (nguồn đã dùng để verify bundle agent ở trên) — không lấy từ nơi khác,
# không tin file nào do máy đích cung cấp.
if ! gpg --armor --export "$CONTENT_SIGNING_TRUSTED_FINGERPRINT" > /tmp/agent-bundle/content-signer.asc 2>/dev/null \
   || [ ! -s /tmp/agent-bundle/content-signer.asc ]; then
  echo "AGENT_INSTALL_STATUS=failed"
  echo "LOI: khong xuat duoc public key cho fingerprint ${CONTENT_SIGNING_TRUSTED_FINGERPRINT} tu keyring cua image nay" >&2
  echo "     — kiem tra apps/execution-env/trusted-signer-pubkey.asc da la key THAT chua (khong phai placeholder)." >&2
  exit 1
fi

echo "=== Copy binary + provision.sh + unit + token/ca-root ==="
echo "##PROGRESS## 50 copy_files"
# scp dùng -P (HOA) cho cổng, KHÁC ssh dùng -p (thường) — -p với scp lại có
# nghĩa "preserve mode/timestamps", nhầm cờ sẽ âm thầm bỏ qua TARGET_PORT.
scp $SSH_OPTS -P "$TARGET_PORT" \
  /tmp/agent-bundle/agent /tmp/agent-bundle/executor /tmp/agent-bundle/provision.sh \
  /tmp/agent-bundle/hardening-agent.service /tmp/agent-bundle/hardening-executor.service \
  /tmp/agent-bundle/enroll-token /tmp/agent-bundle/ca-root.crt /tmp/agent-bundle/agent.env \
  /tmp/agent-bundle/executor.env /tmp/agent-bundle/content-signer.asc \
  "${SSH_USER}@${TARGET_HOST}:/tmp/agent-install/" 2>/tmp/step_stderr.log
RC=$?
if [ "$RC" -ne 0 ]; then
  echo "AGENT_INSTALL_STATUS=failed"
  echo "--- stderr (scp) ---"
  cat /tmp/step_stderr.log
  exit 1
fi

echo "=== Copy datastream SSG (cho agent-scan cục bộ) ==="
echo "##PROGRESS## 65 copy_datastreams"
SSG_CONTENT_DIR="/usr/share/xml/scap/ssg/content"
SSG_DATASTREAMS=()
for f in ssg-ubuntu2204-ds.xml ssg-debian10-ds.xml ssg-debian11-ds.xml; do
  [ -f "${SSG_CONTENT_DIR}/${f}" ] && SSG_DATASTREAMS+=("${SSG_CONTENT_DIR}/${f}")
done
if [ "${#SSG_DATASTREAMS[@]}" -gt 0 ]; then
  scp $SSH_OPTS -P "$TARGET_PORT" \
    "${SSG_DATASTREAMS[@]}" \
    "${SSH_USER}@${TARGET_HOST}:/tmp/agent-install/" 2>/tmp/step_stderr.log
  RC=$?
  if [ "$RC" -ne 0 ]; then
    echo "AGENT_INSTALL_STATUS=failed"
    echo "--- stderr (scp datastream) ---"
    cat /tmp/step_stderr.log
    exit 1
  fi
else
  echo "CẢNH BÁO: không thấy file datastream nào trong ${SSG_CONTENT_DIR} của chính image này — bỏ qua." >&2
fi

echo "=== Chạy cài đặt trên máy đích ==="
echo "##PROGRESS## 80 remote_install"
REMOTE_OUTPUT=$(ssh $SSH_OPTS -p "$TARGET_PORT" "${SSH_USER}@${TARGET_HOST}" 'bash -s' 2>/tmp/step_stderr.log <<'REMOTE_SETUP_EOF'
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo "LOI: phai chay bang root." >&2
  exit 1
fi
mkdir -p /opt/hardening-agent/executor
install -m 0755 /tmp/agent-install/agent /opt/hardening-agent/agent
install -m 0755 /tmp/agent-install/executor /opt/hardening-agent/executor/executor
bash /tmp/agent-install/provision.sh
mkdir -p /usr/share/xml/scap/ssg/content
for f in /tmp/agent-install/ssg-*-ds.xml; do
  [ -e "$f" ] && install -m 0644 "$f" /usr/share/xml/scap/ssg/content/
done
umask 077
install -m 0600 /tmp/agent-install/enroll-token /etc/hardening-agent/enroll-token
install -m 0644 /tmp/agent-install/ca-root.crt /etc/hardening-agent/ca-root.crt
install -m 0644 /tmp/agent-install/agent.env /etc/hardening-agent/agent.env
chown hardening-agent:hardening-agent /etc/hardening-agent/enroll-token /etc/hardening-agent/ca-root.crt /etc/hardening-agent/agent.env
install -m 0644 /tmp/agent-install/hardening-agent.service /etc/systemd/system/hardening-agent.service
install -m 0644 /tmp/agent-install/hardening-executor.service /etc/systemd/system/hardening-executor.service

# Cau hinh Executor -- root:root 0600 (KHAC 3 file tren thuoc
# hardening-agent): file nay do systemd doc bang quyen root TRUOC khi fork
# Executor, Reporter khong can va khong nen doc duoc.
install -m 0600 -o root -g root /tmp/agent-install/executor.env /etc/hardening-agent/executor.env
# Public key content-signing vao keyring ROOT -- Executor shell ra
# "gpg --verify" bang chinh user root, keyring rong = tu choi moi bundle.
gpg --import /tmp/agent-install/content-signer.asc 2>&1 | tail -2 || \
  echo "CANH BAO: import public key content-signing that bai -- Executor se tu choi moi bundle remediation." >&2

if ! command -v oscap >/dev/null 2>&1; then
  echo "Chua co 'oscap' -- tu cai openscap-scanner de agent-scan chay duoc cuc bo..."
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq \
      && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openscap-scanner \
      || echo "CANH BAO: tu cai openscap-scanner that bai -- agent-scan se loi 'oscap: command not found' cho toi khi cai tay (apt-get install -y openscap-scanner)." >&2
  else
    echo "CANH BAO: khong tim thay apt-get -- tu cai openscap-scanner that bai, can cai tay." >&2
  fi
fi

systemctl daemon-reload
systemctl enable hardening-agent.service
# restart (không phải "enable --now") -- neu service dang chay tu lan cai
# truoc, "enable --now" KHONG lam gi vi da active, binary/agent.env moi ghi
# se KHONG duoc ap dung cho toi khi restart/reboot thu cong -- phat hien
# thuc te khi cai lai tren host da co Agent chay tu lan truoc (agent.env
# moi khong co hieu luc, Agent van dung config cu).
systemctl restart hardening-agent.service
rm -rf /tmp/agent-install
echo "Reporter da chay -- xem: journalctl -u hardening-agent -f"
echo "Executor (Active Response) da duoc CHUAN BI DAY DU (executor.env +"
echo "public key trong keyring root) nhung CO Y chua bat -- no chay quyen root"
echo "va thuc thi playbook, bat la quyet dinh cua operator."
if command -v ansible-playbook >/dev/null 2>&1; then
  echo "Muon dung Active Response, chay: systemctl enable --now hardening-executor.service"
else
  # Executor tu Fatal neu thieu ansible-playbook (exec.LookPath luc khoi
  # dong) -- bao ngay o day thay vi de service chet sau khi bat.
  echo "LUU Y: may nay CHUA co ansible-playbook -- Executor se khong khoi dong duoc."
  echo "Muon dung Active Response: apt-get install -y ansible-core (hoac tuong duong),"
  echo "roi: systemctl enable --now hardening-executor.service"
fi
REMOTE_SETUP_EOF
)
RC=$?
set -e

echo "$REMOTE_OUTPUT"
if [ "$RC" -ne 0 ]; then
  echo "AGENT_INSTALL_STATUS=failed"
  echo "--- stderr (cài đặt trên máy đích) ---"
  cat /tmp/step_stderr.log
  exit 1
fi

echo "AGENT_INSTALL_STATUS=ok"
exit 0
