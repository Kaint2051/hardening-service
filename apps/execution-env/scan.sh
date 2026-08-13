#!/usr/bin/env bash
# Agentless OpenSCAP scan qua SSH (mục 7 roadmap: "agentless qua
# Ansible+OpenSCAP cho 1 benchmark CIS"). Dùng oscap-ssh (từ openscap-utils) —
# LƯU Ý: oscap-ssh chỉ upload nội dung SCAP qua scp, máy đích vẫn cần binary
# `oscap` (gói openscap-scanner) — script này tự SSH cài gói đó (apt) nếu máy
# đích chưa có (xem đoạn "Kiểm tra 'oscap'..." bên dưới), operator không cần
# tự SSH tay vào cài trước, KHÁC hẳn trạng thái ban đầu ("không phải
# zero-install hoàn toàn như Ansible") — vẫn cần máy đích có apt + Internet.
#
# Input qua biến môi trường (do job-dispatcher truyền vào lúc `docker run`):
#   TARGET_HOST, SSH_USER, SSH_KEY_B64 — luôn có
#   SSH_CERT_B64 — TUỲ CHỌN: có nếu Orchestrator cấp cert SSH ngắn hạn (xem
#     app/ca_client.py, mặc định); THIẾU nếu host đã cấu hình static SSH key
#     (app/models.py:Host.static_ssh_private_key_encrypted, xem app/jobs.py:
#     _get_ssh_dispatch_environment) — SSH_KEY_B64 khi đó tự đủ để auth,
#     không cần CertificateFile.
#   TARGET_PORT — cổng SSH của host (Host.ssh_port, mặc định 22)
#   SCAP_PROFILE   — vd xccdf_org.ssgproject.content_profile_cis_level1_server
#   SCAP_DATASTREAM — đường dẫn datastream trong image, vd
#     /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
set -euo pipefail
: "${TARGET_HOST:?thiếu TARGET_HOST}"
: "${SSH_USER:?thiếu SSH_USER}"
: "${SSH_KEY_B64:?thiếu SSH_KEY_B64}"
SSH_CERT_B64="${SSH_CERT_B64:-}"
: "${TARGET_PORT:?thiếu TARGET_PORT}"
: "${SCAP_PROFILE:?thiếu SCAP_PROFILE}"
: "${SCAP_DATASTREAM:?thiếu SCAP_DATASTREAM}"

mkdir -p /tmp/ssh
echo "$SSH_KEY_B64" | base64 -d > /tmp/ssh/job_key
chmod 600 /tmp/ssh/job_key
SSH_OPTS=(-i /tmp/ssh/job_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o BatchMode=yes)
SSH_ADDITIONAL_OPTIONS="-i /tmp/ssh/job_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"
if [ -n "$SSH_CERT_B64" ]; then
  echo "$SSH_CERT_B64" | base64 -d > /tmp/ssh/job_key-cert.pub
  chmod 644 /tmp/ssh/job_key-cert.pub
  SSH_OPTS+=(-o CertificateFile=/tmp/ssh/job_key-cert.pub)
  SSH_ADDITIONAL_OPTIONS="$SSH_ADDITIONAL_OPTIONS -o CertificateFile=/tmp/ssh/job_key-cert.pub"
fi
export SSH_ADDITIONAL_OPTIONS

# oscap-ssh chỉ upload NỘI DUNG SCAP qua scp, máy đích vẫn cần tự có binary
# `oscap` (gói openscap-scanner) — tự cài qua chính phiên SSH đang có sẵn
# ở đây (giống hệt cách agent-install.sh đã SSH vào cài Agent), operator
# không cần tự SSH tay vào máy đích trước khi scan lần đầu (phát hiện qua
# test thật: oscap-ssh báo "oscap: command not found", máy đích thiếu gói).
# Chỉ hỗ trợ apt (Debian/Ubuntu) — khớp đúng phạm vi distro SCAP_PROFILES
# đang hỗ trợ, xem app/jobs.py.
echo "Kiểm tra 'oscap' đã có trên máy đích chưa..."
set +e
ssh "${SSH_OPTS[@]}" -p "$TARGET_PORT" "${SSH_USER}@${TARGET_HOST}" 'command -v oscap >/dev/null 2>&1'
OSCAP_PRESENT=$?
set -e

if [ "$OSCAP_PRESENT" -ne 0 ]; then
  echo "Chưa có 'oscap' trên máy đích — tự cài gói openscap-scanner qua SSH..."
  set +e
  ssh "${SSH_OPTS[@]}" -p "$TARGET_PORT" "${SSH_USER}@${TARGET_HOST}" \
    'command -v apt-get >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openscap-scanner'
  INSTALL_RC=$?
  set -e
  if [ "$INSTALL_RC" -ne 0 ]; then
    echo "SCAN_JOB_STATUS=error"
    echo "Tự cài openscap-scanner thất bại trên máy đích (rc=$INSTALL_RC) — kiểm tra máy đích có apt-get + repo/Internet không, hoặc tự cài tay (apt-get install -y openscap-scanner) rồi scan lại."
    exit 1
  fi
  echo "Đã cài xong openscap-scanner trên máy đích."
fi

set +e
oscap-ssh "${SSH_USER}@${TARGET_HOST}" "$TARGET_PORT" xccdf eval \
  --profile "$SCAP_PROFILE" \
  --results /tmp/results.xml \
  --report /tmp/report.html \
  "$SCAP_DATASTREAM"
OSCAP_RC=$?
set -e

# oscap xccdf eval trả 0=tất cả pass, 2=có rule fail (không phải lỗi thực thi),
# các mã khác là lỗi thật (không tạo được kết nối, content lỗi...). Không coi
# rc=2 là job fail — đó là kết quả scan hợp lệ (có finding), chỉ rc ngoài
# {0,2} hoặc thiếu file kết quả mới là job fail thật.
if [ ! -f /tmp/results.xml ]; then
  echo "SCAN_JOB_STATUS=error"
  echo "Không tạo được file kết quả (oscap-ssh rc=$OSCAP_RC) — xem log phía trên."
  exit 1
fi

# grep thoát mã 1 khi KHÔNG tìm thấy dòng nào khớp (vd 0 rule fail) — với
# set -e + pipefail, điều đó làm script dừng giữa chừng dù đây không phải lỗi
# thật (phát hiện qua test thật: oscap-ssh chạy đúng, rc=0, nhưng job vẫn bị
# đánh dấu failed vì script chết ngay tại bước đếm này). Thêm "|| true".
PASS_COUNT=$(grep -o '<result>pass</result>' /tmp/results.xml | wc -l) || true
FAIL_COUNT=$(grep -o '<result>fail</result>' /tmp/results.xml | wc -l) || true
OTHER_COUNT=$(grep -oE '<result>[a-z]+</result>' /tmp/results.xml | grep -vE 'pass|fail' | wc -l) || true

echo "SCAN_JOB_STATUS=completed"
echo "SCAN_RESULT_PASS=$PASS_COUNT"
echo "SCAN_RESULT_FAIL=$FAIL_COUNT"
echo "SCAN_RESULT_OTHER=$OTHER_COUNT"

# Chi tiết từng rule pass/fail (bỏ notapplicable/error/unknown... — chỉ giữ
# 2 loại thật sự hành động được, tránh phình dữ liệu với rule không áp dụng).
python3 - <<'PYEOF'
import json
import xml.etree.ElementTree as ET

NS = "{http://checklists.nist.gov/xccdf/1.2}"
try:
    root = ET.parse("/tmp/results.xml").getroot()
except ET.ParseError:
    root = None

findings = []
if root is not None:
    titles = {}
    for rule in root.iter(f"{NS}Rule"):
        title_el = rule.find(f"{NS}title")
        if title_el is not None and title_el.text:
            titles[rule.get("id")] = title_el.text.strip()

    for rr in root.iter(f"{NS}rule-result"):
        result_el = rr.find(f"{NS}result")
        result = (result_el.text or "").strip() if result_el is not None else ""
        if result not in ("pass", "fail"):
            continue
        rule_id = rr.get("idref")
        findings.append({
            "rule_id": rule_id,
            "title": titles.get(rule_id, rule_id),
            "result": result,
            "severity": rr.get("severity", "unknown"),
        })

with open("/tmp/findings.json", "w") as f:
    json.dump(findings, f)
PYEOF

echo "FINDINGS_JSON_BEGIN"
cat /tmp/findings.json
echo ""
echo "FINDINGS_JSON_END"

if [ "$OSCAP_RC" -ne 0 ] && [ "$OSCAP_RC" -ne 2 ]; then
  echo "SCAN_JOB_STATUS=error"
  exit 1
fi
exit 0
