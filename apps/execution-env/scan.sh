#!/usr/bin/env bash
# Agentless OpenSCAP scan qua SSH (mục 7 roadmap: "agentless qua
# Ansible+OpenSCAP cho 1 benchmark CIS"). Dùng oscap-ssh (từ openscap-utils) —
# LƯU Ý: oscap-ssh chỉ upload nội dung SCAP qua scp, máy đích vẫn cần cài sẵn
# gói openscap-scanner (cung cấp binary `oscap`) — đây không phải zero-install
# hoàn toàn, khác với Ansible (chỉ cần Python).
#
# Input qua biến môi trường (do job-dispatcher truyền vào lúc `docker run`):
#   TARGET_HOST, SSH_USER, SSH_KEY_B64, SSH_CERT_B64  — cert SSH ngắn hạn do
#     Orchestrator cấp riêng cho job này (xem app/ca_client.py)
#   SCAP_PROFILE   — vd xccdf_org.ssgproject.content_profile_cis_level1_server
#   SCAP_DATASTREAM — đường dẫn datastream trong image, vd
#     /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
set -euo pipefail
: "${TARGET_HOST:?thiếu TARGET_HOST}"
: "${SSH_USER:?thiếu SSH_USER}"
: "${SSH_KEY_B64:?thiếu SSH_KEY_B64}"
: "${SSH_CERT_B64:?thiếu SSH_CERT_B64}"
: "${SCAP_PROFILE:?thiếu SCAP_PROFILE}"
: "${SCAP_DATASTREAM:?thiếu SCAP_DATASTREAM}"

mkdir -p /tmp/ssh
echo "$SSH_KEY_B64" | base64 -d > /tmp/ssh/job_key
echo "$SSH_CERT_B64" | base64 -d > /tmp/ssh/job_key-cert.pub
chmod 600 /tmp/ssh/job_key
chmod 644 /tmp/ssh/job_key-cert.pub

export SSH_ADDITIONAL_OPTIONS="-i /tmp/ssh/job_key -o CertificateFile=/tmp/ssh/job_key-cert.pub -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

set +e
oscap-ssh "${SSH_USER}@${TARGET_HOST}" 22 xccdf eval \
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
