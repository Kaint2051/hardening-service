"""Trigger job scan/remediate thật qua Ephemeral Execution Environment (mục
7 roadmap).

Luồng 1 lần scan:
  1. Orchestrator tự cấp 1 SSH cert ngắn hạn RIÊNG cho job này (app/ca_client.py).
  2. Gọi job-dispatcher (service DUY NHẤT giữ quyền Docker) để spawn 1
     container execution-env mới, truyền cert qua biến môi trường.
  3. Container chạy oscap-ssh, huỷ ngay sau khi xong (job-dispatcher tự dọn).
  4. Ghi lại kết quả vào bảng jobs + audit log.

Luồng remediate (2 bước tách biệt, KHÔNG có đường tắt "apply trực tiếp" —
nguyên tắc cốt lõi #2 architecture-proposal.md "dry-run/diff bắt buộc trước
mọi remediation thật"):
  1. `trigger_remediate_dry_run` — chạy `ansible-playbook --check --diff`,
     KHÔNG đổi gì trên host đích, chỉ xem trước sẽ đổi gì.
  2. `trigger_remediate_apply` — bắt buộc tham chiếu đúng 1 dry-run job vừa
     `succeeded`, còn mới (`DRY_RUN_MAX_AGE`); backup cấu hình liên quan
     TRƯỚC khi đổi thật (nguyên tắc cốt lõi #7: "rollback/backup được tạo
     TRƯỚC khi remediate"); four-eyes (người đề xuất dry-run ≠ người apply)
     bắt buộc cho host Tier 0/1, khớp đúng tiền lệ four-eyes CA migration
     (`app/hosts.py`).

Nội dung remediation thật (`RemediationVariant.remediation_ref`) trỏ tới
bundle ĐÃ KÝ trong `scripts/content-signing/signed/` — execution-env's
`remediate.sh` tự verify chữ ký trước khi chạy, KHÔNG tin nội dung mount vào
một cách vô điều kiện. `apps/execution-env/requirements.yml` vẫn giữ nguyên
placeholder commit hash chưa review — pipeline này sẵn sàng chạy ngay khi
Reviewer điền commit hash thật, không cần sửa code gì thêm.

Chạy ĐỒNG BỘ trong request (chấp nhận được ở quy mô ≤50 máy/MVP — xem
docs/architecture-proposal.md mục 6 "Postgres-backed queue ở MVP"; chuyển
sang hàng đợi bất đồng bộ là việc của Giai đoạn sau nếu cần).
"""
import base64
import hmac
import json
import logging
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.audit import write_audit_event
from app.auth import CurrentUser, require_roles
from app.ca_client import mint_agent_manager_server_cert, mint_ssh_certificate
from app.config import settings
from app.db import SessionLocal
from app.models import Control, Host, Job, RemediationVariant
from app.schemas import AgentVerifyEnrollResponse, JobListOut, JobOut, RemediateApplyRequest, RestoreRequest, ScanTrigger

logger = logging.getLogger(__name__)

router = APIRouter(tags=["jobs"])

_OPERATOR_ROLES = ("operator", "admin")

# Khớp đúng _HIGH_TIER_MAX trong app/hosts.py (four-eyes CA migration) — cùng
# ngưỡng "Tier cao" cho four-eyes remediate-apply, xem
# trigger_remediate_apply. Không import trực tiếp (tên private module khác)
# — trùng giá trị cố ý, không phải trùng lặp tình cờ.
_REMEDIATE_HIGH_TIER_MAX = 1

# Dry-run "hết hạn" sau chừng này — chặn apply dựa trên 1 dry-run cũ, có thể
# đã lệch trạng thái thật của host (drift) từ lúc dry-run tới lúc apply.
DRY_RUN_MAX_AGE = timedelta(minutes=30)

# Ngân sách thời gian tối đa Orchestrator CHỜ Agent claim + báo cáo kết quả
# remediate (xem _dispatch_remediate_job_via_agent). Module-level (không
# phải hằng cục bộ trong hàm) để test monkeypatch xuống giá trị nhỏ, không
# phải chờ thật.
#
# PHẢI lớn hơn hẳn tổng ngân sách phía Agent cộng dồn (phát hiện qua rà soát
# đối kháng — giá trị cũ 340s KHỚP ĐÚNG _call_job_dispatcher của đường SSH
# nhưng KHÔNG liên quan gì tới ngân sách thật của đường Agent, trùng hợp chỉ
# vì cùng 1 số): AGENT_REMEDIATE_POLL_INTERVAL mặc định 15s (agent chưa chắc
# nhận job ngay khi Orchestrator vừa đặt "pending") + gpgVerifyTimeout cố
# định 30s (verify.go) + EXECUTOR_REMEDIATE_TIMEOUT mặc định 300s
# (executor/main.go, operator CÓ THỂ tự nâng cho playbook chậm hơn — xem
# comment tại đó) = 345s CHỈ TÍNH riêng 3 ngân sách chính, CHƯA cộng round-
# trip claim/tải bundle/report qua mTLS. 345s > 340s (giá trị cũ) nghĩa là 1
# apply hợp lệ chạy gần hết ngân sách mặc định của Executor GẦN NHƯ CHẮC
# CHẮN bị Orchestrator tự đánh "failed"/agent_remediate_timeout TRƯỚC KHI
# Agent kịp báo kết quả thật — không phải race hiếm, mà là sai lệch cấu
# hình mặc định. Đặt dư margin ~250s cho round-trip mạng + jitter; NẾU tăng
# EXECUTOR_REMEDIATE_TIMEOUT, PHẢI tăng tương ứng giá trị này (chưa có cơ
# chế tự validate 2 giá trị khớp nhau giữa 2 service — ghi rõ ở đây thay vì
# để lại ngầm định).
AGENT_REMEDIATE_DISPATCH_TIMEOUT = 600

# GET /jobs — khác /hosts, /controls (trả list() không giới hạn, chấp nhận
# được vì tự nhiên bị chặn bởi quy mô ≤50 host / số control do người tạo
# tay), bảng jobs tăng KHÔNG giới hạn theo thời gian (mỗi lần scan/remediate/
# canary host đều tạo 1 row) nên bắt buộc phải phân trang ngay từ đầu.
_JOB_LIST_DEFAULT_LIMIT = 50
_JOB_LIST_MAX_LIMIT = 200

# SSG (SCAP Security Guide / ComplianceAsCode) — nội dung mở đóng gói qua apt
# Debian (gói ssg-debderived + ssg-debian, xem apps/execution-env/Dockerfile),
# KHÔNG phải benchmark CIS được CIS chứng nhận/cấp phép chính thức (đòi hỏi
# CIS SecureSuite) — dùng cho mục đích kỹ thuật/demo, cần xác nhận yêu cầu
# pháp lý/giấy phép trước khi dùng làm căn cứ tuân thủ chính thức (xem rủi ro
# #1, mục 8 architecture-proposal.md).
#
# LƯU Ý tên gói apt gây hiểu nhầm (phát hiện qua kiểm tra thật nội dung từng
# gói, không phải suy đoán từ tên): "ssg-debderived" chỉ chứa benchmark cho
# các distro "derived FROM Debian" — tức HỌ UBUNTU (ssg-ubuntu2204-*.xml...),
# KHÔNG chứa bản Debian nào cả. Debian thật (buster/bullseye) nằm ở gói RIÊNG
# "ssg-debian" (ssg-debian10-*.xml/ssg-debian11-*.xml) — không có bản
# debian12/bookworm trong version gói hiện tại (0.1.65-1). Cả 2 gói này chỉ
# có đúng 1 profile chung "standard" cho Debian (không có bản CIS riêng như
# Ubuntu).
SCAP_PROFILES = {
    "ubuntu2204-cis-level1-server": {
        "datastream": "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml",
        "profile": "xccdf_org.ssgproject.content_profile_cis_level1_server",
    },
    "ubuntu2204-standard": {
        "datastream": "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml",
        "profile": "xccdf_org.ssgproject.content_profile_standard",
    },
    "debian10-standard": {
        "datastream": "/usr/share/xml/scap/ssg/content/ssg-debian10-ds.xml",
        "profile": "xccdf_org.ssgproject.content_profile_standard",
    },
    "debian11-standard": {
        "datastream": "/usr/share/xml/scap/ssg/content/ssg-debian11-ds.xml",
        "profile": "xccdf_org.ssgproject.content_profile_standard",
    },
}

# Provisioner "orchestrator" trên step-ca chỉ siết TTL (xem
# infra/step-ca/setup-provisioners.sh), KHÔNG tự giới hạn principal được phép
# cấp cert — nếu không allowlist ở đây, bất kỳ user có role operator/admin
# nào cũng có thể tự chọn cấp SSH cert cho principal tuỳ ý qua ScanTrigger
# (phát hiện qua code review, không phải qua test thật). OpenSCAP cần quyền
# root để đọc đầy đủ cấu hình hệ thống nên chỉ allowlist "root".
ALLOWED_SSH_USERS = ("root",)


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _check_job_dispatcher_auth(authorization: str | None) -> None:
    # Cùng pattern app/agents.py:_check_agent_manager_auth — Bearer + so
    # sánh hằng thời gian.
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="thiếu Authorization header")
    token = authorization[len("Bearer "):]
    if not hmac.compare_digest(token, settings.job_dispatcher_shared_secret):
        raise HTTPException(status_code=401, detail="shared secret sai")


@router.post("/internal/job-dispatcher/server-cert", response_model=AgentVerifyEnrollResponse)
def job_dispatcher_server_cert(authorization: str | None = Header(default=None)) -> AgentVerifyEnrollResponse:
    """job-dispatcher không nối `ca-net` (chỉ Orchestrator được gọi CA) — xin
    cert server mTLS của chính nó qua đây, tự renew định kỳ trước khi hết
    hạn, cùng pattern hệt `app/agents.py:agent_manager_server_cert`
    (subject khác, cùng hàm `mint_agent_manager_server_cert`)."""
    _check_job_dispatcher_auth(authorization)
    try:
        cert_pem, key_pem = mint_agent_manager_server_cert("job-dispatcher")
    except RuntimeError as exc:
        raise HTTPException(
            status_code=502, detail=f"không cấp được server cert cho job-dispatcher: {exc}"
        ) from exc

    write_audit_event(
        actor="job-dispatcher", action="job_dispatcher_server_cert_issued",
        resource="job-dispatcher", payload={},
    )

    with open(settings.stepca_root_cert_path, encoding="utf-8") as f:
        ca_root_pem = f.read()
    return AgentVerifyEnrollResponse(cert_pem=cert_pem, key_pem=key_pem, ca_root_pem=ca_root_pem)


def _call_job_dispatcher(dispatch_body: dict, timeout: float) -> dict:
    """Gọi job-dispatcher qua mTLS — Orchestrator tự mint 1 cert CLIENT MỚI
    cho MỖI lần gọi thay vì cache/renew: mỗi lần gọi `/run` là 1 job RIÊNG
    LẺ (không phải kết nối dài hạn như Agent Manager), nên mint-mới-mỗi-lần
    đơn giản hơn nhiều mà vẫn giữ đúng "no standing privilege" — cùng triết
    lý `mint_ssh_certificate` (mỗi job 1 SSH cert ngắn hạn riêng, không tái
    dùng). TTL do provisioner "orchestrator" quyết định (5-15 phút), thừa đủ
    cho 1 request/response, cert bị xoá khỏi đĩa ngay khi request xong (kể cả
    lỗi) nhờ `TemporaryDirectory`.

    Vẫn giữ NGUYÊN Authorization: Bearer (shared secret) — phòng thủ theo
    chiều sâu, không thay thế lớp cũ mà cộng thêm lớp mTLS, cùng tinh thần
    "2 lớp phòng thủ, cả hai đều bắt buộc" đã ghi ở app/job-dispatcher's
    README (allowlist image + shared secret) — giờ là 3 lớp.

    Raises httpx.HTTPError cho mọi lỗi (mint cert lỗi CŨNG được bọc thành
    httpx.ConnectError) — 3 nơi gọi hàm này đều đã có sẵn đúng 1 nhánh
    `except httpx.HTTPError` xử lý "dispatcher_call_failed", không cần đổi.
    """
    try:
        cert_pem, key_pem = mint_agent_manager_server_cert("orchestrator")
    except RuntimeError as exc:
        raise httpx.ConnectError(f"không cấp được client cert để gọi job-dispatcher: {exc}") from exc

    with tempfile.TemporaryDirectory() as tmpdir:
        cert_path = os.path.join(tmpdir, "client.crt")
        key_path = os.path.join(tmpdir, "client.key")
        with open(cert_path, "w", encoding="utf-8") as f:
            f.write(cert_pem)
        with open(key_path, "w", encoding="utf-8") as f:
            f.write(key_pem)
        os.chmod(key_path, 0o600)

        resp = httpx.post(
            f"{settings.job_dispatcher_url}/run",
            json=dispatch_body,
            headers={"Authorization": f"Bearer {settings.job_dispatcher_shared_secret}"},
            cert=(cert_path, key_path),
            verify=settings.stepca_root_cert_path,
            timeout=timeout,
        )
    resp.raise_for_status()
    return resp.json()


def _parse_scan_summary(logs: str) -> dict:
    # Tách khối FINDINGS_JSON_BEGIN/END ra trước khi cắt raw_log_tail — nếu
    # không, log JSON chi tiết (có thể dài) sẽ lấn hết phần transcript hữu
    # ích (oscap-ssh connect/copy/eval) khỏi 2000 ký tự cuối.
    findings = None
    logs_for_tail = logs
    if "FINDINGS_JSON_BEGIN" in logs and "FINDINGS_JSON_END" in logs:
        before, _, rest = logs.partition("FINDINGS_JSON_BEGIN")
        json_blob, _, _ = rest.partition("FINDINGS_JSON_END")
        logs_for_tail = before
        try:
            findings = json.loads(json_blob.strip())
        except json.JSONDecodeError:
            findings = None

    summary = {"raw_log_tail": logs_for_tail[-2000:]}
    for line in logs_for_tail.splitlines():
        if "=" not in line or not line.startswith(("SCAN_JOB_STATUS", "SCAN_RESULT_")):
            continue
        key, _, value = line.partition("=")
        summary[key.strip().lower()] = value.strip()
    if findings is not None:
        summary["findings"] = findings
        summary["findings_count"] = len(findings)
    return summary


# Giới hạn backup nhúng trong result_summary (JSON column) — bảo vệ CƠ BẢN
# trước khi remediate thật (nguyên tắc cốt lõi #7), KHÔNG phải kho lưu trữ
# backup đầy đủ. Dùng làm nguồn cho "1-click restore" (xem run_restore bên
# dưới) — restore TỪ CHỐI chạy nếu backup bị cắt (backup_truncated=True),
# không âm thầm khôi phục 1 phần.
BACKUP_MAX_BYTES = 2 * 1024 * 1024

# Docker container init process exec() qua kernel Linux giới hạn MỖI giá trị
# env var riêng lẻ ở MAX_ARG_STRLEN (32 trang bộ nhớ = 131072 byte trên hầu
# hết hệ thống) — xác nhận qua thử thật (không phải đọc tài liệu): 1 giá trị
# 131050 byte qua được, đúng 131072 byte thì container exec lỗi "invalid
# argument" (không phải lỗi Docker CLI/ARG_MAX của shell — dùng thẳng
# docker-py, KHÔNG qua `docker run` CLI, vẫn lỗi y hệt vì đây là giới hạn của
# chính execve() bên trong container). Backup (tới BACKUP_MAX_BYTES = 2 MiB)
# vượt xa ngưỡng này nếu nhét vào 1 biến duy nhất — chia nhỏ thành nhiều biến
# `BACKUP_TAR_B64_{i}`, mỗi biến dưới ngưỡng nhiều (chừa dư cho tiền tố
# "KEY=" + chỉ số), restore.sh ghép lại đúng thứ tự trước khi base64 decode.
RESTORE_CHUNK_SIZE = 100_000


def _chunk_backup_env(backup_b64: str) -> dict[str, str]:
    chunks = [backup_b64[i : i + RESTORE_CHUNK_SIZE] for i in range(0, len(backup_b64), RESTORE_CHUNK_SIZE)] or [""]
    env = {f"BACKUP_TAR_B64_{i}": chunk for i, chunk in enumerate(chunks)}
    env["BACKUP_TAR_B64_CHUNKS"] = str(len(chunks))
    return env


def _extract_block(logs: str, begin_marker: str, end_marker: str) -> tuple[str, str | None]:
    """Tách 1 khối đánh dấu BEGIN/END khỏi logs, trả (logs còn lại, nội dung khối)."""
    if begin_marker not in logs or end_marker not in logs:
        return logs, None
    before, _, rest = logs.partition(begin_marker)
    blob, _, after = rest.partition(end_marker)
    return before + after, blob.strip()


def _truncate_backup_b64(backup_b64: str) -> tuple[str, bool]:
    """Cắt backup base64 nếu vượt BACKUP_MAX_BYTES — NGUỒN SỰ THẬT DUY NHẤT
    cho việc cắt backup trong toàn bộ Orchestrator, dùng CHUNG cho cả 2
    đường dispatch remediate: SSH agentless (_parse_remediate_summary bên
    dưới, cắt log block BACKUP_TAR_B64_BEGIN/END) VÀ Agent Active Response
    (app/agents.py:report_remediate_result, cắt field backup_tar_b64 trong
    JSON) — 1 nội dung backup như nhau luôn bị cắt tại đúng 1 điểm bất kể
    remediate qua đường nào, và Agent/Executor KHÔNG được tự cắt phía của
    nó (xem package doc apps/agent/executor).

    So sánh trực tiếp độ dài CHUỖI base64 (không decode) với BACKUP_MAX_BYTES
    — giữ NGUYÊN hành vi đã có từ trước (không phải decode-rồi-đo-byte-gốc):
    chuỗi base64 chỉ gồm ký tự ASCII nên len() cho đúng số byte của chuỗi đó,
    và cắt tại đúng ranh giới ký tự này an toàn vì mục đích CHỈ để hiển thị/
    tham chiếu tóm tắt — run_restore đã TỪ CHỐI chạy nếu backup_truncated=True
    nên không ai giải mã lại phần base64 có thể bị cắt lệch nhóm 4 ký tự này.
    """
    truncated = len(backup_b64) > BACKUP_MAX_BYTES
    return (backup_b64[:BACKUP_MAX_BYTES] if truncated else backup_b64), truncated


def _parse_remediate_summary(logs: str) -> dict:
    logs_for_tail, diff_output = _extract_block(logs, "DIFF_OUTPUT_BEGIN", "DIFF_OUTPUT_END")
    logs_for_tail, backup_b64 = _extract_block(logs_for_tail, "BACKUP_TAR_B64_BEGIN", "BACKUP_TAR_B64_END")

    summary = {"raw_log_tail": logs_for_tail[-2000:]}
    for line in logs_for_tail.splitlines():
        if "=" not in line or not line.startswith(("SCAN_JOB_STATUS", "SCAN_RESULT_")):
            continue
        key, _, value = line.partition("=")
        summary[key.strip().lower()] = value.strip()

    if diff_output is not None:
        summary["diff_output"] = diff_output[-4000:]

    if backup_b64 is not None:
        summary["backup_tar_b64"], summary["backup_truncated"] = _truncate_backup_b64(backup_b64)

    return summary


def _find_remediation_variant(db: Session, control_id: str, host: Host) -> RemediationVariant | None:
    """Chọn RemediationVariant TỰ ĐỘNG theo distro/version máy đích — KHÔNG
    nhận client tự chọn (khác `scap_profile_key` của scan) — đúng nguyên tắc
    "hệ thống từ chối job nếu không tìm thấy RemediationVariant khớp đúng
    distro/version" (mục 3 kiến trúc), remediate rủi ro cao hơn scan nên
    không cho phép chọn nhầm.

    Ưu tiên khớp đúng `os_version` cụ thể; nếu không có, thử bản "mọi
    version" (`os_version IS NULL`) của cùng `os_family` — cho phép 1
    RemediationVariant dùng chung cho cả 1 distro thay vì phải khai từng
    version 1 dòng riêng.
    """
    exact = (
        db.query(RemediationVariant)
        .filter(
            RemediationVariant.control_id == control_id,
            RemediationVariant.os_family == host.os_family,
            RemediationVariant.os_version == host.os_version,
        )
        .first()
    )
    if exact is not None or host.os_version is None:
        return exact
    return (
        db.query(RemediationVariant)
        .filter(
            RemediationVariant.control_id == control_id,
            RemediationVariant.os_family == host.os_family,
            RemediationVariant.os_version.is_(None),
        )
        .first()
    )


def _dispatch_remediate_job(
    db: Session, job: Job, host: Host, variant: RemediationVariant, dry_run: bool,
    user: CurrentUser, audit_action_prefix: str,
) -> Job:
    """Rẽ nhánh MỎNG chọn đường dispatch remediate thật: Agent Active
    Response (mục 4.3/4.4 — Agent tự claim/tải bundle/thực thi/báo cáo) hay
    SSH agentless (mặc định/fallback, hành vi CŨ giữ NGUYÊN 100% qua
    _dispatch_remediate_job_via_ssh).

    Dùng đường Agent CHỈ KHI TẤT CẢ đều đúng — thiếu 1 điều kiện rơi về SSH:
      - settings.active_response_enabled: kill-switch TOÀN CỤC (app/config.py),
        mặc định TẮT — chưa bật thì hệ thống hành xử y hệt trước khi có tính
        năng này, không ai bị ảnh hưởng ngoài ý muốn.
      - host.agent_enrolled_at is not None: host đã enroll Agent thật (khác
        chỉ đăng ký Host thường, xem app/agents.py:verify_and_enroll).
      - host.active_response_enabled: bật RIÊNG cho từng host (app/hosts.py
        PATCH .../active-response) — operator có thể enroll Agent chỉ để
        scan/FIM, chưa cho phép remediate thật trên host đó.
      - NOT host.agent_renewal_blocked: host đang bị khoá renew cert mTLS
        (nghi ngờ bị chiếm, xem app/hosts.py PATCH .../agent-renewal) —
        không gửi lệnh remediate thật qua kênh Agent của 1 host đang bị nghi
        ngờ, dù về lý thuyết cert hiện có vẫn còn hạn.
    """
    use_agent = (
        settings.active_response_enabled
        and host.agent_enrolled_at is not None
        and host.active_response_enabled
        and not host.agent_renewal_blocked
    )
    if use_agent:
        return _dispatch_remediate_job_via_agent(db, job, host, variant, dry_run, audit_action_prefix)
    return _dispatch_remediate_job_via_ssh(
        db, job, host, variant, dry_run, user=user, audit_action_prefix=audit_action_prefix
    )


def _dispatch_remediate_job_via_agent(
    db: Session, job: Job, host: Host, variant: RemediationVariant, dry_run: bool, audit_action_prefix: str,
) -> Job:
    """Dispatch remediate qua Agent Active Response — KHÔNG có kết nối trực
    tiếp/đồng bộ nào tới Agent như đường SSH (_dispatch_remediate_job_via_ssh
    gọi job-dispatcher đồng bộ, chờ ngay response): Agent tự poll claim
    (POST /internal/agent/remediate-jobs/claim), tự tải bundle đã ký
    (POST .../remediation-bundle), tự verify+thực thi qua Executor (Unix
    socket nội bộ trên máy đích), rồi tự báo kết quả về
    (POST .../remediate-result — xem app/agents.py, nơi THẬT SỰ set
    job.status="succeeded"/"failed" + job.result_summary).

    Orchestrator ở đây CHỈ đặt job "pending" (tái dùng giá trị enum
    Job.status đã tồn tại từ trước nhưng trước pass này luôn là dead code —
    đường SSH không bao giờ dùng "pending", job tạo ra đã "running" ngay) rồi
    POLL (đọc lại DB mỗi 2s) tới khi Agent report xong hoặc hết ngân sách
    AGENT_REMEDIATE_DISPATCH_TIMEOUT — vẫn giữ đúng hợp đồng đồng bộ hiện có
    của run_remediate_dry_run/run_remediate_apply (trả JobOut đã xong ngay
    trong response, không có webhook/polling phía client).
    """
    job.status = "pending"
    db.commit()

    start = time.monotonic()
    while True:
        time.sleep(2)
        db.refresh(job)
        if job.status in ("succeeded", "failed"):
            return job
        if time.monotonic() - start > AGENT_REMEDIATE_DISPATCH_TIMEOUT:
            break

    # Refresh + re-check NGAY TRƯỚC KHI ghi đè (phát hiện qua rà soát đối
    # kháng): trước đây gán "failed" VÔ ĐIỀU KIỆN sau khi thoát vòng lặp,
    # không kiểm tra lại status hiện tại — nếu report_remediate_result
    # (app/agents.py, CÓ guard "job.status != running" trước khi ghi) vừa
    # commit "succeeded" kèm backup thật ĐÚNG vào khoảng giữa lần refresh
    # cuối trong vòng lặp trên và đây, bản ghi thật bị lost-update thành
    # "failed" (không có version column/optimistic lock nên
    # db.commit() ghi đè theo PK vô điều kiện). Cửa sổ còn lại sau re-check
    # này rất hẹp (vài dòng Python, không I/O chờ ở giữa) — chấp nhận được,
    # cùng mức độ rủi ro đã chấp nhận cho re-check tương tự ở
    # app/canary.py:_run_rollout (không dựng khoá phân tán cho quy mô 1
    # process/≤50 host hiện tại).
    db.refresh(job)
    if job.status in ("succeeded", "failed"):
        return job

    job.status = "failed"
    job.result_summary = {"error": "agent_remediate_timeout", "dispatch_via": "agent"}
    job.finished_at = datetime.now(timezone.utc)
    db.commit()
    # actor="system" (KHÁC nhánh SSH dùng actor=user.username cho
    # ca_mint_failed/dispatcher_call_failed) — timeout ở đây là 1 điều kiện
    # HỆ THỐNG xảy ra SAU KHI request gốc của user đã "thành công" theo nghĩa
    # tạo job/chuyển pending (Agent chỉ đơn giản không report kịp), không
    # phải lỗi đồng bộ ngay trong chính lệnh gọi API như bên SSH — cùng tiền
    # lệ actor="system" của app/canary.py:reconcile_orphaned_rollouts.
    write_audit_event(
        actor="system", action=f"{audit_action_prefix}_failed", resource=host.hostname,
        payload={"job_id": job.id, "control_id": job.control_id, "error": "agent_remediate_timeout"},
    )
    raise HTTPException(
        status_code=504,
        detail=(
            f"Agent không báo cáo kết quả remediate trong {AGENT_REMEDIATE_DISPATCH_TIMEOUT}s "
            "— job đã được đánh dấu failed"
        ),
    )


def _dispatch_remediate_job_via_ssh(
    db: Session, job: Job, host: Host, variant: RemediationVariant, dry_run: bool,
    user: CurrentUser, audit_action_prefix: str,
) -> Job:
    """Dùng chung cho cả dry-run lẫn apply — chỉ khác `DRY_RUN` env truyền
    xuống execution-env's remediate.sh. Audit event CUỐI CÙNG (thành công)
    do caller tự ghi (payload khác nhau — apply cần thêm `dry_run_job_id`).
    """
    try:
        private_key, cert_pub = mint_ssh_certificate(principal="root")
    except RuntimeError as exc:
        job.status = "failed"
        job.result_summary = {"error": str(exc)}
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        write_audit_event(
            actor=user.username, action=f"{audit_action_prefix}_failed", resource=host.hostname,
            payload={"job_id": job.id, "control_id": job.control_id, "error": "ca_mint_failed"},
        )
        raise HTTPException(status_code=502, detail=f"không cấp được SSH cert cho job: {exc}") from exc

    dispatch_body = {
        "job_id": str(job.id),
        "image": settings.allowed_execution_image,
        "command": ["remediate"],
        "environment": {
            "TARGET_HOST": host.ip_address,
            "SSH_USER": "root",
            "SSH_KEY_B64": base64.b64encode(private_key.encode()).decode(),
            "SSH_CERT_B64": base64.b64encode(cert_pub.encode()).decode(),
            "REMEDIATION_REF": variant.remediation_ref,
            "DRY_RUN": "true" if dry_run else "false",
            "CONTENT_SIGNING_TRUSTED_FINGERPRINT": settings.content_signing_trusted_fingerprint,
        },
        "timeout_seconds": 300,
    }

    try:
        result = _call_job_dispatcher(dispatch_body, timeout=340)
    except httpx.HTTPError as exc:
        job.status = "failed"
        job.result_summary = {"error": str(exc)}
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        write_audit_event(
            actor=user.username, action=f"{audit_action_prefix}_failed", resource=host.hostname,
            payload={"job_id": job.id, "control_id": job.control_id, "error": "dispatcher_call_failed"},
        )
        raise HTTPException(status_code=502, detail=f"job-dispatcher lỗi: {exc}") from exc

    summary = _parse_remediate_summary(result.get("logs", ""))
    summary["exit_code"] = result.get("exit_code")
    summary["dispatch_via"] = "ssh"
    job.status = "succeeded" if result.get("exit_code") == 0 else "failed"
    job.result_summary = summary
    job.finished_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(job)
    return job


def _require_control(db: Session, control_id: str) -> Control:
    control = db.get(Control, control_id)
    if control is None:
        raise HTTPException(status_code=404, detail="control không tồn tại")
    return control


def _lock_host_for_remediate(db: Session, hostname: str) -> Host:
    """SELECT Host FOR UPDATE — giữ khoá tới khi transaction hiện tại commit
    (transaction đó PHẢI bao trùm luôn INSERT Job ngay sau đó trong
    run_remediate_dry_run/run_remediate_apply, KHÔNG được xen db.commit() nào
    giữa lúc gọi hàm này và lúc Job mới commit — nếu không, lock chỉ còn tác
    dụng đúng trong câu SELECT này rồi thả ngay, không bảo vệ được gì) — chặn
    2 request remediate (dry-run HOẶC apply, cả 2 job_type đều tính) trên
    CÙNG 1 host chạy chồng lên nhau, có thể áp 2 thay đổi xung đột nhau lên
    cùng 1 máy đích cùng lúc.

    with_for_update() ĐÃ XÁC NHẬN qua test thật (không suy đoán — xem
    tests/test_jobs.py::test_with_for_update_and_skip_locked_do_not_raise_on_sqlite)
    là compile "trong suốt" trên SQLite: dialect KHÔNG hỗ trợ FOR UPDATE tự
    bỏ qua mệnh đề này khi compile thay vì raise lỗi (SQLite chỉ đơn giản
    KHÔNG khoá gì — chấp nhận được cho mục đích test vì SQLite không có
    concurrent writers thật trong test), nên gọi vô điều kiện ở cả 2 dialect
    là an toàn — chỉ Postgres (thật) mới thực sự khoá dòng.
    """
    host = db.query(Host).filter(Host.hostname == hostname).with_for_update().first()
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    conflicting = (
        db.query(Job)
        .filter(
            Job.hostname == hostname,
            Job.job_type.in_(("remediate-dry-run", "remediate-apply")),
            Job.status.in_(("pending", "running")),
        )
        .first()
    )
    if conflicting is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"host '{hostname}' đang có job remediate khác chạy dở "
                f"(job_id={conflicting.id}, status={conflicting.status}) — chờ job đó hoàn tất trước"
            ),
        )
    return host


def _require_remediation_variant(db: Session, control_id: str, host: Host) -> RemediationVariant:
    variant = _find_remediation_variant(db, control_id, host)
    if variant is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"không tìm thấy RemediationVariant khớp {host.os_family}"
                f"{f' {host.os_version}' if host.os_version else ''} cho control {control_id}"
            ),
        )
    return variant


def run_remediate_dry_run(
    db: Session, hostname: str, control_id: str, user: CurrentUser, canary_rollout_id: int | None = None
) -> Job:
    """Thân xử lý thật của remediate dry-run — tách ra khỏi route handler để
    app/canary.py có thể tái dùng verbatim cho từng host trong 1 canary
    rollout, không phải gọi lại qua HTTP (xem trigger_remediate_dry_run bên
    dưới, giờ chỉ còn là wrapper mỏng).

    `canary_rollout_id` (None cho luồng thủ công single-host) được gán NGAY
    lúc tạo Job — TRƯỚC khi dispatch — để job vẫn được gắn đúng rollout kể cả
    khi `_dispatch_remediate_job` raise HTTPException giữa chừng (vd
    ca_mint_failed/dispatcher_call_failed), thay vì chỉ gán sau khi hàm này
    return bình thường (bug đã phát hiện qua rà soát: nếu chỉ gán ở
    app/canary.py sau khi gọi hàm này, đường raise sẽ khiến Job đó không bao
    giờ được gắn canary_rollout_id, dù rollout đã ghi nhận đúng host gây lỗi
    ở `aborted_hostname`).

    `_lock_host_for_remediate` PHẢI là bước ĐẦU TIÊN, cùng transaction tới
    khi Job mới commit (xem docstring hàm đó) — khoá host + chặn 409 nếu có
    job remediate khác đang pending/running cho CÙNG host này."""
    host = _lock_host_for_remediate(db, hostname)
    _require_control(db, control_id)
    variant = _require_remediation_variant(db, control_id, host)

    job = Job(
        hostname=hostname,
        job_type="remediate-dry-run",
        control_id=control_id,
        remediation_variant_id=variant.id,
        canary_rollout_id=canary_rollout_id,
        status="running",
        triggered_by=user.username,
        started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    job = _dispatch_remediate_job(db, job, host, variant, dry_run=True, user=user, audit_action_prefix="remediate_dry_run")

    write_audit_event(
        actor=user.username,
        action="remediate_dry_run_completed",
        resource=hostname,
        payload={"job_id": job.id, "control_id": control_id, "status": job.status},
    )
    return job


@router.post(
    "/hosts/{hostname}/controls/{control_id}/remediate/dry-run",
    response_model=JobOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def trigger_remediate_dry_run(
    hostname: str,
    control_id: str,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> Job:
    return run_remediate_dry_run(db, hostname, control_id, user)


def run_remediate_apply(
    db: Session, hostname: str, control_id: str, dry_run_job_id: int, user: CurrentUser,
    canary_rollout_id: int | None = None,
) -> Job:
    """Thân xử lý thật của remediate apply — tách ra khỏi route handler để
    app/canary.py có thể tái dùng verbatim (cùng lý do run_remediate_dry_run
    ở trên), giữ NGUYÊN toàn bộ gating (maturity/variant/dry-run staleness/
    four-eyes Tier cao). `canary_rollout_id` gán ngay lúc tạo Job — xem
    docstring run_remediate_dry_run để biết lý do không gán sau khi return.

    `_lock_host_for_remediate` PHẢI là bước ĐẦU TIÊN, cùng lý do như
    run_remediate_dry_run ở trên."""
    host = _lock_host_for_remediate(db, hostname)
    control = _require_control(db, control_id)

    # "control community/untested mặc định khoá auto-remediate, chỉ cho
    # dry-run cho tới khi kiểm định qua lab" (mục 3 kiến trúc) — dry-run
    # luôn được phép kể cả control draft, chỉ APPLY thật mới chặn.
    if control.maturity == "draft":
        raise HTTPException(
            status_code=422,
            detail="control còn ở maturity 'draft' — chỉ cho phép dry-run, chưa cho apply thật",
        )

    variant = _require_remediation_variant(db, control_id, host)

    dry_run_job = db.get(Job, dry_run_job_id)
    if dry_run_job is None:
        raise HTTPException(status_code=422, detail="dry_run_job_id không tồn tại")
    if dry_run_job.job_type != "remediate-dry-run":
        raise HTTPException(status_code=422, detail="dry_run_job_id không phải job dry-run")
    if dry_run_job.hostname != hostname or dry_run_job.control_id != control_id:
        raise HTTPException(status_code=422, detail="dry_run_job_id không khớp đúng host/control đang apply")
    if dry_run_job.status != "succeeded":
        raise HTTPException(status_code=422, detail="dry_run_job_id chưa succeeded")

    dry_run_finished = dry_run_job.finished_at
    if dry_run_finished is None:
        raise HTTPException(status_code=422, detail="dry_run_job_id chưa có finished_at")
    # SQLite (test) trả DateTime(timezone=True) dạng naive, Postgres (thật)
    # trả dạng aware — chuẩn hoá trước khi so sánh, cùng bug đã gặp ở
    # app/agents.py:verify_and_enroll.
    if dry_run_finished.tzinfo is None:
        dry_run_finished = dry_run_finished.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - dry_run_finished > DRY_RUN_MAX_AGE:
        raise HTTPException(
            status_code=422,
            detail=f"dry_run_job_id đã quá hạn (giới hạn {DRY_RUN_MAX_AGE}) — chạy dry-run lại trước khi apply",
        )

    # Four-eyes CHỈ Tier 0/1 (khớp tiền lệ CA migration, app/hosts.py) —
    # người đề xuất dry-run không được tự duyệt apply cho host Tier cao.
    if host.tier <= _REMEDIATE_HIGH_TIER_MAX and dry_run_job.triggered_by == user.username:
        raise HTTPException(
            status_code=403,
            detail="host Tier cao: người đã dry-run không được tự apply (four-eyes)",
        )

    job = Job(
        hostname=hostname,
        job_type="remediate-apply",
        control_id=control_id,
        remediation_variant_id=variant.id,
        canary_rollout_id=canary_rollout_id,
        status="running",
        triggered_by=user.username,
        started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    job = _dispatch_remediate_job(db, job, host, variant, dry_run=False, user=user, audit_action_prefix="remediate_apply")

    write_audit_event(
        actor=user.username,
        action="remediate_apply_completed",
        resource=hostname,
        payload={
            "job_id": job.id,
            "control_id": control_id,
            "dry_run_job_id": dry_run_job.id,
            "status": job.status,
        },
    )
    return job


@router.post(
    "/hosts/{hostname}/controls/{control_id}/remediate/apply",
    response_model=JobOut,
    status_code=status.HTTP_202_ACCEPTED,
)
def trigger_remediate_apply(
    hostname: str,
    control_id: str,
    body: RemediateApplyRequest,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> Job:
    return run_remediate_apply(db, hostname, control_id, body.dry_run_job_id, user)


def run_restore(db: Session, hostname: str, source_job_id: int, user: CurrentUser) -> Job:
    """Khôi phục cấu hình từ backup đã chụp lúc 1 remediate-apply trước đó
    (mục "1-click restore" trong README.md). KHÔNG đòi hỏi dry-run/four-eyes
    riêng như remediate-apply — đây là công cụ khôi phục khẩn cấp
    (break-glass): four-eyes đã áp dụng lúc APPLY ban đầu (host Tier cao), và
    restore đưa hệ thống VỀ trạng thái đã biết trước đó chứ không phải áp
    dụng thay đổi mới chưa kiểm chứng — đòi hỏi duyệt lại lúc restore chỉ làm
    chậm phản ứng sự cố mà không giảm thêm rủi ro tương ứng. Vẫn giữ role
    operator/admin (xem trigger_restore) — không mở cho mọi user.
    """
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    source_job = db.get(Job, source_job_id)
    if source_job is None:
        raise HTTPException(status_code=422, detail="source_job_id không tồn tại")
    if source_job.job_type != "remediate-apply":
        raise HTTPException(status_code=422, detail="source_job_id không phải job remediate-apply")
    if source_job.hostname != hostname:
        raise HTTPException(status_code=422, detail="source_job_id không khớp host đang restore")
    if source_job.status != "succeeded":
        raise HTTPException(status_code=422, detail="source_job_id chưa succeeded")

    summary = source_job.result_summary or {}
    backup_b64 = summary.get("backup_tar_b64")
    if not backup_b64:
        raise HTTPException(
            status_code=422, detail="source_job_id không có backup_tar_b64 trong result_summary"
        )
    if summary.get("backup_truncated"):
        raise HTTPException(
            status_code=422,
            detail=(
                "backup của source_job_id đã bị cắt bớt lúc chụp (vượt "
                f"{BACKUP_MAX_BYTES} byte) — KHÔNG an toàn để restore tự động "
                "vì có thể thiếu file, cần khôi phục thủ công"
            ),
        )

    job = Job(
        hostname=hostname,
        job_type="restore",
        control_id=source_job.control_id,
        status="running",
        triggered_by=user.username,
        started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        private_key, cert_pub = mint_ssh_certificate(principal="root")
    except RuntimeError as exc:
        job.status = "failed"
        job.result_summary = {"error": str(exc)}
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        write_audit_event(
            actor=user.username, action="restore_failed", resource=hostname,
            payload={"job_id": job.id, "source_job_id": source_job_id, "error": "ca_mint_failed"},
        )
        raise HTTPException(status_code=502, detail=f"không cấp được SSH cert cho job: {exc}") from exc

    environment = {
        "TARGET_HOST": host.ip_address,
        "SSH_USER": "root",
        "SSH_KEY_B64": base64.b64encode(private_key.encode()).decode(),
        "SSH_CERT_B64": base64.b64encode(cert_pub.encode()).decode(),
    }
    environment.update(_chunk_backup_env(backup_b64))

    dispatch_body = {
        "job_id": str(job.id),
        "image": settings.allowed_execution_image,
        "command": ["restore"],
        "environment": environment,
        "timeout_seconds": 300,
    }

    try:
        result = _call_job_dispatcher(dispatch_body, timeout=340)
    except httpx.HTTPError as exc:
        job.status = "failed"
        job.result_summary = {"error": str(exc)}
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        write_audit_event(
            actor=user.username, action="restore_failed", resource=hostname,
            payload={"job_id": job.id, "source_job_id": source_job_id, "error": "dispatcher_call_failed"},
        )
        raise HTTPException(status_code=502, detail=f"job-dispatcher lỗi: {exc}") from exc

    logs = result.get("logs", "")
    job.result_summary = {
        "raw_log_tail": logs[-2000:],
        "exit_code": result.get("exit_code"),
        "source_job_id": source_job_id,
    }
    job.status = "succeeded" if result.get("exit_code") == 0 else "failed"
    job.finished_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(job)

    write_audit_event(
        actor=user.username,
        action="restore_completed",
        resource=hostname,
        payload={"job_id": job.id, "source_job_id": source_job_id, "status": job.status},
    )
    return job


@router.post("/hosts/{hostname}/restore", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED)
def trigger_restore(
    hostname: str,
    body: RestoreRequest,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> Job:
    return run_restore(db, hostname, body.source_job_id, user)


def reconcile_orphaned_remediate_jobs() -> int:
    """Gọi 1 lần lúc Orchestrator khởi động (app/main.py `lifespan`) — cùng lý
    do đúng hệt app/canary.py:reconcile_orphaned_rollouts (phát hiện qua rà
    soát đối kháng, không phải lý thuyết suông):

    - `_dispatch_remediate_job_via_agent` (trên) đặt Job.status="pending" rồi
      POLL SỐNG TRONG process (vòng while sleep(2) tới
      AGENT_REMEDIATE_DISPATCH_TIMEOUT) — không phải background task độc
      lập nào có thể tự resume sau khi process chết.
    - Kể cả đường SSH agentless (`_dispatch_remediate_job_via_ssh`) cũng gọi
      job-dispatcher ĐỒNG BỘ trong chính request — nếu Orchestrator
      crash/restart giữa lúc đó, request chết theo, Job vẫn "running" mãi.
    - `_lock_host_for_remediate` coi MỌI Job cùng hostname có status
      "pending"/"running" là "đang chạy dở" (409) — 1 Job mồ côi khoá CỨNG
      luôn host đó khỏi mọi remediate job mới (dry-run HOẶC apply) cho tới
      khi có người sửa DB tay, không chỉ là báo cáo trạng thái sai.

    Luôn đưa về "failed" (KHÔNG thử resume dở dang) — cùng triết lý an toàn
    mặc định với reconcile_orphaned_rollouts: trạng thái thật trên host tại
    đúng thời điểm restart không xác định chắc chắn, resume mù rủi ro áp
    nhầm hoặc bỏ sót bước; "failed" chỉ đơn thuần mở khoá lại host để
    operator tự trigger job mới sau khi đã tự xác minh tình trạng thật.

    Hàm này chạy TRƯỚC khi Orchestrator nhận request đầu tiên (trong
    `lifespan`, trước `yield`) nên KHÔNG có race với request thật nào đang
    xử lý remediate job — mọi Job "pending"/"running" tìm thấy ở đây chắc
    chắn là mồ côi từ lần chạy trước, không phải job đang chạy hợp lệ.
    """
    db = SessionLocal()
    try:
        orphaned = (
            db.query(Job)
            .filter(
                Job.job_type.in_(("remediate-dry-run", "remediate-apply")),
                Job.status.in_(("pending", "running")),
            )
            .all()
        )
        for job in orphaned:
            job.status = "failed"
            job.result_summary = {"error": "orchestrator_restarted"}
            job.finished_at = datetime.now(timezone.utc)
        db.commit()
        for job in orphaned:
            # State chính (đã commit ở trên) là phần BẮT BUỘC đúng — audit
            # chỉ là bản ghi phụ, dùng session/engine RIÊNG (app/audit.py) có
            # thể lỗi độc lập. Bọc try/except như reconcile_orphaned_rollouts
            # đã làm — lỗi audit ở đây KHÔNG được phép làm cả Orchestrator
            # không khởi động được chỉ vì thiếu đúng 1 dòng audit.
            try:
                write_audit_event(
                    actor="system",
                    action="remediate_job_aborted_orphaned",
                    resource=job.hostname,
                    payload={"job_id": job.id, "control_id": job.control_id, "job_type": job.job_type},
                )
            except Exception:
                logger.exception(
                    "ghi audit event cho remediate job mồ côi (job_id=%s) thất bại — state chính đã commit đúng, chỉ thiếu audit",
                    job.id,
                )
        return len(orphaned)
    finally:
        db.close()


@router.post("/hosts/{hostname}/scan", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED)
def trigger_scan(
    hostname: str,
    body: ScanTrigger,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> Job:
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    profile_def = SCAP_PROFILES.get(body.scap_profile_key)
    if profile_def is None:
        raise HTTPException(
            status_code=422,
            detail=f"scap_profile_key không hợp lệ, các giá trị hỗ trợ: {sorted(SCAP_PROFILES)}",
        )

    if body.ssh_user not in ALLOWED_SSH_USERS:
        raise HTTPException(
            status_code=422,
            detail=f"ssh_user không hợp lệ, các giá trị hỗ trợ: {sorted(ALLOWED_SSH_USERS)}",
        )

    job = Job(
        hostname=hostname,
        job_type="scan",
        scap_profile=profile_def["profile"],
        status="running",
        triggered_by=user.username,
        started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        private_key, cert_pub = mint_ssh_certificate(principal=body.ssh_user)
    except RuntimeError as exc:
        job.status = "failed"
        job.result_summary = {"error": str(exc)}
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        write_audit_event(
            actor=user.username, action="scan_failed", resource=hostname,
            payload={"job_id": job.id, "error": "ca_mint_failed"},
        )
        raise HTTPException(status_code=502, detail=f"không cấp được SSH cert cho job: {exc}") from exc

    dispatch_body = {
        "job_id": str(job.id),
        "image": settings.allowed_execution_image,
        "command": ["scan"],
        "environment": {
            "TARGET_HOST": host.ip_address,
            "SSH_USER": body.ssh_user,
            "SSH_KEY_B64": base64.b64encode(private_key.encode()).decode(),
            "SSH_CERT_B64": base64.b64encode(cert_pub.encode()).decode(),
            "SCAP_PROFILE": profile_def["profile"],
            "SCAP_DATASTREAM": profile_def["datastream"],
        },
        "timeout_seconds": 300,
    }

    try:
        result = _call_job_dispatcher(dispatch_body, timeout=340)
    except httpx.HTTPError as exc:
        job.status = "failed"
        job.result_summary = {"error": str(exc)}
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        write_audit_event(
            actor=user.username, action="scan_failed", resource=hostname,
            payload={"job_id": job.id, "error": "dispatcher_call_failed"},
        )
        raise HTTPException(status_code=502, detail=f"job-dispatcher lỗi: {exc}") from exc

    summary = _parse_scan_summary(result.get("logs", ""))
    summary["exit_code"] = result.get("exit_code")
    job.status = "succeeded" if result.get("exit_code") == 0 else "failed"
    job.result_summary = summary
    job.finished_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(job)

    write_audit_event(
        actor=user.username,
        action="scan_completed",
        resource=hostname,
        payload={"job_id": job.id, "status": job.status, "summary": summary},
    )
    return job


@router.get("/jobs", response_model=list[JobListOut])
def list_jobs(
    hostname: str | None = None,
    job_type: str | None = None,
    status: str | None = None,
    limit: int = _JOB_LIST_DEFAULT_LIMIT,
    offset: int = 0,
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(
        require_roles("viewer", "auditor", "rule-editor", "approver", "operator", "admin")
    ),
) -> list[Job]:
    if not 1 <= limit <= _JOB_LIST_MAX_LIMIT:
        raise HTTPException(status_code=422, detail=f"limit phải trong khoảng 1..{_JOB_LIST_MAX_LIMIT}")
    if offset < 0:
        raise HTTPException(status_code=422, detail="offset không được âm")

    query = db.query(Job)
    if hostname is not None:
        query = query.filter(Job.hostname == hostname)
    if job_type is not None:
        query = query.filter(Job.job_type == job_type)
    if status is not None:
        query = query.filter(Job.status == status)
    # id.desc() (không phải created_at) — id tăng đơn điệu đúng thứ tự tạo,
    # tận dụng luôn index primary key thay vì cần thêm index riêng trên
    # created_at (2 cột thực tế tương đương thứ tự vì Job chỉ được tạo, không
    # bao giờ sửa created_at sau đó).
    return query.order_by(Job.id.desc()).offset(offset).limit(limit).all()


@router.get("/jobs/{job_id}", response_model=JobOut)
def get_job(
    job_id: int,
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(
        require_roles("viewer", "auditor", "rule-editor", "approver", "operator", "admin")
    ),
) -> Job:
    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job không tồn tại")
    return job
