"""Agent tự phát triển — enrollment + báo cáo (mục 4.3 architecture-proposal.md).

Luồng enrollment (bootstrap token dùng 1 lần):
  1. operator/admin gọi POST /hosts/{hostname}/agent-enrollment-tokens ->
     Orchestrator sinh OTT qua step-ca (provisioner "agent-enrollment", tạo
     sẵn từ Giai đoạn 0), trả token thô ĐÚNG 1 LẦN.
  2. operator tự đưa token lên máy đích (out-of-band, ngoài phạm vi code này).
  3. Agent (qua Agent Manager — xem apps/agent-manager/) gọi
     POST /internal/agent/verify-and-enroll với token đó -> Orchestrator
     verify chưa dùng + còn hạn, gọi step-ca đổi token lấy cert mTLS thật,
     đánh dấu token đã dùng.

Từ pass này, /internal/agent-manager/server-cert phục vụ chính Agent
Manager (apps/agent-manager/) — nó không có quyền gọi step-ca (chỉ
Orchestrator được gọi CA), nên xin cert server mTLS của chính nó qua đây,
tự renew định kỳ trước khi hết hạn. Agent binary (apps/agent/) enroll +
heartbeat qua Agent Manager, không gọi thẳng các endpoint /internal/agent/*
này — những endpoint đó chỉ Agent Manager (giữ shared secret) được gọi.

POST /internal/agent/renew-cert: renew cert mTLS ĐỊNH KỲ cho 1 agent ĐÃ
enroll trước đó — khác luồng bootstrap ở trên vì không cần OTT dùng-1-lần
(danh tính agent đã được chứng minh qua chính handshake mTLS gọi request
này, xem apps/agent-manager/main.go handleMTLSRelay: CN cert phải khớp
hostname trong body trước khi relay). operator/admin có thể tạm khoá renew
cho 1 host qua PATCH /hosts/{hostname}/agent-renewal (xem app/hosts.py) —
vd host nghi ngờ bị chiếm, chờ điều tra.

CHƯA làm ở lần này: scan/FIM trong Reporter, Executor, Web UI hiển thị
trạng thái agent — xem kế hoạch đầy đủ đã thống nhất với người dùng.
"""
import base64
import hmac
import os
from datetime import datetime, timezone

import httpx
import jwt as pyjwt
from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.audit import write_audit_event
from app.auth import CurrentUser, require_roles
from app.ca_client import (
    create_agent_enrollment_token,
    mint_agent_client_cert,
    mint_agent_manager_server_cert,
    mint_ssh_certificate,
)
from app.config import settings
from app.db import SessionLocal
from app.jobs import _call_job_dispatcher, _truncate_backup_b64
from app.models import AgentEnrollmentToken, AgentFimEvent, Host, Job, RemediationVariant
from app.schemas import (
    AgentEnrollmentTokenOut,
    AgentFimEventRequest,
    AgentHeartbeatRequest,
    AgentInstallScriptOut,
    AgentRemediateClaimRequest,
    AgentRemediateClaimResponse,
    AgentRemediateResultRequest,
    AgentRemediationBundleRequest,
    AgentRemediationBundleResponse,
    AgentScanResultRequest,
    AgentVerifyEnrollRequest,
    AgentVerifyEnrollResponse,
    JobOut,
)

router = APIRouter(tags=["agents"])

_OPERATOR_ROLES = ("operator", "admin")


def _get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _require_active_host(db: Session, hostname: str) -> Host:
    """Dùng chung cho create_enrollment_token/create_agent_install_script —
    cả 2 đều là điểm bắt đầu enrollment Agent mới, không có lý do enroll host
    đã decommission (xem app/hosts.py:update_decommission)."""
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")
    if host.decommissioned_at is not None:
        raise HTTPException(status_code=422, detail="host đã decommission — recommission trước khi enroll agent")
    return host


def _check_agent_manager_auth(authorization: str | None) -> None:
    # Cùng pattern job-dispatcher/app/main.py:_check_auth — Bearer + so sánh
    # hằng thời gian, không cho phép Agent Manager giả mạo actor.
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="thiếu Authorization header")
    token = authorization[len("Bearer "):]
    if not hmac.compare_digest(token, settings.agent_manager_shared_secret):
        raise HTTPException(status_code=401, detail="shared secret sai")


@router.post("/internal/agent-manager/server-cert", response_model=AgentVerifyEnrollResponse)
def agent_manager_server_cert(
    authorization: str | None = Header(default=None),
) -> AgentVerifyEnrollResponse:
    # Agent Manager tự gọi endpoint này lúc khởi động + định kỳ renew (nó
    # không có quyền gọi step-ca trực tiếp) — không cần hostname trong body,
    # danh tính "agent-manager" cố định, không phải cert cho 1 host cụ thể
    # trong fleet.
    _check_agent_manager_auth(authorization)
    try:
        cert_pem, key_pem = mint_agent_manager_server_cert()
    except RuntimeError as exc:
        raise HTTPException(
            status_code=502, detail=f"không cấp được server cert cho Agent Manager: {exc}"
        ) from exc

    write_audit_event(
        actor="agent-manager",
        action="agent_manager_server_cert_issued",
        resource="agent-manager",
        payload={},
    )

    with open(settings.stepca_root_cert_path, encoding="utf-8") as f:
        ca_root_pem = f.read()
    return AgentVerifyEnrollResponse(cert_pem=cert_pem, key_pem=key_pem, ca_root_pem=ca_root_pem)


def _issue_agent_enrollment_token(
    db: Session, hostname: str, user: CurrentUser
) -> AgentEnrollmentTokenOut:
    """Sinh + lưu sổ sách 1 bootstrap token OTT mới cho `hostname` — dùng
    chung bởi endpoint trả token thô (create_enrollment_token) và endpoint
    sinh script cài đặt gộp sẵn (create_agent_install_script bên dưới), để
    logic lưu jti/expires_at/audit không bao giờ lệch nhau giữa 2 đường.

    Raises HTTPException(502) nếu step-ca từ chối cấp.
    """
    try:
        token = create_agent_enrollment_token(hostname)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=f"không tạo được enrollment token: {exc}") from exc

    # Chỉ đọc claim để lưu sổ sách (jti/exp) — KHÔNG verify chữ ký ở đây vì
    # chính Orchestrator vừa tự ký token này qua step-ca; verify chữ ký thật
    # xảy ra ở step-ca lúc đổi token lấy cert (verify_and_enroll bên dưới).
    claims = pyjwt.decode(token, options={"verify_signature": False})
    expires_at = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)

    db.add(
        AgentEnrollmentToken(
            hostname=hostname,
            jti=claims["jti"],
            issued_by=user.username,
            expires_at=expires_at,
        )
    )
    db.commit()

    write_audit_event(
        actor=user.username,
        action="agent_enrollment_token_created",
        resource=hostname,
        payload={"expires_at": expires_at.isoformat()},
    )
    return AgentEnrollmentTokenOut(hostname=hostname, token=token, expires_at=expires_at)


@router.post(
    "/hosts/{hostname}/agent-enrollment-tokens",
    response_model=AgentEnrollmentTokenOut,
    status_code=status.HTTP_201_CREATED,
)
def create_enrollment_token(
    hostname: str,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> AgentEnrollmentTokenOut:
    _require_active_host(db, hostname)
    return _issue_agent_enrollment_token(db, hostname, user)


def _build_agent_install_script(hostname: str, token: str, ca_root_pem: str) -> str:
    """Sinh script bash cài Agent hoàn chỉnh cho `hostname`, gộp provision.sh
    + 2 systemd unit file có sẵn (mount read-only từ apps/agent/, xem
    docker-compose.yml) với token/ca-root vừa cấp riêng cho lần gọi này —
    operator chỉ cần dán 1 lần vào phiên SSH CỦA CHÍNH HỌ tới máy đích.

    Cố tình KHÔNG để Orchestrator tự SSH/push script này hộ — giữ đúng
    nguyên tắc "không standing RCE console->fleet" (mục 4.2/4.3
    architecture-proposal.md): operator vẫn là người thực thi trên máy đích,
    console chỉ chuẩn bị sẵn nội dung. Cũng KHÔNG tự tải/copy binary
    agent/executor — vẫn phải scp thủ công trước (xem apps/agent/README.md),
    vì dự án chưa có nơi phân phối binary đã build; script chỉ kiểm tra tồn
    tại + báo lỗi rõ ràng nếu thiếu, không âm thầm bỏ qua.

    Raises OSError nếu không đọc được 1 trong 3 file asset (mount thiếu).
    """
    assets_dir = settings.agent_assets_dir
    with open(os.path.join(assets_dir, "provision.sh"), encoding="utf-8") as f:
        provision_sh = f.read()
    with open(os.path.join(assets_dir, "hardening-agent.service"), encoding="utf-8") as f:
        agent_unit = f.read()
    with open(os.path.join(assets_dir, "hardening-executor.service"), encoding="utf-8") as f:
        executor_unit = f.read()

    # hardening-agent.service mặc định AGENT_MANAGER_URL=https://localhost:8443
    # (chỉ đúng khi Agent Manager chạy CÙNG máy) — ghi agent.env với địa chỉ
    # THẬT nếu đã cấu hình settings.agent_manager_public_url, tránh lặp lại
    # lỗi "cài xong nhưng không bao giờ enroll" đã gặp thật (xem
    # app/agents.py:trigger_agent_install). Nếu CHƯA cấu hình, giữ hành vi cũ
    # (operator tự tạo agent.env — xem apps/agent/README.md).
    agent_env_block = ""
    if settings.agent_manager_public_url:
        agent_env_block = f"""cat > /etc/hardening-agent/agent.env <<'AGENT_ENV_EOF_9f21'
AGENT_MANAGER_URL={settings.agent_manager_public_url}
AGENT_HOSTNAME={hostname}
AGENT_ENV_EOF_9f21
chown hardening-agent:hardening-agent /etc/hardening-agent/agent.env
chmod 644 /etc/hardening-agent/agent.env
"""

    return f"""#!/usr/bin/env bash
# Script cai Agent tu sinh cho host "{hostname}" -- DAN VAO PHIEN SSH CUA
# CHINH BAN toi may dich roi chay bang root. KHONG phai Orchestrator tu SSH
# ho -- xem apps/agent/README.md. Chua bootstrap token DUNG 1 LAN, het han
# nhanh -- khong luu lai, khong chia se voi ai khac.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "LOI: phai chay bang root (sudo)." >&2
  exit 1
fi

for bin in /opt/hardening-agent/agent /opt/hardening-agent/executor/executor; do
  if [[ ! -x "$bin" ]]; then
    echo "LOI: thieu $bin -- scp binary da build (./build.sh) len may nay TRUOC khi chay script nay, xem apps/agent/README.md." >&2
    exit 1
  fi
done

echo "==> Buoc 1/4: provision user/group/thu muc"
{provision_sh}

echo "==> Buoc 2/4: ghi bootstrap token + ca-root.crt"
umask 077
cat > /etc/hardening-agent/enroll-token <<'AGENT_TOKEN_EOF_9f21'
{token}
AGENT_TOKEN_EOF_9f21
cat > /etc/hardening-agent/ca-root.crt <<'AGENT_CAROOT_EOF_9f21'
{ca_root_pem}
AGENT_CAROOT_EOF_9f21
chown hardening-agent:hardening-agent /etc/hardening-agent/enroll-token /etc/hardening-agent/ca-root.crt
chmod 600 /etc/hardening-agent/enroll-token
chmod 644 /etc/hardening-agent/ca-root.crt
{agent_env_block}
echo "==> Buoc 3/4: cai 2 systemd unit"
cat > /etc/systemd/system/hardening-agent.service <<'AGENT_UNIT_EOF_9f21'
{agent_unit}
AGENT_UNIT_EOF_9f21
cat > /etc/systemd/system/hardening-executor.service <<'EXECUTOR_UNIT_EOF_9f21'
{executor_unit}
EXECUTOR_UNIT_EOF_9f21

echo "==> Buoc 4/4: khoi dong hardening-agent (Reporter)"
systemctl daemon-reload
systemctl enable hardening-agent.service
systemctl restart hardening-agent.service

echo "Reporter da chay -- xem: journalctl -u hardening-agent -f"
echo "Executor (Active Response) CHUA duoc bat tu dong -- tao truoc"
echo "/etc/hardening-agent/executor.env (EXECUTOR_TRUSTED_SIGNER_FINGERPRINT=...)"
echo "roi chay tay: systemctl enable --now hardening-executor.service"
"""


@router.post(
    "/hosts/{hostname}/agent-install-script",
    response_model=AgentInstallScriptOut,
    status_code=status.HTTP_201_CREATED,
)
def create_agent_install_script(
    hostname: str,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> AgentInstallScriptOut:
    _require_active_host(db, hostname)

    token_out = _issue_agent_enrollment_token(db, hostname, user)

    with open(settings.stepca_root_cert_path, encoding="utf-8") as f:
        ca_root_pem = f.read()

    try:
        script = _build_agent_install_script(hostname, token_out.token, ca_root_pem)
    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "không đọc được asset cài Agent (provision.sh/systemd unit) "
                f"— kiểm tra mount agent_assets_dir trong docker-compose.yml: {exc}"
            ),
        ) from exc

    write_audit_event(
        actor=user.username,
        action="agent_install_script_generated",
        resource=hostname,
        payload={"expires_at": token_out.expires_at.isoformat()},
    )
    return AgentInstallScriptOut(hostname=hostname, expires_at=token_out.expires_at, script=script)


def _parse_agent_install_summary(logs: str) -> dict:
    # Chỉ đọc dòng AGENT_INSTALL_STATUS do agent-install.sh in ra — KHÔNG bao
    # giờ đưa token/ca-root vào summary (script tự nó cũng không echo lại,
    # xem apps/execution-env/agent-install.sh).
    summary = {"raw_log_tail": logs[-2000:]}
    for line in logs.splitlines():
        if "=" not in line or not line.startswith("AGENT_INSTALL_"):
            continue
        key, _, value = line.partition("=")
        summary[key.strip().lower()] = value.strip()
    return summary


@router.post(
    "/hosts/{hostname}/agent-install", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED
)
def trigger_agent_install(
    hostname: str,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_roles(*_OPERATOR_ROLES)),
) -> Job:
    """Remote-deploy Agent tự động — KHÁC create_agent_install_script (dán
    tay): tự SSH bằng cert ephemeral (đúng cơ chế trigger_ssh_check,
    app/jobs.py), scp binary agent+executor đã ký qua content-signing +
    provision.sh + 2 systemd unit, chạy cài đặt ngay trên máy đích — operator
    không cần tự thực thi gì (xem apps/execution-env/agent-install.sh).

    Chỉ khả thi cho host ĐÃ trust_deployed/migrated (cần SSH bằng cert
    ephemeral được, giống trigger_ssh_check) — KHÔNG cần legacy credential
    nào (khác trigger_ca_bootstrap, vốn chạy TRƯỚC khi CA trust tồn tại).
    Cần settings.agent_bundle_ref + settings.agent_bundle_trusted_fingerprint đã
    cấu hình (trỏ tới bundle đã ký qua đúng quy trình 3 vai trò, xem
    scripts/content-signing/README.md + apps/agent/README.md mục đóng gói) —
    vẫn giữ create_agent_install_script làm phương án dự phòng cho host chưa
    qua CA trust hoặc khi chưa có bundle nào được ký. agent_bundle_trusted_fingerprint
    CỐ Ý tách khỏi content_signing_trusted_fingerprint (dùng cho remediation)
    — đổi 1 bên không ảnh hưởng verify của bên còn lại, xem app/config.py.

    Mọi bước chuẩn bị (mint cert, issue token, đọc ca-root) đều bọc try/except
    RIÊNG, tự đánh Job "failed" trước khi raise lại — tránh lớp bug "Job kẹt
    vĩnh viễn ở status running" đã từng gặp (xem docstring mint_ssh_certificate/
    _call_job_dispatcher), vì hàm này (khác create_agent_install_script) tạo
    Job row TRƯỚC khi làm các bước có thể lỗi.
    """
    host = _require_active_host(db, hostname)

    if host.ca_migration_status not in ("trust_deployed", "migrated"):
        raise HTTPException(
            status_code=422,
            detail=(
                "host chưa deploy CA trust (ca_migration_status phải là "
                "trust_deployed hoặc migrated) — chạy Zero-to-CA Migration "
                "playbook hoặc bootstrap-ca-trust trước"
            ),
        )
    if host.ssh_user not in settings.allowed_ssh_users_set:
        raise HTTPException(
            status_code=422,
            detail=(
                f"ssh_user hiện tại của host ('{host.ssh_user}') không còn nằm trong "
                f"allowlist ({sorted(settings.allowed_ssh_users_set)}) — sửa lại qua PATCH /hosts/{{hostname}}"
            ),
        )
    if not settings.agent_bundle_ref or not settings.agent_bundle_trusted_fingerprint:
        raise HTTPException(
            status_code=422,
            detail=(
                "chưa cấu hình AGENT_BUNDLE_REF/AGENT_BUNDLE_TRUSTED_FINGERPRINT — ký 1 "
                "bundle agent qua scripts/content-signing/{pull,review,sign}.sh trước, xem "
                "apps/agent/README.md mục đóng gói bundle"
            ),
        )
    if not settings.agent_manager_public_url:
        raise HTTPException(
            status_code=422,
            detail=(
                "chưa cấu hình AGENT_MANAGER_PUBLIC_URL — thiếu biến này Agent cài xong "
                "sẽ KHÔNG enroll được trên host khác máy Agent Manager, xem app/config.py"
            ),
        )

    job = Job(
        hostname=hostname,
        job_type="agent-install",
        status="running",
        triggered_by=user.username,
        started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    def _fail(error_tag: str, detail: str, http_status: int, cause: Exception) -> None:
        job.status = "failed"
        job.result_summary = {"error": error_tag}
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        write_audit_event(
            actor=user.username, action="agent_install_failed", resource=hostname,
            payload={"job_id": job.id, "error": error_tag},
        )
        raise HTTPException(status_code=http_status, detail=detail) from cause

    try:
        private_key, cert_pub = mint_ssh_certificate(principal=host.ssh_user)
    except RuntimeError as exc:
        _fail("ca_mint_failed", f"không cấp được SSH cert cho job: {exc}", 502, exc)

    try:
        token_out = _issue_agent_enrollment_token(db, hostname, user)
    except HTTPException as exc:
        _fail("enrollment_token_issue_failed", exc.detail, 502, exc)

    try:
        with open(settings.stepca_root_cert_path, encoding="utf-8") as f:
            ca_root_pem = f.read()
    except OSError as exc:
        _fail("ca_root_read_failed", f"không đọc được CA root cert: {exc}", 500, exc)

    dispatch_body = {
        "job_id": str(job.id),
        "image": settings.allowed_execution_image,
        "command": ["agent-install"],
        "environment": {
            "TARGET_HOST": host.ip_address,
            "SSH_USER": host.ssh_user,
            "SSH_KEY_B64": base64.b64encode(private_key.encode()).decode(),
            "SSH_CERT_B64": base64.b64encode(cert_pub.encode()).decode(),
            "AGENT_HOSTNAME": host.hostname,
            "AGENT_BUNDLE_REF": settings.agent_bundle_ref,
            "AGENT_BUNDLE_TRUSTED_FINGERPRINT": settings.agent_bundle_trusted_fingerprint,
            "AGENT_ENROLL_TOKEN_B64": base64.b64encode(token_out.token.encode()).decode(),
            "CA_ROOT_PEM_B64": base64.b64encode(ca_root_pem.encode()).decode(),
            "AGENT_MANAGER_PUBLIC_URL": settings.agent_manager_public_url,
        },
        "timeout_seconds": 120,
    }

    try:
        result = _call_job_dispatcher(dispatch_body, timeout=150)
    except httpx.HTTPError as exc:
        _fail("dispatcher_call_failed", f"job-dispatcher lỗi: {exc}", 502, exc)

    summary = _parse_agent_install_summary(result.get("logs", ""))
    summary["exit_code"] = result.get("exit_code")
    job.status = "succeeded" if result.get("exit_code") == 0 else "failed"
    job.result_summary = summary
    job.finished_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(job)

    write_audit_event(
        actor=user.username,
        action="agent_install_completed",
        resource=hostname,
        payload={"job_id": job.id, "status": job.status},
    )
    return job


@router.post("/internal/agent/verify-and-enroll", response_model=AgentVerifyEnrollResponse)
def verify_and_enroll(
    body: AgentVerifyEnrollRequest,
    db: Session = Depends(_get_db),
    authorization: str | None = Header(default=None),
) -> AgentVerifyEnrollResponse:
    _check_agent_manager_auth(authorization)

    if db.get(Host, body.hostname) is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    try:
        claims = pyjwt.decode(body.token, options={"verify_signature": False})
        jti = claims["jti"]
    except pyjwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail=f"token không hợp lệ: {exc}") from exc

    # SELECT ... FOR UPDATE — khoá đúng dòng token này cho tới khi commit, để
    # 2 request đồng thời cùng 1 token không thể cùng "claim" thành công (mới
    # kiểm tra used_at IS NULL rồi mới set thì vẫn race nếu không khoá).
    token_row = (
        db.query(AgentEnrollmentToken)
        .filter(AgentEnrollmentToken.jti == jti, AgentEnrollmentToken.hostname == body.hostname)
        .with_for_update()
        .first()
    )
    if token_row is None:
        raise HTTPException(status_code=401, detail="token không tồn tại hoặc không khớp hostname")
    if token_row.used_at is not None:
        raise HTTPException(status_code=401, detail="token đã được dùng")
    # SQLite (dùng trong test) trả DateTime(timezone=True) dạng naive (mất
    # tzinfo), Postgres (thật) trả dạng aware — so sánh trực tiếp giữa 2 loại
    # này ném TypeError trên SQLite (phát hiện qua test thật, không chỉ đọc
    # code). Chuẩn hoá về aware/UTC trước khi so sánh để đúng trên cả 2 backend.
    expires_at = token_row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="token đã hết hạn")

    try:
        cert_pem, key_pem = mint_agent_client_cert(body.hostname, body.token)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=f"không cấp được agent cert: {exc}") from exc

    token_row.used_at = datetime.now(timezone.utc)
    host = db.get(Host, body.hostname)
    if host.agent_enrolled_at is None:
        host.agent_enrolled_at = datetime.now(timezone.utc)
    db.commit()

    write_audit_event(
        actor="agent-manager",
        action="agent_enrolled",
        resource=body.hostname,
        payload={},
    )

    with open(settings.stepca_root_cert_path, encoding="utf-8") as f:
        ca_root_pem = f.read()
    return AgentVerifyEnrollResponse(cert_pem=cert_pem, key_pem=key_pem, ca_root_pem=ca_root_pem)


@router.post("/internal/agent/renew-cert", response_model=AgentVerifyEnrollResponse)
def renew_agent_cert(
    body: AgentHeartbeatRequest,
    db: Session = Depends(_get_db),
    authorization: str | None = Header(default=None),
) -> AgentVerifyEnrollResponse:
    # Renew cert mTLS định kỳ cho 1 agent ĐÃ enroll — khác verify_and_enroll
    # (bootstrap, cần OTT dùng-1-lần vì danh tính chưa được chứng minh):
    # ở đây agent đã tự chứng minh danh tính qua chính handshake mTLS đang
    # dùng để gọi request này (xem apps/agent-manager/main.go handleMTLSRelay
    # — CN cert phải khớp hostname trong body trước khi relay tới đây), nên
    # bỏ qua bảng AgentEnrollmentToken/luồng OTT dùng-1-lần, tạo token nội bộ
    # rồi đổi lấy cert ngay trong cùng lệnh gọi (cùng pattern
    # mint_agent_manager_server_cert — "chỉ Orchestrator được gọi CA").
    _check_agent_manager_auth(authorization)

    host = db.get(Host, body.hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")
    if host.agent_renewal_blocked:
        raise HTTPException(
            status_code=403,
            detail=(
                f"renew cert cho host '{body.hostname}' đang bị khoá "
                "(agent_renewal_blocked=true) — liên hệ operator/admin để mở khoá "
                "qua PATCH /hosts/{hostname}/agent-renewal"
            ),
        )

    try:
        token = create_agent_enrollment_token(body.hostname, ttl="5m")
        cert_pem, key_pem = mint_agent_client_cert(body.hostname, token)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=f"không renew được agent cert: {exc}") from exc

    write_audit_event(
        actor="agent-manager",
        action="agent_cert_renewed",
        resource=body.hostname,
        payload={},
    )

    with open(settings.stepca_root_cert_path, encoding="utf-8") as f:
        ca_root_pem = f.read()
    return AgentVerifyEnrollResponse(cert_pem=cert_pem, key_pem=key_pem, ca_root_pem=ca_root_pem)


@router.post("/internal/agent/heartbeat", status_code=status.HTTP_204_NO_CONTENT)
def agent_heartbeat(
    body: AgentHeartbeatRequest,
    db: Session = Depends(_get_db),
    authorization: str | None = Header(default=None),
) -> None:
    _check_agent_manager_auth(authorization)
    host = db.get(Host, body.hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")
    host.agent_last_seen = datetime.now(timezone.utc)
    db.commit()


@router.post("/internal/agent/scan-result", status_code=status.HTTP_201_CREATED)
def agent_scan_result(
    body: AgentScanResultRequest,
    db: Session = Depends(_get_db),
    authorization: str | None = Header(default=None),
) -> dict:
    _check_agent_manager_auth(authorization)
    if db.get(Host, body.hostname) is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    job = Job(
        hostname=body.hostname,
        job_type="agent-scan",
        scap_profile=body.scap_profile,
        status="succeeded",
        result_summary=body.result_summary,
        triggered_by="agent",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    write_audit_event(
        actor="agent-manager",
        action="agent_scan_reported",
        resource=body.hostname,
        payload={"job_id": job.id, "scap_profile": body.scap_profile},
    )
    return {"job_id": job.id}


@router.post("/internal/agent/fim-event", status_code=status.HTTP_201_CREATED)
def agent_fim_event(
    body: AgentFimEventRequest,
    db: Session = Depends(_get_db),
    authorization: str | None = Header(default=None),
) -> dict:
    _check_agent_manager_auth(authorization)
    if db.get(Host, body.hostname) is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    event = AgentFimEvent(
        hostname=body.hostname,
        path=body.path,
        event_type=body.event_type,
        old_hash=body.old_hash,
        new_hash=body.new_hash,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    write_audit_event(
        actor="agent-manager",
        action="agent_fim_event",
        resource=body.hostname,
        payload={"path": body.path, "event_type": body.event_type},
    )
    return {"id": event.id}


# ---- Active Response (Agent thực thi remediation thật — mục 4.3/4.4,
# xem app/jobs.py:_dispatch_remediate_job_via_agent) ----


@router.post("/internal/agent/remediate-jobs/claim", response_model=AgentRemediateClaimResponse)
def claim_remediate_job(
    body: AgentRemediateClaimRequest,
    db: Session = Depends(_get_db),
    authorization: str | None = Header(default=None),
) -> AgentRemediateClaimResponse | Response:
    """Agent (qua Reporter, xem apps/agent/) poll định kỳ để hỏi "có job
    remediate nào đang chờ mình không" — mirror đúng phong cách heartbeat
    (204 khi không có gì để báo cáo). `with_for_update(skip_locked=True)`
    (tính năng Postgres) đảm bảo 2 lần poll gần như đồng thời (vd Reporter bị
    restart, gọi lại claim trước khi lần cũ kịp trả) không cùng claim được 1
    Job — lần thứ 2 tự động bỏ qua dòng đã bị lần đầu khoá thay vì đợi rồi
    đọc trúng dữ liệu đã bị lần đầu đổi. Đã XÁC NHẬN qua test thật (không
    suy đoán, xem tests/test_jobs.py:
    test_with_for_update_and_skip_locked_do_not_raise_on_sqlite) không raise
    lỗi trên SQLite (dialect không hỗ trợ tự bỏ qua mệnh đề khi compile).
    """
    _check_agent_manager_auth(authorization)
    host = db.get(Host, body.hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    job = (
        db.query(Job)
        .filter(
            Job.hostname == body.hostname,
            Job.status == "pending",
            Job.job_type.in_(("remediate-dry-run", "remediate-apply")),
        )
        .order_by(Job.id.asc())
        .with_for_update(skip_locked=True)
        .first()
    )
    if job is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    # Re-check kill-switch NGAY LÚC CLAIM, không chỉ lúc dispatch tạo job
    # (app/jobs.py:_dispatch_remediate_job đọc 3 cờ này ĐÚNG 1 LẦN trước khi
    # chuyển job sang "pending") — phát hiện qua rà soát đối kháng: operator
    # tắt active_response_enabled hoặc đặt agent_renewal_blocked=true (vd
    # nghi ngờ host bị chiếm, xem app/hosts.py PATCH .../agent-renewal) SAU
    # KHI job đã "pending" trước đó KHÔNG có tác dụng gì — Agent vẫn claim +
    # Executor vẫn thực thi thật, kill-switch chỉ chặn được job MỚI. Trả 204
    # (coi như không có job, KHÔNG claim) — job vẫn "pending" trong DB, tự
    # bị AGENT_REMEDIATE_DISPATCH_TIMEOUT phía Orchestrator đánh "failed"
    # sau đó như đường timeout thông thường, không cần cơ chế cancel riêng.
    if not settings.active_response_enabled or not host.active_response_enabled or host.agent_renewal_blocked:
        write_audit_event(
            actor="agent-manager",
            action="remediate_claim_blocked_killswitch",
            resource=body.hostname,
            payload={"job_id": job.id, "control_id": job.control_id},
        )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    variant = db.get(RemediationVariant, job.remediation_variant_id)
    if variant is None:
        # Không nên xảy ra (remediation_variant_id bắt buộc NOT NULL cho mọi
        # Job job_type remediate-*, xem run_remediate_dry_run/apply) — nhưng
        # từ chối rõ ràng thay vì crash AttributeError nếu dữ liệu lệch.
        raise HTTPException(status_code=500, detail="job thiếu remediation_variant_id hợp lệ")

    job.status = "running"
    db.commit()
    db.refresh(job)

    return AgentRemediateClaimResponse(
        job_id=job.id,
        control_id=job.control_id,
        remediation_ref=variant.remediation_ref,
        dry_run=(job.job_type == "remediate-dry-run"),
    )


@router.post("/internal/agent/remediation-bundle", response_model=AgentRemediationBundleResponse)
def get_remediation_bundle(
    body: AgentRemediationBundleRequest,
    db: Session = Depends(_get_db),
    authorization: str | None = Header(default=None),
) -> AgentRemediationBundleResponse:
    """Trả nội dung ĐÃ KÝ (content.tar.gz + .sig) cho Agent tự verify+thực
    thi — remediation_ref đến từ Agent Manager relay (agent tự khai lại từ
    response claim ở trên), tức là BỀ MẶT TẤN CÔNG MỚI: 1 agent bị chiếm có
    thể tự ý gửi remediation_ref tuỳ ý để dò đường dẫn (path traversal), nên
    KHÔNG thể tin cậy như remediation_ref do chính Orchestrator vừa tạo ra ở
    claim_remediate_job.

    Chặn 2 lớp ĐỘC LẬP, port ĐÚNG cơ chế apps/agent/executor/verify.go dòng
    56-63 (không suy đoán riêng 1 cách khác):
      1. remediation_ref hợp lệ (đúng quy ước scripts/content-signing/*.sh:
         "<name>-<timestamp>") không bao giờ cần chứa dấu phân cách đường
         dẫn ("/" hoặc "\\") hay "..".
      2. Containment check: đường dẫn SAU KHI resolve (realpath — theo cả
         symlink, khác Clean() của Go chỉ chuẩn hoá cú pháp) vẫn phải nằm
         trong signed_dir đã resolve, phòng trường hợp lớp 1 có lỗ hổng chưa
         lường hết.
    """
    _check_agent_manager_auth(authorization)
    if db.get(Host, body.hostname) is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")

    ref = body.remediation_ref
    if any(sep in ref for sep in ("/", "\\")) or ".." in ref:
        raise HTTPException(status_code=404, detail="remediation_ref không hợp lệ")

    signed_dir = os.path.realpath(settings.content_signing_signed_dir)
    bundle_dir = os.path.realpath(os.path.join(settings.content_signing_signed_dir, ref))
    if bundle_dir != signed_dir and not bundle_dir.startswith(signed_dir + os.sep):
        raise HTTPException(status_code=404, detail="remediation_ref không hợp lệ")

    # Ràng buộc theo job ĐANG "running" khớp đúng host + remediation_ref này
    # (phát hiện qua rà soát đối kháng — trước đây endpoint chỉ kiểm tra host
    # tồn tại + path an toàn, KHÔNG kiểm tra gì về nghiệp vụ): thiếu ràng
    # buộc này, 1 host CHỈ enroll Agent để scan/FIM (active_response_enabled
    # vẫn False) vẫn có thể tự ý gửi BẤT KỲ remediation_ref nào đang tồn tại
    # trong content_signing_signed_dir và tải được — tức là 1 agent hợp lệ
    # bất kỳ có thể đọc nội dung remediation đã ký của TOÀN BỘ fleet, không
    # chỉ control/host mình đang thực thi.
    job = (
        db.query(Job)
        .join(RemediationVariant, Job.remediation_variant_id == RemediationVariant.id)
        .filter(
            Job.hostname == body.hostname,
            Job.status == "running",
            Job.job_type.in_(("remediate-dry-run", "remediate-apply")),
            RemediationVariant.remediation_ref == ref,
        )
        .first()
    )
    if job is None:
        raise HTTPException(
            status_code=404,
            detail="không có job remediate đang running cho host này khớp remediation_ref — bundle chỉ phục vụ đúng job đã claim",
        )

    data_path = os.path.join(bundle_dir, "content.tar.gz")
    sig_path = os.path.join(bundle_dir, "content.tar.gz.sig")
    try:
        with open(data_path, "rb") as f:
            content_tar_gz = f.read()
        with open(sig_path, "rb") as f:
            signature_asc = f.read()
    except OSError:
        raise HTTPException(status_code=404, detail="remediation_ref không tồn tại") from None

    write_audit_event(
        actor="agent-manager",
        action="agent_remediation_bundle_served",
        resource=body.hostname,
        payload={"job_id": job.id, "remediation_ref": ref},
    )
    return AgentRemediationBundleResponse(
        remediation_ref=ref,
        content_tar_gz_b64=base64.b64encode(content_tar_gz).decode(),
        signature_asc_b64=base64.b64encode(signature_asc).decode(),
    )


@router.post("/internal/agent/remediate-result")
def report_remediate_result(
    body: AgentRemediateResultRequest,
    db: Session = Depends(_get_db),
    authorization: str | None = Header(default=None),
) -> dict:
    """Agent báo kết quả remediate thật (dry-run HOẶC apply) sau khi tự
    claim + tải bundle + verify + thực thi (Executor, Unix socket nội bộ) —
    ĐÍCH ĐẾN cuối cùng chỉnh job.status/result_summary cho đường Agent, mirror
    đúng việc _dispatch_remediate_job_via_ssh (app/jobs.py) làm ở cuối đường
    SSH agentless.
    """
    _check_agent_manager_auth(authorization)

    job = db.get(Job, body.job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job không tồn tại")
    if job.hostname != body.hostname:
        raise HTTPException(status_code=422, detail="job_id không khớp hostname")
    if job.status != "running":
        # Chặn report trùng (Agent gửi lại do timeout mạng tưởng lần đầu
        # thất bại) VÀ report cho job chưa được claim (status vẫn "pending")
        # — cả 2 đều là dấu hiệu request KHÔNG đúng thời điểm, không nên âm
        # thầm ghi đè kết quả đã có.
        #
        # Trường hợp đáng chú ý nhất (phát hiện qua rà soát đối kháng):
        # remediation THẬT SỰ đã chạy xong (có thể "succeeded", kèm backup)
        # nhưng đến muộn SAU KHI _dispatch_remediate_job_via_agent
        # (app/jobs.py) đã tự đánh job "failed"/agent_remediate_timeout do
        # hết AGENT_REMEDIATE_DISPATCH_TIMEOUT — kết quả thật đó bị 409 và
        # KHÔNG có nơi nào ghi lại được (không tự merge lại Job an toàn: đã
        # trả "failed" cho operator, âm thầm đổi lại "succeeded" sau đó dễ
        # gây hiểu lầm hơn là để lộ rõ qua audit). Ghi audit event RIÊNG
        # (không đổi Job) để không mất dấu hoàn toàn — đúng nguyên tắc
        # "assume breach" của kiến trúc: log phải còn dù state không tự sửa
        # được.
        write_audit_event(
            actor="agent-manager",
            action="agent_remediate_result_discarded_not_running",
            resource=body.hostname,
            payload={"job_id": job.id, "job_status": job.status, "exit_code": body.exit_code, "dry_run": body.dry_run},
        )
        raise HTTPException(
            status_code=409,
            detail=f"job đang ở status '{job.status}', không phải 'running' — có thể đã report trước đó hoặc chưa được claim",
        )

    # BACKUP_MAX_BYTES/_truncate_backup_b64 (app/jobs.py) là NGUỒN SỰ THẬT
    # DUY NHẤT cho việc cắt backup — Agent/Executor KHÔNG được tự cắt phía
    # của nó (xem package doc apps/agent/executor), áp lại ĐÚNG giới hạn này
    # ở đây y hệt logic _parse_remediate_summary dùng cho đường SSH.
    #
    # log_tail/diff_output cũng cắt theo ĐÚNG độ dài _parse_remediate_summary
    # (jobs.py) đã dùng cho đường SSH (2000/4000 ký tự) — trước đây đường
    # Agent không cắt gì cả (phát hiện qua rà soát đối kháng), lệch hành vi
    # + không giới hạn dung lượng result_summary so với đường agentless.
    summary: dict = {
        "exit_code": body.exit_code,
        "dry_run": body.dry_run,
        "log_tail": body.log_tail[-2000:] if body.log_tail else body.log_tail,
        "dispatch_via": "agent",
    }
    if body.diff_output is not None:
        summary["diff_output"] = body.diff_output[-4000:]
    if body.error is not None:
        summary["error"] = body.error
    if body.backup_tar_b64 is not None:
        summary["backup_tar_b64"], summary["backup_truncated"] = _truncate_backup_b64(body.backup_tar_b64)

    job.status = "succeeded" if body.exit_code == 0 else "failed"
    job.result_summary = summary
    job.finished_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(job)

    write_audit_event(
        actor="agent-manager",
        action="agent_remediate_result_reported",
        resource=body.hostname,
        payload={"job_id": job.id, "status": job.status, "dry_run": body.dry_run},
    )
    return {}
