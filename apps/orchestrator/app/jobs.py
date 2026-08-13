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
     TRƯỚC khi remediate"). Four-eyes (người đề xuất dry-run ≠ người apply)
     đã bị bỏ hoàn toàn theo yêu cầu người dùng — cùng chủ trương đã áp dụng
     cho CA migration (`app/hosts.py`).

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
import contextlib
import hmac
import json
import logging
import os
import secrets
import tempfile
import time
from datetime import datetime, timedelta, timezone

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.audit import write_audit_event
from app.auth import CurrentUser
from app.ca_client import get_ssh_user_ca_pubkey, mint_agent_manager_server_cert, mint_ssh_certificate
from app.config import settings
from app.db import SessionLocal
from app.models import Control, Host, Job, RemediationVariant
from app.permissions import (
    JOBS_CA_BOOTSTRAP,
    JOBS_REMEDIATE_APPLY,
    JOBS_REMEDIATE_DRY_RUN,
    JOBS_RESTORE,
    JOBS_SCAN,
    JOBS_SSH_CHECK,
    JOBS_SSH_PORT_CHANGE,
    JOBS_STATIC_SSH_KEY_BOOTSTRAP,
    JOBS_VIEW,
)
from app.rbac import require_permission
from app.schemas import (
    AgentVerifyEnrollResponse,
    CaBootstrapRequest,
    HostSshPortChangeRequest,
    JobListOut,
    JobOut,
    JobProgressOut,
    RemediateApplyRequest,
    RemediateDryRunRequest,
    RestoreRequest,
    ScanTrigger,
    StaticSshKeyBootstrapRequest,
)
from app.secrets_crypto import decrypt_host_secret, encrypt_host_secret

logger = logging.getLogger(__name__)

router = APIRouter(tags=["jobs"])

# 2 job_type DUY NHẤT có script in marker ##PROGRESS## ra stdout (xem
# apps/execution-env/ssh-check.sh + agent-install.sh) — GET /jobs/{id}/progress
# chỉ gọi job-dispatcher cho 2 loại này, job_type khác luôn trả 0/"unknown"
# lúc đang chạy (không có gì để đọc), không cần sửa script của chúng.
_PROGRESS_SUPPORTED_JOB_TYPES = ("ssh-check", "agent-install")

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
    # Datastream RIÊNG (vendor trực tiếp từ release ComplianceAsCode v0.1.81,
    # KHÔNG phải gói apt ssg-debderived — gói đó không có profile stig), xem
    # comment trong apps/execution-env/Dockerfile. File này thật ra chứa đủ
    # cả CIS lẫn STIG nhưng CHỈ dùng đúng profile "stig" ở đây — scan CIS vẫn
    # đi qua "ubuntu2204-cis-level1-server"/"ubuntu2204-standard" ở trên,
    # không đổi.
    "ubuntu2204-stig": {
        "datastream": "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-stig-ds.xml",
        "profile": "xccdf_org.ssgproject.content_profile_stig",
    },
    # Datastream RIÊNG, cùng nguồn/cùng cách vendor như ubuntu2204-stig ở trên
    # (release ComplianceAsCode v0.1.81, sha512 đã verify) — gói apt
    # ssg-debderived (Debian bookworm, 0.1.65-1) không có product ubuntu2404
    # (ComplianceAsCode chỉ thêm hỗ trợ 24.04 từ v0.1.76, Debian stable không
    # tự nâng version gói này). CHỈ mở rộng scan, chưa có RemediationVariant
    # nào cho 24.04 (cùng giới hạn đã ghi khi mở rộng sang Debian).
    "ubuntu2404-cis-level1-server": {
        "datastream": "/usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml",
        "profile": "xccdf_org.ssgproject.content_profile_cis_level1_server",
    },
}

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


def _check_keycloak_tls_auth(authorization: str | None) -> None:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="thiếu Authorization header")
    token = authorization[len("Bearer "):]
    if not hmac.compare_digest(token, settings.keycloak_tls_shared_secret):
        raise HTTPException(status_code=401, detail="shared secret sai")


def _check_web_tls_auth(authorization: str | None) -> None:
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="thiếu Authorization header")
    token = authorization[len("Bearer "):]
    if not hmac.compare_digest(token, settings.web_tls_shared_secret):
        raise HTTPException(status_code=401, detail="shared secret sai")


@router.post("/internal/keycloak/server-cert", response_model=AgentVerifyEnrollResponse)
def keycloak_server_cert(authorization: str | None = Header(default=None)) -> AgentVerifyEnrollResponse:
    """Keycloak (image gốc, không tự viết) không nối `ca-net` — xin cert TLS
    server qua đây, gọi bằng entrypoint wrapper tự viết (bash, image gốc
    không có curl/python — xem infra/keycloak/fetch-cert.sh) qua ĐÚNG cổng
    HTTP thường KHÔNG published ra host (settings không đổi — xem
    app/serve.py: Orchestrator tự phục vụ 2 cổng, cổng nội bộ này dùng cho
    mọi lần "xin cert" thay vì cổng HTTPS chính, để tránh đòi hỏi TLS client
    ở những nơi (bash thuần) không có khả năng đó).

    2 SAN bắt buộc: DNS "keycloak" (Orchestrator tự fetch JWKS qua docker
    network nội bộ) VÀ IP `settings.public_host` (trình duyệt truy cập theo
    IP LAN) — thiếu 1 trong 2 sẽ khiến 1 trong 2 phía báo lỗi "cert không
    khớp tên miền" dù chain hợp lệ.
    """
    _check_keycloak_tls_auth(authorization)
    try:
        cert_pem, key_pem = mint_agent_manager_server_cert("keycloak", extra_sans=[settings.public_host])
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=f"không cấp được server cert cho keycloak: {exc}") from exc

    write_audit_event(actor="keycloak", action="keycloak_server_cert_issued", resource="keycloak", payload={})

    with open(settings.stepca_root_cert_path, encoding="utf-8") as f:
        ca_root_pem = f.read()
    return AgentVerifyEnrollResponse(cert_pem=cert_pem, key_pem=key_pem, ca_root_pem=ca_root_pem)


@router.post("/internal/web/server-cert", response_model=AgentVerifyEnrollResponse)
def web_server_cert(authorization: str | None = Header(default=None)) -> AgentVerifyEnrollResponse:
    """Web (nginx, ảnh tự build sẵn — apps/web/Dockerfile) — cùng lý do/cùng
    cơ chế với keycloak_server_cert ở trên. Web KHÔNG có gì gọi tới nó từ
    nội bộ (SPA tĩnh, chỉ browser mở), nên chỉ cần đúng 1 SAN IP
    (`settings.public_host`) — không cần DNS "web" như Keycloak.
    """
    _check_web_tls_auth(authorization)
    try:
        cert_pem, key_pem = mint_agent_manager_server_cert("web", extra_sans=[settings.public_host])
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=f"không cấp được server cert cho web: {exc}") from exc

    write_audit_event(actor="web", action="web_server_cert_issued", resource="web", payload={})

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
    with _job_dispatcher_client_cert() as (cert_path, key_path):
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


@contextlib.contextmanager
def _job_dispatcher_client_cert():
    """Mint 1 mTLS client cert MỚI dùng đúng 1 lần, tự xoá khỏi đĩa ngay khi
    xong (kể cả lỗi) — tách ra từ _call_job_dispatcher để dùng chung với
    _call_job_dispatcher_progress bên dưới (GET .../progress, phục vụ
    progress bar % thật cho ssh-check/agent-install), tránh lặp lại đoạn
    TemporaryDirectory giống nhau. Raise httpx.ConnectError nếu mint cert lỗi
    — CÙNG hợp đồng _call_job_dispatcher (mọi call site bắt
    except httpx.HTTPError).
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
        yield cert_path, key_path


def _call_job_dispatcher_progress(job_id: int, timeout: float = 5) -> dict:
    """GET job-dispatcher's /jobs/{job_id}/progress (đọc log LIVE của
    container đang chạy) — dùng bởi GET /jobs/{job_id}/progress bên dưới.
    Raises httpx.HTTPError cho MỌI lỗi (kể cả 404 — container chưa tạo xong
    hoặc đã dọn xong) qua raise_for_status(), CÙNG hợp đồng _call_job_dispatcher
    — caller coi mọi lỗi ở đây là "chưa biết tiến độ", KHÔNG lộ ra người
    dùng (đây chỉ là gợi ý UI polled liên tục, không phải nguồn trạng thái
    chính thức).
    """
    with _job_dispatcher_client_cert() as (cert_path, key_path):
        resp = httpx.get(
            f"{settings.job_dispatcher_url}/jobs/{job_id}/progress",
            headers={"Authorization": f"Bearer {settings.job_dispatcher_shared_secret}"},
            cert=(cert_path, key_path),
            verify=settings.stepca_root_cert_path,
            timeout=timeout,
        )
    resp.raise_for_status()
    return resp.json()


def _get_ssh_dispatch_environment(host: Host, principal: str) -> dict:
    """Điểm TẬP TRUNG DUY NHẤT quyết định 1 job SSH dùng static SSH key đã
    lưu (app/models.py:Host.static_ssh_private_key_encrypted, xem
    trigger_static_ssh_key_bootstrap) hay mint cert CA ngắn hạn mới
    (mint_ssh_certificate, mặc định) — mọi điểm dispatch SSH trong app này
    (scan/remediate/restore/ssh-check/ssh-port-change/agent-install/
    agent-uninstall) PHẢI gọi qua đây, không tự gọi mint_ssh_certificate
    trực tiếp, để bật static key cho 1 host là tự áp dụng cho MỌI job sau đó.

    `principal` CHỈ có ý nghĩa ở nhánh cert CA (cert cần khai principal để
    step-ca ký đúng quyền) — nhánh static key BỎ QUA tham số này: cùng 1 key
    được cài vào CẢ "root" VÀ Host.ssh_user lúc bootstrap (xem
    trigger_static_ssh_key_bootstrap), nên dùng được cho principal nào cũng
    như nhau, không cần cấp lại theo từng principal như cert.

    Raises RuntimeError — CÙNG hợp đồng với mint_ssh_certificate, để mọi call
    site giữ nguyên đúng `except RuntimeError` đang có, chỉ đổi 2-3 dòng gọi.
    """
    if host.static_ssh_private_key_encrypted is not None:
        private_key = decrypt_host_secret(host.static_ssh_private_key_encrypted, "static_ssh_private_key")
        return {"SSH_KEY_B64": base64.b64encode(private_key.encode()).decode()}

    private_key, cert_pub = mint_ssh_certificate(principal=principal)
    return {
        "SSH_KEY_B64": base64.b64encode(private_key.encode()).decode(),
        "SSH_CERT_B64": base64.b64encode(cert_pub.encode()).decode(),
    }


# Số vòng PBKDF2 + digest PIN CỨNG (không dùng default của openssl) — khớp
# ĐÚNG cờ `-iter`/`-md` phía script, để không lệ thuộc phiên bản openssl của
# 2 image (execution-env mã hoá, Orchestrator giải mã) có default KDF khác
# nhau hay không — cả 2 bên LUÔN khai rõ tường minh cùng 1 giá trị.
_TRANSPORT_KDF_ITER = 200_000


def _decrypt_transport_payload(ciphertext_b64: str, passphrase: str) -> bytes:
    """Giải mã payload từ `openssl enc -aes-256-cbc -pbkdf2 -iter
    {_TRANSPORT_KDF_ITER} -md sha256 -pass env:...` phía script — dùng
    `-pass env:` (KHÔNG phải `-K`/`-iv` làm CLI argument trần) để passphrase
    không lộ qua `ps aux`/`docker top`, cùng lý do Dockerfile đã ghi rõ cho
    sshpass (`-f <file>`, không phải `-p <chuỗi>`). Định dạng output của
    openssl: 8 byte "Salted__" + 8 byte salt + ciphertext — tự parse lại
    đúng định dạng này (không có thư viện Python nào làm sẵn).

    Dùng cho _parse_static_ssh_key_bootstrap_summary — passphrase chỉ sinh
    riêng cho 1 lần gọi (secrets.token_urlsafe), không lưu lại.
    """
    raw = base64.b64decode(ciphertext_b64)
    if not raw.startswith(b"Salted__"):
        raise ValueError("payload thiếu header 'Salted__' — không đúng định dạng openssl enc -pbkdf2")
    salt = raw[8:16]
    ciphertext = raw[16:]
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=48, salt=salt, iterations=_TRANSPORT_KDF_ITER)
    key_iv = kdf.derive(passphrase.encode())
    key, iv = key_iv[:32], key_iv[32:]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _parse_static_ssh_key_bootstrap_summary(logs: str, transport_passphrase: str) -> tuple[dict, str | None]:
    """Trích STATIC_KEY_BOOTSTRAP_STATUS=/STATIC_SSH_PUBLIC_KEY=/
    STATIC_SSH_PRIVATE_KEY_ENC_B64= từ logs — CỐ TÌNH KHÔNG lưu `raw_log_tail`
    (khác mọi parser khác trong file này, xem _parse_scan_summary/_parse_ca_
    bootstrap_summary): summary trả về đây sẽ ghi vào `Job.result_summary`,
    đọc được bởi MỌI role qua GET /jobs — không có lý do lưu thêm log thô ở
    đó (script không in gì nhạy cảm khác ngoài key đã mã hoá, nhưng vẫn không
    cần thiết).

    Trả `(summary, private_key_pem_or_None)` — private_key_pem CHỈ tồn tại
    trong bộ nhớ của request handler gọi hàm này (trigger_static_ssh_key_
    bootstrap), KHÔNG BAO GIỜ đưa vào `summary` trả về ở đây. None nếu logs
    thiếu dòng STATIC_SSH_PRIVATE_KEY_ENC_B64= hoặc giải mã thất bại (caller
    PHẢI coi đây là job thất bại, không phải "thành công nhưng thiếu key").
    """
    summary: dict = {}
    private_key_pem = None
    for line in logs.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key == "STATIC_KEY_BOOTSTRAP_STATUS":
            summary["static_key_bootstrap_status"] = value
        elif key == "STATIC_SSH_PUBLIC_KEY":
            summary["public_key_installed"] = value
        elif key == "STATIC_SSH_PRIVATE_KEY_ENC_B64":
            try:
                private_key_pem = _decrypt_transport_payload(value, transport_passphrase).decode()
            except (ValueError, UnicodeDecodeError) as exc:
                summary["private_key_decrypt_error"] = str(exc)
    return summary, private_key_pem


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

    `os_family` khớp KHÔNG phân biệt hoa/thường: Host.os_family đến từ máy
    tự khai (`ID=` trong /etc/os-release — luôn chữ thường: "ubuntu",
    "debian"), qua Agent heartbeat hoặc job ssh-check; còn
    RemediationVariant.os_family do người tạo Control GÕ TAY nên rất dễ
    thành "Ubuntu". Trước đây lệch hoa/thường làm variant không khớp và
    trang "Kiểm tra & Khắc phục" báo "Chưa có bản vá" — không sai kiểu báo
    lỗi, nhưng chỉ đúng lý do ở tầng chuỗi ký tự, người dùng không tài nào
    đoán ra. So sánh lower() cả 2 vế để 2 nguồn dữ liệu này gặp được nhau.
    """
    os_family = (host.os_family or "").lower()
    exact = (
        db.query(RemediationVariant)
        .filter(
            RemediationVariant.control_id == control_id,
            func.lower(RemediationVariant.os_family) == os_family,
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
            func.lower(RemediationVariant.os_family) == os_family,
            RemediationVariant.os_version.is_(None),
        )
        .first()
    )


def _agent_ineligible_reason(host: Host) -> str | None:
    """None nếu host đủ điều kiện dùng đường Agent Active Response cho
    remediate — ngược lại trả lý do KHÔNG đủ điều kiện (dùng cả để tự động
    chọn kênh khi caller không chỉ định `connection_method`, VÀ để báo lỗi
    422 rõ ràng khi caller CHỌN TAY "agent" nhưng thiếu 1 trong các điều
    kiện dưới đây):
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
    if not settings.active_response_enabled:
        return "Active Response đang tắt toàn cục (kill-switch settings.active_response_enabled)"
    if host.agent_enrolled_at is None:
        return "host chưa enroll Agent"
    if not host.active_response_enabled:
        return "Active Response chưa được bật riêng cho host này (PATCH /hosts/{hostname}/active-response)"
    if host.agent_renewal_blocked:
        return "host đang bị khoá renew cert Agent (agent_renewal_blocked=true)"
    return None


def _dispatch_remediate_job(
    db: Session, job: Job, host: Host, variant: RemediationVariant, dry_run: bool,
    user: CurrentUser, audit_action_prefix: str, connection_method: str | None = None,
) -> Job:
    """Rẽ nhánh MỎNG chọn đường dispatch remediate thật: Agent Active
    Response (mục 4.3/4.4 — Agent tự claim/tải bundle/thực thi/báo cáo) hay
    SSH agentless (_dispatch_remediate_job_via_ssh).

    `connection_method` (None/"ssh"/"agent" — xem schemas.ConnectionMethod):
      - None (KHÔNG chỉ định — hành vi CŨ giữ NGUYÊN 100%): tự động dùng
        Agent nếu `_agent_ineligible_reason(host)` trả None, ngược lại rơi
        về SSH, không báo lỗi gì.
      - "ssh": CHỌN TAY — luôn dùng SSH, bỏ qua hoàn toàn tình trạng Agent
        (giống hệt trước khi tính năng Agent tồn tại).
      - "agent": CHỌN TAY — bắt buộc `_agent_ineligible_reason(host)` phải
        None, KHÔNG tự rơi về SSH nếu thiếu điều kiện (im lặng rơi về SSH
        khi người gọi cố ý chọn "agent" sẽ đánh lừa đúng ý định của họ) —
        đánh job "failed" + ghi audit + báo 422 rõ lý do, cùng pattern lỗi
        ca_mint_failed/dispatcher_call_failed đã có trong file này.
    """
    if connection_method == "ssh":
        use_agent = False
    elif connection_method == "agent":
        reason = _agent_ineligible_reason(host)
        if reason is not None:
            job.status = "failed"
            job.result_summary = {"error": "agent_connection_method_unavailable", "reason": reason}
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            write_audit_event(
                actor=user.username, action=f"{audit_action_prefix}_failed", resource=host.hostname,
                payload={
                    "job_id": job.id, "control_id": job.control_id,
                    "error": "agent_connection_method_unavailable", "reason": reason,
                },
            )
            raise HTTPException(
                status_code=422,
                detail=f"không thể dùng đường Agent cho host '{host.hostname}': {reason}",
            )
        use_agent = True
    else:
        use_agent = _agent_ineligible_reason(host) is None

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
        ssh_auth_env = _get_ssh_dispatch_environment(host, principal="root")
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

    # Override RIÊNG theo host — CHỈ lấy đúng phần giao với
    # Control.overridable_variables (danh sách biến Control NÀY thật sự dùng,
    # xem app/control_templates.py): override 1 biến không thuộc Control đang
    # chạy sẽ bị bỏ qua, không âm thầm áp nhầm sang playbook khác tình cờ
    # trùng tên biến.
    #
    # Endpoint ghi + UI đã bị GỠ (xem docstring Host.ansible_var_overrides,
    # app/models.py) — giá trị tuỳ chỉnh giờ đặt thẳng trong template kiểm tra
    # hardening. Đoạn này GIỮ NGUYÊN để dữ liệu override còn sót lại từ trước
    # vẫn được áp đúng như cũ thay vì bị bỏ qua lặng lẽ; với host không có
    # override nào thì extra_vars = {} (không đổi hành vi).
    control = db.get(Control, variant.control_id)
    overridable = (control.overridable_variables or {}) if control else {}
    host_overrides = host.ansible_var_overrides or {}
    extra_vars = {k: v for k, v in host_overrides.items() if k in overridable}

    dispatch_body = {
        "job_id": str(job.id),
        "image": settings.allowed_execution_image,
        "command": ["remediate"],
        "environment": {
            "TARGET_HOST": host.ip_address,
            "TARGET_PORT": str(host.ssh_port),
            "SSH_USER": "root",
            **ssh_auth_env,
            "REMEDIATION_REF": variant.remediation_ref,
            "DRY_RUN": "true" if dry_run else "false",
            "CONTENT_SIGNING_TRUSTED_FINGERPRINT": settings.content_signing_trusted_fingerprint,
            "EXTRA_VARS_JSON": json.dumps(extra_vars),
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
    run_remediate_dry_run/run_remediate_apply/run_ssh_port_change, KHÔNG được
    xen db.commit() nào giữa lúc gọi hàm này và lúc Job mới commit — nếu
    không, lock chỉ còn tác dụng đúng trong câu SELECT này rồi thả ngay,
    không bảo vệ được gì) — chặn 2 request cùng đổi kênh kết nối/cấu hình SSH
    trên CÙNG 1 host chạy chồng lên nhau (dry-run/apply remediate LẪN
    ssh-port-change đều tính — port đổi giữa chừng 1 job remediate khác đang
    chạy là kịch bản cần tránh, không chỉ 2 remediate xung đột nhau).

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
    if host.decommissioned_at is not None:
        raise HTTPException(status_code=422, detail="host đang tạm ngưng quản lý — khôi phục quản lý trước khi remediate")

    conflicting = (
        db.query(Job)
        .filter(
            Job.hostname == hostname,
            Job.job_type.in_(("remediate-dry-run", "remediate-apply", "ssh-port-change")),
            Job.status.in_(("pending", "running")),
        )
        .first()
    )
    if conflicting is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                f"host '{hostname}' đang có job remediate/đổi cổng SSH khác chạy dở "
                f"(job_id={conflicting.id}, status={conflicting.status}) — chờ job đó hoàn tất trước"
            ),
        )
    return host


def _require_remediation_variant(db: Session, control_id: str, host: Host) -> RemediationVariant:
    # os_family có thể còn None (chưa cài Agent tự báo cáo — xem
    # app/agents.py:agent_heartbeat — VÀ chưa ai điền tay qua PATCH
    # /hosts/{hostname}) — báo lỗi RÕ RÀNG riêng cho trường hợp này (422,
    # "chưa xác định OS") thay vì để lọt xuống nhánh 404 "không tìm thấy
    # RemediationVariant khớp None" bên dưới, dễ gây hiểu lầm là do CHƯA khai
    # RemediationVariant cho distro đó (đúng nguyên nhân KHÁC hẳn).
    if host.os_family is None:
        raise HTTPException(
            status_code=422,
            detail=(
                f"host '{host.hostname}' chưa xác định OS (os_family) — cài Agent để tự báo cáo "
                f"mỗi heartbeat, hoặc điền tay qua PATCH /hosts/{host.hostname} trước khi remediate"
            ),
        )
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
    db: Session, hostname: str, control_id: str, user: CurrentUser, canary_rollout_id: int | None = None,
    connection_method: str | None = None,
) -> Job:
    """Thân xử lý thật của remediate dry-run — tách ra khỏi route handler để
    app/canary.py có thể tái dùng verbatim cho từng host trong 1 canary
    rollout, không phải gọi lại qua HTTP (xem trigger_remediate_dry_run bên
    dưới, giờ chỉ còn là wrapper mỏng). `connection_method` (None/"ssh"/
    "agent") xem docstring _dispatch_remediate_job — canary rollout KHÔNG
    truyền giá trị này (luôn None, giữ nguyên hành vi tự động chọn kênh).

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

    job = _dispatch_remediate_job(
        db, job, host, variant, dry_run=True, user=user, audit_action_prefix="remediate_dry_run",
        connection_method=connection_method,
    )

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
    body: RemediateDryRunRequest | None = None,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(JOBS_REMEDIATE_DRY_RUN)),
) -> Job:
    # body optional (KHÔNG có default_factory) — request KHÔNG gửi body nào
    # (client.ts cũ/mọi test hiện có) vẫn phải hoạt động y hệt trước, giữ
    # đúng backward-compat.
    return run_remediate_dry_run(
        db, hostname, control_id, user,
        connection_method=body.connection_method if body is not None else None,
    )


def run_remediate_apply(
    db: Session, hostname: str, control_id: str, dry_run_job_id: int, user: CurrentUser,
    canary_rollout_id: int | None = None, connection_method: str | None = None,
) -> Job:
    """Thân xử lý thật của remediate apply — tách ra khỏi route handler để
    app/canary.py có thể tái dùng verbatim (cùng lý do run_remediate_dry_run
    ở trên), giữ NGUYÊN toàn bộ gating (maturity/variant/dry-run staleness).
    `canary_rollout_id` gán ngay lúc tạo Job — xem
    docstring run_remediate_dry_run để biết lý do không gán sau khi return.
    `connection_method` cùng ý nghĩa như run_remediate_dry_run ở trên.

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

    job = _dispatch_remediate_job(
        db, job, host, variant, dry_run=False, user=user, audit_action_prefix="remediate_apply",
        connection_method=connection_method,
    )

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
    user: CurrentUser = Depends(require_permission(JOBS_REMEDIATE_APPLY)),
) -> Job:
    return run_remediate_apply(
        db, hostname, control_id, body.dry_run_job_id, user, connection_method=body.connection_method
    )


def _dispatch_restore_job_via_agent(
    db: Session, job: Job, host: Host, source_job_id: int, user: CurrentUser,
) -> Job:
    """Dispatch restore qua Agent Active Response — mirror ĐÚNG mô hình
    _dispatch_remediate_job_via_agent (Orchestrator chỉ đặt job "pending" rồi
    poll DB 2s/lần, Agent tự claim + Executor tự giải nén backup cục bộ +
    báo kết quả về qua app/agents.py:claim_remediate_job (mở rộng)/
    report_restore_result). KHÔNG tái dùng trực tiếp
    _dispatch_remediate_job_via_agent — hàm đó nhận variant/dry_run (restore
    không có RemediationVariant) — trùng logic vòng lặp poll (~30 dòng)
    nhưng tách riêng để không đụng code remediate đã test kỹ.

    source_job_id lưu vào job.result_summary NGAY LÚC chuyển "pending" —
    claim_remediate_job đọc lại giá trị này để biết lấy backup_tar_b64 từ
    Job nào khi Agent claim (backup không nằm trên chính job "restore" này).
    """
    job.status = "pending"
    job.result_summary = {"source_job_id": source_job_id}
    db.commit()

    start = time.monotonic()
    while True:
        time.sleep(2)
        db.refresh(job)
        if job.status in ("succeeded", "failed"):
            return job
        if time.monotonic() - start > AGENT_REMEDIATE_DISPATCH_TIMEOUT:
            break

    # Refresh + re-check NGAY TRƯỚC KHI ghi đè — cùng lý do
    # _dispatch_remediate_job_via_agent (chống lost-update nếu
    # report_restore_result vừa commit "succeeded" đúng vào khoảng giữa lần
    # refresh cuối trong vòng lặp trên và đây).
    db.refresh(job)
    if job.status in ("succeeded", "failed"):
        return job

    job.status = "failed"
    job.result_summary = {"error": "agent_restore_timeout", "source_job_id": source_job_id}
    job.finished_at = datetime.now(timezone.utc)
    db.commit()
    write_audit_event(
        actor="system", action="restore_failed", resource=host.hostname,
        payload={"job_id": job.id, "source_job_id": source_job_id, "error": "agent_restore_timeout"},
    )
    raise HTTPException(
        status_code=504,
        detail=(
            f"Agent không báo cáo kết quả restore trong {AGENT_REMEDIATE_DISPATCH_TIMEOUT}s "
            "— job đã được đánh dấu failed"
        ),
    )


def run_restore(
    db: Session, hostname: str, source_job_id: int, user: CurrentUser, connection_method: str | None = None,
) -> Job:
    """Khôi phục cấu hình từ backup đã chụp lúc 1 remediate-apply trước đó
    (mục "1-click restore" trong README.md). KHÔNG đòi hỏi dry-run riêng như
    remediate-apply — đây là công cụ khôi phục khẩn cấp (break-glass): restore
    đưa hệ thống VỀ trạng thái đã biết trước đó chứ không phải áp dụng thay
    đổi mới chưa kiểm chứng — đòi hỏi duyệt lại lúc restore chỉ làm chậm phản
    ứng sự cố mà không giảm thêm rủi ro tương ứng. Vẫn giữ role
    operator/admin (xem trigger_restore) — không mở cho mọi user.

    `connection_method` (None/"ssh"/"agent" — xem schemas.ConnectionMethod)
    mirror ĐÚNG 3 nhánh của _dispatch_remediate_job: None tự động chọn Agent
    nếu `_agent_ineligible_reason(host)` trả None (SSH BACKUP_MAX_BYTES/
    truncation check ở trên áp dụng CHUNG cho cả 2 đường, chạy TRƯỚC khi rẽ
    nhánh); "agent" ép dùng Agent, 422 rõ lý do nếu không đủ điều kiện (KHÔNG
    âm thầm rơi về SSH); "ssh" ép dùng SSH bất kể Agent có sẵn sàng hay không.
    """
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")
    if host.decommissioned_at is not None:
        raise HTTPException(status_code=422, detail="host đang tạm ngưng quản lý — khôi phục quản lý trước khi restore")

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

    if connection_method == "ssh":
        use_agent = False
    elif connection_method == "agent":
        reason = _agent_ineligible_reason(host)
        if reason is not None:
            job.status = "failed"
            job.result_summary = {"error": "agent_connection_method_unavailable", "reason": reason}
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            write_audit_event(
                actor=user.username, action="restore_failed", resource=hostname,
                payload={
                    "job_id": job.id, "source_job_id": source_job_id,
                    "error": "agent_connection_method_unavailable", "reason": reason,
                },
            )
            raise HTTPException(
                status_code=422,
                detail=f"không thể dùng đường Agent cho host '{hostname}': {reason}",
            )
        use_agent = True
    else:
        use_agent = _agent_ineligible_reason(host) is None

    if use_agent:
        return _dispatch_restore_job_via_agent(db, job, host, source_job_id, user)

    try:
        ssh_auth_env = _get_ssh_dispatch_environment(host, principal="root")
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
        "TARGET_PORT": str(host.ssh_port),
        "SSH_USER": "root",
        **ssh_auth_env,
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
    user: CurrentUser = Depends(require_permission(JOBS_RESTORE)),
) -> Job:
    return run_restore(db, hostname, body.source_job_id, user, connection_method=body.connection_method)


def reconcile_orphaned_remediate_jobs() -> int:
    """Gọi 1 lần lúc Orchestrator khởi động (app/main.py `lifespan`) — cùng lý
    do đúng hệt app/canary.py:reconcile_orphaned_rollouts (phát hiện qua rà
    soát đối kháng, không phải lý thuyết suông):

    - `_dispatch_remediate_job_via_agent` (trên) đặt Job.status="pending" rồi
      POLL SỐNG TRONG process (vòng while sleep(2) tới
      AGENT_REMEDIATE_DISPATCH_TIMEOUT) — không phải background task độc
      lập nào có thể tự resume sau khi process chết.
    - Kể cả đường SSH agentless (`_dispatch_remediate_job_via_ssh`,
      `run_ssh_port_change`) cũng gọi job-dispatcher ĐỒNG BỘ trong chính
      request — nếu Orchestrator crash/restart giữa lúc đó, request chết
      theo, Job vẫn "running" mãi.
    - `_lock_host_for_remediate` coi MỌI Job cùng hostname có status
      "pending"/"running" (remediate-dry-run/remediate-apply/ssh-port-change)
      là "đang chạy dở" (409) — 1 Job mồ côi khoá CỨNG luôn host đó khỏi mọi
      job mới thuộc nhóm này cho tới khi có người sửa DB tay, không chỉ là
      báo cáo trạng thái sai.

    Luôn đưa về "failed" (KHÔNG thử resume dở dang) — cùng triết lý an toàn
    mặc định với reconcile_orphaned_rollouts: trạng thái thật trên host tại
    đúng thời điểm restart không xác định chắc chắn, resume mù rủi ro áp
    nhầm hoặc bỏ sót bước; "failed" chỉ đơn thuần mở khoá lại host để
    operator tự trigger job mới sau khi đã tự xác minh tình trạng thật.

    "agent-install" (app/agents.py:trigger_agent_install) cũng đặt
    status="running" rồi gọi job-dispatcher ĐỒNG BỘ (timeout tới 150s) trong
    CÙNG request, giống hệt pattern trên dù không có host-lock riêng như 3
    job type kia — thiếu trong danh sách dưới đây trước đây khiến 1 job
    agent-install mồ côi (Orchestrator restart giữa lúc dispatch) kẹt vĩnh
    viễn ở "running", gây nhiễu trang Jobs dù không khoá gì thêm (phát hiện
    qua rà soát đối kháng riêng cho toàn bộ subsystem Agent).

    "ssh-check" (trigger_ssh_check ở trên) giờ CŨNG chạy phần chờ job-
    dispatcher qua BackgroundTasks (mục "progress bar % thật", xem
    _dispatch_ssh_check_job) thay vì đồng bộ hoàn toàn trong request — cùng
    rủi ro mồ côi y hệt agent-install nếu Orchestrator restart giữa lúc
    BackgroundTasks đang chạy (task đó chết theo process, không có cơ chế
    tự resume), nên thêm vào danh sách dưới đây cùng lý do.

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
                Job.job_type.in_(
                    ("remediate-dry-run", "remediate-apply", "ssh-port-change", "agent-install", "ssh-check")
                ),
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
    user: CurrentUser = Depends(require_permission(JOBS_SCAN)),
) -> Job:
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")
    if host.decommissioned_at is not None:
        raise HTTPException(status_code=422, detail="host đang tạm ngưng quản lý — khôi phục quản lý trước khi scan")

    profile_def = SCAP_PROFILES.get(body.scap_profile_key)
    if profile_def is None:
        raise HTTPException(
            status_code=422,
            detail=f"scap_profile_key không hợp lệ, các giá trị hỗ trợ: {sorted(SCAP_PROFILES)}",
        )

    # Re-check ĐỘC LẬP với validate lúc sửa host (app/hosts.py:update_host) —
    # phòng trường hợp settings.allowed_ssh_users bị thắt lại SAU khi host đã
    # có giá trị không còn hợp lệ (defense-in-depth, cùng mẫu re-check
    # kill-switch lúc claim thay vì chỉ lúc dispatch — xem app/agents.py).
    if host.ssh_user not in settings.allowed_ssh_users_set:
        raise HTTPException(
            status_code=422,
            detail=(
                f"ssh_user hiện tại của host ('{host.ssh_user}') không còn nằm trong "
                f"allowlist ({sorted(settings.allowed_ssh_users_set)}) — sửa lại qua PATCH /hosts/{{hostname}}"
            ),
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
        ssh_auth_env = _get_ssh_dispatch_environment(host, principal=host.ssh_user)
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
            "TARGET_PORT": str(host.ssh_port),
            "SSH_USER": host.ssh_user,
            **ssh_auth_env,
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


# Các khoá thông tin máy mà ssh-check.sh được phép báo về (mục "lấy thông tin
# OS/kernel/phần cứng sau khi test SSH thành công"). ALLOWLIST CỐ Ý, không
# nhận mọi key có tiền tố SSH_CHECK_: nội dung log đến từ máy đích, 1 host bị
# chiếm có thể in thêm dòng "SSH_CHECK_<gì đó>=..." tuỳ ý để bơm rác vào
# Host.system_info (bảng hiển thị cho mọi role đọc được). Key lạ vẫn nằm
# trong result_summary của Job (để debug) nhưng KHÔNG được ghi vào Host.
_SSH_CHECK_SYSTEM_KEYS = (
    "os_id",
    "os_version_id",
    "os_pretty",
    "kernel",
    "arch",
    "cpu_model",
    "cpu_cores",
    "mem_total_kb",
    "disk_root",
    "virt",
    "uptime_sec",
)

# Cắt lần 2 phía Orchestrator dù ssh-check.sh đã cut -c1-200 — script chạy
# TRÊN máy đích không phải nơi đáng tin để thực thi giới hạn (xem docstring
# Host.system_info).
_SSH_CHECK_VALUE_MAX = 200


def _parse_ssh_check_summary(logs: str) -> dict:
    summary = {"raw_log_tail": logs[-2000:]}
    for line in logs.splitlines():
        if "=" not in line or not line.startswith("SSH_CHECK_"):
            continue
        key, _, value = line.partition("=")
        summary[key.strip().lower()] = value.strip()[:_SSH_CHECK_VALUE_MAX]
    return summary


def _extract_system_info(summary: dict) -> dict:
    """Lọc summary của ssh-check xuống đúng phần thông tin máy trong
    allowlist, bỏ giá trị rỗng/"unknown" (script trả "unknown" khi máy đích
    thiếu lệnh/file tương ứng — lưu lại chỉ làm nhiễu bảng hiển thị)."""
    info: dict[str, str] = {}
    for key in _SSH_CHECK_SYSTEM_KEYS:
        value = summary.get(f"ssh_check_{key}")
        if isinstance(value, str) and value and value != "unknown":
            info[key] = value
    return info


@router.post("/hosts/{hostname}/ssh-check", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED)
def trigger_ssh_check(
    hostname: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(JOBS_SSH_CHECK)),
) -> Job:
    """Kiểm tra khả năng SSH tới host trước khi trigger scan/remediate thật
    — dùng đúng cơ chế mint SSH cert ngắn hạn có sẵn (như trigger_scan),
    KHÔNG lưu/dùng static credential nào (giữ đúng nguyên tắc #1 "no standing
    privilege"). Chỉ khả thi cho host ĐÃ deploy trust CA — với host
    `not_started`, chưa có cách nào test mà không cần credential cũ (xem
    Zero-to-CA Migration playbook, `ansible/README.md`). Không đổi state
    trên target nên KHÔNG cần four-eyes, giống trigger_scan.

    Mọi bước validate + mint cert/lấy static key vẫn ĐỒNG BỘ (lỗi 422/502
    trả nhanh như trước) — CHỈ phần chờ job-dispatcher chạy xong container
    (`_call_job_dispatcher`, có thể mất vài giây tới ~30s) được đưa vào
    `background_tasks` (xem `_dispatch_ssh_check_job`), để response trả về
    NGAY với Job còn "running", cho phép frontend poll
    `GET /jobs/{id}/progress` (job-dispatcher đọc log live của container) để
    hiển thị % tiến độ thật — mục "progress bar % thật cho Test SSH/Cài
    Agent". response_model vẫn JobOut của Job LÚC "running", không phải kết
    quả cuối.
    """
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")
    if host.decommissioned_at is not None:
        raise HTTPException(status_code=422, detail="host đang tạm ngưng quản lý — khôi phục quản lý trước khi test SSH")

    if host.ca_migration_status not in ("trust_deployed", "migrated"):
        raise HTTPException(
            status_code=422,
            detail=(
                "host chưa deploy CA trust (ca_migration_status phải là "
                "trust_deployed hoặc migrated) — chạy Zero-to-CA Migration "
                "playbook trước, xem ansible/README.md"
            ),
        )

    # Re-check độc lập, cùng lý do trigger_scan ở trên.
    if host.ssh_user not in settings.allowed_ssh_users_set:
        raise HTTPException(
            status_code=422,
            detail=(
                f"ssh_user hiện tại của host ('{host.ssh_user}') không còn nằm trong "
                f"allowlist ({sorted(settings.allowed_ssh_users_set)}) — sửa lại qua PATCH /hosts/{{hostname}}"
            ),
        )

    job = Job(
        hostname=hostname,
        job_type="ssh-check",
        status="running",
        triggered_by=user.username,
        started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        ssh_auth_env = _get_ssh_dispatch_environment(host, principal=host.ssh_user)
    except RuntimeError as exc:
        job.status = "failed"
        job.result_summary = {"error": str(exc)}
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        write_audit_event(
            actor=user.username, action="ssh_check_failed", resource=hostname,
            payload={"job_id": job.id, "error": "ca_mint_failed"},
        )
        raise HTTPException(status_code=502, detail=f"không cấp được SSH cert cho job: {exc}") from exc

    dispatch_body = {
        "job_id": str(job.id),
        "image": settings.allowed_execution_image,
        "command": ["ssh-check"],
        "environment": {
            "TARGET_HOST": host.ip_address,
            "TARGET_PORT": str(host.ssh_port),
            "SSH_USER": host.ssh_user,
            **ssh_auth_env,
        },
        "timeout_seconds": 30,
    }

    background_tasks.add_task(_dispatch_ssh_check_job, job.id, hostname, user.username, dispatch_body)
    return job


def _dispatch_ssh_check_job(job_id: int, hostname: str, triggered_by: str, dispatch_body: dict) -> None:
    """Phần CHỜ job-dispatcher chạy xong của trigger_ssh_check — chạy trong
    BackgroundTasks (xem docstring trigger_ssh_check). Mở SessionLocal()
    RIÊNG (session request-scoped của trigger_ssh_check đã đóng ngay khi
    response được gửi), cùng pattern app/canary.py:_run_rollout.

    Bọc try/except Exception NGOÀI CÙNG (không chỉ httpx.HTTPError) — lúc
    còn chạy đồng bộ trong request, 1 lỗi không lường được vẫn lọt ra
    HTTPException cho FastAPI xử lý; ở đây không còn ai chờ nhận exception,
    nên PHẢI tự bắt và tự đánh Job "failed", nếu không Job kẹt vĩnh viễn ở
    "running" — đúng lớp bug codebase này đã nhiều lần sửa (xem docstring
    _get_ssh_dispatch_environment/mint_ssh_certificate).
    """
    db = SessionLocal()
    try:
        job = db.get(Job, job_id)
        if job is None:
            return

        try:
            result = _call_job_dispatcher(dispatch_body, timeout=60)
        except httpx.HTTPError as exc:
            job.status = "failed"
            job.result_summary = {"error": str(exc)}
            job.finished_at = datetime.now(timezone.utc)
            db.commit()
            write_audit_event(
                actor=triggered_by, action="ssh_check_failed", resource=hostname,
                payload={"job_id": job.id, "error": "dispatcher_call_failed"},
            )
            return

        summary = _parse_ssh_check_summary(result.get("logs", ""))
        summary["exit_code"] = result.get("exit_code")
        job.status = "succeeded" if result.get("exit_code") == 0 else "failed"
        job.result_summary = summary
        job.finished_at = datetime.now(timezone.utc)

        # Chỉ ghi thông tin máy khi job THÀNH CÔNG — job failed nghĩa là
        # không SSH được, phần thông tin (nếu có sót trong log) không đáng
        # tin và cũng không mới hơn lần thu thập trước.
        os_changes: dict[str, str] = {}
        if job.status == "succeeded":
            system_info = _extract_system_info(summary)
            if system_info:
                host = db.get(Host, hostname)
                if host is not None:
                    host.system_info = system_info  # gán MỚI (không mutate) để SQLAlchemy nhận diện thay đổi cột JSON
                    host.system_info_updated_at = datetime.now(timezone.utc)

                    # Điền/cập nhật luôn os_family + os_version — cùng semantics
                    # app/agents.py:agent_heartbeat (chỉ ghi khi có giá trị THẬT
                    # và khác giá trị đang lưu; thiếu field KHÔNG có nghĩa là
                    # "xoá"). Nhờ đó host thuần agentless không phải điền tay 2
                    # field này nữa — vốn là điều kiện BẮT BUỘC trước khi
                    # remediate (_require_remediation_variant từ chối nếu
                    # os_family còn None).
                    os_id = system_info.get("os_id")
                    os_version_id = system_info.get("os_version_id")
                    if os_id and os_id != host.os_family:
                        os_changes["os_family"] = os_id
                        host.os_family = os_id
                    if os_version_id and os_version_id != host.os_version:
                        os_changes["os_version"] = os_version_id
                        host.os_version = os_version_id

        db.commit()

        write_audit_event(
            actor=triggered_by,
            action="ssh_check_completed",
            resource=hostname,
            # CHỈ ghi tên khoá đã đổi + kernel/arch (giá trị ngắn, không nhạy
            # cảm) — KHÔNG nhét cả system_info vào audit payload, đúng quy ước
            # "payload tối giản, không log thô" của dự án (xem app/audit.py).
            payload={"job_id": job.id, "status": job.status, "os_updated": os_changes or None},
        )
    except Exception:
        logger.exception("ssh-check job %s: lỗi ngoài dự kiến trong background dispatch", job_id)
        try:
            db.rollback()
            job = db.get(Job, job_id)
            if job is not None and job.status == "running":
                job.status = "failed"
                job.result_summary = {"error": "internal_error"}
                job.finished_at = datetime.now(timezone.utc)
                db.commit()
                write_audit_event(
                    actor=triggered_by, action="ssh_check_failed", resource=hostname,
                    payload={"job_id": job_id, "error": "internal_error"},
                )
        except Exception:
            logger.exception(
                "ssh-check job %s: KHÔNG THỂ đánh 'failed' sau lỗi ngoài dự kiến — kẹt "
                "'running' tới lần Orchestrator khởi động lại kế tiếp "
                "(reconcile_orphaned_remediate_jobs tự dọn lúc đó)", job_id,
            )
    finally:
        db.close()


def _parse_ca_bootstrap_summary(logs: str) -> dict:
    # CHỈ đọc dòng CA_BOOTSTRAP_STATUS do ca-bootstrap.sh in ra — KHÔNG bao
    # giờ đưa credential vào summary (script tự nó cũng không echo lại
    # credential, xem apps/execution-env/ca-bootstrap.sh).
    summary = {"raw_log_tail": logs[-2000:]}
    for line in logs.splitlines():
        if "=" not in line or not line.startswith("CA_BOOTSTRAP_"):
            continue
        key, _, value = line.partition("=")
        summary[key.strip().lower()] = value.strip()
    return summary


@router.post(
    "/hosts/{hostname}/bootstrap-ca-trust", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED
)
def trigger_ca_bootstrap(
    hostname: str,
    body: CaBootstrapRequest,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(JOBS_CA_BOOTSTRAP)),
) -> Job:
    """Tự động hoá BƯỚC 1 (đẩy public key SSH User CA + bật TrustedUserCAKeys
    + reload sshd) của Zero-to-CA Migration (ansible/playbooks/
    zero-to-ca-migration.yml) bằng credential SSH CŨ do operator cung cấp —
    dùng ĐÚNG 1 LẦN cho job này rồi bỏ, KHÔNG BAO GIỜ lưu vào DB/log/
    result_summary ở bất kỳ đâu (chỉ truyền qua biến môi trường của 1
    container execution-env dùng 1 lần, xem
    apps/execution-env/ca-bootstrap.sh).

    Cố tình CHỈ tự động hoá bước 1 — bước 2 ("thu hồi credential cũ", tương
    đương ansible/playbooks/revoke-old-credential.yml) VẪN thủ công, đòi hỏi
    operator tự xác nhận cert mới thật sự dùng được trước (xem
    ansible/README.md) — không rút ngắn "cửa sổ rủi ro lớn nhất vòng đời hệ
    thống" (rủi ro #8 architecture-proposal.md) bằng cách tự động cả 2 bước.

    Set `ca_migration_status="trust_deployed"` + `ca_migration_updated_by`
    (cùng người vừa chạy job này) khi thành công — GIỐNG HỆT ngữ nghĩa PATCH
    /hosts/{hostname}/ca-migration-status thủ công (app/hosts.py:
    update_ca_migration_status), giữ nhất quán dữ liệu giữa 2 đường set field
    này dù không còn ràng buộc four-eyes nào áp dụng cho bước "migrated" sau.
    """
    host = db.get(Host, hostname)
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")
    if host.decommissioned_at is not None:
        raise HTTPException(
            status_code=422, detail="host đang tạm ngưng quản lý — khôi phục quản lý trước khi bootstrap CA trust"
        )
    if host.ca_migration_status != "not_started":
        raise HTTPException(
            status_code=422,
            detail=(
                f"host đã ở trạng thái '{host.ca_migration_status}' — bootstrap CA trust chỉ áp dụng "
                "cho host còn 'not_started'"
            ),
        )
    if bool(body.legacy_ssh_password) == bool(body.legacy_ssh_private_key):
        raise HTTPException(
            status_code=422,
            detail="phải cung cấp ĐÚNG 1 trong legacy_ssh_password hoặc legacy_ssh_private_key",
        )

    job = Job(
        hostname=hostname,
        job_type="ca-bootstrap",
        status="running",
        triggered_by=user.username,
        started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        ca_pubkey = get_ssh_user_ca_pubkey()
    except RuntimeError as exc:
        job.status = "failed"
        job.result_summary = {"error": str(exc)}
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        write_audit_event(
            actor=user.username, action="ca_bootstrap_failed", resource=hostname,
            payload={"job_id": job.id, "error": "ca_pubkey_fetch_failed"},
        )
        raise HTTPException(status_code=502, detail=f"không lấy được SSH User CA public key: {exc}") from exc

    environment = {
        "TARGET_HOST": host.ip_address,
        "TARGET_PORT": str(host.ssh_port),
        "LEGACY_SSH_USER": body.legacy_ssh_user,
        "CA_SSH_USER_PUBKEY": ca_pubkey,
    }
    if body.legacy_ssh_private_key:
        environment["LEGACY_SSH_PRIVATE_KEY_B64"] = base64.b64encode(
            body.legacy_ssh_private_key.encode()
        ).decode()
    else:
        environment["LEGACY_SSH_PASSWORD_B64"] = base64.b64encode(
            body.legacy_ssh_password.encode()
        ).decode()

    dispatch_body = {
        "job_id": str(job.id),
        "image": settings.allowed_execution_image,
        "command": ["ca-bootstrap"],
        "environment": environment,
        "timeout_seconds": 60,
    }

    try:
        result = _call_job_dispatcher(dispatch_body, timeout=90)
    except httpx.HTTPError as exc:
        job.status = "failed"
        job.result_summary = {"error": str(exc)}
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        write_audit_event(
            actor=user.username, action="ca_bootstrap_failed", resource=hostname,
            payload={"job_id": job.id, "error": "dispatcher_call_failed"},
        )
        raise HTTPException(status_code=502, detail=f"job-dispatcher lỗi: {exc}") from exc

    summary = _parse_ca_bootstrap_summary(result.get("logs", ""))
    summary["exit_code"] = result.get("exit_code")
    job.status = "succeeded" if result.get("exit_code") == 0 else "failed"
    job.result_summary = summary
    job.finished_at = datetime.now(timezone.utc)

    if job.status == "succeeded":
        host.ca_migration_status = "trust_deployed"
        host.ca_migration_updated_by = user.username

    db.commit()
    db.refresh(job)

    write_audit_event(
        actor=user.username,
        action="ca_bootstrap_completed",
        resource=hostname,
        payload={"job_id": job.id, "status": job.status},
    )
    return job


@router.post(
    "/hosts/{hostname}/bootstrap-static-ssh-key", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED
)
def trigger_static_ssh_key_bootstrap(
    hostname: str,
    body: StaticSshKeyBootstrapRequest,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(JOBS_STATIC_SSH_KEY_BOOTSTRAP)),
) -> Job:
    """Lựa chọn THAY THẾ cho bootstrap-ca-trust (app/hosts.py không đụng gì
    tới endpoint đó — vẫn giữ nguyên 100%) — theo yêu cầu người dùng (đã giải
    thích rõ đánh đổi bảo mật, xác nhận muốn làm tiếp): tạo 1 SSH keypair
    MỚI, cài public key lên host bằng credential SSH CŨ (dùng đúng 1 lần),
    LƯU LẠI private key (mã hoá) trên Orchestrator để MỌI job SSH sau này
    dùng lại — xem _get_ssh_dispatch_environment. KHÔNG đụng sshd_config/
    TrustedUserCAKeys (khác bootstrap-ca-trust) — script apps/execution-env/
    static-ssh-key-bootstrap.sh chỉ ghi authorized_keys.

    Chọn ĐÚNG 1 trong 2 cơ chế cho mỗi host (guard `ca_migration_status ==
    "not_started"` dùng CHUNG với bootstrap-ca-trust — 1 khi đã chọn 1 trong
    2, cái còn lại tự bị chặn vì status đã đổi).

    Cài public key vào CẢ "root" VÀ host.ssh_user (nếu khác nhau) — 2
    principal thực sự được dùng rải rác qua 7 điểm dispatch SSH khác nhau
    (remediate/restore/ssh-port-change hardcode "root", scan/ssh-check/
    agent-install/agent-uninstall dùng host.ssh_user); 1 static key không tự
    mang theo claim principal như cert CA, thiếu bước này sẽ khiến nhóm job
    còn lại auth fail âm thầm dù ca_migration_status báo đã xong.

    Private key mới sinh ra được mã hoá TRÊN ĐƯỜNG TRUYỀN bằng 1 passphrase
    AES-256/PBKDF2 CHỈ DÙNG CHO LẦN GỌI NÀY (transport_passphrase, không lưu
    lại) TRƯỚC KHI script in ra stdout — Docker's json-file log driver ghi
    NGUYÊN VĂN log của container xuống đĩa máy chạy job-dispatcher TRƯỚC KHI
    container bị xoá, nên in plaintext ra stdout sẽ lộ key ra ngoài tầm kiểm
    soát của Orchestrator (khác legacy_ssh_password — credential đó sắp bị
    revoke, còn key MỚI này thì sống mãi, không có bước revoke nào). Dùng
    `-pass env:` (không phải `-K`/`-iv` CLI argument trần) — tránh lộ qua
    `ps aux`, xem _decrypt_transport_payload.

    Khoá row Host bằng `with_for_update()` (khác `db.get()` của bootstrap-ca-
    trust) — chặn 2 request đồng thời cùng bootstrap 1 host tạo 2 keypair
    khác nhau đè lên nhau (bootstrap-ca-trust không cần vì hậu quả của race
    đó vô hại — chỉ 1 dòng TrustedUserCAKeys trùng lặp; ở đây hậu quả là 1
    trong 2 keypair bị mồ côi, không ai giữ private key).
    """
    host = db.query(Host).filter(Host.hostname == hostname).with_for_update().first()
    if host is None:
        raise HTTPException(status_code=404, detail="host không tồn tại")
    if host.decommissioned_at is not None:
        raise HTTPException(
            status_code=422,
            detail="host đang tạm ngưng quản lý — khôi phục quản lý trước khi bootstrap static SSH key",
        )
    if host.ca_migration_status != "not_started":
        raise HTTPException(
            status_code=422,
            detail=(
                f"host đã ở trạng thái '{host.ca_migration_status}' — bootstrap static SSH key chỉ áp dụng "
                "cho host còn 'not_started'"
            ),
        )
    if bool(body.legacy_ssh_password) == bool(body.legacy_ssh_private_key):
        raise HTTPException(
            status_code=422,
            detail="phải cung cấp ĐÚNG 1 trong legacy_ssh_password hoặc legacy_ssh_private_key",
        )

    job = Job(
        hostname=hostname,
        job_type="static-ssh-key-bootstrap",
        status="running",
        triggered_by=user.username,
        started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Passphrase RIÊNG cho lần gọi này (KHÔNG lưu lại) — script mã hoá private
    # key mới sinh bằng passphrase này qua `openssl enc -pass env:...` TRƯỚC
    # KHI in ra stdout, xem _decrypt_transport_payload.
    transport_passphrase = secrets.token_urlsafe(32)
    # sorted({...}) -> thứ tự cố định (vd "deploy,root" luôn giống nhau) để
    # dễ so sánh trong test/log, không phải vì thứ tự cài đặt quan trọng.
    target_users = ",".join(sorted({"root", host.ssh_user}))

    environment = {
        "TARGET_HOST": host.ip_address,
        "TARGET_PORT": str(host.ssh_port),
        "LEGACY_SSH_USER": body.legacy_ssh_user,
        "STATIC_KEY_TARGET_USERS": target_users,
        "TRANSPORT_PASSPHRASE": transport_passphrase,
    }
    if body.legacy_ssh_private_key:
        environment["LEGACY_SSH_PRIVATE_KEY_B64"] = base64.b64encode(
            body.legacy_ssh_private_key.encode()
        ).decode()
    else:
        environment["LEGACY_SSH_PASSWORD_B64"] = base64.b64encode(
            body.legacy_ssh_password.encode()
        ).decode()

    dispatch_body = {
        "job_id": str(job.id),
        "image": settings.allowed_execution_image,
        "command": ["static-ssh-key-bootstrap"],
        "environment": environment,
        "timeout_seconds": 60,
    }

    try:
        result = _call_job_dispatcher(dispatch_body, timeout=90)
    except httpx.HTTPError as exc:
        job.status = "failed"
        job.result_summary = {"error": str(exc)}
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        write_audit_event(
            actor=user.username, action="static_ssh_key_bootstrap_failed", resource=hostname,
            payload={"job_id": job.id, "error": "dispatcher_call_failed"},
        )
        raise HTTPException(status_code=502, detail=f"job-dispatcher lỗi: {exc}") from exc

    summary, private_key_pem = _parse_static_ssh_key_bootstrap_summary(
        result.get("logs", ""), transport_passphrase
    )
    summary["exit_code"] = result.get("exit_code")

    # PHẢI có cả exit_code=0 VÀ giải mã được private key — thiếu 1 trong 2
    # (vd script "ok" nhưng dòng STATIC_SSH_PRIVATE_KEY_ENC_B64= bị cắt cụt
    # giữa đường) đều là thất bại, không được set ca_migration_status="trust_
    # deployed" mà KHÔNG có key thật để dùng cho các job SSH sau này.
    succeeded = result.get("exit_code") == 0 and private_key_pem is not None
    job.status = "succeeded" if succeeded else "failed"
    job.result_summary = summary
    job.finished_at = datetime.now(timezone.utc)

    if succeeded:
        host.static_ssh_private_key_encrypted = encrypt_host_secret(private_key_pem)
        host.ca_migration_status = "trust_deployed"
        host.ca_migration_updated_by = user.username

    db.commit()
    db.refresh(job)

    write_audit_event(
        actor=user.username,
        action="static_ssh_key_bootstrap_completed",
        resource=hostname,
        payload={"job_id": job.id, "status": job.status},
    )
    return job


def _parse_ssh_port_change_summary(logs: str) -> dict:
    # Tái dùng NGUYÊN _extract_block/_truncate_backup_b64 của remediate — cùng
    # 1 quy tắc cắt backup dù job type nào (xem docstring _truncate_backup_b64).
    logs_for_tail, backup_b64 = _extract_block(logs, "BACKUP_TAR_B64_BEGIN", "BACKUP_TAR_B64_END")
    summary = {"raw_log_tail": logs_for_tail[-2000:]}
    for line in logs_for_tail.splitlines():
        if "=" not in line or not line.startswith("PORT_CHANGE_"):
            continue
        key, _, value = line.partition("=")
        summary[key.strip().lower()] = value.strip()
    if backup_b64 is not None:
        summary["backup_tar_b64"], summary["backup_truncated"] = _truncate_backup_b64(backup_b64)
    return summary


def run_ssh_port_change(db: Session, hostname: str, new_port: int, user: CurrentUser) -> Job:
    """Đổi cổng SSH thật của 1 host, có xác minh kết nối trước khi coi thành
    công — hạng mục rủi ro cao nhất còn lại (xem docs/architecture-proposal.md
    mục 8, rủi ro #5: không phải host nào cũng có phương án khôi phục ngoài
    băng thông nếu bị khoá mất SSH).

    KHÔNG dùng mô hình dry-run/apply 2 bước như remediate — ở đây chỉ có
    đúng 1 câu hỏi cần trả lời ("cổng mới có kết nối được không?"), và 1 lần
    kết nối SSH thật (do apps/execution-env/ssh-port-change.sh tự làm, xem
    docstring file đó) trả lời chắc chắn hơn con người đọc diff. Vì vậy
    KHÔNG bắt four-eyes ở Tier 0/1 — lý do four-eyes tồn tại (ngăn 1 người tự
    đánh giá sai) không áp dụng ở đây, hệ thống tự xác minh chứ không dựa
    phán đoán con người.

    `Host.ssh_port` CHỈ được cập nhật khi log trả về đúng
    `PORT_CHANGE_STATUS=cutover_complete` — never dựa exit_code, cùng nguyên
    tắc mọi `_parse_*_summary` khác trong file này. Nếu script báo
    `verify_failed` (hoặc bất kỳ giá trị nào khác `cutover_complete`, kể cả
    thiếu hẳn dòng này vì lỗi sớm trước khi kịp in ra), host coi như VẪN Ở
    CỔNG CŨ — script tự thiết kế để không đụng gì thêm trong trường hợp đó
    (xem ssh-port-change.sh).

    `_lock_host_for_remediate` dùng chung với remediate — chặn cả 2 chiều
    (remediate đang chạy thì không cho đổi cổng, và ngược lại), xem docstring
    hàm đó.
    """
    host = _lock_host_for_remediate(db, hostname)

    if host.ca_migration_status == "not_started":
        raise HTTPException(
            status_code=422,
            detail=(
                "host chưa deploy CA trust (ca_migration_status phải là "
                "trust_deployed hoặc migrated) — chạy Zero-to-CA Migration playbook trước"
            ),
        )
    if new_port == host.ssh_port:
        raise HTTPException(status_code=422, detail=f"cổng mới trùng cổng hiện tại ({host.ssh_port})")

    from_port = host.ssh_port

    job = Job(
        hostname=hostname,
        job_type="ssh-port-change",
        status="running",
        triggered_by=user.username,
        started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        ssh_auth_env = _get_ssh_dispatch_environment(host, principal="root")
    except RuntimeError as exc:
        job.status = "failed"
        job.result_summary = {"error": str(exc)}
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        write_audit_event(
            actor=user.username, action="ssh_port_change_failed", resource=hostname,
            payload={"job_id": job.id, "error": "ca_mint_failed"},
        )
        raise HTTPException(status_code=502, detail=f"không cấp được SSH cert cho job: {exc}") from exc

    dispatch_body = {
        "job_id": str(job.id),
        "image": settings.allowed_execution_image,
        "command": ["ssh-port-change"],
        "environment": {
            "TARGET_HOST": host.ip_address,
            "SSH_USER": "root",
            **ssh_auth_env,
            "CURRENT_PORT": str(from_port),
            "NEW_PORT": str(new_port),
        },
        "timeout_seconds": 60,
    }

    try:
        result = _call_job_dispatcher(dispatch_body, timeout=90)
    except httpx.HTTPError as exc:
        job.status = "failed"
        job.result_summary = {"error": str(exc)}
        job.finished_at = datetime.now(timezone.utc)
        db.commit()
        write_audit_event(
            actor=user.username, action="ssh_port_change_failed", resource=hostname,
            payload={"job_id": job.id, "error": "dispatcher_call_failed"},
        )
        raise HTTPException(status_code=502, detail=f"job-dispatcher lỗi: {exc}") from exc

    summary = _parse_ssh_port_change_summary(result.get("logs", ""))
    summary["exit_code"] = result.get("exit_code")
    cutover_complete = summary.get("port_change_status") == "cutover_complete"
    job.status = "succeeded" if cutover_complete else "failed"
    job.result_summary = summary
    job.finished_at = datetime.now(timezone.utc)

    if cutover_complete:
        host.ssh_port = new_port

    db.commit()
    db.refresh(job)

    write_audit_event(
        actor=user.username,
        action="ssh_port_change_completed",
        resource=hostname,
        payload={"job_id": job.id, "from_port": from_port, "to_port": new_port, "status": job.status},
    )
    return job


@router.post(
    "/hosts/{hostname}/ssh-port-change", response_model=JobOut, status_code=status.HTTP_202_ACCEPTED
)
def trigger_ssh_port_change(
    hostname: str,
    body: HostSshPortChangeRequest,
    db: Session = Depends(_get_db),
    user: CurrentUser = Depends(require_permission(JOBS_SSH_PORT_CHANGE)),
) -> Job:
    return run_ssh_port_change(db, hostname, body.new_port, user)


@router.get("/jobs", response_model=list[JobListOut])
def list_jobs(
    hostname: str | None = None,
    job_type: str | None = None,
    status: str | None = None,
    limit: int = _JOB_LIST_DEFAULT_LIMIT,
    offset: int = 0,
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(require_permission(JOBS_VIEW)),
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
    _user: CurrentUser = Depends(require_permission(JOBS_VIEW)),
) -> Job:
    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job không tồn tại")
    return job


@router.get("/jobs/{job_id}/progress", response_model=JobProgressOut)
def get_job_progress(
    job_id: int,
    db: Session = Depends(_get_db),
    _user: CurrentUser = Depends(require_permission(JOBS_VIEW)),
) -> JobProgressOut:
    """% tiến độ THẬT cho job đang chạy — chỉ có ý nghĩa cho job_type thuộc
    _PROGRESS_SUPPORTED_JOB_TYPES (script của các job_type khác không in
    marker ##PROGRESS## nào). Đây là gợi ý UI polled liên tục (frontend gọi
    lại mỗi 2s trong lúc Job còn "running") — KHÔNG BAO GIỜ raise lỗi ra
    ngoài vì lỗi/timeout gọi job-dispatcher ở đây (container chưa kịp tạo,
    job-dispatcher tạm không tới được...) không nên làm phiền người dùng,
    Job.status (không phải endpoint này) vẫn là nguồn trạng thái chính thức.
    """
    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job không tồn tại")

    if job.status not in ("pending", "running"):
        return JobProgressOut(job_id=job.id, status=job.status, pct=100, stage=job.status)
    if job.status == "pending":
        return JobProgressOut(job_id=job.id, status=job.status, pct=0, stage="queued")
    if job.job_type not in _PROGRESS_SUPPORTED_JOB_TYPES:
        return JobProgressOut(job_id=job.id, status=job.status, pct=0, stage="unknown")

    try:
        raw = _call_job_dispatcher_progress(job.id)
    except httpx.HTTPError:
        return JobProgressOut(job_id=job.id, status=job.status, pct=0, stage="unknown")
    return JobProgressOut(job_id=job.id, status=job.status, pct=raw["pct"], stage=raw["stage"])
