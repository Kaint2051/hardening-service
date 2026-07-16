import ipaddress
import re
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator

MATURITY_LEVELS = ("draft", "reviewed", "production")
CA_MIGRATION_STATUSES = ("not_started", "trust_deployed", "migrated")
# "A" = đủ điều kiện canary rollout tự động; "B" (mặc định) = chỉ remediate
# thủ công từng host (xem app/models.py:Control.risk_group).
RISK_GROUPS = ("A", "B")

# RFC 1123-ish hostname/FQDN: chữ/số, dấu gạch ngang, dấu chấm, không bắt đầu/
# kết thúc bằng ký tự đặc biệt — chặn ký tự lạ lọt vào hostname (dùng làm
# primary key + resource trong audit log).
_HOSTNAME_PATTERN = r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$"


class ControlCreate(BaseModel):
    title: str = Field(..., max_length=255)
    description: str = ""
    category: str = Field(..., max_length=64)


class ControlOut(BaseModel):
    id: str
    title: str
    description: str
    category: str
    maturity: str
    risk_group: str
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ControlMaturityUpdate(BaseModel):
    maturity: str = Field(..., description=f"1 trong {MATURITY_LEVELS}")


class ControlRiskGroupUpdate(BaseModel):
    risk_group: str = Field(..., description=f"1 trong {RISK_GROUPS}")


class StandardMappingCreate(BaseModel):
    standard: str = Field(..., max_length=32)
    standard_version: str = Field(..., max_length=128)
    section_id: str = Field(..., max_length=64)
    reference_url: Optional[str] = Field(None, max_length=512)


class StandardMappingOut(StandardMappingCreate):
    id: int
    control_id: str

    class Config:
        from_attributes = True


class RemediationVariantCreate(BaseModel):
    os_family: str = Field(..., max_length=64)
    os_version: Optional[str] = Field(None, max_length=32)
    check_method: str = Field(..., max_length=32)
    remediation_ref: str = Field(..., max_length=255)
    rollback_available: bool = False


class RemediationVariantOut(RemediationVariantCreate):
    id: int
    control_id: str

    class Config:
        from_attributes = True


class ControlDetailOut(ControlOut):
    standard_mappings: list[StandardMappingOut] = []
    remediation_variants: list[RemediationVariantOut] = []


class ControlVersionOut(BaseModel):
    id: int
    control_id: str
    event_type: str
    actor: str
    created_at: datetime
    from_maturity: Optional[str]
    to_maturity: Optional[str]
    detail: Optional[dict]

    class Config:
        from_attributes = True


def _validate_ip_address_value(v: str) -> str:
    # Bắt buộc là IP thật (chặn chuỗi kiểu "a@b -oProxyCommand=..." lọt
    # xuống thẳng lệnh oscap-ssh) và chặn loopback/link-local/multicast/
    # reserved — vd 169.254.169.254 (cloud metadata endpoint), 127.0.0.1
    # — để 1 operator không thể tự đăng ký "host" trỏ vào endpoint nội
    # bộ nhạy cảm rồi trigger scan, khiến cert SSH root thật (mint riêng
    # cho job) bị StrictHostKeyChecking=no gửi thẳng tới đó (phát hiện
    # qua review, không phải test thật — xem README). Tách hàm module-level
    # (không phải method riêng của HostCreate) để HostUpdate tái dùng ĐÚNG
    # cùng 1 rule khi sửa ip_address, không lệch validation giữa tạo/sửa.
    try:
        parsed = ipaddress.ip_address(v)
    except ValueError as exc:
        raise ValueError("ip_address phải là địa chỉ IPv4/IPv6 hợp lệ") from exc
    if (
        parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_unspecified
        or parsed.is_multicast
        or parsed.is_reserved
    ):
        raise ValueError(
            "ip_address không được là loopback/link-local/multicast/reserved "
            "(vd 169.254.169.254, 127.0.0.1)"
        )
    return str(parsed)


class HostCreate(BaseModel):
    hostname: str = Field(..., max_length=255, pattern=_HOSTNAME_PATTERN)
    ip_address: str = Field(..., max_length=64)
    os_family: str = Field(..., max_length=64)
    os_version: Optional[str] = Field(None, max_length=32)
    tier: int = 2
    ssh_user: str = Field("root", max_length=64, description="Phải nằm trong settings.allowed_ssh_users")
    # Lưu THAM KHẢO, mã hoá trước khi ghi DB — CHƯA được job pipeline nào
    # dùng (scan/remediate/restore/ssh-check đều dùng SSH cert), xem
    # app/models.py:Host.ssh_password_encrypted.
    ssh_password: Optional[str] = Field(None, max_length=512)

    @field_validator("ip_address")
    @classmethod
    def _validate_ip_address(cls, v: str) -> str:
        return _validate_ip_address_value(v)


class HostUpdate(BaseModel):
    """Body cho PATCH /hosts/{hostname} — sửa thông tin host đã đăng ký (xem
    app/hosts.py:update_host). Mọi trường đều optional — chỉ field có mặt
    trong request mới bị đổi (partial update, khác HostCreate).

    `tier` CHỈ admin được đổi (không phải operator) — đây là ngưỡng
    four-eyes (Tier 0/1 bắt buộc four-eyes cho CA migration + remediate-
    apply), để operator tự hạ tier host của chính mình sẽ là đường né
    four-eyes tương tự lỗ hổng "sửa nội dung Control sau khi đã production"
    đã tìm thấy và vá trước đây (xem app/controls.py:_demote_if_production).

    Đổi `ip_address` sẽ tự động reset `ca_migration_status` về
    "not_started" (xem update_host) — trust CA đã deploy là cho địa chỉ CŨ,
    giữ nguyên "migrated" cho địa chỉ mới sẽ là thông tin sai.
    """

    ip_address: Optional[str] = Field(None, max_length=64)
    os_family: Optional[str] = Field(None, max_length=64)
    os_version: Optional[str] = Field(None, max_length=32)
    tier: Optional[int] = None
    ssh_user: Optional[str] = Field(None, max_length=64)
    # "" (chuỗi rỗng) xoá password đã lưu, None (không truyền field) giữ
    # nguyên — khác nhau có chủ đích (xem update_host).
    ssh_password: Optional[str] = Field(None, max_length=512)

    @field_validator("ip_address")
    @classmethod
    def _validate_ip_address(cls, v: Optional[str]) -> Optional[str]:
        return v if v is None else _validate_ip_address_value(v)


class HostOut(BaseModel):
    hostname: str
    ip_address: str
    os_family: str
    os_version: Optional[str]
    tier: int
    ssh_user: str
    # KHÔNG BAO GIỜ trả password/ciphertext qua đây — chỉ cờ đã cấu hình hay
    # chưa (xem app/models.py:Host.has_ssh_password). Xem giá trị thật qua
    # GET /hosts/{hostname}/ssh-credential (admin-only, tự ghi audit mỗi lần).
    has_ssh_password: bool
    ca_migration_status: str
    ca_migration_updated_by: Optional[str]
    added_by: str
    created_at: datetime
    updated_at: datetime
    agent_enrolled_at: Optional[datetime]
    agent_last_seen: Optional[datetime]
    agent_renewal_blocked: bool
    active_response_enabled: bool
    decommissioned_at: Optional[datetime]
    decommissioned_by: Optional[str]

    class Config:
        from_attributes = True


class HostSshCredentialOut(BaseModel):
    """Response cho GET /hosts/{hostname}/ssh-credential — admin-only, tự
    ghi 1 audit event MỖI LẦN gọi (xem lộ credential đã lưu là hành động
    nhạy cảm, cần audit từng lần đọc chứ không chỉ từng lần ghi)."""

    hostname: str
    ssh_user: str
    ssh_password: Optional[str]


class HostMigrationStatusUpdate(BaseModel):
    ca_migration_status: str = Field(..., description=f"1 trong {CA_MIGRATION_STATUSES}")


class HostDecommissionUpdate(BaseModel):
    """Body cho PATCH /hosts/{hostname}/decommission — ngừng/khôi phục quản
    lý 1 host (xem app/hosts.py). KHÔNG xoá Host record — job/audit history
    được giữ nguyên, chỉ chặn các hành động mới (scan/remediate/restore/
    ssh-check/enrollment agent) trên host này cho tới khi recommission."""

    decommissioned: bool


class HostAgentRenewalUpdate(BaseModel):
    """Body cho PATCH /hosts/{hostname}/agent-renewal — khoá/mở renew cert
    mTLS định kỳ của Agent trên host này (xem app/hosts.py, app/agents.py)."""

    blocked: bool


class HostActiveResponseUpdate(BaseModel):
    """Body cho PATCH /hosts/{hostname}/active-response — bật/tắt Active
    Response RIÊNG cho host này (xem app/hosts.py, app/models.py:
    Host.active_response_enabled). Vẫn cần kill-switch TOÀN CỤC
    settings.active_response_enabled bật thì host mới thật sự dùng đường
    Agent (app/jobs.py:_dispatch_remediate_job)."""

    enabled: bool


class CaBootstrapRequest(BaseModel):
    """Body cho POST /hosts/{hostname}/bootstrap-ca-trust — dùng credential
    SSH CŨ (password HOẶC private key, không phải cả hai) ĐÚNG 1 LẦN để tự
    động hoá bước 1 Zero-to-CA Migration (ansible/playbooks/
    zero-to-ca-migration.yml), xem app/jobs.py:trigger_ca_bootstrap.

    Credential này KHÔNG được lưu vào DB/log/result_summary ở BẤT KỲ đâu —
    chỉ truyền qua biến môi trường của 1 container execution-env dùng đúng 1
    lần rồi huỷ. Pydantic model này chỉ tồn tại trong bộ nhớ tiến trình lúc
    xử lý request, không có field nào được persist.
    """

    legacy_ssh_user: str = Field(..., max_length=64)
    legacy_ssh_password: Optional[str] = None
    legacy_ssh_private_key: Optional[str] = None


class ScanTrigger(BaseModel):
    # ssh_user KHÔNG còn là tham số request — dùng thẳng Host.ssh_user (mục
    # "sửa host") để chỉ có đúng 1 nguồn sự thật, tránh operator override tuỳ
    # ý per-request giá trị đã được xác lập/audit lúc sửa host.
    scap_profile_key: str = Field(..., description="Khoá trong app.jobs.SCAP_PROFILES")


class JobOut(BaseModel):
    id: int
    hostname: str
    job_type: str
    scap_profile: Optional[str]
    control_id: Optional[str] = None
    remediation_variant_id: Optional[int] = None
    status: str
    result_summary: Optional[dict]
    triggered_by: str
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]

    class Config:
        from_attributes = True


class JobListOut(BaseModel):
    """Dùng riêng cho GET /jobs (list nhiều job) — CỐ Ý bỏ result_summary.

    result_summary của job remediate-apply nhúng base64 cả 1 bản backup cấu
    hình (tới BACKUP_MAX_BYTES = 2 MiB, xem app/jobs.py) — trả trường này cho
    MỖI job trong 1 trang list (tới limit=200) sẽ ép response lên tới hàng
    trăm MB cho 1 request đọc duy nhất, gọi được bởi bất kỳ role nào (kể cả
    viewer). GET /jobs/{job_id} (JobOut đầy đủ) vẫn là nơi duy nhất trả
    result_summary — đúng, vì ở đó luôn đúng 1 job/request nên không có rủi
    ro nhân bản kích thước theo trang.
    """

    id: int
    hostname: str
    job_type: str
    scap_profile: Optional[str]
    control_id: Optional[str] = None
    remediation_variant_id: Optional[int] = None
    status: str
    triggered_by: str
    created_at: datetime
    started_at: Optional[datetime]
    finished_at: Optional[datetime]

    class Config:
        from_attributes = True


class RemediateApplyRequest(BaseModel):
    # Bắt buộc tham chiếu ĐÚNG 1 job dry-run đã succeeded trước đó — không
    # có đường tắt "apply trực tiếp" (nguyên tắc cốt lõi #2 architecture-
    # proposal.md). Xem app/jobs.py:trigger_remediate_apply để biết các
    # điều kiện xác thực (cùng host/control, còn mới, chưa quá hạn).
    dry_run_job_id: int


class RestoreRequest(BaseModel):
    # Tham chiếu ĐÚNG 1 job remediate-apply đã succeeded, có backup chưa bị
    # cắt bớt (backup_tar_b64/backup_truncated trong result_summary) — xem
    # app/jobs.py:run_restore để biết đầy đủ điều kiện xác thực.
    source_job_id: int


class CanaryRolloutHostOutcome(BaseModel):
    hostname: str
    dry_run_job_id: Optional[int]
    apply_job_id: Optional[int]
    status: str


class CanaryRolloutOut(BaseModel):
    id: int
    control_id: str
    status: str
    triggered_by: str
    eligible_host_count: int
    aborted_hostname: Optional[str]
    abort_reason: Optional[str]
    created_at: datetime
    finished_at: Optional[datetime]

    class Config:
        from_attributes = True


class CanaryRolloutDetailOut(CanaryRolloutOut):
    hosts: list[CanaryRolloutHostOutcome] = []


class AgentEnrollmentTokenOut(BaseModel):
    hostname: str
    token: str = Field(..., description="Chỉ trả về đúng 1 lần, không lưu lại được")
    expires_at: datetime


class AgentInstallScriptOut(BaseModel):
    hostname: str
    expires_at: datetime
    script: str = Field(
        ...,
        description=(
            "Script bash chứa bootstrap token dùng-1-lần — chỉ trả về đúng 1 "
            "lần, không lưu lại được. Dán vào phiên SSH của chính operator "
            "tới máy đích, KHÔNG phải Orchestrator tự chạy."
        ),
    )


class AgentVerifyEnrollRequest(BaseModel):
    hostname: str = Field(..., max_length=255)
    token: str = Field(..., max_length=4096)


class AgentVerifyEnrollResponse(BaseModel):
    cert_pem: str
    key_pem: str
    ca_root_pem: str


class AgentHeartbeatRequest(BaseModel):
    hostname: str = Field(..., max_length=255)


class AgentScanResultRequest(BaseModel):
    hostname: str = Field(..., max_length=255)
    scap_profile: str = Field(..., max_length=255)
    result_summary: dict


class AgentFimEventRequest(BaseModel):
    hostname: str = Field(..., max_length=255)
    path: str = Field(..., max_length=512)
    event_type: str = Field(..., max_length=16, description="1 trong created/modified/deleted")
    old_hash: Optional[str] = Field(None, max_length=64)
    new_hash: Optional[str] = Field(None, max_length=64)


# ---- Active Response (Agent thực thi remediation thật — mục 4.3/4.4,
# xem app/jobs.py:_dispatch_remediate_job / app/agents.py) ----


class AgentRemediateClaimRequest(BaseModel):
    hostname: str = Field(..., max_length=255)


class AgentRemediateClaimResponse(BaseModel):
    job_id: int
    control_id: str
    remediation_ref: str
    dry_run: bool


class AgentRemediationBundleRequest(BaseModel):
    hostname: str = Field(..., max_length=255)
    remediation_ref: str = Field(..., max_length=255)


class AgentRemediationBundleResponse(BaseModel):
    remediation_ref: str
    content_tar_gz_b64: str
    signature_asc_b64: str


class AgentRemediateResultRequest(BaseModel):
    hostname: str = Field(..., max_length=255)
    job_id: int
    exit_code: int
    dry_run: bool
    diff_output: Optional[str] = None
    backup_tar_b64: Optional[str] = None
    log_tail: str
    error: Optional[str] = None
