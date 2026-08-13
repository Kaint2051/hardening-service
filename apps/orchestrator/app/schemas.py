import ipaddress
import re
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

MATURITY_LEVELS = ("draft", "reviewed", "production")
CA_MIGRATION_STATUSES = ("not_started", "trust_deployed", "migrated")
# Mức độ tiếp xúc Internet (app/models.py:Host.exposure) — thứ tự rủi ro tăng
# dần, dùng nguyên văn trong app/risk.py:compute_attention_level ("direct"
# luôn coi như internet_facing=True cũ, "proxied" ở giữa, "local" như False cũ).
EXPOSURE_LEVELS = ("local", "proxied", "direct")
# "A" = đủ điều kiện canary rollout tự động; "B" (mặc định) = chỉ remediate
# thủ công từng host (xem app/models.py:Control.risk_group).
RISK_GROUPS = ("A", "B")

# Chọn tay kênh dispatch remediate — None (mặc định, KHÔNG khai field trong
# request) giữ nguyên hành vi tự động cũ (ưu tiên Agent nếu host đủ điều
# kiện, không thì SSH — xem app/jobs.py:_agent_ineligible_reason). "ssh" ép
# luôn dùng đường agentless. "agent" ép dùng Agent Active Response — báo lỗi
# 422 RÕ RÀNG nếu host chưa đủ điều kiện, CỐ Ý không tự rơi về SSH (chọn tay
# "agent" mà lại lặng lẽ chạy SSH sẽ đánh lừa đúng ý định người gọi).
ConnectionMethod = Literal["ssh", "agent"]

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
    # {tên biến: giá trị mặc định} — chỉ khác rỗng nếu Control tạo từ tab
    # "Template" (xem app/control_templates.py). Đường override RIÊNG theo
    # host đã bị gỡ (xem app/models.py:Host.ansible_var_overrides) — giá trị
    # ở đây giờ đặt thẳng trong playbook của template lúc tạo Control.
    overridable_variables: dict[str, str] = {}

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
    # rule_id gốc từ ComplianceAsCode template — CHỈ set khi tạo từ tab
    # "Template" (app/control_templates.py:create_control_from_template).
    # Xem app/models.py:StandardMapping.cis_rule_id, GET /controls/lookup.
    cis_rule_id: Optional[str] = Field(None, max_length=255)


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


# Control Templates (app/control_templates.py) — duyệt + chọn rule từ nội
# dung chuẩn chính thức (ComplianceAsCode) để tạo Control mới, xem docstring
# module đó.
class ControlTemplateOut(BaseModel):
    id: str
    title: str
    rule_count: int


class ControlTemplateRuleOut(BaseModel):
    rule_id: str
    title: str
    severity: Optional[str] = None
    complexity: Optional[str] = None
    disruption: Optional[str] = None
    compliance_refs: list[str] = []
    task_count: int
    # {tên biến: giá trị mặc định trong template} — biến playbook rule này
    # THẬT SỰ tham chiếu (suy ra bằng cách quét {{ tên_biến }} trong task,
    # đối chiếu với vars: của template), không phải toàn bộ vars: dùng chung.
    variables: dict[str, str] = {}


class ControlTemplatePreviewRequest(BaseModel):
    rule_ids: list[str] = Field(..., min_length=1)


class ControlTemplatePreviewResponse(BaseModel):
    playbook_yaml: str


class ControlTemplateCreateRequest(BaseModel):
    title: str = Field(..., max_length=255)
    description: str = ""
    category: str = Field(..., max_length=64)
    rule_ids: list[str] = Field(..., min_length=1)
    # Nội dung playbook cuối cùng operator gửi lên — có thể đã sửa tay so với
    # bản preview ban đầu (xem docstring create_control_from_template).
    # KHÔNG re-assemble lại từ rule_ids phía backend, dùng ĐÚNG chuỗi này.
    playbook_yaml: str


class ControlTemplateCreateResponse(BaseModel):
    control_id: str
    standard_mappings_added: int
    playbook_yaml: str
    overridable_variables: dict[str, str] = {}


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
    # os_family/os_version KHÔNG khai lúc đăng ký nữa — Agent tự báo cáo qua
    # heartbeat (app/agents.py:agent_heartbeat) hoặc điền tay sau qua PATCH
    # /hosts/{hostname} (HostUpdate vẫn còn 2 field này). Host(os_family=None)
    # remediate được ngay khi có giá trị, KHÔNG cần đăng ký lại.
    tier: int = 2
    ssh_user: str = Field("root", max_length=64, description="Phải nằm trong settings.allowed_ssh_users")
    # Mặc định 22 — chỉ khác nếu host đã có cổng SSH riêng TỪ TRƯỚC khi vào
    # hệ thống này (khai lại, không đụng gì host thật). Đổi cổng 1 host ĐANG
    # quản lý an toàn qua POST /hosts/{hostname}/ssh-port-change (app/jobs.py),
    # không phải sửa field này trực tiếp trên host đang chạy.
    ssh_port: int = Field(22, ge=1, le=65535)
    # Lưu THAM KHẢO, mã hoá trước khi ghi DB — CHƯA được job pipeline nào
    # dùng (scan/remediate/restore/ssh-check đều dùng SSH cert), xem
    # app/models.py:Host.ssh_password_encrypted.
    ssh_password: Optional[str] = Field(None, max_length=512)
    # Xem app/models.py:Host.exposure — độc lập với tier. 1 trong
    # EXPOSURE_LEVELS, validate ở app/hosts.py (cùng pattern ca_migration_status).
    exposure: str = Field("local", description=f"1 trong {EXPOSURE_LEVELS}")

    @field_validator("ip_address")
    @classmethod
    def _validate_ip_address(cls, v: str) -> str:
        return _validate_ip_address_value(v)


class HostUpdate(BaseModel):
    """Body cho PATCH /hosts/{hostname} — sửa thông tin host đã đăng ký (xem
    app/hosts.py:update_host). Mọi trường đều optional — chỉ field có mặt
    trong request mới bị đổi (partial update, khác HostCreate).

    `tier` CHỈ admin được đổi (không phải operator) — mức độ quan trọng của
    host (dùng cho thứ tự canary/rollout) không nên tự hạ được bởi chính
    operator vận hành host đó.

    Đổi `ip_address` sẽ tự động reset `ca_migration_status` về
    "not_started" (xem update_host) — trust CA đã deploy là cho địa chỉ CŨ,
    giữ nguyên "migrated" cho địa chỉ mới sẽ là thông tin sai.
    """

    ip_address: Optional[str] = Field(None, max_length=64)
    os_family: Optional[str] = Field(None, max_length=64)
    os_version: Optional[str] = Field(None, max_length=32)
    tier: Optional[int] = None
    ssh_user: Optional[str] = Field(None, max_length=64)
    # Chỉ dùng để KHAI LẠI cổng đã biết (vd host đã cấu hình cổng khác 22 từ
    # trước) — không tự đổi gì trên host thật. Đổi cổng an toàn có xác minh
    # kết nối cho 1 host đang quản lý phải qua
    # POST /hosts/{hostname}/ssh-port-change, không phải field này.
    ssh_port: Optional[int] = Field(None, ge=1, le=65535)
    # "" (chuỗi rỗng) xoá password đã lưu, None (không truyền field) giữ
    # nguyên — khác nhau có chủ đích (xem update_host).
    ssh_password: Optional[str] = Field(None, max_length=512)
    # Xem app/models.py:Host.exposure — None (không truyền field) giữ nguyên.
    # 1 trong EXPOSURE_LEVELS nếu có, validate ở app/hosts.py:update_host.
    exposure: Optional[str] = Field(None, description=f"1 trong {EXPOSURE_LEVELS}")
    # True xoá static_ssh_private_key_encrypted đã lưu (nếu có), False (mặc
    # định) giữ nguyên — sau khi xoá, mọi job SSH cho host này rơi về nhánh
    # cert CA ngắn hạn (xem app/jobs.py:_get_ssh_dispatch_environment), chỉ
    # hoạt động nếu host đã bootstrap-ca-trust từ trước.
    clear_static_ssh_key: bool = False

    @field_validator("ip_address")
    @classmethod
    def _validate_ip_address(cls, v: Optional[str]) -> Optional[str]:
        return v if v is None else _validate_ip_address_value(v)


class HostOut(BaseModel):
    hostname: str
    ip_address: str
    os_family: Optional[str]
    os_version: Optional[str]
    tier: int
    ssh_user: str
    ssh_port: int
    # KHÔNG BAO GIỜ trả password/ciphertext qua đây — chỉ cờ đã cấu hình hay
    # chưa (xem app/models.py:Host.has_ssh_password). Xem giá trị thật qua
    # GET /hosts/{hostname}/ssh-credential (admin-only, tự ghi audit mỗi lần).
    has_ssh_password: bool
    # Cờ đã cấu hình hay chưa (xem app/models.py:Host.has_static_ssh_key) —
    # KHÁC has_ssh_password: cột này KHÔNG có endpoint đọc lại plaintext nào
    # cả (secret sống mãi, không revoke — không nên có đường trả lại).
    has_static_ssh_key: bool
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
    # {tên biến: giá trị override riêng} — CHỈ ĐỌC: endpoint ghi đã bị gỡ,
    # giá trị còn lại là dữ liệu cũ từ trước (xem app/models.py:
    # Host.ansible_var_overrides). Host mới luôn {}.
    ansible_var_overrides: dict[str, str] = {}
    exposure: str
    # OS/kernel/phần cứng tự thu thập lúc "Test SSH" thành công — THAM KHẢO,
    # do chính máy đích tự khai (xem app/models.py:Host.system_info). {} =
    # chưa test SSH thành công lần nào kể từ khi có tính năng này.
    system_info: dict[str, str] = {}
    system_info_updated_at: Optional[datetime] = None
    # Số liệu tài nguyên (CPU/RAM/Disk %, interface mạng chính/% băng thông)
    # do Agent tự đo, báo lên mỗi ~3 phút — CHỈ có với host đã cài Agent
    # (khác system_info ở trên, tới từ SSH nên dùng được cho mọi host). {} =
    # chưa nhận báo cáo nào, xem app/models.py:Host.metrics.
    metrics: dict[str, float | str] = {}
    metrics_updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class HostRiskOverviewItem(BaseModel):
    """1 dòng của GET /hosts/risk-overview (app/hosts.py) — tổng hợp "cần
    chú ý" cho 1 host, xem app/risk.py để biết cách tính `compliance_score`/
    `attention_level`. Không lưu trong DB — tính lại MỖI lần gọi từ job quét
    thành công gần nhất của host đó."""

    hostname: str
    tier: int
    exposure: str
    ca_migration_status: str
    # None = chưa có lần quét thành công nào (KHÔNG phải 100 — xem
    # app/risk.py:compute_compliance_score).
    compliance_score: Optional[float]
    attention_level: str
    latest_scan_job_id: Optional[int]
    latest_scan_at: Optional[datetime]


class HostSshPortChangeRequest(BaseModel):
    """POST /hosts/{hostname}/ssh-port-change — xem app/jobs.py:
    trigger_ssh_port_change. Đổi cổng SSH thật của host với xác minh kết nối
    trước khi coi thành công (không giống HostUpdate.ssh_port chỉ khai lại)."""

    new_port: int = Field(..., ge=1, le=65535)


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


class StaticSshKeyBootstrapRequest(BaseModel):
    """Body cho POST /hosts/{hostname}/bootstrap-static-ssh-key — CÙNG kiểu
    input với CaBootstrapRequest (credential SSH CŨ, đúng 1 lần) nhưng khác
    hành động: tạo 1 SSH keypair MỚI, cài public key lên host, LƯU LẠI
    private key (mã hoá) trên Orchestrator để dùng lại cho MỌI job SSH sau
    này — xem app/jobs.py:trigger_static_ssh_key_bootstrap. Lựa chọn THAY THẾ
    cho bootstrap-ca-trust, không phải bước tiếp theo của nó — chọn ĐÚNG 1
    trong 2 cho mỗi host (ca_migration_status phải đang "not_started").

    Credential CŨ trong request này KHÔNG được lưu — chỉ private key MỚI tự
    sinh mới bị lưu (mã hoá), khác CaBootstrapRequest ở điểm này.
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


class JobProgressOut(BaseModel):
    """GET /jobs/{id}/progress — % tiến độ THẬT, chỉ có ý nghĩa cho
    job_type="ssh-check"/"agent-install" (2 script duy nhất in marker
    ##PROGRESS## ra stdout, xem app/jobs.py). Job terminal luôn trả 100 bất
    kể job_type; job_type khác đang chạy luôn trả 0/"unknown" (không có
    marker nào để đọc) — KHÔNG raise lỗi, đây chỉ là gợi ý UI polled liên
    tục, không phải nguồn trạng thái chính thức (đó vẫn là Job.status)."""

    job_id: int
    status: str
    pct: int
    stage: str


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


class RemediateDryRunRequest(BaseModel):
    """Body (optional — {} hoặc bỏ trống hoàn toàn) cho POST .../remediate/
    dry-run. `connection_method=None` (mặc định) giữ nguyên hành vi tự động
    chọn SSH/Agent theo cấu hình host, xem ConnectionMethod ở trên."""

    connection_method: Optional[ConnectionMethod] = None


class RemediateApplyRequest(BaseModel):
    # Bắt buộc tham chiếu ĐÚNG 1 job dry-run đã succeeded trước đó — không
    # có đường tắt "apply trực tiếp" (nguyên tắc cốt lõi #2 architecture-
    # proposal.md). Xem app/jobs.py:trigger_remediate_apply để biết các
    # điều kiện xác thực (cùng host/control, còn mới, chưa quá hạn).
    dry_run_job_id: int
    connection_method: Optional[ConnectionMethod] = None


class RestoreRequest(BaseModel):
    # Tham chiếu ĐÚNG 1 job remediate-apply đã succeeded, có backup chưa bị
    # cắt bớt (backup_tar_b64/backup_truncated trong result_summary) — xem
    # app/jobs.py:run_restore để biết đầy đủ điều kiện xác thực.
    source_job_id: int
    # None (mặc định) = tự động chọn Agent/SSH theo cấu hình host, giống
    # remediate — xem ConnectionMethod ở trên + app/jobs.py:run_restore.
    connection_method: Optional[ConnectionMethod] = None


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
    # Agent tự đọc /etc/os-release lúc khởi động (apps/agent/main.go:detectOS)
    # rồi gửi lại MỖI heartbeat — None/thiếu field = Agent không nhận diện
    # được (không phải "xoá" giá trị đã biết, khác semantics ssh_password của
    # HostUpdate), orchestrator chỉ cập nhật khi có giá trị THẬT không rỗng
    # (xem app/agents.py:agent_heartbeat).
    os_family: Optional[str] = Field(None, max_length=64)
    os_version: Optional[str] = Field(None, max_length=32)


class AgentMetricsRequest(BaseModel):
    """Số liệu tài nguyên Agent tự đo, báo lên mỗi ~3 phút (khác cadence
    heartbeat) — xem apps/agent/metrics.go, app/agents.py:agent_metrics.
    cpu_pct/ram_pct/disk_pct BẮT BUỘC (Agent chỉ gửi cả lần báo cáo khi đọc
    được cả 3, xem collectMetrics() phía agent); net_iface/net_pct TUỲ CHỌN
    — thiếu tốc độ link (rất phổ biến trên NIC virtio-net của máy ảo) là
    tình huống bình thường, không phải lỗi.
    """

    hostname: str = Field(..., max_length=255)
    cpu_pct: float = Field(..., ge=0, le=100)
    ram_pct: float = Field(..., ge=0, le=100)
    disk_pct: float = Field(..., ge=0, le=100)
    net_iface: Optional[str] = Field(None, max_length=64)
    net_pct: Optional[float] = Field(None, ge=0, le=100)
    # Tín hiệu chủ động "Executor còn sống không" — Agent chỉ connect-rồi-
    # đóng ngay Unix socket, KHÔNG gửi job thật (xem apps/agent/metrics.go:
    # executorReachable). None = Agent bản cũ chưa có field này (không phải
    # "không xác định được" — Agent MỚI luôn gửi True/False, không bao giờ
    # None).
    executor_reachable: Optional[bool] = None
    # OS/kernel/CPU/RAM tổng/ổ đĩa — Agent tự đọc trực tiếp trên máy (KHÔNG
    # cần round-trip SSH nữa, xem apps/agent/metrics.go:collectSystemInfo).
    # Ghi vào ĐÚNG Host.system_info/system_info_updated_at — cùng 2 cột
    # ssh-check.sh đang dùng, chỉ khác nguồn gọi (xem app/agents.py:agent_metrics).
    system_info: Optional[dict[str, str]] = None


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
    """job_kind phân biệt 2 loại job Agent có thể claim qua CÙNG endpoint
    này (xem app/agents.py:claim_remediate_job) — "remediate" (mặc định,
    control_id/remediation_ref/dry_run bắt buộc có ý nghĩa) hoặc "restore"
    (backup_tar_b64 bắt buộc có ý nghĩa, 3 field kia rỗng/False vì restore
    không có RemediationVariant). Cả 3 field remediate-only vẫn giữ non-
    Optional với giá trị rỗng mặc định (không đổi thành Optional=None) để
    KHÔNG phá tương thích ngược field JSON phía Agent cũ (client bản cũ vẫn
    đọc được control_id/remediation_ref là string rỗng thay vì null)."""

    job_id: int
    job_kind: str = "remediate"
    control_id: str = ""
    remediation_ref: str = ""
    dry_run: bool = False
    backup_tar_b64: Optional[str] = None


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


class AgentRestoreResultRequest(BaseModel):
    """Report riêng cho job "restore" qua Agent — TÁCH KHỎI
    AgentRemediateResultRequest vì shape khác hẳn (không có dry_run/
    diff_output/backup_tar_b64 — restore CONSUME 1 backup có sẵn, không tạo
    ra backup mới), xem app/agents.py:report_restore_result."""

    hostname: str = Field(..., max_length=255)
    job_id: int
    exit_code: int
    log_tail: str
    error: Optional[str] = None


class ControlLookupItem(BaseModel):
    """1 mục trong GET /controls/lookup — cầu nối rule_id lúc quét (SCAP) tới
    Control dùng để sửa lỗi đó, xem app/controls.py:lookup_controls_by_rule."""

    rule_id: str
    fixable: bool
    control_id: Optional[str] = None
    control_title: Optional[str] = None


class RemediationSubmitRequest(BaseModel):
    """POST .../remediate/submit-for-approval — xem
    app/remediation_requests.py:submit_remediation_request. Cùng yêu cầu
    dry_run_job_id như RemediateApplyRequest (tham chiếu ĐÚNG 1 job dry-run
    đã succeeded), nhưng KHÔNG áp dụng ngay — chỉ tạo 1 yêu cầu chờ duyệt.

    `connection_method` chọn LÚC GỬI DUYỆT — lưu nguyên vào
    RemediationRequest, dùng lại y hệt lúc approve gọi run_remediate_apply
    (xem approve_remediation_request), KHÔNG cho approver chọn lại lần 2 để
    tránh lệch với nội dung diff đã xem trước lúc dry-run."""

    dry_run_job_id: int
    connection_method: Optional[ConnectionMethod] = None


class RemediationRejectRequest(BaseModel):
    reason: Optional[str] = Field(None, max_length=1024)


class RemediationRequestOut(BaseModel):
    id: int
    hostname: str
    control_id: str
    dry_run_job_id: int
    connection_method: Optional[ConnectionMethod]
    status: str
    requested_by: str
    requested_at: datetime
    decided_by: Optional[str]
    decided_at: Optional[datetime]
    decision_note: Optional[str]
    apply_job_id: Optional[int]

    class Config:
        from_attributes = True


class UserOut(BaseModel):
    """1 user Keycloak thật (app/keycloak_admin.py) — KHÔNG map từ ORM (app
    này không lưu user cục bộ, Keycloak chỉ còn xác thực danh tính). `roles`
    JOIN thêm từ app_roles/user_role_assignments (app/rbac.py, KHÔNG còn đọc
    từ Keycloak) — KHÔNG cần Config.from_attributes, build trực tiếp từ dict."""

    id: str
    username: str
    email: Optional[str] = None
    enabled: bool
    roles: list[str] = []


class UserRolesUpdate(BaseModel):
    roles: list[str] = Field(..., description="Tập vai trò MONG MUỐN sau khi cập nhật — phải là tên vai trò đã tồn tại (GET /roles)")


class UserRolesOut(BaseModel):
    user_id: str
    roles: list[str]


class RoleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    description: Optional[str] = Field(None, max_length=255)


class RolePermissionsUpdate(BaseModel):
    permissions: list[str] = Field(..., description="Tập permission MONG MUỐN sau khi cập nhật (app/permissions.py:ALL_PERMISSIONS)")


class RoleOut(BaseModel):
    name: str
    is_builtin: bool
    description: Optional[str] = None
    permissions: list[str] = []


class PermissionOut(BaseModel):
    permission: str
    description: str
