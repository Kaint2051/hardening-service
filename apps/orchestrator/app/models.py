from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from app.db import Base

GENESIS_HASH = "0" * 64


class AuditLog(Base):
    """Append-only, hash-chain audit log (nguyên tắc 4 trong architecture-proposal.md).

    Mỗi bản ghi băm theo (prev_hash + created_at + actor + action + resource +
    payload) — chỉnh sửa hồi tố bất kỳ bản ghi nào sẽ làm sai lệch hash của mọi
    bản ghi phía sau, giúp phát hiện can thiệp dữ liệu.

    Quyền ghi bảng này chỉ cấp cho role Postgres riêng (orchestrator_audit) với
    INSERT + SELECT — không có UPDATE/DELETE (áp bằng GRANT trong migration
    0001, không chỉ dựa vào code tầng application).
    """

    __tablename__ = "audit_log"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    actor = Column(String(255), nullable=False)
    action = Column(String(255), nullable=False)
    resource = Column(String(255), nullable=True)
    payload = Column(JSONB, nullable=False, server_default="{}")
    prev_hash = Column(String(64), nullable=False)
    # unique=True — khớp với UNIQUE constraint thật trong migration 0001
    # (trước đây model thiếu, chỉ migration có -> lệch schema nếu ai đó
    # provision bảng này qua Base.metadata.create_all() thay vì Alembic,
    # giống cách hosts/jobs/controls đã làm trong test — phát hiện qua
    # review, không phải test thật).
    record_hash = Column(String(64), nullable=False, unique=True)


class SystemSettings(Base):
    """Cấu hình chung toàn hệ thống, đổi được NGAY qua tab "Cài đặt" (UI) —
    khác các setting trong app/config.py (đọc từ .env, cố định lúc container
    khởi động, chỉ đổi được bằng sửa .env + restart). CHỈ 1 dòng duy nhất
    (id luôn = 1) — xem app/system_settings.py.

    Hiện chỉ có active_response_enabled: trước đây là kill-switch TĨNH
    settings.active_response_enabled (app/config.py), chuyển hẳn sang đây vì
    việc đổi cờ này qua .env + redeploy từng gây gián đoạn thật giữa lúc vận
    hành (chuyển kênh sang Agent thấy "gateway time-out" do trùng lúc
    container restart) — admin cần bật/tắt ngay không cần SSH vào server.
    """

    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True)
    active_response_enabled = Column(Boolean, nullable=False, server_default=false())


class AppRole(Base):
    """Vai trò do APP biết tới — RBAC tuỳ biến (thay require_roles(...) cứng
    cũ, xem app/rbac.py, app/permissions.py, migration 0026). Keycloak từ nay
    CHỈ xác thực danh tính; vai trò/quyền của user 100% nằm ở 3 bảng này,
    KHÔNG còn đọc từ realm_access.roles trong JWT.

    `name` khớp tuỳ ý (không cần trùng tên gì bên Keycloak nữa — khác thiết
    kế cũ). 6 role builtin (is_builtin=True, seed bởi migration 0026) không
    xoá được (app/roles.py:delete_role) và role "admin" luôn phải giữ
    permission "rbac.manage" (app/rbac.py) — không có Keycloak console nào
    cứu được nếu lỡ tay tự khoá hết đường quản lý RBAC của chính app này.
    """

    __tablename__ = "app_roles"

    name = Column(String(64), primary_key=True)
    is_builtin = Column(Boolean, nullable=False, server_default=false())
    description = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_by = Column(String(255), nullable=True)


class RolePermission(Base):
    """Ma trận role -> permission (app/permissions.py:ALL_PERMISSIONS) — dữ
    liệu ĐỘNG duy nhất admin sửa được qua app/roles.py; permission tự nó luôn
    cố định trong code."""

    __tablename__ = "role_permissions"

    role_name = Column(String(64), ForeignKey("app_roles.name", ondelete="CASCADE"), primary_key=True)
    permission = Column(String(128), primary_key=True)


class UserRoleAssignment(Base):
    """User -> role — nguồn sự thật DUY NHẤT cho "user này có vai trò gì"
    (app/auth.py:get_current_user đọc bảng này, KHÔNG đọc JWT claim nữa).

    `user_id` = Keycloak "sub" (UUID ổn định trong token, KHÔNG đổi khi user
    tự đổi username hiển thị ở Keycloak) — KHÔNG dùng username làm khoá."""

    __tablename__ = "user_role_assignments"

    user_id = Column(String(64), primary_key=True)
    role_name = Column(String(64), ForeignKey("app_roles.name", ondelete="CASCADE"), primary_key=True)
    assigned_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    assigned_by = Column(String(255), nullable=True)


class Control(Base):
    """1 control hardening, độc lập với bất kỳ chuẩn cụ thể nào (mục 3/6:
    "Control Registry mapping đa chuẩn"). Một Control có thể map tới nhiều
    StandardMapping (CIS, STIG, TCVN...) và nhiều RemediationVariant (theo
    distro/version) khác nhau.

    `maturity` theo roadmap Giai đoạn 1 ("Control Registry với maturity
    labelling"): draft -> reviewed -> production. Chuyển từ draft lên phải
    qua role "approver"/"admin" (xem app/controls.py) — không còn ràng buộc
    four-eyes, approver có thể là chính người tạo.
    """

    __tablename__ = "controls"

    id = Column(String(128), primary_key=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False, server_default="")
    category = Column(String(64), nullable=False)
    maturity = Column(String(16), nullable=False, server_default="draft")
    # "A" = đã kiểm định đủ để chạy canary rollout tự động nhiều host (mục 7
    # roadmap); "B" (mặc định) = chỉ cho phép remediate thủ công từng host.
    # Chỉ được gán "A" khi maturity đã "production" (xem app/controls.py
    # PATCH .../risk-group), và tự reset về "B" bất cứ khi nào control rời
    # khỏi "production" (app/controls.py update_control_maturity/
    # _demote_if_production) — risk_group="A" không bao giờ được phép tồn tại
    # cùng maturity != "production".
    risk_group = Column(String(1), nullable=False, server_default="B")
    created_by = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    # {tên biến: giá trị mặc định} — CHỈ set khi Control được tạo từ tab
    # "Template" (app/control_templates.py:create_control_from_template),
    # suy ra từ các biến playbook thật sự tham chiếu trong rule đã chọn (xem
    # _ParsedRule.variables). Control tạo thủ công (POST /controls) luôn rỗng
    # — không có gì để override vì chưa có playbook nào gắn kèm. Dùng để: (1)
    # hiển thị cho operator biết Control này CÓ THỂ override biến gì, (2) lọc
    # Host.ansible_var_overrides xuống đúng phần liên quan Control này lúc
    # remediate (app/jobs.py) — override 1 biến không thuộc Control đang chạy
    # sẽ bị bỏ qua, không âm thầm áp nhầm.
    #
    # JSON (không phải JSONB, cùng lý do Job.result_summary — JSONB
    # Postgres-only làm test SQLite crash) — không cần index/query theo nội
    # dung, chỉ đọc/ghi nguyên khối.
    overridable_variables = Column(JSON, nullable=False, server_default="{}")

    standard_mappings = relationship(
        "StandardMapping", back_populates="control", cascade="all, delete-orphan"
    )
    remediation_variants = relationship(
        "RemediationVariant", back_populates="control", cascade="all, delete-orphan"
    )


class ControlVersion(Base):
    """1 dòng lịch sử thay đổi của 1 Control (hạng mục "versioning lịch sử
    thay đổi Control" trong roadmap). Ghi trong CÙNG transaction/session với
    thay đổi thực tế (bảng `controls`/`standard_mappings`/`remediation_variants`)
    — khác với `audit_log` (dùng session/role Postgres riêng, không atomic
    với thay đổi nghiệp vụ, xem app/audit.py) — nên bảng này không thể lệch
    khỏi trạng thái thật của Control dù audit log có gặp sự cố tạm thời.

    Không thay thế `audit_log` (đó vẫn là nguồn tamper-evident duy nhất) —
    bảng này chỉ phục vụ hiển thị lịch sử MỘT control cụ thể cho người dùng
    (approver/auditor) mà không phải lọc trong audit_log dùng chung toàn hệ
    thống.
    """

    __tablename__ = "control_versions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    control_id = Column(String(128), ForeignKey("controls.id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String(32), nullable=False)
    actor = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    from_maturity = Column(String(16), nullable=True)
    to_maturity = Column(String(16), nullable=True)
    detail = Column(JSON, nullable=True)


class CanaryRollout(Base):
    """1 lần canary rollout tự động (mục 7 roadmap: "canary/rollout theo
    Tier") cho 1 Control risk_group="A" (đã kiểm định, xem app/controls.py) —
    lần lượt dry-run rồi apply NGAY trên từng host Tier 2 có RemediationVariant
    khớp, dừng ngay khi có 1 host lỗi (xem app/canary.py `_run_rollout`).

    `status`: "running" -> "completed" (hết danh sách host, không host nào
    lỗi) hoặc "aborted" (1 host dry-run/apply lỗi, hoặc bị huỷ thủ công qua
    `cancel_requested`, hoặc lỗi nội bộ ngoài dự kiến).

    Partial unique index `ux_canary_rollouts_running` (migration 0009) đảm bảo
    1 control chỉ có tối đa 1 rollout "running" tại 1 thời điểm — enforce ở
    tầng DB, không chỉ dựa vào code kiểm tra trước khi insert (tránh race
    condition 2 request đồng thời).
    """

    __tablename__ = "canary_rollouts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    control_id = Column(String(128), ForeignKey("controls.id"), nullable=False)
    status = Column(String(16), nullable=False, server_default="running")
    triggered_by = Column(String(255), nullable=False)
    eligible_host_count = Column(Integer, nullable=False)
    aborted_hostname = Column(String(255), nullable=True)
    abort_reason = Column(String(32), nullable=True)
    # Cờ huỷ thủ công (PATCH .../cancel) — background task tự kiểm tra cờ
    # này ở đầu MỖI vòng lặp host (app/canary.py `_run_rollout`), KHÔNG hủy
    # ngay lập tức, vì 1 host đang dry-run/apply dở dang không nên bị ngắt
    # giữa chừng.
    # server_default=false() (construct SQL, KHÔNG phải chuỗi Python "false")
    # — bug thật phát hiện qua chạy test thật (không phải chỉ đọc code):
    # server_default="false" (chuỗi trần) compile thành `DEFAULT 'false'`
    # (literal CHUỖI có nháy đơn), Postgres tự cast chuỗi 'false' này sang
    # boolean khi đọc (nên production KHÔNG bị ảnh hưởng), nhưng SQLite (test,
    # Base.metadata.create_all()) lưu nguyên chuỗi "false" rồi trả về y hệt —
    # SQLAlchemy Boolean type coi chuỗi non-empty này là truthy, khiến MỌI
    # CanaryRollout mới tạo có cancel_requested=True ngay từ đầu khi test qua
    # SQLite (mọi rollout tự abort "cancelled" ngay lập tức). false() compile
    # đúng theo dialect (0 cho SQLite, false cho Postgres), round-trip đúng ở
    # cả 2 nơi.
    cancel_requested = Column(Boolean, nullable=False, server_default=false())
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    finished_at = Column(DateTime(timezone=True), nullable=True)


class StandardMapping(Base):
    """Ánh xạ 1 Control sang 1 mục cụ thể trong 1 chuẩn (CIS/STIG/TCVN/CUSTOM)."""

    __tablename__ = "standard_mappings"
    __table_args__ = (
        UniqueConstraint(
            "control_id", "standard", "standard_version", "section_id",
            name="uq_standard_mapping",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    control_id = Column(String(128), ForeignKey("controls.id", ondelete="CASCADE"), nullable=False)
    standard = Column(String(32), nullable=False)
    standard_version = Column(String(128), nullable=False)
    section_id = Column(String(64), nullable=False)
    reference_url = Column(String(512), nullable=True)
    # rule_id GỐC từ ComplianceAsCode template (vd "sshd_disable_root_login",
    # xem app/control_templates.py:_parse_template) — CHỈ set khi mapping này
    # sinh ra từ tab "Template" (create_control_from_template). Cầu nối duy
    # nhất giữa rule_id lúc QUÉT (scan.sh dùng full XCCDF idref dạng
    # "xccdf_org.ssgproject.content_rule_{cis_rule_id}") và Control dùng để
    # SỬA lỗi đó — xem GET /controls/lookup (app/controls.py). NULL cho
    # StandardMapping tạo thủ công (POST .../standard-mappings) vì không gắn
    # với rule_id template nào. index=True vì lookup theo cột này là truy vấn
    # chính của endpoint trên (không cần unique — 1 rule_id có thể xuất hiện
    # ở nhiều StandardMapping nếu curate lại nhiều Control tương tự nhau).
    cis_rule_id = Column(String(255), nullable=True, index=True)

    control = relationship("Control", back_populates="standard_mappings")


class RemediationVariant(Base):
    """Bản remediation cụ thể theo distro/version cho 1 Control.

    `remediation_ref` là con trỏ (vd. tên file/hash nội dung) trỏ tới nội dung
    ĐÃ KÝ trong scripts/content-signing/signed/ — KHÔNG lưu script thực thi
    trực tiếp ở đây (mục 4.2/4.3: Agent Active Response chỉ nhận
    control_id + remediation_ref đã ký, không nhận lệnh tự do).
    """

    __tablename__ = "remediation_variants"
    __table_args__ = (
        UniqueConstraint(
            "control_id", "os_family", "os_version",
            name="uq_remediation_variant",
        ),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    control_id = Column(String(128), ForeignKey("controls.id", ondelete="CASCADE"), nullable=False)
    os_family = Column(String(64), nullable=False)
    os_version = Column(String(32), nullable=True)
    check_method = Column(String(32), nullable=False)
    remediation_ref = Column(String(255), nullable=False)
    rollback_available = Column(Boolean, nullable=False, server_default="false")
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    control = relationship("Control", back_populates="remediation_variants")


class Host(Base):
    """1 máy đích trong fleet (mục 7 roadmap: quy mô ban đầu ≤50 máy).

    `tier` theo phân loại Tier 0/1/2 (mục 7: "Agent tự phát triển... cho nhóm
    Tier 0/1") — dùng để quyết định thứ tự canary/rollout, KHÔNG tự động suy
    ra, phải gán thủ công lúc đăng ký máy.

    `ca_migration_status` theo dõi tiến độ Zero-to-CA Migration
    (ansible/README.md, mục 4.4): "not_started" -> "trust_deployed" (đã chạy
    zero-to-ca-migration.yml, credential cũ CÒN hoạt động) -> "migrated" (đã
    verify cert mới + chạy revoke-old-credential.yml). Trước bảng này, muốn
    biết máy nào đang migrate dở dang phải tự query DB thủ công.

    `ca_migration_updated_by` lưu người thực hiện lần cập nhật ca_migration_status
    gần nhất — chỉ còn phục vụ audit trail (ai đã xác nhận trạng thái nào).
    Trước đây còn dùng để enforce four-eyes khi xác nhận "migrated" cho host
    Tier 0/1 (chặn người vừa đặt "trust_deployed" tự xác nhận nốt) — đã bỏ
    theo yêu cầu người dùng (xem app/hosts.py:update_ca_migration_status).
    Four-eyes cho remediate-apply (app/jobs.py) cũng đã bị bỏ tương tự, không
    còn ràng buộc nào theo tier ở bất kỳ đâu trong hệ thống.
    """

    __tablename__ = "hosts"

    hostname = Column(String(255), primary_key=True)
    ip_address = Column(String(64), nullable=False)
    # KHÔNG bắt buộc điền lúc đăng ký (xem app/schemas.py:HostCreate) — NULL
    # nghĩa là "chưa xác định OS", khác hẳn 1 giá trị sai đoán mò. Agent (nếu
    # có cài) tự báo cáo qua mỗi heartbeat (app/agents.py:agent_heartbeat);
    # host thuần agentless vẫn điền tay qua PATCH /hosts/{hostname}. Bắt buộc
    # phải có giá trị TRƯỚC khi remediate (app/jobs.py:_require_remediation_variant
    # từ chối rõ ràng nếu còn None) — remediate rủi ro cao hơn scan, không cho
    # chọn nhầm variant.
    os_family = Column(String(64), nullable=True)
    os_version = Column(String(32), nullable=True)
    tier = Column(Integer, nullable=False, server_default="2")
    # Principal dùng cho scan/ssh-check qua SSH (mục "sửa host") — PHẢI nằm
    # trong settings.allowed_ssh_users (enforce ở app/hosts.py lúc sửa VÀ lại
    # ở app/jobs.py lúc trigger, phòng trường hợp allowlist bị thắt lại SAU
    # khi host đã có giá trị không còn hợp lệ). remediate-apply/restore
    # KHÔNG dùng cột này — luôn cứng "root" vì Ansible playbook bắt buộc ghi
    # /etc/ssh, /etc/pam.d, /etc/sysctl.d cần quyền root, không có ngoại lệ.
    ssh_user = Column(String(64), nullable=False, server_default="root")
    # Cổng SSH thật của host — mặc định 22 cho mọi host hiện có/mới đăng ký.
    # Sửa qua PATCH /hosts/{hostname} (khai lại, không đụng host thật — vd
    # host vốn đã cấu hình cổng khác 22 từ trước khi vào hệ thống này) HOẶC
    # tự động cập nhật bởi POST /hosts/{hostname}/ssh-port-change (app/jobs.py)
    # — CHỈ SAU KHI job đó xác nhận kết nối thật thành công trên cổng mới,
    # không bao giờ ghi trước khi verify (xem ssh-port-change.sh). Dùng bởi
    # TẤT CẢ 6 script SSH agentless (scan/remediate/restore/ssh-check/
    # ca-bootstrap/agent-install) làm TARGET_PORT.
    ssh_port = Column(Integer, nullable=False, server_default="22")
    # Password SSH lưu THAM KHẢO theo yêu cầu người dùng — mã hoá bằng Fernet
    # (settings.host_credential_encryption_key, xem app/hosts.py), KHÔNG bao
    # giờ lưu plaintext. CHƯA được job pipeline nào dùng tới (scan/ssh-check/
    # remediate/restore đều dùng SSH cert, không dùng password) — quyết định
    # có chủ đích, xem trao đổi trong README.md mục liên quan. NULL nghĩa là
    # chưa cấu hình password cho host này.
    ssh_password_encrypted = Column(Text, nullable=True)
    ca_migration_status = Column(String(32), nullable=False, server_default="not_started")
    ca_migration_updated_by = Column(String(255), nullable=True)
    added_by = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    # Agent tự phát triển (mục 4.3 architecture-proposal.md) — riêng biệt với
    # ca_migration_status ở trên (đó là PKI cho SSH cert của Ephemeral
    # Execution Env, khác hoàn toàn với mTLS cert riêng của Agent). NULL nghĩa
    # là host chưa từng enroll agent.
    agent_enrolled_at = Column(DateTime(timezone=True), nullable=True)
    agent_last_seen = Column(DateTime(timezone=True), nullable=True)
    # Cờ operator/admin bật khi cần tạm khoá renew cert mTLS cho 1 host cụ thể
    # (vd host nghi ngờ bị chiếm, chờ điều tra) — PATCH /hosts/{hostname}/
    # agent-renewal (xem app/hosts.py), enforce trong
    # POST /internal/agent/renew-cert (xem app/agents.py).
    # server_default=false() (construct SQL, KHÔNG phải chuỗi Python "false")
    # — cùng bug thật đã phát hiện qua test cho CanaryRollout.cancel_requested
    # ở trên: chuỗi trần compile thành literal CHUỖI 'false' trong DDL, SQLite
    # lưu/trả nguyên chuỗi đó (không tự cast sang boolean như Postgres) khiến
    # cột luôn truthy ngay từ dòng đầu tiên khi test qua SQLite.
    agent_renewal_blocked = Column(Boolean, nullable=False, server_default=false())
    # Bật/tắt Active Response RIÊNG cho từng host (mục 4.3/4.4 — Agent thực
    # thi remediation thật thay vì chỉ SSH+Ansible agentless), TÁCH BIỆT với
    # kill-switch TOÀN CỤC SystemSettings.active_response_enabled (bảng
    # system_settings ở trên, xem app/system_settings.py): cả 2 điều kiện
    # đều phải đúng thì app/jobs.py:_dispatch_remediate_job
    # mới chọn đường Agent — operator có thể enroll Agent chỉ để scan/FIM
    # trước, chưa cho phép remediate thật trên host đó (mặc định TẮT, an
    # toàn hơn). PATCH /hosts/{hostname}/active-response (xem app/hosts.py).
    # server_default=false() (construct SQL, KHÔNG phải chuỗi Python "false")
    # — cùng bug thật đã phát hiện qua test cho agent_renewal_blocked/
    # cancel_requested ở trên: chuỗi trần compile thành literal CHUỖI 'false'
    # trong DDL, SQLite lưu/trả nguyên chuỗi đó (không tự cast sang boolean
    # như Postgres) khiến cột luôn truthy ngay từ dòng đầu tiên khi test qua
    # SQLite.
    active_response_enabled = Column(Boolean, nullable=False, server_default=false())
    # Ngừng quản lý (mục "Host Registry — decommission"): NULL = đang quản lý
    # (mặc định). Đặt cả 2 cột (KHÔNG chỉ 1 cờ Boolean) để giữ được audit
    # trail lúc nào/ai đã decommission, cùng mẫu ca_migration_updated_by ở
    # trên. Khác DELETE /hosts/{hostname} (hard-delete THẬT, xoá kèm lịch sử
    # job — xem app/hosts.py:delete_host) — decommission GIỮ NGUYÊN record +
    # lịch sử, chỉ đổi trạng thái, dùng cho host còn cần tra cứu lại sau này.
    decommissioned_at = Column(DateTime(timezone=True), nullable=True)
    decommissioned_by = Column(String(255), nullable=True)
    # {tên biến: giá trị} — override RIÊNG cho host này khi remediate 1
    # Control có biến trùng tên trong Control.overridable_variables.
    #
    # KHÔNG CÒN ĐƯỜNG GHI: endpoint PATCH /hosts/{hostname}/variable-overrides
    # + toàn bộ UI đi kèm đã bị GỠ theo yêu cầu người dùng — việc tuỳ chỉnh
    # giá trị biến giờ làm ngay trong template kiểm tra hardening (đặt thẳng
    # vào playbook lúc tạo Control từ tab "Template", xem
    # app/control_templates.py) thay vì override riêng theo từng host. Cột
    # được GIỮ LẠI (không drop) để không mất dữ liệu cũ và để khôi phục tính
    # năng không cần migration nếu sau này đổi ý; app/jobs.py vẫn đọc nó lúc
    # remediate nên giá trị còn sót lại từ trước VẪN có hiệu lực — muốn bỏ
    # hẳn thì phải xoá dữ liệu trong cột này.
    #
    # JSON (không phải JSONB, cùng lý do Control.overridable_variables ở
    # trên) — không cần index/query theo nội dung.
    ansible_var_overrides = Column(JSON, nullable=False, server_default="{}")
    # Mức độ tiếp xúc Internet — ĐỘC LẬP với `tier` (đó là mức độ quan trọng
    # dịch vụ, đây là mức độ lộ ra ngoài). 1 trong app/schemas.py:
    # EXPOSURE_LEVELS = ("local", "proxied", "direct") — "local" chỉ LAN/VPN,
    # "proxied" phục vụ traffic Internet nhưng qua 1 lớp trung gian (reverse
    # proxy/WAF/LB), "direct" expose thẳng IP/cổng ra Internet không lớp chặn
    # nào. app/risk.py:compute_attention_level siết ngưỡng cảnh báo khắt khe
    # hơn theo đúng thứ tự này, kể cả khi Tier thấp. Gán thủ công lúc đăng
    # ký/sửa host, KHÔNG tự suy ra từ ip_address (không có cách nào tự động
    # phân biệt IP nội bộ/công khai/có-proxy đáng tin cậy 100% ở tầng này).
    exposure = Column(String(16), nullable=False, server_default="local")
    # SSH key TĨNH, dùng LẠI cho MỌI job SSH tới host này thay vì mint cert
    # ngắn hạn mỗi lần (xem app/jobs.py:_get_ssh_dispatch_environment) — theo
    # yêu cầu người dùng, đánh đổi bảo mật CÓ CHỦ ĐÍCH (đã giải thích + xác
    # nhận): khác ssh_password_encrypted (chỉ lưu tham khảo, có endpoint trả
    # lại plaintext), cột này KHÔNG có endpoint đọc lại plaintext — 1 khi lưu,
    # chỉ dùng nội bộ để dispatch SSH, không bao giờ trả ra ngoài qua API nào.
    # NULL nghĩa là host này vẫn dùng cert CA ngắn hạn (mặc định, an toàn hơn).
    # Xoá qua PATCH /hosts/{hostname} (HostUpdate.clear_static_ssh_key=true).
    static_ssh_private_key_encrypted = Column(Text, nullable=True)
    # {khoá: giá trị} thông tin OS/kernel/phần cứng máy đích — tự thu thập
    # trong CÙNG phiên SSH của job "ssh-check" (apps/execution-env/ssh-check.sh
    # chạy các lệnh CHỈ ĐỌC uname/os-release/cpuinfo/meminfo/df), rồi ghi vào
    # đây ở app/jobs.py:_dispatch_ssh_check_job. {} = chưa test SSH lần nào
    # thành công kể từ khi có tính năng này.
    #
    # DỮ LIỆU THAM KHẢO, KHÔNG phải nguồn sự thật để ra quyết định bảo mật:
    # nội dung do chính máy đích tự khai, nên 1 host đã bị chiếm hoàn toàn có
    # thể khai sai (báo kernel đã vá trong khi thật ra chưa). Chỉ dùng để hiển
    # thị/tra cứu nhanh — mọi kết luận tuân thủ vẫn phải dựa vào job scan
    # (OpenSCAP, có bằng chứng từng rule). Vì vậy KHÔNG có luật nghiệp vụ nào
    # được đọc cột này. Riêng os_family/os_version (2 cột riêng bên trên, ẢNH
    # HƯỞNG tới việc chọn RemediationVariant) cũng được cập nhật từ cùng nguồn
    # — chấp nhận được vì Agent heartbeat (app/agents.py:agent_heartbeat) vốn
    # đã tin máy đích tự khai OS y hệt như vậy, và mọi remediate vẫn phải qua
    # dry-run + duyệt trước khi áp thật.
    #
    # Giá trị đã bị cắt độ dài 2 lớp trước khi tới đây (script cắt 200 ký tự/
    # giá trị, parser chỉ nhận key trong allowlist _SSH_CHECK_SYSTEM_KEYS) —
    # không tin độ dài/nội dung do máy đích trả về.
    system_info = Column(JSON, nullable=False, server_default="{}")
    # Thời điểm thu thập system_info gần nhất — tách riêng khỏi JSON để UI
    # cảnh báo "dữ liệu cũ" mà không phải parse, xem migration 0024.
    system_info_updated_at = Column(DateTime(timezone=True), nullable=True)

    # Số liệu tài nguyên (CPU/RAM/Disk % + interface mạng chính/% băng
    # thông) — Agent TỰ đo tại chỗ và báo lên mỗi ~3 phút (xem
    # apps/agent/metrics.go, app/agents.py:agent_metrics). CHỈ có với host
    # đã cài Agent, KHÔNG áp dụng cho host thuần SSH agentless — khác
    # system_info ở trên (tới từ job "ssh-check" nên dùng được cho MỌI
    # host). {} = chưa nhận báo cáo nào (mới enroll, hoặc Agent đang dừng/
    # mất kết nối lâu hơn 1 chu kỳ báo cáo).
    metrics = Column(JSON, nullable=False, server_default="{}")
    metrics_updated_at = Column(DateTime(timezone=True), nullable=True)

    @property
    def has_ssh_password(self) -> bool:
        # Property Python thuần (KHÔNG phải Column) — HostOut đọc field này
        # qua from_attributes để báo "đã cấu hình/chưa" mà KHÔNG bao giờ trả
        # ciphertext (nói gì tới plaintext) qua GET /hosts, xem app/schemas.py.
        return self.ssh_password_encrypted is not None

    @property
    def has_static_ssh_key(self) -> bool:
        return self.static_ssh_private_key_encrypted is not None


class AgentEnrollmentToken(Base):
    """1 bootstrap token (OTT) đã cấp cho 1 host để enroll Agent (mục 4.3).

    Chỉ lưu `jti` (token identifier, rút ra từ chính JWT) chứ KHÔNG lưu token
    thô — token thô chỉ tồn tại trong response trả về đúng 1 lần lúc tạo,
    giống hệt cách xử lý client secret Keycloak trong hệ thống này. `used_at`
    là cơ chế thực thi "chỉ dùng 1 lần" ở tầng application — không phụ thuộc
    hoàn toàn vào hành vi nội bộ (chưa verify hết) của từng loại provisioner
    step-ca cho việc chống dùng lại token.
    """

    __tablename__ = "agent_enrollment_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String(255), ForeignKey("hosts.hostname", ondelete="CASCADE"), nullable=False)
    jti = Column(String(255), nullable=False, unique=True)
    issued_by = Column(String(255), nullable=False)
    issued_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True), nullable=True)


class AgentFimEvent(Base):
    """1 lần phát hiện thay đổi file qua so sánh hash định kỳ (FIM MVP theo
    mục 4.3: "so sánh hash định kỳ, nâng lên inotify real-time ở giai đoạn
    sau nếu cần"). Do Reporter trên agent tự phát hiện và báo về, KHÔNG phải
    Orchestrator tự đi kiểm tra (Orchestrator không có quyền truy cập trực
    tiếp vào máy đích ngoài phiên SSH ngắn hạn cho job scan).
    """

    __tablename__ = "agent_fim_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String(255), ForeignKey("hosts.hostname", ondelete="CASCADE"), nullable=False)
    path = Column(String(512), nullable=False)
    event_type = Column(String(16), nullable=False)
    old_hash = Column(String(64), nullable=True)
    new_hash = Column(String(64), nullable=True)
    detected_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())


class Job(Base):
    """1 lần chạy job nhắm vào 1 host (mục 7 roadmap: "agentless qua
    Ansible+OpenSCAP cho 1 benchmark CIS"). Job được thực thi THẬT trong 1
    container Ephemeral Execution Environment RIÊNG cho lần chạy này (qua
    job-dispatcher — xem apps/job-dispatcher/), với 1 SSH cert ngắn hạn cấp
    RIÊNG cho job đó (app/ca_client.py) — không có control node thường trực
    nào giữ cert hay kết quả job giữa các lần chạy.

    `job_type`: "scan" (agentless qua SSH), "agent-scan" (agent tự phát
    triển báo cáo lên), "remediate-dry-run"/"remediate-apply" (agentless
    qua Ansible — xem app/jobs.py `trigger_remediate_dry_run`/
    `trigger_remediate_apply`; content thật vẫn chờ commit hash đã review,
    xem apps/execution-env/README.md, nhưng pipeline đã sẵn sàng).
    """

    __tablename__ = "jobs"

    # Integer (không phải BigInteger) — SQLite chỉ tự autoincrement ROWID cho
    # cột khai báo đúng affinity "INTEGER"; BigInteger làm INSERT để id=NULL
    # trên SQLite (test), phát hiện qua test thật ("NOT NULL constraint
    # failed: jobs.id"). Integer đủ dùng cho bảng jobs (khác audit_log — bảng
    # tăng nhanh hơn nhiều, giữ nguyên BigInteger, chỉ test qua Postgres thật).
    id = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String(255), ForeignKey("hosts.hostname"), nullable=False)
    job_type = Column(String(32), nullable=False)
    scap_profile = Column(String(255), nullable=True)
    # Chỉ set cho job_type remediate-* — tham chiếu Control/RemediationVariant
    # cụ thể đã áp dụng, phục vụ audit trail ("đã remediate control gì, bằng
    # variant nào") và để endpoint apply xác thực đúng dry-run job đi kèm
    # đúng control (xem app/jobs.py).
    control_id = Column(String(128), ForeignKey("controls.id"), nullable=True)
    remediation_variant_id = Column(Integer, ForeignKey("remediation_variants.id"), nullable=True)
    # Chỉ set cho job phát sinh từ 1 canary rollout (app/canary.py) — cho phép
    # GET /canary-rollouts/{id} tái tạo lại outcome từng host (dry-run +
    # apply Job nào thuộc rollout nào) mà không cần bảng join riêng.
    canary_rollout_id = Column(Integer, ForeignKey("canary_rollouts.id"), nullable=True)
    status = Column(String(16), nullable=False, server_default="pending")
    # JSON (không phải JSONB) — chỉ dùng để lưu tóm tắt kết quả job hiển thị
    # lại, không cần index/query theo nội dung, và cần compile được trên cả
    # SQLite (test) lẫn Postgres (thật) — JSONB Postgres-only làm test crash
    # (phát hiện qua test thật: SQLite "can't render element of type JSONB").
    result_summary = Column(JSON, nullable=True)
    triggered_by = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)


class RemediationRequest(Base):
    """Hàng đợi chờ duyệt cho việc áp dụng remediate thật (mục "Kiểm tra &
    Khắc phục" — xem app/remediation_requests.py): operator "Gửi duyệt" sau
    khi xem dry-run, tạo 1 dòng "pending" ở đây, KHÔNG tạo Job apply ngay.
    Chỉ khi 1 approver bấm "Duyệt" (POST .../approve) mới thật sự gọi
    run_remediate_apply. Four-eyes (approver phải khác requested_by) đã bị bỏ
    hoàn toàn theo yêu cầu người dùng — approver/admin có thể tự duyệt/từ
    chối yêu cầu do chính mình gửi.

    status: "pending" (mới gửi) | "approved" (đã duyệt + áp dụng thành công,
    xem apply_job_id) | "rejected" (approver từ chối, xem decision_note) |
    "failed" (approver bấm Duyệt nhưng run_remediate_apply tự nó raise lỗi,
    vd dry-run đã hết hạn — KHÁC "rejected" về ý nghĩa: đây là lỗi hệ thống/
    dữ liệu cũ, không phải approver không đồng ý nội dung, tránh đổ lỗi sai).
    """

    __tablename__ = "remediation_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    hostname = Column(String(255), ForeignKey("hosts.hostname"), nullable=False)
    control_id = Column(String(128), ForeignKey("controls.id"), nullable=False)
    dry_run_job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False)
    # "ssh"/"agent" (chọn tay lúc gửi duyệt) hoặc NULL (tự động chọn theo cấu
    # hình host — xem app/jobs.py:_agent_ineligible_reason). Dùng lại Y HỆT
    # giá trị này lúc approve gọi run_remediate_apply, KHÔNG cho approver
    # chọn lại (xem app/remediation_requests.py).
    connection_method = Column(String(16), nullable=True)
    status = Column(String(16), nullable=False, server_default="pending")
    requested_by = Column(String(255), nullable=False)
    requested_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    decided_by = Column(String(255), nullable=True)
    decided_at = Column(DateTime(timezone=True), nullable=True)
    decision_note = Column(Text, nullable=True)
    # Job "remediate-apply" THẬT — chỉ set khi status="approved" (xem
    # app/remediation_requests.py:approve_remediation_request).
    apply_job_id = Column(Integer, ForeignKey("jobs.id"), nullable=True)
