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


class Control(Base):
    """1 control hardening, độc lập với bất kỳ chuẩn cụ thể nào (mục 3/6:
    "Control Registry mapping đa chuẩn"). Một Control có thể map tới nhiều
    StandardMapping (CIS, STIG, TCVN...) và nhiều RemediationVariant (theo
    distro/version) khác nhau.

    `maturity` theo roadmap Giai đoạn 1 ("Control Registry với maturity
    labelling"): draft -> reviewed -> production. Chuyển từ draft lên phải
    qua role "approver"/"admin" khác người tạo (four-eyes — xem app/controls.py).
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
    gần nhất — dùng để enforce four-eyes (mục 1.3 architecture-proposal.md:
    "four-eyes cho mọi thay đổi trên production/Tier cao") khi xác nhận
    "migrated" (khẳng định credential cũ đã bị thu hồi) cho host Tier 0/1:
    người xác nhận "migrated" không được là người vừa đặt "trust_deployed"
    (xem app/hosts.py) — tránh 1 người tự làm rồi tự xác nhận xong toàn bộ.
    """

    __tablename__ = "hosts"

    hostname = Column(String(255), primary_key=True)
    ip_address = Column(String(64), nullable=False)
    os_family = Column(String(64), nullable=False)
    os_version = Column(String(32), nullable=True)
    tier = Column(Integer, nullable=False, server_default="2")
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
    # kill-switch TOÀN CỤC settings.active_response_enabled (app/config.py):
    # cả 2 điều kiện đều phải đúng thì app/jobs.py:_dispatch_remediate_job
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
