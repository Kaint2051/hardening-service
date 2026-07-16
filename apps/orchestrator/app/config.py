from typing import Optional

from pydantic import model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Kết nối bằng role app thông thường (CRUD nghiệp vụ ở các giai đoạn sau).
    database_url: str
    # Kết nối bằng role bị giới hạn quyền INSERT/SELECT-only trên audit_log
    # (nguyên tắc "audit log append-only" — xem docs/architecture-proposal.md mục 1.4).
    audit_database_url: str
    # URL Keycloak mà TRÌNH DUYỆT/client dùng để lấy token — phải khớp CHÍNH XÁC
    # với claim "iss" trong token thật (Keycloak set "iss" theo URL công khai
    # dùng để gọi token endpoint, không phải theo config nội bộ).
    keycloak_issuer_url: str
    # URL Keycloak mà Orchestrator (chạy trong container riêng) dùng để tự fetch
    # JWKS — thường là hostname nội bộ trong docker network (vd "http://keycloak:8080/...").
    # "localhost" trong keycloak_issuer_url (dùng cho browser) KHÔNG resolve được
    # tới container Keycloak từ bên trong container Orchestrator — phát hiện qua
    # test thật trên lab server (connection refused). Nếu không set, dùng chung
    # keycloak_issuer_url (trường hợp Keycloak/Orchestrator cùng network namespace).
    keycloak_internal_url: Optional[str] = None
    # Danh sách clientId hợp lệ (trong realm-export.json), phân cách bằng dấu
    # phẩy — dùng để kiểm tra claim "azp" (authorized party) của access token,
    # chặn token phát hành cho client khác bị dùng sai chỗ. Có 2 client hợp lệ:
    # "orchestrator" (confidential, dùng cho service/test qua password grant)
    # và "web" (public, Authorization Code + PKCE cho SPA — xem apps/web/).
    keycloak_client_ids: str = "orchestrator,web"
    secret_key: str
    # Origin của Web UI, dùng để cấu hình CORS cho phép trình duyệt gọi API
    # (SPA và API khác port/origin nên cần CORS, không có middleware này thì
    # mọi fetch() từ apps/web sẽ bị trình duyệt chặn).
    web_origin: str = "http://localhost:3000"

    # --- Job execution (mục 7 roadmap: agentless scan qua OpenSCAP) ---
    # URL nội bộ của job-dispatcher — service DUY NHẤT giữ quyền Docker, xem
    # apps/job-dispatcher/README.md để hiểu vì sao tách riêng khỏi Orchestrator.
    # https (mTLS, Giai đoạn 2 — xem app/jobs.py:_call_job_dispatcher) — vẫn
    # giữ shared secret làm lớp phòng thủ thứ 2, không thay thế.
    job_dispatcher_url: str = "https://job-dispatcher:9100"
    job_dispatcher_shared_secret: str
    # Orchestrator tự cấp SSH cert ngắn hạn cho MỖI job qua step-ca (không tái
    # dùng cert của toán tử người) — xem app/ca_client.py.
    stepca_url: str = "https://step-ca:9000"
    stepca_root_cert_path: str = "/stepca-root/certs/root_ca.crt"
    stepca_provisioner_password: str
    stepca_provisioner_name: str = "orchestrator"
    # Provisioner riêng cho bootstrap token của Agent (mục 4.3), tạo sẵn từ
    # Giai đoạn 0 bởi infra/step-ca/setup-provisioners.sh — dùng chung
    # password với provisioner "orchestrator" ở trên (setup-provisioners.sh
    # dùng lại DOCKER_STEPCA_INIT_PASSWORD lúc tạo provisioner này).
    stepca_agent_provisioner_name: str = "agent-enrollment"
    allowed_execution_image: str = "hardening-console-execution-env:latest"
    # Shared secret cho Agent Manager gọi vào các endpoint /internal/agent/*
    # — cùng pattern JOB_DISPATCHER_SHARED_SECRET (Bearer, so sánh hằng thời
    # gian, xem app/agents.py).
    agent_manager_shared_secret: str
    # Fingerprint GPG tin cậy để execution-env's remediate.sh verify chữ ký
    # bundle trong scripts/content-signing/signed/ trước khi chạy — BẮT BUỘC
    # cấu hình out-of-band (không default), không đọc fingerprint tin cậy từ
    # chính bundle đang verify, cùng nguyên tắc scripts/content-signing/verify.sh.
    content_signing_trusted_fingerprint: str

    # --- Active Response (Agent tự phát triển thực thi remediation thật,
    # xem app/jobs.py:_dispatch_remediate_job) ---
    # Kill-switch TOÀN CỤC, mặc định TẮT — bật (true) chỉ sau khi Executor đã
    # qua pentest riêng (xem apps/agent/executor/README.md). Muốn 1 host cụ
    # thể thật sự dùng đường Agent còn cần ĐỦ CẢ: host.agent_enrolled_at
    # (đã enroll Agent) + Host.active_response_enabled (bật riêng từng host,
    # xem app/hosts.py PATCH .../active-response) + KHÔNG agent_renewal_blocked
    # (host nghi ngờ bị chiếm) — thiếu 1 điều kiện vẫn rơi về SSH agentless.
    active_response_enabled: bool = False
    # Đường dẫn TRONG CONTAINER Orchestrator, đọc TRỰC TIẾP content.tar.gz +
    # .sig đã ký để trả cho Agent qua POST /internal/agent/remediation-bundle
    # — KHÁC CONTENT_SIGNING_SIGNED_HOST_PATH (job-dispatcher dùng path đó
    # trên HOST DOCKER thật cho bind-mount kiểu Docker-outside-of-Docker).
    # Ở đây là mount read-only trực tiếp vào chính container Orchestrator
    # (xem docker-compose.yml, cùng vật lý với CONTENT_SIGNING_SIGNED_HOST_PATH).
    content_signing_signed_dir: str = "/content-signed"
    # Mount read-only 3 file tĩnh từ apps/agent/ (provision.sh + 2 systemd
    # unit) — dùng để sinh script cài Agent gộp sẵn cho operator dán vào
    # phiên SSH của chính họ (xem app/agents.py:_build_agent_install_script).
    # Đọc TRỰC TIẾP từ file thật trong repo (không copy/paste lại nội dung
    # vào code Python) để không bao giờ lệch khỏi bản gốc nếu ai đó sửa
    # provision.sh/unit file sau này.
    agent_assets_dir: str = "/agent-assets"
    # Tên bundle đã ký hiện hành trong scripts/content-signing/signed/, chứa
    # agent+executor binary + provision.sh + 2 systemd unit — dùng bởi
    # POST /hosts/{hostname}/agent-install (app/agents.py) để remote-deploy
    # Agent tự động (không cần operator tự SSH/paste tay, khác
    # _build_agent_install_script cũ). Operator tự cập nhật giá trị này mỗi
    # khi ký 1 bản build agent mới qua đúng quy trình 3 vai trò
    # (scripts/content-signing/README.md). KHÔNG hard-required lúc khởi động
    # (app vẫn chạy được trước khi có bundle đầu tiên) — endpoint tự báo lỗi
    # rõ ràng nếu rỗng, xem trigger_agent_install.
    agent_bundle_ref: str = ""
    # Fingerprint GPG tin cậy RIÊNG cho bundle agent — CỐ Ý tách khỏi
    # content_signing_trusted_fingerprint (dùng cho remediation content) dù
    # cùng cơ chế 3 vai trò/cùng file trusted-signer-pubkey.asc (gpg import
    # được nhiều key cùng lúc từ 1 file). Lý do: agent_bundle_ref có thể được
    # ký bởi 1 authority/lịch ký khác remediation — dùng chung 1 setting sẽ
    # khiến đổi 1 trong 2 bên vô tình làm hỏng verify của bên còn lại (phát
    # hiện lúc chuẩn bị ký bundle agent thật lần đầu: fingerprint đang cấu
    # hình cho remediation, đổi sang key agent sẽ làm mọi bundle remediation
    # đã ký trước đó không còn verify được nữa).
    agent_bundle_trusted_fingerprint: str = ""
    # Địa chỉ Agent Manager mà AGENT THẬT (chạy trên máy đích trong fleet,
    # ngoài docker network này) gọi tới — PHẢI là địa chỉ external (khớp
    # "ports: 8443:8443" của agent-manager trong docker-compose.yml, vd
    # "https://172.30.2.111:8443"), KHÔNG phải "localhost" (mặc định của
    # chính agent binary, chỉ đúng khi Agent Manager chạy CÙNG máy với Agent
    # — xem apps/agent/hardening-agent.service). Thiếu biến này, agent-install
    # (cả tự động và dán tay) vẫn "chạy xong" (script cài đặt không lỗi) nhưng
    # Agent trên host thật KHÔNG BAO GIỜ enroll được — lỗi âm thầm, phát hiện
    # qua audit log thiếu "agent_enrolled" dù "agent_install_completed" đã có
    # (không phải suy đoán — xem app/agents.py:_build_agent_env_file).
    agent_manager_public_url: str = ""
    # Allowlist principal SSH cho scan/ssh-check (mục "sửa host"), phân cách
    # dấu phẩy — quyết định ở CẤP TRIỂN KHAI (.env), không phải operator tự
    # chọn tuỳ ý qua UI: provisioner "orchestrator" trên step-ca không tự
    # giới hạn principal được phép cấp cert, nên đây là lớp chặn DUY NHẤT
    # (xem app/jobs.py ALLOWED_SSH_USERS cũ, giờ chuyển thành setting này).
    # remediate-apply/restore KHÔNG dùng allowlist này — luôn cứng "root".
    allowed_ssh_users: str = "root"
    # Mã hoá Host.ssh_password_encrypted (xem app/hosts.py) — Fernet key
    # (`python3 -c "from cryptography.fernet import Fernet; print(Fernet.
    # generate_key().decode())"`), PHẢI khác secret_key và không dùng chung
    # với bất kỳ secret nào khác — khoá này KHÔNG lưu trong DB (đúng nguyên
    # tắc "khoá giải mã tách khỏi nơi lưu dữ liệu đã mã hoá"), chỉ ở .env.
    # LƯU Ý: đây KHÔNG chặn được kịch bản Orchestrator (ứng dụng) bị chiếm —
    # ứng dụng tự giải mã được thì kẻ tấn công qua ứng dụng cũng vậy; chỉ
    # chặn được kịch bản lộ riêng bản backup DB mà không lộ kèm .env/server.
    host_credential_encryption_key: str = ""

    class Config:
        env_file = ".env"

    @property
    def keycloak_jwks_base_url(self) -> str:
        return self.keycloak_internal_url or self.keycloak_issuer_url

    @property
    def keycloak_client_ids_set(self) -> frozenset[str]:
        return frozenset(c.strip() for c in self.keycloak_client_ids.split(",") if c.strip())

    @property
    def allowed_ssh_users_set(self) -> frozenset[str]:
        return frozenset(u.strip() for u in self.allowed_ssh_users.split(",") if u.strip())

    @model_validator(mode="after")
    def _reject_empty_required_secrets(self) -> "Settings":
        # pydantic chỉ tự chặn env RỖNG cho field bool/int (coerce "" thất
        # bại lúc parse — đúng cơ chế đã bắt ACTIVE_RESPONSE_ENABLED thiếu
        # trong .env thật, xem README.md). Field `str` chấp nhận "" như 1
        # giá trị HỢP LỆ — 1 biến bị thiếu trong .env thật (nhưng docker-
        # compose.yml không có fallback ${VAR:-...}) âm thầm trở thành
        # secret="" thay vì crash rõ ràng như field bool (phát hiện qua rà
        # soát đối kháng, không phải lý thuyết: đã xảy ra thật 1 lần với
        # ACTIVE_RESPONSE_ENABLED). Với secret dùng hmac.compare_digest() để
        # xác thực (job_dispatcher_shared_secret/agent_manager_shared_secret),
        # compare_digest("", "") luôn True — secret rỗng = FAIL-OPEN hoàn
        # toàn cho toàn bộ endpoint /internal/*, /internal/agent/*, và
        # job-dispatcher's /run. Chặn tường minh ngay lúc khởi động, cùng
        # mức độ "fail loudly" như field bool.
        required_nonempty = {
            "secret_key": self.secret_key,
            "job_dispatcher_shared_secret": self.job_dispatcher_shared_secret,
            "stepca_provisioner_password": self.stepca_provisioner_password,
            "agent_manager_shared_secret": self.agent_manager_shared_secret,
            "content_signing_trusted_fingerprint": self.content_signing_trusted_fingerprint,
            "host_credential_encryption_key": self.host_credential_encryption_key,
        }
        empty = [name for name, value in required_nonempty.items() if not value]
        if empty:
            raise ValueError(
                f"biến môi trường RỖNG cho field bắt buộc: {', '.join(empty)} — "
                "kiểm tra lại .env (thiếu dòng này trong .env thật sẽ bị "
                "docker-compose.yml âm thầm thay bằng chuỗi rỗng, KHÔNG phải "
                "unset, vì không có fallback ${VAR:-...})"
            )
        return self


settings = Settings()
