"""Permission taxonomy — RBAC tuỳ biến (thay cho require_roles(...) rải rác
cũ, xem app/rbac.py + docs/architecture-proposal.md mục 4.7).

Permission là hằng số CỐ ĐỊNH trong code — mỗi permission tương ứng ĐÚNG 1
điểm enforce thật (1 hoặc vài endpoint làm cùng 1 hành vi nghiệp vụ). Admin
KHÔNG tự "phát minh" permission mới qua UI — chỉ được sửa MA TRẬN role→
permission (app/roles.py) và tạo/xoá ROLE mới gán vào các permission đã có
sẵn ở đây. Thêm permission mới = thêm code (1 endpoint mới), không phải việc
admin làm qua UI lúc vận hành.

BUILTIN_ROLE_PERMISSIONS là bản dịch 1-1 từ 49 call site `require_roles(...)`
cũ (rà soát toàn bộ apps/orchestrator/app/*.py trước khi thiết kế lại) — seed
DUY NHẤT cho 6 role gốc, dùng bởi CẢ migration 0026 (Postgres thật) VÀ
`app/rbac.py:seed_builtin_roles` (fixture test SQLite) để 2 nơi không lệch
nhau. Tái hiện ĐÚNG hành vi cũ tại thời điểm cutover — role/permission tuỳ
biến chỉ phát huy tác dụng khi admin sửa ma trận SAU cutover.
"""

# --- hosts.py ---
HOSTS_VIEW = "hosts.view"
HOSTS_MANAGE = "hosts.manage"
HOSTS_VIEW_SSH_CREDENTIAL = "hosts.view_ssh_credential"
HOSTS_DELETE = "hosts.delete"
# Ràng buộc admin-only RIÊNG cho field "tier" trong PATCH /hosts/{hostname}
# (trước đây so tên role "admin" literal ngay trong hosts.py — không phải
# 1 call site require_roles(...) nên KHÔNG có trong bảng rà soát 49 call
# site ban đầu, phát hiện thêm qua grep riêng "user.roles"). Tách khỏi
# HOSTS_MANAGE vì rủi ro khác hẳn (đổi tier ảnh hưởng ngưỡng canary/backup
# bắt buộc, xem docs/architecture-proposal.md mục 4.5-4.6).
HOSTS_MANAGE_TIER = "hosts.manage_tier"

# --- agents.py ---
AGENTS_MANAGE = "agents.manage"

# --- jobs.py ---
JOBS_VIEW = "jobs.view"
JOBS_SCAN = "jobs.scan"
JOBS_REMEDIATE_DRY_RUN = "jobs.remediate_dry_run"
JOBS_REMEDIATE_APPLY = "jobs.remediate_apply"
JOBS_RESTORE = "jobs.restore"
JOBS_SSH_CHECK = "jobs.ssh_check"
JOBS_CA_BOOTSTRAP = "jobs.ca_bootstrap"
JOBS_STATIC_SSH_KEY_BOOTSTRAP = "jobs.static_ssh_key_bootstrap"
JOBS_SSH_PORT_CHANGE = "jobs.ssh_port_change"

# --- remediation_requests.py ---
REMEDIATION_REQUESTS_VIEW = "remediation_requests.view"
REMEDIATION_REQUESTS_SUBMIT = "remediation_requests.submit"
REMEDIATION_REQUESTS_APPROVE = "remediation_requests.approve"

# --- controls.py ---
CONTROLS_VIEW = "controls.view"
CONTROLS_EDIT = "controls.edit"
CONTROLS_PROMOTE = "controls.promote"

# --- canary.py ---
CANARY_VIEW = "canary.view"
CANARY_MANAGE = "canary.manage"

# --- control_templates.py ---
CONTROL_TEMPLATES_VIEW = "control_templates.view"
CONTROL_TEMPLATES_EDIT = "control_templates.edit"

# --- users.py / roles.py / main.py ---
USERS_MANAGE = "users.manage"
RBAC_MANAGE = "rbac.manage"
AUDIT_WRITE = "audit.write"
AUDIT_VERIFY = "audit.verify"

# Toàn bộ permission hợp lệ — dùng để validate input (vd PATCH
# /roles/{name}/permissions) và làm nguồn cho GET /permissions.
ALL_PERMISSIONS = frozenset(
    {
        HOSTS_VIEW,
        HOSTS_MANAGE,
        HOSTS_VIEW_SSH_CREDENTIAL,
        HOSTS_DELETE,
        HOSTS_MANAGE_TIER,
        AGENTS_MANAGE,
        JOBS_VIEW,
        JOBS_SCAN,
        JOBS_REMEDIATE_DRY_RUN,
        JOBS_REMEDIATE_APPLY,
        JOBS_RESTORE,
        JOBS_SSH_CHECK,
        JOBS_CA_BOOTSTRAP,
        JOBS_STATIC_SSH_KEY_BOOTSTRAP,
        JOBS_SSH_PORT_CHANGE,
        REMEDIATION_REQUESTS_VIEW,
        REMEDIATION_REQUESTS_SUBMIT,
        REMEDIATION_REQUESTS_APPROVE,
        CONTROLS_VIEW,
        CONTROLS_EDIT,
        CONTROLS_PROMOTE,
        CANARY_VIEW,
        CANARY_MANAGE,
        CONTROL_TEMPLATES_VIEW,
        CONTROL_TEMPLATES_EDIT,
        USERS_MANAGE,
        RBAC_MANAGE,
        AUDIT_WRITE,
        AUDIT_VERIFY,
    }
)

# Mô tả ngắn cho UI (GET /permissions) — group theo tiền tố resource.
PERMISSION_DESCRIPTIONS: dict[str, str] = {
    HOSTS_VIEW: "Xem danh sách/chi tiết host, risk overview",
    HOSTS_MANAGE: "Đăng ký host mới, sửa metadata, CA migration, agent-renewal, active-response, decommission",
    HOSTS_VIEW_SSH_CREDENTIAL: "Xem mật khẩu SSH đã lưu của host",
    HOSTS_DELETE: "Xoá cứng host (kèm toàn bộ Job/RemediationRequest liên quan)",
    HOSTS_MANAGE_TIER: "Đổi tier (mức độ quan trọng) của host",
    AGENTS_MANAGE: "Tạo enrollment token, script cài Agent, remote-deploy Agent",
    JOBS_VIEW: "Xem danh sách/chi tiết/tiến độ job",
    JOBS_SCAN: "Chạy scan compliance",
    JOBS_REMEDIATE_DRY_RUN: "Chạy remediate ở chế độ xem trước (dry-run)",
    JOBS_REMEDIATE_APPLY: "Áp remediate thật lên host",
    JOBS_RESTORE: "Khôi phục host từ backup của 1 lần remediate-apply trước đó",
    JOBS_SSH_CHECK: "Kiểm tra kết nối SSH tới host",
    JOBS_CA_BOOTSTRAP: "Đưa host vào Zero-to-CA Migration (bước 1)",
    JOBS_STATIC_SSH_KEY_BOOTSTRAP: "Bootstrap static SSH key cho host",
    JOBS_SSH_PORT_CHANGE: "Đổi cổng SSH của host",
    REMEDIATION_REQUESTS_VIEW: "Xem danh sách yêu cầu chờ duyệt",
    REMEDIATION_REQUESTS_SUBMIT: "Gửi yêu cầu remediate để chờ duyệt",
    REMEDIATION_REQUESTS_APPROVE: "Duyệt/từ chối yêu cầu remediate",
    CONTROLS_VIEW: "Xem danh sách/chi tiết/lịch sử Control",
    CONTROLS_EDIT: "Tạo Control, thêm StandardMapping/RemediationVariant",
    CONTROLS_PROMOTE: "Đổi maturity/risk-group của Control",
    CANARY_VIEW: "Xem trạng thái canary rollout",
    CANARY_MANAGE: "Bắt đầu/huỷ canary rollout",
    CONTROL_TEMPLATES_VIEW: "Xem danh sách template/rule chuẩn",
    CONTROL_TEMPLATES_EDIT: "Preview/tạo Control từ template",
    USERS_MANAGE: "Xem danh sách user, gán vai trò cho user",
    RBAC_MANAGE: "Tạo/sửa/xoá vai trò và ma trận quyền",
    AUDIT_WRITE: "Ghi thủ công 1 audit event",
    AUDIT_VERIFY: "Kiểm tra tính nguyên vẹn hash-chain của audit log",
}

# 6 vai trò gốc — tái hiện ĐÚNG hành vi require_roles(...) cũ tại thời điểm
# cutover (không suy diễn lại, lấy trực tiếp từ bảng rà soát 49 call site).
_ALL_6 = frozenset(
    {
        JOBS_VIEW,
        HOSTS_VIEW,
        REMEDIATION_REQUESTS_VIEW,
        CONTROLS_VIEW,
        CANARY_VIEW,
        CONTROL_TEMPLATES_VIEW,
    }
)
_OPERATOR_EXTRA = frozenset(
    {
        HOSTS_MANAGE,
        HOSTS_VIEW_SSH_CREDENTIAL,
        AGENTS_MANAGE,
        JOBS_SCAN,
        JOBS_REMEDIATE_DRY_RUN,
        JOBS_REMEDIATE_APPLY,
        JOBS_RESTORE,
        JOBS_SSH_CHECK,
        JOBS_CA_BOOTSTRAP,
        JOBS_STATIC_SSH_KEY_BOOTSTRAP,
        JOBS_SSH_PORT_CHANGE,
        REMEDIATION_REQUESTS_SUBMIT,
        CANARY_MANAGE,
    }
)
_EDITOR_EXTRA = frozenset({CONTROLS_EDIT, CONTROL_TEMPLATES_EDIT})
_APPROVER_EXTRA = frozenset({REMEDIATION_REQUESTS_APPROVE, CONTROLS_PROMOTE})

BUILTIN_ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": _ALL_6,
    "auditor": _ALL_6 | {AUDIT_VERIFY},
    "rule-editor": _ALL_6 | _EDITOR_EXTRA,
    "approver": _ALL_6 | _APPROVER_EXTRA,
    "operator": _ALL_6 | _OPERATOR_EXTRA,
    "admin": frozenset(ALL_PERMISSIONS),
}

BUILTIN_ROLE_NAMES = tuple(BUILTIN_ROLE_PERMISSIONS.keys())
