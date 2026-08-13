// Mirror của apps/orchestrator/app/schemas.py — giữ 2 bên khớp thủ công (repo
// không có codegen OpenAPI->TS ở bước khung sườn này).

export const MATURITY_LEVELS = ["draft", "reviewed", "production"] as const;
export type Maturity = (typeof MATURITY_LEVELS)[number];

export const CA_MIGRATION_STATUSES = ["not_started", "trust_deployed", "migrated"] as const;
export type CaMigrationStatus = (typeof CA_MIGRATION_STATUSES)[number];

// Mức độ tiếp xúc Internet (app/models.py:Host.exposure) — thứ tự rủi ro
// tăng dần, xem app/risk.py:compute_attention_level.
export const EXPOSURE_LEVELS = ["local", "proxied", "direct"] as const;
export type ExposureLevel = (typeof EXPOSURE_LEVELS)[number];

// "A" = đủ điều kiện canary rollout tự động; "B" (mặc định) = chỉ remediate
// thủ công từng host (xem app/schemas.py RISK_GROUPS / app/models.py Control.risk_group).
export const RISK_GROUPS = ["A", "B"] as const;
export type RiskGroup = (typeof RISK_GROUPS)[number];

// Chọn tay kênh dispatch remediate — xem app/schemas.py:ConnectionMethod.
// undefined/null = tự động (ưu tiên Agent nếu host đủ điều kiện, không thì
// SSH); "agent" báo lỗi rõ ràng (KHÔNG tự rơi về SSH) nếu host chưa đủ điều
// kiện, xem app/jobs.py:_agent_ineligible_reason.
export const CONNECTION_METHODS = ["ssh", "agent"] as const;
export type ConnectionMethod = (typeof CONNECTION_METHODS)[number];

// RBAC tuỳ biến (app/permissions.py, app/rbac.py, app/roles.py) — vai trò
// KHÔNG còn cố định 6 cái, admin tự tạo vai trò mới + tự chọn quyền qua tab
// Cài đặt, nên KHÔNG có union type cố định như trước (RealmRole cũ) — chỉ
// còn `string`, danh sách THẬT lấy từ GET /roles lúc runtime.
export interface PermissionOut {
  permission: string;
  description: string;
}

export interface RoleOut {
  name: string;
  is_builtin: boolean;
  description: string | null;
  permissions: string[];
}

export interface ControlOut {
  id: string;
  title: string;
  description: string;
  category: string;
  maturity: Maturity;
  risk_group: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  // {tên biến: giá trị mặc định} — chỉ khác rỗng nếu Control tạo từ tab
  // "Template". Đường override riêng theo host đã bị gỡ; giá trị giờ đặt
  // thẳng trong playbook của template lúc tạo Control.
  overridable_variables: Record<string, string>;
}

export interface StandardMappingOut {
  id: number;
  control_id: string;
  standard: string;
  standard_version: string;
  section_id: string;
  reference_url: string | null;
}

export interface RemediationVariantOut {
  id: number;
  control_id: string;
  os_family: string;
  os_version: string | null;
  check_method: string;
  remediation_ref: string;
  rollback_available: boolean;
}

export interface ControlDetailOut extends ControlOut {
  standard_mappings: StandardMappingOut[];
  remediation_variants: RemediationVariantOut[];
}

// Control Templates (tab "Template") — duyệt + chọn rule từ nội dung chuẩn
// chính thức (ComplianceAsCode/CIS) để tạo Control mới, xem
// app/control_templates.py.
export interface ControlTemplateOut {
  id: string;
  title: string;
  rule_count: number;
}

export interface ControlTemplateRuleOut {
  rule_id: string;
  title: string;
  severity: string | null;
  complexity: string | null;
  disruption: string | null;
  compliance_refs: string[];
  task_count: number;
  // {tên biến: giá trị mặc định trong template} — biến playbook rule này
  // THẬT SỰ tham chiếu, xem app/control_templates.py.
  variables: Record<string, string>;
}

export interface ControlTemplateCreateResponse {
  control_id: string;
  standard_mappings_added: number;
  playbook_yaml: string;
  overridable_variables: Record<string, string>;
}

// Cầu nối rule_id lúc quét <-> Control dùng để sửa, xem GET /controls/lookup
// (app/controls.py). Dùng bởi trang "Kiểm tra & Khắc phục".
export interface ControlLookupItem {
  rule_id: string;
  fixable: boolean;
  control_id: string | null;
  control_title: string | null;
}

// Hàng đợi chờ duyệt remediate-apply thật, xem app/models.py:RemediationRequest,
// app/remediation_requests.py.
export const REMEDIATION_REQUEST_STATUSES = ["pending", "approved", "rejected", "failed"] as const;
export type RemediationRequestStatus = (typeof REMEDIATION_REQUEST_STATUSES)[number];

export interface RemediationRequestOut {
  id: number;
  hostname: string;
  control_id: string;
  dry_run_job_id: number;
  connection_method: ConnectionMethod | null;
  status: RemediationRequestStatus;
  requested_by: string;
  requested_at: string;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  apply_job_id: number | null;
}

export interface ControlVersionOut {
  id: number;
  control_id: string;
  event_type: string;
  actor: string;
  created_at: string;
  from_maturity: Maturity | null;
  to_maturity: Maturity | null;
  detail: Record<string, unknown> | null;
}

export interface HostOut {
  hostname: string;
  ip_address: string;
  // Không còn khai lúc đăng ký (xem client.ts registerHost) — null nghĩa là
  // "chưa xác định OS", điền qua Agent heartbeat hoặc PATCH /hosts/{hostname}.
  os_family: string | null;
  os_version: string | null;
  tier: number;
  ssh_user: string;
  ssh_port: number;
  has_ssh_password: boolean;
  // KHÁC has_ssh_password: cột này KHÔNG có endpoint đọc lại plaintext nào
  // cả (secret sống mãi, không revoke) — xem app/models.py:Host.has_static_
  // ssh_key. Chỉ xoá được (clear_static_ssh_key), không xem lại được.
  has_static_ssh_key: boolean;
  ca_migration_status: CaMigrationStatus;
  ca_migration_updated_by: string | null;
  added_by: string;
  created_at: string;
  updated_at: string;
  agent_enrolled_at: string | null;
  agent_last_seen: string | null;
  // Cùng 2 điều kiện eligibility kênh Agent phía backend (xem
  // app/jobs.py:_agent_ineligible_reason, thiếu kill-switch toàn cục
  // settings.active_response_enabled — không có API đọc setting đó, backend
  // luôn là nguồn sự thật cuối cho điều kiện này qua lỗi 422) — dùng để
  // disable option "Agent" trên UI trước khi submit, không phải validate đầy đủ.
  active_response_enabled: boolean;
  agent_renewal_blocked: boolean;
  decommissioned_at: string | null;
  decommissioned_by: string | null;
  // {tên biến: giá trị override riêng} — CHỈ ĐỌC: endpoint ghi + UI đã bị gỡ,
  // giá trị còn lại là dữ liệu cũ từ trước. Host mới luôn {}.
  ansible_var_overrides: Record<string, string>;
  // Độc lập với `tier` (đó là mức độ quan trọng dịch vụ, đây là mức độ lộ
  // ra ngoài) — xem GET /hosts/risk-overview.
  exposure: ExposureLevel;
  // OS/kernel/phần cứng tự thu thập khi "Test SSH" chạy thành công (xem
  // app/models.py:Host.system_info). Khoá có thể có: os_id, os_version_id,
  // os_pretty, kernel, arch, cpu_model, cpu_cores, mem_total_kb, disk_root,
  // virt, uptime_sec — đều TUỲ CHỌN (máy thiếu lệnh/file tương ứng thì khoá
  // đó vắng mặt). Là dữ liệu THAM KHẢO do máy đích tự khai, không dùng để
  // kết luận tuân thủ.
  system_info: Record<string, string>;
  system_info_updated_at: string | null;
  // Số liệu tài nguyên (cpu_pct/ram_pct/disk_pct/net_iface/net_pct) do Agent
  // TỰ đo, báo lên mỗi ~3 phút (xem app/models.py:Host.metrics) — CHỈ có
  // với host đã cài Agent, KHÁC system_info ở trên (tới từ SSH, dùng được
  // cho mọi host). {} = chưa nhận báo cáo nào. net_iface là string,
  // executor_reachable là boolean, các khoá còn lại là number.
  metrics: Record<string, number | string | boolean>;
  metrics_updated_at: string | null;
}

// GET /hosts/risk-overview — xem app/risk.py để biết cách tính
// compliance_score/attention_level (KHÔNG lưu trong DB, tính lại mỗi lần gọi).
export const ATTENTION_LEVELS = ["high", "medium", "low"] as const;
export type AttentionLevel = (typeof ATTENTION_LEVELS)[number];

export interface HostRiskOverviewItem {
  hostname: string;
  tier: number;
  exposure: ExposureLevel;
  ca_migration_status: CaMigrationStatus;
  // null = chưa có lần quét thành công nào (KHÔNG phải điểm 100).
  compliance_score: number | null;
  attention_level: AttentionLevel;
  latest_scan_job_id: number | null;
  latest_scan_at: string | null;
}

export interface AgentEnrollmentTokenOut {
  hostname: string;
  token: string;
  expires_at: string;
}

export interface AgentInstallScriptOut {
  hostname: string;
  expires_at: string;
  script: string;
}

export interface HostSshCredentialOut {
  hostname: string;
  ssh_user: string;
  ssh_password: string | null;
}

// Khớp app/schemas.py:JobListOut — GET /jobs (list) CỐ Ý không có
// result_summary (có thể chứa backup base64 tới 2 MiB/job cho remediate-
// apply; trả trong 1 trang tới 200 job sẽ ép response lên hàng trăm MB).
// Muốn xem result_summary phải gọi riêng api.getJob(id) (GET /jobs/{id}),
// xem JobsPage.tsx.
export interface JobListItemOut {
  id: number;
  hostname: string;
  job_type: string;
  scap_profile: string | null;
  control_id?: string;
  remediation_variant_id?: number;
  status: string;
  triggered_by: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface JobOut extends JobListItemOut {
  result_summary: Record<string, unknown> | null;
}

// GET /jobs/{id}/progress — % tiến độ THẬT, chỉ có ý nghĩa cho
// job_type "ssh-check"/"agent-install" (xem app/jobs.py:JobProgressOut).
// Job terminal luôn pct=100; job_type khác hoặc lỗi tạm thời khi gọi
// job-dispatcher luôn pct=0/stage="unknown" — KHÔNG BAO GIỜ là lỗi HTTP.
export interface JobProgressOut {
  job_id: number;
  status: string;
  pct: number;
  stage: string;
}

export interface Finding {
  rule_id: string;
  title: string;
  result: "pass" | "fail";
  severity: string;
}

// Khớp app/schemas.py CanaryRollout* (mục 7 roadmap — canary rollout tự động
// cho control risk_group "A" + maturity "production").
export interface CanaryRolloutHostOutcome {
  hostname: string;
  dry_run_job_id: number | null;
  apply_job_id: number | null;
  status: string;
}

export interface CanaryRolloutOut {
  id: number;
  control_id: string;
  status: string;
  triggered_by: string;
  eligible_host_count: number;
  aborted_hostname: string | null;
  abort_reason: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface CanaryRolloutDetailOut extends CanaryRolloutOut {
  hosts: CanaryRolloutHostOutcome[];
}

// Khớp app/jobs.py SCAP_PROFILES — chưa có endpoint để tự khám phá danh sách
// này nên khai cứng ở đây, cập nhật cùng lúc nếu backend thêm profile mới.
export const SCAP_PROFILE_KEYS = [
  "ubuntu2204-standard",
  "ubuntu2204-cis-level1-server",
  "ubuntu2204-stig",
  "ubuntu2404-cis-level1-server",
  "debian10-standard",
  "debian11-standard",
] as const;

// job_type/status thật sự được gán trong app/jobs.py + app/agents.py — chỉ
// dùng làm option cho dropdown lọc ở JobsPage, KHÔNG phải enum backend enforce
// (GET /jobs nhận bất kỳ chuỗi nào, không khớp gì trả về rỗng chứ không 422).
export const JOB_TYPES = [
  "scan", "agent-scan", "remediate-dry-run", "remediate-apply", "restore", "ssh-check", "ca-bootstrap",
  "agent-install", "ssh-port-change",
] as const;
export const JOB_STATUSES = ["pending", "running", "succeeded", "failed"] as const;

// User Keycloak thật (app/keycloak_admin.py qua app/users.py) — Keycloak chỉ
// còn xác thực danh tính, `roles` JOIN từ user_role_assignments (DB app).
export interface UserOut {
  id: string;
  username: string;
  email: string | null;
  enabled: boolean;
  roles: string[];
}
