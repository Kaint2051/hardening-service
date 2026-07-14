// Mirror của apps/orchestrator/app/schemas.py — giữ 2 bên khớp thủ công (repo
// không có codegen OpenAPI->TS ở bước khung sườn này).

export const MATURITY_LEVELS = ["draft", "reviewed", "production"] as const;
export type Maturity = (typeof MATURITY_LEVELS)[number];

export const CA_MIGRATION_STATUSES = ["not_started", "trust_deployed", "migrated"] as const;
export type CaMigrationStatus = (typeof CA_MIGRATION_STATUSES)[number];

// "A" = đủ điều kiện canary rollout tự động; "B" (mặc định) = chỉ remediate
// thủ công từng host (xem app/schemas.py RISK_GROUPS / app/models.py Control.risk_group).
export const RISK_GROUPS = ["A", "B"] as const;
export type RiskGroup = (typeof RISK_GROUPS)[number];

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
  os_family: string;
  os_version: string | null;
  tier: number;
  ca_migration_status: CaMigrationStatus;
  ca_migration_updated_by: string | null;
  added_by: string;
  created_at: string;
  updated_at: string;
  agent_enrolled_at: string | null;
  agent_last_seen: string | null;
}

export interface AgentEnrollmentTokenOut {
  hostname: string;
  token: string;
  expires_at: string;
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
  "debian10-standard",
  "debian11-standard",
] as const;

// job_type/status thật sự được gán trong app/jobs.py + app/agents.py — chỉ
// dùng làm option cho dropdown lọc ở JobsPage, KHÔNG phải enum backend enforce
// (GET /jobs nhận bất kỳ chuỗi nào, không khớp gì trả về rỗng chứ không 422).
export const JOB_TYPES = ["scan", "agent-scan", "remediate-dry-run", "remediate-apply", "restore"] as const;
export const JOB_STATUSES = ["pending", "running", "succeeded", "failed"] as const;
