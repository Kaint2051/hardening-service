import keycloak from "../auth/keycloak";
import type {
  AgentEnrollmentTokenOut,
  AgentInstallScriptOut,
  CaMigrationStatus,
  CanaryRolloutDetailOut,
  CanaryRolloutOut,
  ConnectionMethod,
  ControlDetailOut,
  ControlLookupItem,
  ControlOut,
  ControlTemplateCreateResponse,
  ControlTemplateOut,
  ControlTemplateRuleOut,
  ControlVersionOut,
  ExposureLevel,
  HostOut,
  HostRiskOverviewItem,
  HostSshCredentialOut,
  JobListItemOut,
  JobOut,
  JobProgressOut,
  PermissionOut,
  RemediationRequestOut,
  RoleOut,
  UserOut,
} from "./types";

// Mục "thống nhất 1 port" — không còn là địa chỉ tuyệt đối riêng nữa
// (trước đây VITE_API_BASE_URL phải bake sẵn đúng IP:port lúc build). nginx
// (apps/web/nginx.conf) giờ reverse-proxy "/api/*" sang Orchestrator, luôn
// SAME-ORIGIN với chính SPA này bất kể truy cập qua IP/hostname nào.
const BASE_URL = "/api";

export class ApiError extends Error {
  status: number;
  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  // Làm mới token nếu còn dưới 30s là hết hạn — tránh vừa gọi API vừa hết
  // hạn token giữa chừng (keycloak-js tự lo phần refresh_token).
  try {
    await keycloak.updateToken(30);
  } catch {
    keycloak.login();
    throw new ApiError(401, "Phiên đăng nhập đã hết hạn, đang chuyển hướng đăng nhập lại");
  }

  const resp = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${keycloak.token}`,
      ...init?.headers,
    },
  });

  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const body = await resp.json();
      detail = body.detail ?? detail;
    } catch {
      // response không có body JSON (vd 404 do proxy) — giữ statusText
    }
    throw new ApiError(resp.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }

  if (resp.status === 204) {
    return undefined as T;
  }
  return (await resp.json()) as T;
}

export const api = {
  me: () => request<{ username: string; roles: string[] }>("/me"),
  // Cờ phía server UI cần để hiển thị đúng kênh remediate thật — xem
  // app/main.py:runtime_config. Không có nó, cột "Kết nối" sẽ báo "Agent"
  // cho host đã bật Active Response dù kill-switch toàn cục đang tắt.
  getRuntimeConfig: () => request<{ active_response_enabled: boolean }>("/runtime-config"),

  listHosts: (caMigrationStatus?: CaMigrationStatus, includeDecommissioned = false) => {
    const query = new URLSearchParams();
    if (caMigrationStatus) query.set("ca_migration_status", caMigrationStatus);
    if (includeDecommissioned) query.set("include_decommissioned", "true");
    const qs = query.toString();
    return request<HostOut[]>(`/hosts${qs ? `?${qs}` : ""}`);
  },
  // os_family/os_version KHÔNG khai lúc đăng ký nữa (host mới luôn os_family
  // null) — Agent tự báo cáo qua heartbeat, hoặc điền tay sau qua updateHost.
  registerHost: (body: {
    hostname: string;
    ip_address: string;
    tier?: number;
    ssh_user?: string;
    ssh_port?: number;
    ssh_password?: string;
    exposure?: ExposureLevel;
  }) => request<HostOut>("/hosts", { method: "POST", body: JSON.stringify(body) }),
  // Partial update — chỉ field có mặt mới bị đổi. `tier` chỉ admin sửa được
  // (backend 403 nếu không phải admin) — UI không tự ẩn field theo role,
  // cùng quy ước RBAC 100% phía backend đã dùng xuyên suốt app này.
  // ssh_password: "" xoá password đã lưu, undefined (không truyền) giữ nguyên.
  updateHost: (
    hostname: string,
    body: {
      ip_address?: string; os_family?: string; os_version?: string; tier?: number;
      ssh_user?: string; ssh_port?: number; ssh_password?: string; exposure?: ExposureLevel;
      clear_static_ssh_key?: boolean;
    }
  ) =>
    request<HostOut>(`/hosts/${encodeURIComponent(hostname)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  // Tổng hợp "cần chú ý" cho toàn fleet (Tier × điểm compliance có trọng số
  // × exposure × ca_migration_status) — xem app/risk.py. Trả về đã sort theo
  // mức ưu tiên (high trước), mọi role đã đăng nhập gọi được.
  getRiskOverview: () => request<HostRiskOverviewItem[]>("/hosts/risk-overview"),
  // Admin-only phía backend, tự ghi audit mỗi lần gọi — xem app/hosts.py.
  getSshCredential: (hostname: string) =>
    request<HostSshCredentialOut>(`/hosts/${encodeURIComponent(hostname)}/ssh-credential`),
  // Hard-delete THẬT TOÀN BỘ, admin-only — xoá kèm lịch sử job/remediation
  // request, cố gắng gỡ Agent trên máy thật trước (best-effort) — xem
  // app/hosts.py:delete_host. KHÔNG hoàn tác được, dùng updateHostDecommission
  // nếu muốn GIỮ lịch sử.
  deleteHost: (hostname: string) =>
    request<void>(`/hosts/${encodeURIComponent(hostname)}`, { method: "DELETE" }),
  updateHostMigrationStatus: (hostname: string, ca_migration_status: CaMigrationStatus) =>
    request<HostOut>(`/hosts/${encodeURIComponent(hostname)}/ca-migration-status`, {
      method: "PATCH",
      body: JSON.stringify({ ca_migration_status }),
    }),
  // Bật/tắt Active Response RIÊNG cho 1 host = chuyển kênh remediate giữa
  // Agent và SSH agentless (xem app/hosts.py:update_active_response). Vẫn cần
  // kill-switch TOÀN CỤC settings.active_response_enabled bật thì đường Agent
  // mới thật sự chạy — backend là nơi quyết định cuối, trả 422 nếu chưa bật.
  updateHostActiveResponse: (hostname: string, enabled: boolean) =>
    request<HostOut>(`/hosts/${encodeURIComponent(hostname)}/active-response`, {
      method: "PATCH",
      body: JSON.stringify({ enabled }),
    }),
  // Ngừng/khôi phục quản lý host — KHÔNG xoá record (xem app/hosts.py).
  updateHostDecommission: (hostname: string, decommissioned: boolean) =>
    request<HostOut>(`/hosts/${encodeURIComponent(hostname)}/decommission`, {
      method: "PATCH",
      body: JSON.stringify({ decommissioned }),
    }),
  // ssh_user KHÔNG còn là tham số request — dùng thẳng Host.ssh_user phía
  // backend (xem app/schemas.py:ScanTrigger).
  triggerScan: (hostname: string, scap_profile_key: string) =>
    request<JobOut>(`/hosts/${encodeURIComponent(hostname)}/scan`, {
      method: "POST",
      body: JSON.stringify({ scap_profile_key }),
    }),
  // Chỉ khả thi cho host đã trust_deployed/migrated — xem app/jobs.py:trigger_ssh_check.
  testSshReachability: (hostname: string) =>
    request<JobOut>(`/hosts/${encodeURIComponent(hostname)}/ssh-check`, { method: "POST" }),
  // Credential CŨ chỉ dùng ĐÚNG 1 LẦN cho request này, KHÔNG lưu lại ở phía
  // client (component tự xoá state ngay sau khi gọi xong) lẫn server — xem
  // app/jobs.py:trigger_ca_bootstrap. Chỉ khả thi khi host còn "not_started".
  bootstrapCaTrust: (
    hostname: string,
    body: { legacy_ssh_user: string; legacy_ssh_password?: string; legacy_ssh_private_key?: string }
  ) =>
    request<JobOut>(`/hosts/${encodeURIComponent(hostname)}/bootstrap-ca-trust`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  // Lựa chọn THAY THẾ cho bootstrapCaTrust — cùng kiểu input (credential SSH
  // CŨ, đúng 1 lần), nhưng tạo 1 SSH key TĨNH mới, lưu lại trên Orchestrator
  // để dùng cho MỌI job SSH sau này (không mint cert mới mỗi lần) — xem
  // app/jobs.py:trigger_static_ssh_key_bootstrap. Chọn ĐÚNG 1 trong 2 cơ chế
  // cho mỗi host (cùng guard ca_migration_status == "not_started").
  bootstrapStaticSshKey: (
    hostname: string,
    body: { legacy_ssh_user: string; legacy_ssh_password?: string; legacy_ssh_private_key?: string }
  ) =>
    request<JobOut>(`/hosts/${encodeURIComponent(hostname)}/bootstrap-static-ssh-key`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  // Đổi cổng SSH thật, có xác minh kết nối trước khi coi thành công — xem
  // app/jobs.py:trigger_ssh_port_change. KHÔNG có "dry-run" riêng (cơ chế tự
  // xác minh chính là cửa an toàn), xem docstring backend.
  changeSshPort: (hostname: string, newPort: number) =>
    request<JobOut>(`/hosts/${encodeURIComponent(hostname)}/ssh-port-change`, {
      method: "POST",
      body: JSON.stringify({ new_port: newPort }),
    }),
  // Script gộp sẵn (provision.sh + 2 systemd unit + token + ca-root.crt) để
  // operator tự dán vào phiên SSH của chính họ — Orchestrator KHÔNG tự SSH
  // hộ, xem app/agents.py:create_agent_install_script. Giữ làm phương án dự
  // phòng cho host chưa qua CA trust hoặc chưa có bundle nào được ký — xem
  // installAgent bên dưới cho đường tự động.
  createAgentInstallScript: (hostname: string) =>
    request<AgentInstallScriptOut>(
      `/hosts/${encodeURIComponent(hostname)}/agent-install-script`,
      { method: "POST" }
    ),
  // Remote-deploy tự động — Orchestrator tự SSH bằng cert ephemeral + scp
  // bundle agent đã ký, không cần operator tự thực thi gì. Chỉ khả thi cho
  // host đã trust_deployed/migrated VÀ đã có bundle được ký (xem
  // app/agents.py:trigger_agent_install).
  installAgent: (hostname: string) =>
    request<JobOut>(`/hosts/${encodeURIComponent(hostname)}/agent-install`, { method: "POST" }),
  getJob: (jobId: number) => request<JobOut>(`/jobs/${jobId}`),
  // % tiến độ THẬT — chỉ có ý nghĩa cho job_type "ssh-check"/"agent-install"
  // (xem app/jobs.py:get_job_progress). Dùng để poll trong lúc dialog tiến
  // độ đang mở (xem HostsPage.tsx), KHÔNG BAO GIỜ trả lỗi HTTP.
  getJobProgress: (jobId: number) => request<JobProgressOut>(`/jobs/${jobId}/progress`),
  // "1-click restore" (break-glass) — khôi phục từ backup đã chụp lúc 1 job
  // remediate-apply đã succeeded (app/jobs.py:run_restore). KHÔNG cần
  // dry-run/four-eyes riêng, xem docstring backend.
  restoreHost: (hostname: string, sourceJobId: number) =>
    request<JobOut>(`/hosts/${encodeURIComponent(hostname)}/restore`, {
      method: "POST",
      body: JSON.stringify({ source_job_id: sourceJobId }),
    }),
  listJobs: (params: {
    hostname?: string;
    job_type?: string;
    status?: string;
    limit: number;
    offset: number;
  }) => {
    const query = new URLSearchParams();
    if (params.hostname) query.set("hostname", params.hostname);
    if (params.job_type) query.set("job_type", params.job_type);
    if (params.status) query.set("status", params.status);
    query.set("limit", String(params.limit));
    query.set("offset", String(params.offset));
    return request<JobListItemOut[]>(`/jobs?${query.toString()}`);
  },
  // Trả token thô ĐÚNG 1 LẦN (không lưu lại được ở backend) — xem
  // apps/orchestrator/app/agents.py. Operator tự đưa token này lên máy đích
  // out-of-band (ngoài phạm vi UI này).
  createAgentEnrollmentToken: (hostname: string) =>
    request<AgentEnrollmentTokenOut>(
      `/hosts/${encodeURIComponent(hostname)}/agent-enrollment-tokens`,
      { method: "POST" }
    ),

  listControls: () => request<ControlOut[]>("/controls"),
  getControl: (controlId: string) => request<ControlDetailOut>(`/controls/${controlId}`),
  getControlHistory: (controlId: string) =>
    request<ControlVersionOut[]>(`/controls/${controlId}/history`),
  createControl: (body: { title: string; description?: string; category: string }) =>
    request<ControlOut>("/controls", { method: "POST", body: JSON.stringify(body) }),
  updateControlMaturity: (controlId: string, maturity: string) =>
    request<ControlOut>(`/controls/${controlId}/maturity`, {
      method: "PATCH",
      body: JSON.stringify({ maturity }),
    }),
  updateControlRiskGroup: (controlId: string, riskGroup: string) =>
    request<ControlOut>(`/controls/${controlId}/risk-group`, {
      method: "PATCH",
      body: JSON.stringify({ risk_group: riskGroup }),
    }),
  // app/canary.py: router không có prefix riêng, path khai trực tiếp trên
  // route (giống jobs_router sở hữu /hosts/.../remediate/...).
  startCanaryRollout: (controlId: string) =>
    request<CanaryRolloutOut>(`/controls/${controlId}/canary-rollout`, { method: "POST" }),
  getCanaryRollout: (rolloutId: number) =>
    request<CanaryRolloutDetailOut>(`/canary-rollouts/${rolloutId}`),
  cancelCanaryRollout: (rolloutId: number) =>
    request<CanaryRolloutOut>(`/canary-rollouts/${rolloutId}/cancel`, { method: "PATCH" }),
  addStandardMapping: (
    controlId: string,
    body: { standard: string; standard_version: string; section_id: string; reference_url?: string }
  ) =>
    request(`/controls/${controlId}/standard-mappings`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  addRemediationVariant: (
    controlId: string,
    body: {
      os_family: string;
      os_version?: string;
      check_method: string;
      remediation_ref: string;
      rollback_available?: boolean;
    }
  ) =>
    request(`/controls/${controlId}/remediation-variants`, {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // Control Templates (tab "Template") — xem app/control_templates.py.
  listControlTemplates: () => request<ControlTemplateOut[]>("/control-templates"),
  listTemplateRules: (templateId: string, q?: string) => {
    const qs = q ? `?q=${encodeURIComponent(q)}` : "";
    return request<ControlTemplateRuleOut[]>(
      `/control-templates/${encodeURIComponent(templateId)}/rules${qs}`
    );
  },
  previewTemplatePlaybook: (templateId: string, ruleIds: string[]) =>
    request<{ playbook_yaml: string }>(
      `/control-templates/${encodeURIComponent(templateId)}/preview`,
      { method: "POST", body: JSON.stringify({ rule_ids: ruleIds }) }
    ),
  // KHÔNG tự ký/tạo RemediationVariant — chỉ tạo Control (draft) +
  // StandardMapping, trả playbook_yaml để operator tự đưa qua quy trình 3
  // vai trò (scripts/content-signing/), xem app/control_templates.py.
  createControlFromTemplate: (
    templateId: string,
    body: { title: string; category: string; description?: string; rule_ids: string[]; playbook_yaml: string }
  ) =>
    request<ControlTemplateCreateResponse>(
      `/control-templates/${encodeURIComponent(templateId)}/create-control`,
      { method: "POST", body: JSON.stringify(body) }
    ),

  // Trang "Kiểm tra & Khắc phục" — cầu nối rule_id lúc quét sang Control dùng
  // để sửa, xem app/controls.py:lookup_controls_by_rule.
  lookupControlsByRule: (ruleIds: string[], osFamily: string, osVersion?: string) => {
    const query = new URLSearchParams();
    query.set("rule_ids", ruleIds.join(","));
    query.set("os_family", osFamily);
    if (osVersion) query.set("os_version", osVersion);
    return request<ControlLookupItem[]>(`/controls/lookup?${query.toString()}`);
  },
  // Dùng chung với luồng thủ công cũ (canary/four-eyes) — app/jobs.py:trigger_remediate_dry_run.
  // connectionMethod undefined = tự động (mặc định cũ, không đổi hành vi) —
  // xem ConnectionMethod trong api/types.ts.
  triggerRemediateDryRun: (hostname: string, controlId: string, connectionMethod?: ConnectionMethod) =>
    request<JobOut>(`/hosts/${encodeURIComponent(hostname)}/controls/${encodeURIComponent(controlId)}/remediate/dry-run`, {
      method: "POST",
      body: connectionMethod ? JSON.stringify({ connection_method: connectionMethod }) : undefined,
    }),

  // Hàng đợi chờ duyệt remediate-apply — xem app/remediation_requests.py.
  // connectionMethod lưu NGUYÊN vào RemediationRequest, dùng lại y hệt lúc
  // approve (approver không chọn lại) — xem docstring RemediationSubmitRequest.
  submitForApproval: (hostname: string, controlId: string, dryRunJobId: number, connectionMethod?: ConnectionMethod) =>
    request<RemediationRequestOut>(
      `/hosts/${encodeURIComponent(hostname)}/controls/${encodeURIComponent(controlId)}/remediate/submit-for-approval`,
      { method: "POST", body: JSON.stringify({ dry_run_job_id: dryRunJobId, connection_method: connectionMethod ?? null }) }
    ),
  listRemediationRequests: (params: { statusFilter?: string; mineOnly?: boolean } = {}) => {
    const query = new URLSearchParams();
    if (params.statusFilter) query.set("status_filter", params.statusFilter);
    if (params.mineOnly) query.set("mine_only", "true");
    const qs = query.toString();
    return request<RemediationRequestOut[]>(`/remediation-requests${qs ? `?${qs}` : ""}`);
  },
  approveRemediationRequest: (requestId: number) =>
    request<RemediationRequestOut>(`/remediation-requests/${requestId}/approve`, { method: "POST" }),
  rejectRemediationRequest: (requestId: number, reason?: string) =>
    request<RemediationRequestOut>(`/remediation-requests/${requestId}/reject`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),

  // Quản lý người dùng (tab "Cài đặt") — xem app/users.py. Chỉ xem + đổi vai
  // trò, KHÔNG tạo/xoá user/đổi mật khẩu (vẫn qua Keycloak admin console).
  listUsers: () => request<UserOut[]>("/users"),
  updateUserRoles: (userId: string, roles: string[]) =>
    request<{ user_id: string; roles: string[] }>(`/users/${encodeURIComponent(userId)}/roles`, {
      method: "PATCH",
      body: JSON.stringify({ roles }),
    }),

  // RBAC tuỳ biến (tab "Cài đặt") — xem app/roles.py. rbac.manage-only phía
  // backend, trừ getMyPermissions (mở cho mọi user đã đăng nhập).
  listRoles: () => request<RoleOut[]>("/roles"),
  listPermissions: () => request<PermissionOut[]>("/permissions"),
  createRole: (name: string, description?: string) =>
    request<RoleOut>("/roles", { method: "POST", body: JSON.stringify({ name, description }) }),
  updateRolePermissions: (name: string, permissions: string[]) =>
    request<RoleOut>(`/roles/${encodeURIComponent(name)}/permissions`, {
      method: "PATCH",
      body: JSON.stringify({ permissions }),
    }),
  deleteRole: (name: string) => request<void>(`/roles/${encodeURIComponent(name)}`, { method: "DELETE" }),
  getMyPermissions: () => request<{ permissions: string[] }>("/me/permissions"),
};
