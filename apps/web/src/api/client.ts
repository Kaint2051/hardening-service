import keycloak from "../auth/keycloak";
import type {
  AgentEnrollmentTokenOut,
  AgentInstallScriptOut,
  CaMigrationStatus,
  CanaryRolloutDetailOut,
  CanaryRolloutOut,
  ControlDetailOut,
  ControlOut,
  ControlVersionOut,
  HostOut,
  HostSshCredentialOut,
  JobListItemOut,
  JobOut,
} from "./types";

const BASE_URL = import.meta.env.VITE_API_BASE_URL;

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

  listHosts: (caMigrationStatus?: CaMigrationStatus, includeDecommissioned = false) => {
    const query = new URLSearchParams();
    if (caMigrationStatus) query.set("ca_migration_status", caMigrationStatus);
    if (includeDecommissioned) query.set("include_decommissioned", "true");
    const qs = query.toString();
    return request<HostOut[]>(`/hosts${qs ? `?${qs}` : ""}`);
  },
  registerHost: (body: {
    hostname: string;
    ip_address: string;
    os_family: string;
    os_version?: string;
    tier?: number;
    ssh_user?: string;
    ssh_password?: string;
  }) => request<HostOut>("/hosts", { method: "POST", body: JSON.stringify(body) }),
  // Partial update — chỉ field có mặt mới bị đổi. `tier` chỉ admin sửa được
  // (backend 403 nếu không phải admin) — UI không tự ẩn field theo role,
  // cùng quy ước RBAC 100% phía backend đã dùng xuyên suốt app này.
  // ssh_password: "" xoá password đã lưu, undefined (không truyền) giữ nguyên.
  updateHost: (
    hostname: string,
    body: {
      ip_address?: string; os_family?: string; os_version?: string; tier?: number;
      ssh_user?: string; ssh_password?: string;
    }
  ) =>
    request<HostOut>(`/hosts/${encodeURIComponent(hostname)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  // Admin-only phía backend, tự ghi audit mỗi lần gọi — xem app/hosts.py.
  getSshCredential: (hostname: string) =>
    request<HostSshCredentialOut>(`/hosts/${encodeURIComponent(hostname)}/ssh-credential`),
  // Hard-delete, admin-only, CHỈ thành công nếu host chưa từng chạy job nào
  // (409 nếu đã có lịch sử — dùng updateHostDecommission thay vào đó).
  deleteHost: (hostname: string) =>
    request<void>(`/hosts/${encodeURIComponent(hostname)}`, { method: "DELETE" }),
  updateHostMigrationStatus: (hostname: string, ca_migration_status: CaMigrationStatus) =>
    request<HostOut>(`/hosts/${encodeURIComponent(hostname)}/ca-migration-status`, {
      method: "PATCH",
      body: JSON.stringify({ ca_migration_status }),
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
};
