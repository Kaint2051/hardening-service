import keycloak from "../auth/keycloak";
import type {
  AgentEnrollmentTokenOut,
  CaMigrationStatus,
  CanaryRolloutDetailOut,
  CanaryRolloutOut,
  ControlDetailOut,
  ControlOut,
  ControlVersionOut,
  HostOut,
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

  listHosts: (caMigrationStatus?: CaMigrationStatus) =>
    request<HostOut[]>(
      `/hosts${caMigrationStatus ? `?ca_migration_status=${caMigrationStatus}` : ""}`
    ),
  registerHost: (body: {
    hostname: string;
    ip_address: string;
    os_family: string;
    os_version?: string;
    tier?: number;
  }) => request<HostOut>("/hosts", { method: "POST", body: JSON.stringify(body) }),
  updateHostMigrationStatus: (hostname: string, ca_migration_status: CaMigrationStatus) =>
    request<HostOut>(`/hosts/${encodeURIComponent(hostname)}/ca-migration-status`, {
      method: "PATCH",
      body: JSON.stringify({ ca_migration_status }),
    }),
  triggerScan: (hostname: string, scap_profile_key: string, ssh_user: string) =>
    request<JobOut>(`/hosts/${encodeURIComponent(hostname)}/scan`, {
      method: "POST",
      body: JSON.stringify({ scap_profile_key, ssh_user }),
    }),
  getJob: (jobId: number) => request<JobOut>(`/jobs/${jobId}`),
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
