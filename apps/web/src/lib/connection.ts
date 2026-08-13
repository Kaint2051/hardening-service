import type { HostOut } from "../api/types";

// Kênh Orchestrator dùng để tác động lên host khi remediate — port ĐÚNG 4
// điều kiện trong app/jobs.py:_agent_ineligible_reason, KHÔNG tự nghĩ ra quy
// tắc riêng. Điều kiện thứ 4 (kill-switch TOÀN CỤC
// settings.active_response_enabled) không nằm trên Host mà ở phía server, nên
// phải truyền vào từ GET /runtime-config (app/main.py) — thiếu nó UI sẽ báo
// "Agent" cho host đã bật Active Response trong khi mọi remediate thực tế vẫn
// đi đường SSH.
export type ConnectionChannel = "ssh" | "agent";

/**
 * null = host đủ điều kiện dùng đường Agent; ngược lại là lý do KHÔNG đủ.
 * `globalActiveResponse` lấy từ api.getRuntimeConfig(); truyền `undefined`
 * khi chưa tải xong -> bỏ qua điều kiện toàn cục thay vì đoán bừa (tránh
 * nhấp nháy nhãn sai trong lúc chờ request đầu tiên).
 */
export function agentIneligibleReason(
  host: HostOut | null,
  globalActiveResponse?: boolean
): string | null {
  if (!host) return null;
  if (globalActiveResponse === false) return "Active Response đang tắt toàn cục trên server";
  if (!host.agent_enrolled_at) return "host chưa cài Agent";
  if (!host.active_response_enabled) return "Active Response chưa được bật cho host này";
  if (host.agent_renewal_blocked) return "Agent đang bị khoá renew cert";
  // executor_reachable (app/agents.py:agent_metrics, báo mỗi ~3 phút) — tín
  // hiệu THAM KHẢO, có thể trễ tới 1 chu kỳ báo cáo, KHÔNG dùng để chặn ở
  // backend (_agent_ineligible_reason không kiểm tra field này, xem
  // app/jobs.py) vì lỡ trễ sẽ từ chối nhầm ngay sau khi Executor đã hồi
  // phục. Ở đây thì NÊN chặn trước trên UI — thà báo trước "đang lỗi" còn
  // hơn để người dùng chọn "Agent" rồi đợi job fail.
  if (host.metrics.executor_reachable === false) return "Executor không phản hồi trên host này";
  return null;
}

/** Kênh host này ĐANG dùng để remediate. */
export function connectionChannel(
  host: HostOut,
  globalActiveResponse?: boolean
): ConnectionChannel {
  return agentIneligibleReason(host, globalActiveResponse) === null ? "agent" : "ssh";
}

export const CONNECTION_CHANNEL_LABELS: Record<ConnectionChannel, string> = {
  ssh: "SSH (agentless)",
  agent: "Agent",
};

// Đã cài Agent nhưng chưa bật Active Response -> vẫn đi đường SSH cho
// remediate, NHƯNG Agent vẫn đang chạy để scan/FIM. Phân biệt 2 trạng thái
// này trên UI vì "có Agent" và "dùng Agent để sửa lỗi" là 2 việc khác nhau —
// mặc định enroll Agent chỉ để giám sát, xem
// app/models.py:Host.active_response_enabled.
export function hasAgentInstalled(host: HostOut): boolean {
  return host.agent_enrolled_at !== null;
}
