import type { ChipProps } from "@mui/material/Chip";
import type {
  AttentionLevel,
  CaMigrationStatus,
  ExposureLevel,
  Maturity,
  RemediationRequestStatus,
} from "../api/types";

// Màu chip trạng thái dùng chung. CỐ TÌNH tách theo từng ngữ nghĩa RIÊNG (job/
// canary vs CA-migration vs maturity vs remediation-request vs pass/fail) thay
// vì 1 map "thần thánh" — các miền giá trị này khác nhau, gộp lại dễ tô nhầm
// màu khi 2 miền tình cờ trùng tên trạng thái.
type ChipColor = ChipProps["color"];

// Vòng đời job (jobs) + canary rollout — miền giá trị không đụng nhau nên gộp
// được. running -> "info" để thống nhất (JobsPage cũ dùng "warning", giờ về
// "info" cho khớp semantics "đang chạy" chứ không phải "cảnh báo").
export function progressColor(status: string): ChipColor {
  if (status === "succeeded" || status === "completed") return "success";
  if (status === "failed" || status === "aborted") return "error";
  if (status === "running") return "info";
  return "default";
}

export const caMigrationColor: Record<CaMigrationStatus, ChipColor> = {
  not_started: "default",
  trust_deployed: "warning",
  migrated: "success",
};

export const maturityColor: Record<Maturity, ChipColor> = {
  draft: "default",
  reviewed: "warning",
  production: "success",
};

export const remediationColor: Record<RemediationRequestStatus, ChipColor> = {
  pending: "warning",
  approved: "success",
  rejected: "default",
  failed: "error",
};

export function passFailColor(result: string): ChipColor {
  return result === "pass" ? "success" : "error";
}

// Ngưỡng % cho gauge tài nguyên (CPU/RAM/Disk/Network) ở HostsPage — cố
// định (<70 success, 70-90 warning, >=90 error), chỉ để "xem nhanh", không
// phải alerting cấu hình được. null/undefined (chưa có dữ liệu) -> "inherit"
// (màu xám trung tính của theme, không tô theo ngưỡng).
export function gaugeColor(pct: number | null | undefined): "success" | "warning" | "error" | "inherit" {
  if (pct == null) return "inherit";
  if (pct >= 90) return "error";
  if (pct >= 70) return "warning";
  return "success";
}

// GET /hosts/risk-overview (app/risk.py) — mức ưu tiên cần chú ý.
export const attentionColor: Record<AttentionLevel, ChipColor> = {
  high: "error",
  medium: "warning",
  low: "success",
};

export const attentionLabel: Record<AttentionLevel, string> = {
  high: "Cần chú ý ngay",
  medium: "Theo dõi",
  low: "Ổn",
};

// Host.exposure (app/models.py) — mức độ tiếp xúc Internet, xem app/risk.py.
export const exposureColor: Record<ExposureLevel, ChipColor> = {
  local: "default",
  proxied: "warning",
  direct: "error",
};

export const exposureLabel: Record<ExposureLevel, string> = {
  local: "Local (nội bộ)",
  proxied: "Internet-facing qua proxy/WAF",
  direct: "Internet-facing trực tiếp",
};
