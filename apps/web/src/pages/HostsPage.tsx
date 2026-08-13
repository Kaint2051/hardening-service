import { useEffect, useState } from "react";
import Table from "@mui/material/Table";
import TableHead from "@mui/material/TableHead";
import TableBody from "@mui/material/TableBody";
import TableRow from "@mui/material/TableRow";
import TableCell from "@mui/material/TableCell";
import Paper from "@mui/material/Paper";
import TableContainer from "@mui/material/TableContainer";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";
import Button from "@mui/material/Button";
import Chip from "@mui/material/Chip";
import Select from "@mui/material/Select";
import MenuItem from "@mui/material/MenuItem";
import Menu from "@mui/material/Menu";
import ListSubheader from "@mui/material/ListSubheader";
import Divider from "@mui/material/Divider";
import IconButton from "@mui/material/IconButton";
import FormControl from "@mui/material/FormControl";
import InputLabel from "@mui/material/InputLabel";
import Dialog from "@mui/material/Dialog";
import DialogTitle from "@mui/material/DialogTitle";
import DialogContent from "@mui/material/DialogContent";
import DialogActions from "@mui/material/DialogActions";
import TextField from "@mui/material/TextField";
import Alert from "@mui/material/Alert";
import CircularProgress from "@mui/material/CircularProgress";
import LinearProgress from "@mui/material/LinearProgress";
import Tooltip from "@mui/material/Tooltip";
import Link from "@mui/material/Link";
import Box from "@mui/material/Box";
import Checkbox from "@mui/material/Checkbox";
import FormControlLabel from "@mui/material/FormControlLabel";
import FormLabel from "@mui/material/FormLabel";
import Radio from "@mui/material/Radio";
import RadioGroup from "@mui/material/RadioGroup";
import { api } from "../api/client";
import { CA_MIGRATION_STATUSES, EXPOSURE_LEVELS, SCAP_PROFILE_KEYS } from "../api/types";
import type {
  AgentEnrollmentTokenOut,
  AgentInstallScriptOut,
  CaMigrationStatus,
  ExposureLevel,
  Finding,
  HostOut,
  HostSshCredentialOut,
  JobOut,
  JobProgressOut,
} from "../api/types";
import FindingsTable from "../components/FindingsTable";
import PageHeader from "../components/PageHeader";
import { useSnackbar } from "../hooks/useSnackbar";
import { useLatestRequest } from "../hooks/useLatestRequest";
import { errMessage } from "../lib/errors";
import { caMigrationColor, exposureLabel, gaugeColor, progressColor } from "../lib/statusColors";
import {
  CONNECTION_CHANNEL_LABELS,
  agentIneligibleReason,
  connectionChannel,
  hasAgentInstalled,
} from "../lib/connection";

// Nhãn dễ hiểu cho ca_migration_status — CHỈ đổi chữ hiển thị, giá trị thật
// gửi lên API vẫn là "not_started"/"trust_deployed"/"migrated" (xem
// CA_MIGRATION_STATUSES). Rút gọn theo phản hồi thật: người dùng không cần
// biết tên field/trạng thái tiếng Anh để hiểu máy đang ở bước nào.
const CA_MIGRATION_LABELS: Record<CaMigrationStatus, string> = {
  not_started: "Chưa chuyển sang CA",
  trust_deployed: "Đang chuyển (đường lui còn)",
  migrated: "Đã chuyển xong",
};

// Thứ tự + nhãn tiếng Việt cho Host.system_info (khoá do
// apps/execution-env/ssh-check.sh sinh ra, allowlist ở
// app/jobs.py:_SSH_CHECK_SYSTEM_KEYS). Khai tường minh thay vì lặp
// Object.entries: kiểm soát được THỨ TỰ hiển thị và không đổ khoá lạ
// (nếu backend sau này thêm khoá mới) ra UI dưới dạng tên kỹ thuật thô.
const SYSTEM_INFO_ROWS: { key: string; label: string; format?: (v: string) => string }[] = [
  { key: "os_pretty", label: "Hệ điều hành" },
  { key: "kernel", label: "Kernel" },
  { key: "arch", label: "Kiến trúc" },
  { key: "virt", label: "Ảo hoá" },
  { key: "cpu_model", label: "CPU" },
  { key: "cpu_cores", label: "Số nhân CPU" },
  {
    key: "mem_total_kb",
    label: "RAM",
    // /proc/meminfo trả KiB — đổi sang GiB cho dễ đọc, giữ nguyên chuỗi gốc
    // nếu không phải số (máy lạ trả gì đó ngoài dự kiến).
    format: (v) => {
      const kb = Number(v);
      return Number.isFinite(kb) && kb > 0 ? `${(kb / 1024 / 1024).toFixed(1)} GiB` : v;
    },
  },
  {
    key: "disk_root",
    // ssh-check.sh trả dạng "<tổng>/<còn trống>" (vd "40G/22G") — ghép bằng
    // "/" thay vì khoảng trắng để không phải quote gì thêm khi đi qua nhiều
    // lớp shell.
    label: "Ổ đĩa /",
    format: (v) => {
      const [total, free] = v.split("/");
      return free ? `${total} tổng, còn trống ${free}` : v;
    },
  },
  {
    key: "uptime_sec",
    label: "Uptime",
    format: (v) => {
      const sec = Number(v);
      if (!Number.isFinite(sec) || sec <= 0) return v;
      const days = Math.floor(sec / 86400);
      const hours = Math.floor((sec % 86400) / 3600);
      return days > 0 ? `${days} ngày ${hours} giờ` : `${hours} giờ`;
    },
  },
];

// 1 vòng tròn %-gauge (CPU/RAM/Disk/Network) — dùng CircularProgress có sẵn
// của MUI (đã import, đủ để vẽ 1 vòng tròn % thật), KHÔNG thêm thư viện
// chart nào. pct=null nghĩa là chưa có dữ liệu (host chưa cài Agent, hoặc
// đã cài nhưng chưa có lần báo cáo nào) — hiện "N/A" thay vì 0% giả.
function ResourceGauge({
  label,
  pct,
  sublabel,
}: {
  label: string;
  pct: number | null;
  sublabel?: string;
}) {
  return (
    <Stack alignItems="center" spacing={0.5}>
      <Box sx={{ position: "relative", display: "inline-flex" }}>
        <CircularProgress variant="determinate" value={pct ?? 0} size={96} thickness={4.5} color={gaugeColor(pct)} />
        <Box
          sx={{
            position: "absolute",
            inset: 0,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <Typography variant="body1">{pct != null ? `${Math.round(pct)}%` : "N/A"}</Typography>
        </Box>
      </Box>
      <Typography variant="body2">{label}</Typography>
      {sublabel && (
        <Typography variant="caption" color="text.secondary">
          {sublabel}
        </Typography>
      )}
    </Stack>
  );
}

function formatRelativeTime(iso: string): string {
  const diffSec = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (diffSec < 60) return `${Math.max(diffSec, 0)}s trước`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin} phút trước`;
  const diffHour = Math.floor(diffMin / 60);
  if (diffHour < 24) return `${diffHour} giờ trước`;
  return `${Math.floor(diffHour / 24)} ngày trước`;
}

// Heartbeat mặc định mỗi 60s (AGENT_HEARTBEAT_INTERVAL, xem apps/agent/README.md)
// — quá 5 phút không heartbeat coi như agent mất kết nối/đã dừng, cảnh báo
// màu warning thay vì success dù đã từng enroll.
const AGENT_STALE_AFTER_MIN = 5;

function agentStatus(h: HostOut): { label: string; color: "default" | "warning" | "success" } {
  if (!h.agent_enrolled_at) {
    return { label: "Chưa enroll", color: "default" };
  }
  if (!h.agent_last_seen) {
    return { label: "Đã enroll, chưa có heartbeat", color: "warning" };
  }
  const diffMin = (Date.now() - new Date(h.agent_last_seen).getTime()) / 60000;
  return {
    label: formatRelativeTime(h.agent_last_seen),
    color: diffMin > AGENT_STALE_AFTER_MIN ? "warning" : "success",
  };
}

export default function HostsPage() {
  const { showSuccess, showError } = useSnackbar();
  const [hosts, setHosts] = useState<HostOut[]>([]);
  const [loading, setLoading] = useState(true);
  // Mặc định ẩn host đã decommission (khớp include_decommissioned=false mặc
  // định phía backend) — bật lên khi cần tra cứu/khôi phục.
  const [includeDecommissioned, setIncludeDecommissioned] = useState(false);
  // Kill-switch Active Response TOÀN CỤC phía server — điều kiện thứ 4 quyết
  // định kênh remediate mà không nằm trên Host (xem lib/connection.ts,
  // app/main.py:runtime_config). undefined = chưa tải xong.
  const [globalActiveResponse, setGlobalActiveResponse] = useState<boolean | undefined>(undefined);

  // os_family/os_version KHÔNG khai lúc đăng ký (xem client.ts registerHost)
  // — Agent tự báo cáo qua heartbeat sau khi cài, hoặc điền tay qua "Sửa
  // host" cho máy thuần agentless (editForm bên dưới vẫn còn 2 field này).
  const [registerOpen, setRegisterOpen] = useState(false);
  const [registerForm, setRegisterForm] = useState({
    hostname: "",
    ip_address: "",
    tier: 2,
    ssh_user: "root",
    ssh_port: 22,
    ssh_password: "",
    exposure: "local" as ExposureLevel,
  });
  // Phương thức quản lý dự định cho host này — CHỈ ảnh hưởng UI (ẩn field
  // ssh_password không cần dùng, tự mở tiếp dialog "Sinh script cài Agent"
  // ngay sau khi đăng ký nếu chọn "agent"). KHÔNG gửi lên API — backend chưa
  // có khái niệm này, host luôn có thể dùng cả 2 đường (SSH agentless/Agent)
  // sau khi đăng ký, đây chỉ là gợi ý luồng làm việc lúc đăng ký mới.
  const [registerMethod, setRegisterMethod] = useState<"ssh" | "agent">("ssh");

  // Sửa host đã đăng ký (ip_address/os_family/os_version/tier/ssh_user/
  // ssh_port) — xem app/hosts.py:update_host. `tier` chỉ admin sửa được,
  // form KHÔNG tự ẩn field theo role (RBAC 100% phía backend, cùng quy ước
  // toàn app). `ssh_port` ở đây chỉ KHAI LẠI (vd host vốn đã dùng cổng khác
  // 22 từ trước, hoặc sửa tay khi DB lệch thật) — KHÔNG tự đổi gì trên host
  // đang chạy, đổi thật phải qua "Đổi cổng SSH" ở menu Actions.
  // ssh_password: ô để trống + KHÔNG tick "xoá" = giữ nguyên (không gửi field
  // này lên server); tick "xoá" = gửi "" (server xoá); có nhập chữ = ghi đè.
  // Không bao giờ điền sẵn giá trị cũ vào ô này (chỉ xem qua "Xem SSH
  // credential" riêng, xem viewCredentialHost bên dưới).
  const [editHost, setEditHost] = useState<HostOut | null>(null);
  const [editForm, setEditForm] = useState({
    ip_address: "", os_family: "", os_version: "", tier: 2, ssh_user: "root", ssh_port: 22,
    ssh_password: "", clearSshPassword: false, exposure: "local" as ExposureLevel,
    clearStaticSshKey: false,
  });
  const [editSaving, setEditSaving] = useState(false);

  // Xem OS/kernel/phần cứng đã thu thập ở lần "Test SSH" thành công gần nhất
  // (Host.system_info) — thuần hiển thị dữ liệu ĐÃ CÓ trong danh sách host,
  // KHÔNG gọi thêm API nào, nên không cần state loading/lỗi.
  const [systemInfoHost, setSystemInfoHost] = useState<HostOut | null>(null);

  // Xem lại SSH credential đã lưu (admin-only phía backend, tự audit mỗi
  // lần gọi) — tách riêng khỏi dialog Sửa, chỉ fetch khi bấm rõ ràng.
  const [viewCredentialHost, setViewCredentialHost] = useState<HostOut | null>(null);
  const [viewingCredential, setViewingCredential] = useState(false);
  const [viewCredentialResult, setViewCredentialResult] = useState<HostSshCredentialOut | null>(null);

  // Xoá host thật (hard-delete, admin-only) — xoá TOÀN BỘ dữ liệu liên quan,
  // kể cả lịch sử job/remediation request đã có (KHÔNG hoàn tác được), và cố
  // gắng gỡ Agent trên máy thật qua SSH trước (best-effort, không chặn xoá
  // nếu máy không còn online) — xem app/hosts.py:delete_host.
  const [deleteHostTarget, setDeleteHostTarget] = useState<HostOut | null>(null);
  const [deleting, setDeleting] = useState(false);

  const [scanHost, setScanHost] = useState<HostOut | null>(null);
  const [scapProfileKey, setScapProfileKey] = useState<string>(SCAP_PROFILE_KEYS[0]);
  const [scanning, setScanning] = useState(false);
  const [jobResult, setJobResult] = useState<JobOut | null>(null);

  const [enrollHost, setEnrollHost] = useState<HostOut | null>(null);
  const [enrolling, setEnrolling] = useState(false);
  const [enrollResult, setEnrollResult] = useState<AgentEnrollmentTokenOut | null>(null);
  // Bấm "Tạo enrollment token" liên tiếp cho 2 host khác nhau trước khi
  // request đầu hoàn tất có thể khiến token của host A hiện dưới dialog
  // đang mở cho host B (hoặc lỗi của A đóng nhầm dialog đang mở cho B) —
  // dùng request id tăng dần, chỉ áp dụng kết quả nếu vẫn là request mới
  // nhất khi nó resolve (race-guard dùng chung useLatestRequest).
  const beginEnroll = useLatestRequest();

  // "Test SSH" — chỉ khả thi cho host đã trust_deployed/migrated (xem
  // app/jobs.py:trigger_ssh_check). Kết quả cuối vẫn báo qua Snackbar —
  // testingSshHostname chỉ còn dùng để disable menu item lúc đang chạy,
  // phần hiển thị tiến độ THẬT giờ nằm ở Dialog progressJob/jobProgress bên
  // dưới (dùng chung với "Cài Agent") vì trigger_ssh_check/trigger_agent_install
  // giờ trả về NGAY (job "running") rồi mới chạy job-dispatcher trong
  // BackgroundTasks — trước đây menu tự đóng ngay lúc bấm nên người dùng
  // không thấy gì trong lúc chờ, đây là chỗ sửa gốc vấn đề đó.
  const [testingSshHostname, setTestingSshHostname] = useState<string | null>(null);
  const beginTestSsh = useLatestRequest();

  // Remote-deploy Agent tự động — cùng lớp race-condition beginTestSsh ngay
  // trên (bấm liên tiếp cho 2 host khác nhau).
  const [installingAgentHostname, setInstallingAgentHostname] = useState<string | null>(null);
  const beginInstallAgent = useLatestRequest();

  // Dialog tiến độ % THẬT — dùng chung cho "Test SSH" và "Cài Agent" (2
  // job_type duy nhất có script in marker ##PROGRESS##, xem
  // app/jobs.py:_PROGRESS_SUPPORTED_JOB_TYPES). progressJob != null nghĩa là
  // đang mở; jobProgress là kết quả poll gần nhất (null = chưa poll lần nào).
  const [progressJob, setProgressJob] = useState<
    { kind: "ssh-check" | "agent-install"; hostname: string; jobId: number } | null
  >(null);
  const [jobProgress, setJobProgress] = useState<JobProgressOut | null>(null);

  // Menu "..." gộp toàn bộ action của 1 dòng host — thay cho việc xếp thẳng
  // hàng 9 nút riêng biệt trong cột Actions (quá dài/rối khi nhiều host).
  const [actionMenu, setActionMenu] = useState<{ anchorEl: HTMLElement; host: HostOut } | null>(null);

  // Sinh script cài Agent gộp sẵn — cùng lớp race-condition beginEnroll phía
  // trên (bấm liên tiếp cho 2 host khác nhau).
  const [installScriptHost, setInstallScriptHost] = useState<HostOut | null>(null);
  const [generatingInstallScript, setGeneratingInstallScript] = useState(false);
  const [installScriptResult, setInstallScriptResult] = useState<AgentInstallScriptOut | null>(null);
  const beginInstallScript = useLatestRequest();

  // Thiết lập trust cho host còn "not_started" bằng credential CŨ — dùng
  // ĐÚNG 1 LẦN, chọn 1 trong 2 cơ chế LOẠI TRỪ NHAU (mechanism):
  //   "ca_cert" — Bootstrap CA trust (app/jobs.py:trigger_ca_bootstrap,
  //     khuyến nghị — không lưu secret nào, mỗi job mint cert mới).
  //   "static_key" — tạo + LƯU LẠI 1 SSH key tĩnh dùng cho mọi job sau này
  //     (app/jobs.py:trigger_static_ssh_key_bootstrap) — đánh đổi bảo mật
  //     người dùng đã xác nhận muốn dùng, xem docstring backend.
  // Form tự xoá password/private key khỏi state ngay sau khi request xong
  // (thành công lẫn lỗi) — không giữ lại trong React state lâu hơn cần thiết.
  const [bootstrapHost, setBootstrapHost] = useState<HostOut | null>(null);
  const [bootstrapForm, setBootstrapForm] = useState({
    mechanism: "ca_cert" as "ca_cert" | "static_key",
    legacy_ssh_user: "root",
    authMethod: "password" as "password" | "key",
    legacy_ssh_password: "",
    legacy_ssh_private_key: "",
  });
  const [bootstrapping, setBootstrapping] = useState(false);

  // Đổi cổng SSH thật, có xác minh kết nối trước khi coi thành công — xem
  // app/jobs.py:trigger_ssh_port_change. KHÔNG có bước "xem trước" riêng
  // (cơ chế tự xác minh chính là cửa an toàn) — chỉ 1 dialog xác nhận rồi
  // chạy thật, hiển thị rõ job có succeeded/failed và log chi tiết.
  const [portChangeHost, setPortChangeHost] = useState<HostOut | null>(null);
  const [newSshPort, setNewSshPort] = useState(22);
  const [changingPort, setChangingPort] = useState(false);
  const [portChangeResult, setPortChangeResult] = useState<JobOut | null>(null);

  const loadHosts = () => {
    setLoading(true);
    api
      .listHosts(undefined, includeDecommissioned)
      .then(setHosts)
      .catch((err) => showError(errMessage(err)))
      .finally(() => setLoading(false));
  };

  useEffect(loadHosts, [includeDecommissioned]);

  // Tải 1 lần/phiên — cờ này chỉ đổi khi sửa .env + khởi động lại server, và
  // lỗi ở đây KHÔNG được chặn cả trang: bỏ qua im lặng, connectionChannel tự
  // rơi về chế độ chỉ xét cấu hình host (xem lib/connection.ts).
  useEffect(() => {
    api
      .getRuntimeConfig()
      .then((cfg) => setGlobalActiveResponse(cfg.active_response_enabled))
      .catch(() => undefined);
  }, []);

  const handleRegister = async () => {
    try {
      const host = await api.registerHost({
        ...registerForm,
        // Đường Agent không dùng ssh_password (agent tự xác thực qua mTLS
        // cert riêng, xem app/agents.py) — không lưu lại dù form còn giá trị
        // từ lần trước đó.
        ssh_password:
          registerMethod === "agent" ? undefined : registerForm.ssh_password || undefined,
      });
      setRegisterOpen(false);
      setRegisterForm({
        hostname: "", ip_address: "", tier: 2,
        ssh_user: "root", ssh_port: 22, ssh_password: "", exposure: "local",
      });
      showSuccess("Đã đăng ký host");
      loadHosts();
      // Chọn "Agent" lúc đăng ký -> dẫn thẳng operator sang bước tiếp theo
      // (sinh script cài Agent) thay vì phải tự tìm trong menu Actions.
      if (registerMethod === "agent") {
        handleGenerateInstallScript(host);
      }
      setRegisterMethod("ssh");
    } catch (err) {
      showError(errMessage(err));
    }
  };

  const openEditHost = (host: HostOut) => {
    setEditHost(host);
    setEditForm({
      ip_address: host.ip_address,
      os_family: host.os_family ?? "",
      os_version: host.os_version ?? "",
      tier: host.tier,
      ssh_user: host.ssh_user,
      ssh_port: host.ssh_port,
      ssh_password: "",
      clearSshPassword: false,
      exposure: host.exposure,
      clearStaticSshKey: false,
    });
  };

  const handleSaveEdit = async () => {
    if (!editHost) return;
    setEditSaving(true);
    try {
      // ssh_password: có nhập chữ -> ghi đè; rỗng + tick "xoá" -> gửi "" (xoá);
      // rỗng + KHÔNG tick -> omit hẳn field (giữ nguyên, không đụng gì).
      const ssh_password =
        editForm.ssh_password !== ""
          ? editForm.ssh_password
          : editForm.clearSshPassword
          ? ""
          : undefined;
      await api.updateHost(editHost.hostname, {
        ip_address: editForm.ip_address,
        // "" -> undefined (omit) — KHÔNG có khái niệm "xoá os_family bằng
        // chuỗi rỗng" (khác ssh_password): os_family giờ có thể là None thật
        // (chưa xác định), gửi "" sẽ vô tình ghi đè None -> "" nếu người
        // dùng mở dialog Sửa mà không đụng tới 2 field OS này.
        os_family: editForm.os_family || undefined,
        os_version: editForm.os_version || undefined,
        tier: editForm.tier,
        ssh_user: editForm.ssh_user,
        ssh_port: editForm.ssh_port,
        ssh_password,
        exposure: editForm.exposure,
        clear_static_ssh_key: editForm.clearStaticSshKey || undefined,
      });
      showSuccess(`Đã cập nhật ${editHost.hostname}`);
      setEditHost(null);
      loadHosts();
    } catch (err) {
      showError(errMessage(err));
    } finally {
      // Xoá password khỏi state ngay dù thành công hay lỗi — không giữ lại
      // lâu hơn mức cần thiết trong bộ nhớ trình duyệt.
      setEditForm((f) => ({ ...f, ssh_password: "", clearSshPassword: false, clearStaticSshKey: false }));
      setEditSaving(false);
    }
  };

  const handleMigrationStatusChange = async (host: HostOut, status: CaMigrationStatus) => {
    try {
      await api.updateHostMigrationStatus(host.hostname, status);
      showSuccess(`Đã cập nhật ${host.hostname} -> ${status}`);
      loadHosts();
    } catch (err) {
      showError(errMessage(err));
    }
  };

  const handleTriggerScan = async () => {
    if (!scanHost) return;
    setScanning(true);
    setJobResult(null);
    try {
      // ssh_user không còn là tham số request — dùng thẳng Host.ssh_user
      // (sửa qua nút "Edit" nếu cần khác "root").
      const job = await api.triggerScan(scanHost.hostname, scapProfileKey);
      setJobResult(job);
    } catch (err) {
      showError(errMessage(err));
    } finally {
      setScanning(false);
    }
  };

  const handleCreateEnrollmentToken = async (host: HostOut) => {
    const isStale = beginEnroll();
    setEnrollHost(host);
    setEnrollResult(null);
    setEnrolling(true);
    try {
      const result = await api.createAgentEnrollmentToken(host.hostname);
      // 1 request mới hơn (click host khác) đã bắt đầu trong lúc chờ — bỏ
      // kết quả cũ, không ghi đè dialog đang mở cho host khác.
      if (isStale()) return;
      setEnrollResult(result);
    } catch (err) {
      if (isStale()) return;
      showError(errMessage(err));
      // KHÔNG đóng dialog (khác các handler khác trong app luôn giữ dialog
      // mở khi lỗi để retry tại chỗ) — chỉ dừng spinner, còn lại nút "Thử
      // lại" bên dưới xử lý.
    } finally {
      if (!isStale()) {
        setEnrolling(false);
      }
    }
  };

  const handleTestSsh = async (host: HostOut) => {
    const isStale = beginTestSsh();
    setTestingSshHostname(host.hostname);
    try {
      // Trả về NGAY (job "running") — job-dispatcher chạy trong
      // BackgroundTasks phía Orchestrator, xem app/jobs.py:trigger_ssh_check.
      // Kết quả cuối (thành công/lỗi) được useEffect polling bên dưới phát
      // hiện và bắn Snackbar, không phải ở đây.
      const job = await api.testSshReachability(host.hostname);
      if (isStale()) return;
      setJobProgress(null);
      setProgressJob({ kind: "ssh-check", hostname: host.hostname, jobId: job.id });
    } catch (err) {
      if (isStale()) return;
      showError(errMessage(err));
      setTestingSshHostname(null);
    }
  };

  const handleInstallAgent = async (host: HostOut) => {
    const isStale = beginInstallAgent();
    setInstallingAgentHostname(host.hostname);
    try {
      // Cùng lý do handleTestSsh — trả về NGAY, kết quả cuối xử lý ở
      // useEffect polling bên dưới (bao gồm cả loadHosts() lúc thành công).
      const job = await api.installAgent(host.hostname);
      if (isStale()) return;
      setJobProgress(null);
      setProgressJob({ kind: "agent-install", hostname: host.hostname, jobId: job.id });
    } catch (err) {
      if (isStale()) return;
      showError(errMessage(err));
      setInstallingAgentHostname(null);
    }
  };

  // Poll % tiến độ thật mỗi 2s trong lúc dialog progressJob còn mở — dừng
  // (và bắn Snackbar kết quả cuối, đúng nội dung message trước đây nằm
  // trong handleTestSsh/handleInstallAgent) ngay khi job không còn
  // "running"/"pending". Mirror pattern polling canary rollout ở
  // ControlsPage.tsx. Poll ngay lúc mở (không đợi 2s đầu) cho cảm giác mượt.
  useEffect(() => {
    if (!progressJob) return;
    let cancelled = false;
    const { jobId, hostname, kind } = progressJob;

    const poll = async () => {
      let progress: JobProgressOut;
      try {
        progress = await api.getJobProgress(jobId);
      } catch {
        return; // Lỗi mạng tạm thời lúc poll — thử lại ở lần kế tiếp, không đóng dialog.
      }
      if (cancelled) return;
      setJobProgress(progress);
      if (progress.status === "running" || progress.status === "pending") return;

      try {
        const job = await api.getJob(jobId);
        if (cancelled) return;
        if (job.status === "succeeded") {
          if (kind === "ssh-check") {
            const uname = (job.result_summary?.ssh_check_uname as string | undefined) ?? "";
            showSuccess(`SSH tới ${hostname} OK — ${uname}`);
          } else {
            showSuccess(`Đã cài Agent lên ${hostname} (job #${job.id})`);
            // agent_enrolled_at chỉ được set lúc Agent TỰ enroll thành công
            // (xem app/agents.py:verify_and_enroll), xảy ra vài giây SAU khi
            // job cài đặt kết thúc — lần tải này có thể còn thấy "Chưa
            // enroll", bấm "Tải lại" sau đó là thấy.
            loadHosts();
          }
        } else {
          const label = kind === "ssh-check" ? "SSH tới" : "Cài Agent lên";
          showError(`${label} ${hostname} thất bại — xem chi tiết ở job #${job.id} (trang Jobs)`);
        }
      } finally {
        if (!cancelled) {
          setProgressJob(null);
          setJobProgress(null);
          setTestingSshHostname(null);
          setInstallingAgentHostname(null);
        }
      }
    };

    poll();
    const intervalId = window.setInterval(poll, 2000);
    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [progressJob?.jobId]);

  // Chuyển kênh remediate giữa Agent và SSH agentless = bật/tắt Active
  // Response riêng cho host (PATCH .../active-response). KHÔNG đụng gì tới
  // Agent đang chạy trên máy — tắt chỉ nghĩa là "không dùng Agent để SỬA
  // lỗi nữa", Agent vẫn tiếp tục scan/FIM như cũ (xem lib/connection.ts).
  const handleSwitchChannel = async (host: HostOut, useAgent: boolean) => {
    try {
      await api.updateHostActiveResponse(host.hostname, useAgent);
      showSuccess(
        useAgent
          ? globalActiveResponse === false
            ? `Đã bật Agent cho ${host.hostname}, NHƯNG Active Response đang tắt toàn cục — remediate vẫn đi đường SSH cho tới khi bật ACTIVE_RESPONSE_ENABLED phía server`
            : `${host.hostname} sẽ remediate qua Agent (Active Response)`
          : `${host.hostname} sẽ remediate qua SSH agentless — Agent vẫn chạy để scan/FIM`
      );
      loadHosts();
    } catch (err) {
      showError(errMessage(err));
    }
  };

  const handleToggleDecommission = async (host: HostOut, decommissioned: boolean) => {
    try {
      await api.updateHostDecommission(host.hostname, decommissioned);
      showSuccess(
        decommissioned
          ? `Đã tạm ngưng quản lý ${host.hostname} — lịch sử job/audit vẫn giữ nguyên`
          : `Đã khôi phục quản lý ${host.hostname}`
      );
      loadHosts();
    } catch (err) {
      showError(errMessage(err));
    }
  };

  const handleViewCredential = async (host: HostOut) => {
    setViewCredentialHost(host);
    setViewCredentialResult(null);
    setViewingCredential(true);
    try {
      const result = await api.getSshCredential(host.hostname);
      setViewCredentialResult(result);
    } catch (err) {
      showError(errMessage(err));
      setViewCredentialHost(null);
    } finally {
      setViewingCredential(false);
    }
  };

  const handleDeleteHost = async () => {
    if (!deleteHostTarget) return;
    setDeleting(true);
    try {
      await api.deleteHost(deleteHostTarget.hostname);
      showSuccess(`Đã xoá ${deleteHostTarget.hostname}`);
      setDeleteHostTarget(null);
      loadHosts();
    } catch (err) {
      showError(errMessage(err));
    } finally {
      setDeleting(false);
    }
  };

  const handleGenerateInstallScript = async (host: HostOut) => {
    const isStale = beginInstallScript();
    setInstallScriptHost(host);
    setInstallScriptResult(null);
    setGeneratingInstallScript(true);
    try {
      const result = await api.createAgentInstallScript(host.hostname);
      if (isStale()) return;
      setInstallScriptResult(result);
    } catch (err) {
      if (isStale()) return;
      showError(errMessage(err));
    } finally {
      if (!isStale()) setGeneratingInstallScript(false);
    }
  };

  const resetBootstrapForm = () => {
    setBootstrapHost(null);
    setBootstrapForm({
      mechanism: "ca_cert",
      legacy_ssh_user: "root",
      authMethod: "password",
      legacy_ssh_password: "",
      legacy_ssh_private_key: "",
    });
  };

  const handleBootstrapCaTrust = async () => {
    if (!bootstrapHost) return;
    setBootstrapping(true);
    const credential = {
      legacy_ssh_user: bootstrapForm.legacy_ssh_user,
      ...(bootstrapForm.authMethod === "password"
        ? { legacy_ssh_password: bootstrapForm.legacy_ssh_password }
        : { legacy_ssh_private_key: bootstrapForm.legacy_ssh_private_key }),
    };
    try {
      const job =
        bootstrapForm.mechanism === "ca_cert"
          ? await api.bootstrapCaTrust(bootstrapHost.hostname, credential)
          : await api.bootstrapStaticSshKey(bootstrapHost.hostname, credential);
      if (job.status === "succeeded") {
        showSuccess(
          bootstrapForm.mechanism === "ca_cert"
            ? `Đã bật CA trust cho ${bootstrapHost.hostname} (job #${job.id}) — ca_migration_status = trust_deployed. Nhớ tự verify + thu hồi credential cũ (ansible/README.md bước 2).`
            : `Đã tạo + cài SSH key tĩnh cho ${bootstrapHost.hostname} (job #${job.id}) — ca_migration_status = trust_deployed, mọi job SSH sau này dùng key này. Nhớ tự verify + thu hồi credential cũ (ansible/README.md bước 2).`
        );
      } else {
        showError(`Thiết lập trust thất bại cho ${bootstrapHost.hostname} — xem job #${job.id} (trang Jobs)`);
      }
      resetBootstrapForm();
      loadHosts();
    } catch (err) {
      showError(errMessage(err));
    } finally {
      // Xoá credential khỏi state NGAY dù thành công hay lỗi — không giữ
      // lại trong bộ nhớ trình duyệt lâu hơn mức cần thiết.
      setBootstrapForm((f) => ({ ...f, legacy_ssh_password: "", legacy_ssh_private_key: "" }));
      setBootstrapping(false);
    }
  };

  const openPortChangeDialog = (host: HostOut) => {
    setPortChangeHost(host);
    setNewSshPort(host.ssh_port);
    setPortChangeResult(null);
  };

  const handleChangeSshPort = async () => {
    if (!portChangeHost) return;
    setChangingPort(true);
    setPortChangeResult(null);
    try {
      const job = await api.changeSshPort(portChangeHost.hostname, newSshPort);
      setPortChangeResult(job);
      if (job.status === "succeeded") {
        showSuccess(`Đã đổi cổng SSH ${portChangeHost.hostname} -> ${newSshPort} (đã xác minh kết nối)`);
      } else {
        showError(`Đổi cổng SSH thất bại cho ${portChangeHost.hostname} — xem chi tiết bên dưới`);
      }
      loadHosts();
    } catch (err) {
      showError(errMessage(err));
    } finally {
      setChangingPort(false);
    }
  };

  const findings = (jobResult?.result_summary?.findings as Finding[] | undefined) ?? [];

  return (
    <Stack spacing={2}>
      <PageHeader
        title="Hosts"
        actions={
          <>
            <FormControlLabel
              control={
                <Checkbox
                  size="small"
                  checked={includeDecommissioned}
                  onChange={(e) => setIncludeDecommissioned(e.target.checked)}
                />
              }
              label="Hiện cả host đã tạm ngưng"
            />
            <Button variant="outlined" onClick={loadHosts}>
              Tải lại
            </Button>
            <Button variant="contained" onClick={() => setRegisterOpen(true)}>
              Đăng ký host
            </Button>
          </>
        }
      />

      {loading ? (
        <CircularProgress />
      ) : (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Hostname</TableCell>
                <TableCell>IP</TableCell>
                <TableCell>OS</TableCell>
                <TableCell>Tier</TableCell>
                <TableCell>SSH user</TableCell>
                <TableCell>CA Migration Status</TableCell>
                <TableCell>Kết nối</TableCell>
                <TableCell>Agent</TableCell>
                <TableCell>Added by</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {hosts.map((h) => {
                const isDecommissioned = h.decommissioned_at !== null;
                const hasSystemInfo = Object.keys(h.system_info).length > 0;
                const hasMetrics = Object.keys(h.metrics).length > 0;
                const hasHostDetail = hasSystemInfo || hasMetrics;
                return (
                  <TableRow key={h.hostname} sx={isDecommissioned ? { opacity: 0.6 } : undefined}>
                    <TableCell>
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Tooltip
                          title={
                            hasHostDetail
                              ? "Xem thông tin phần cứng/tài nguyên đã thu thập"
                              : "Chưa có dữ liệu — chạy 'Test SSH' hoặc cài Agent để thu thập"
                          }
                        >
                          <Link
                            component="button"
                            underline={hasHostDetail ? "hover" : "none"}
                            color={hasHostDetail ? "primary" : "text.primary"}
                            onClick={() => hasHostDetail && setSystemInfoHost(h)}
                            sx={{
                              font: "inherit",
                              cursor: hasHostDetail ? "pointer" : "default",
                            }}
                          >
                            {h.hostname}
                          </Link>
                        </Tooltip>
                        {isDecommissioned && <Chip label="Đã tạm ngưng" size="small" color="default" />}
                      </Stack>
                    </TableCell>
                    <TableCell>{h.ip_address}</TableCell>
                    <TableCell>
                      {(() => {
                        // os_pretty (vd "Ubuntu 22.04.4 LTS") dễ đọc hơn ghép
                        // os_family+os_version thô, nhưng chỉ có sau khi Test
                        // SSH thành công — fallback về 2 cột cũ để host chưa
                        // test vẫn hiện đúng như trước.
                        const pretty = h.system_info.os_pretty;
                        const label = pretty
                          ? pretty
                          : h.os_family
                          ? `${h.os_family}${h.os_version ? ` ${h.os_version}` : ""}`
                          : "Chưa xác định";
                        const kernel = h.system_info.kernel;
                        return (
                          <Stack spacing={0}>
                            <span>{label}</span>
                            {kernel && (
                              <Typography variant="caption" color="text.secondary">
                                kernel {kernel}
                              </Typography>
                            )}
                          </Stack>
                        );
                      })()}
                    </TableCell>
                    <TableCell>
                      <Chip label={`Tier ${h.tier}`} size="small" />
                    </TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={0.5} alignItems="center">
                        {h.ssh_user}:{h.ssh_port}
                        {h.has_ssh_password && (
                          <Tooltip title="Đã lưu password SSH (mã hoá) — bấm 'Xem credential' để xem">
                            <Chip label="Password" size="small" variant="outlined" />
                          </Tooltip>
                        )}
                      </Stack>
                    </TableCell>
                    <TableCell>
                      <Select
                        size="small"
                        value={h.ca_migration_status}
                        disabled={isDecommissioned}
                        onChange={(e) =>
                          handleMigrationStatusChange(h, e.target.value as CaMigrationStatus)
                        }
                        renderValue={(value) => (
                          <Chip
                            label={CA_MIGRATION_LABELS[value as CaMigrationStatus]}
                            size="small"
                            color={caMigrationColor[value as CaMigrationStatus]}
                          />
                        )}
                      >
                        {CA_MIGRATION_STATUSES.map((s) => (
                          <MenuItem key={s} value={s}>
                            {CA_MIGRATION_LABELS[s]}
                          </MenuItem>
                        ))}
                      </Select>
                    </TableCell>
                    <TableCell>
                      {(() => {
                        // Kênh ĐANG dùng để remediate — xem lib/connection.ts
                        // (port đúng app/jobs.py:_agent_ineligible_reason).
                        // Tooltip nêu rõ VÌ SAO chưa dùng Agent, để operator
                        // không phải đoán giữa "chưa cài" và "cài rồi nhưng
                        // chưa bật Active Response".
                        const channel = connectionChannel(h, globalActiveResponse);
                        const reason = agentIneligibleReason(h, globalActiveResponse);
                        return (
                          <Tooltip
                            title={
                              channel === "agent"
                                ? "Remediate đi qua Agent (Active Response) — vẫn cần kill-switch toàn cục bật phía server"
                                : `Remediate đi qua SSH agentless — ${reason}`
                            }
                          >
                            <Chip
                              label={CONNECTION_CHANNEL_LABELS[channel]}
                              size="small"
                              color={channel === "agent" ? "primary" : "default"}
                              variant={channel === "agent" ? "filled" : "outlined"}
                            />
                          </Tooltip>
                        );
                      })()}
                    </TableCell>
                    <TableCell>
                      {(() => {
                        const status = agentStatus(h);
                        return <Chip label={status.label} size="small" color={status.color} />;
                      })()}
                    </TableCell>
                    <TableCell>{h.added_by}</TableCell>
                    <TableCell align="right">
                      <IconButton
                        size="small"
                        aria-label="Actions"
                        onClick={(e) => setActionMenu({ anchorEl: e.currentTarget, host: h })}
                      >
                        ⋮
                      </IconButton>
                    </TableCell>
                  </TableRow>
                );
              })}
              {hosts.length === 0 && (
                <TableRow>
                  <TableCell colSpan={10} align="center">
                    Chưa có host nào.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Menu Actions gộp — dùng chung 1 Menu cho mọi dòng, chỉ đổi anchorEl +
          host đang chọn (đúng pattern MUI cho action menu theo dòng bảng,
          tránh render N Menu cho N dòng). */}
      <Menu
        anchorEl={actionMenu?.anchorEl}
        open={actionMenu !== null}
        onClose={() => setActionMenu(null)}
      >
        {actionMenu &&
          (() => {
            const h = actionMenu.host;
            const isDecommissioned = h.decommissioned_at !== null;
            const decommissionedTooltip = isDecommissioned
              ? "Host đang tạm ngưng quản lý — khôi phục trước khi thao tác"
              : "";
            const sshTooltip = isDecommissioned
              ? decommissionedTooltip
              : h.ca_migration_status === "not_started"
              ? "Cần trust_deployed/migrated trước — chạy Zero-to-CA Migration playbook"
              : "";
            // Nút chuyển kênh bám theo CỜ CỦA HOST (h.active_response_enabled
            // — thứ endpoint này thật sự bật/tắt), KHÔNG theo kênh hiệu lực
            // connectionChannel(): khi kill-switch toàn cục đang tắt, kênh
            // hiệu lực luôn là "ssh", nên nếu lấy nó làm nhãn thì operator bấm
            // "Chuyển sang Agent" xong vẫn thấy y nguyên nhãn cũ — tưởng nút
            // hỏng. Tooltip bên dưới nói rõ phần kill-switch.
            const agentInstalled = hasAgentInstalled(h);
            const wantsAgent = h.active_response_enabled;
            const hasHostDetail = Object.keys(h.system_info).length > 0 || Object.keys(h.metrics).length > 0;
            const closeMenu = () => setActionMenu(null);
            return [
              // Thao tác chính — việc làm hằng ngày/thường xuyên nhất trên 1 host.
              <MenuItem
                key="edit"
                disabled={isDecommissioned}
                onClick={() => {
                  openEditHost(h);
                  closeMenu();
                }}
              >
                Sửa
              </MenuItem>,
              // Chuyển kênh remediate SSH <-> Agent. Chỉ chuyển SANG Agent
              // được khi host đã cài Agent thật — nút vẫn hiện (không ẩn) kèm
              // tooltip nêu lý do, cùng quy ước với các mục khác trong menu này.
              <Tooltip
                key="switch-channel"
                title={
                  isDecommissioned
                    ? decommissionedTooltip
                    : wantsAgent
                    ? "Chuyển remediate về SSH agentless — Agent vẫn chạy để scan/FIM"
                    : !agentInstalled
                    ? "Cần cài Agent lên host này trước"
                    : h.agent_renewal_blocked
                    ? "Agent đang bị khoá renew cert — mở khoá trước"
                    : globalActiveResponse === false
                    ? "Bật được, NHƯNG Active Response đang tắt toàn cục trên server nên remediate vẫn sẽ đi đường SSH cho tới khi bật ACTIVE_RESPONSE_ENABLED"
                    : "Chuyển remediate sang Agent (Active Response)"
                }
              >
                <span>
                  <MenuItem
                    disabled={
                      isDecommissioned ||
                      (!wantsAgent && (!agentInstalled || h.agent_renewal_blocked))
                    }
                    onClick={() => {
                      handleSwitchChannel(h, !wantsAgent);
                      closeMenu();
                    }}
                  >
                    {wantsAgent ? "Chuyển kết nối sang SSH" : "Chuyển kết nối sang Agent"}
                  </MenuItem>
                </span>
              </Tooltip>,
              <Tooltip
                key="system-info"
                title={
                  hasHostDetail ? "" : "Chưa có dữ liệu — chạy 'Test SSH' hoặc cài Agent để thu thập"
                }
              >
                <span>
                  <MenuItem
                    disabled={!hasHostDetail}
                    onClick={() => {
                      setSystemInfoHost(h);
                      closeMenu();
                    }}
                  >
                    Thông tin máy
                  </MenuItem>
                </span>
              </Tooltip>,
              <MenuItem
                key="scan"
                disabled={isDecommissioned}
                onClick={() => {
                  setScanHost(h);
                  closeMenu();
                }}
              >
                Trigger scan
              </MenuItem>,
              <MenuItem
                key="decommission"
                onClick={() => {
                  handleToggleDecommission(h, !isDecommissioned);
                  closeMenu();
                }}
              >
                {isDecommissioned ? "Khôi phục quản lý" : "Tạm ngưng quản lý"}
              </MenuItem>,
              <MenuItem
                key="delete"
                sx={{ color: "error.main" }}
                onClick={() => {
                  setDeleteHostTarget(h);
                  closeMenu();
                }}
              >
                Xoá
              </MenuItem>,

              // Nâng cao / thiết lập 1 lần — hầu như chỉ đụng tới lúc mới thêm
              // host, hoặc khi cần tuỳ biến riêng cho 1 máy cụ thể. Gộp riêng
              // xuống đây cho gọn (phản hồi thật: quá nhiều mục ở 1 menu phẳng
              // gây rối, không phải vì từng mục vô dụng).
              <Divider key="advanced-divider" />,
              <ListSubheader key="advanced-header">Nâng cao / thiết lập 1 lần</ListSubheader>,
              <MenuItem
                key="credential"
                onClick={() => {
                  handleViewCredential(h);
                  closeMenu();
                }}
              >
                Xem SSH credential
              </MenuItem>,
              <Tooltip
                key="bootstrap"
                title={
                  isDecommissioned
                    ? decommissionedTooltip
                    : h.ca_migration_status !== "not_started"
                    ? "Chỉ dùng cho host còn not_started"
                    : ""
                }
              >
                <span>
                  <MenuItem
                    disabled={isDecommissioned || h.ca_migration_status !== "not_started"}
                    onClick={() => {
                      setBootstrapHost(h);
                      closeMenu();
                    }}
                  >
                    Thiết lập trust (CA cert / SSH key tĩnh)
                  </MenuItem>
                </span>
              </Tooltip>,
              <Tooltip key="ssh-check" title={sshTooltip}>
                <span>
                  <MenuItem
                    disabled={
                      h.ca_migration_status === "not_started" ||
                      isDecommissioned ||
                      testingSshHostname === h.hostname
                    }
                    onClick={() => {
                      handleTestSsh(h);
                      closeMenu();
                    }}
                  >
                    Test SSH
                  </MenuItem>
                </span>
              </Tooltip>,
              <Tooltip key="port-change" title={sshTooltip}>
                <span>
                  <MenuItem
                    disabled={h.ca_migration_status === "not_started" || isDecommissioned}
                    onClick={() => {
                      openPortChangeDialog(h);
                      closeMenu();
                    }}
                  >
                    Đổi cổng SSH
                  </MenuItem>
                </span>
              </Tooltip>,
              <MenuItem
                key="enroll-token"
                disabled={isDecommissioned}
                onClick={() => {
                  handleCreateEnrollmentToken(h);
                  closeMenu();
                }}
              >
                Tạo enrollment token
              </MenuItem>,
              // Host đã enroll Agent rồi thì KHÔNG cho bấm cài lại — cài đè
              // sẽ cấp enrollment token mới + ghi đè cert mTLS đang dùng, dễ
              // làm Agent đang chạy mất kết nối vì lý do không đáng có. Muốn
              // cài lại thật (vd Agent hỏng, nâng cấp) thì xoá host rồi thêm
              // lại, hoặc dùng "Sinh script cài Agent (dán tay)" bên dưới.
              <Tooltip
                key="agent-install"
                title={
                  agentInstalled
                    ? "Host này đã cài Agent — không cần cài lại (xem cột Agent để biết còn heartbeat hay không)"
                    : sshTooltip
                }
              >
                <span>
                  <MenuItem
                    disabled={
                      agentInstalled ||
                      h.ca_migration_status === "not_started" ||
                      isDecommissioned ||
                      installingAgentHostname === h.hostname
                    }
                    onClick={() => {
                      handleInstallAgent(h);
                      closeMenu();
                    }}
                  >
                    {agentInstalled ? "Cài Agent (đã cài)" : "Cài Agent"}
                  </MenuItem>
                </span>
              </Tooltip>,
              <MenuItem
                key="install-script"
                disabled={isDecommissioned}
                onClick={() => {
                  handleGenerateInstallScript(h);
                  closeMenu();
                }}
              >
                Sinh script cài Agent (dán tay)
              </MenuItem>,
            ];
          })()}
      </Menu>

      {/* Đăng ký host */}
      <Dialog
        open={registerOpen}
        onClose={() => {
          setRegisterOpen(false);
          setRegisterMethod("ssh");
        }}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>Đăng ký host</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <FormLabel>Phương thức quản lý</FormLabel>
            <RadioGroup
              row
              value={registerMethod}
              onChange={(e) => setRegisterMethod(e.target.value as "ssh" | "agent")}
            >
              <FormControlLabel value="ssh" control={<Radio />} label="Qua SSH (agentless)" />
              <FormControlLabel value="agent" control={<Radio />} label="Qua Agent" />
            </RadioGroup>
            {registerMethod === "agent" && (
              <Alert severity="info">
                Sau khi đăng ký, hệ thống sẽ mở sẵn màn hình sinh script cài Agent. Vẫn có thể dùng
                cả SSH agentless cho host này sau đó (không loại trừ nhau) — "SSH user"/"SSH port"
                dưới đây vẫn cần điền đúng vì Agent tự cài qua SSH cert (menu "Cài Agent"), không
                phải qua SSH password.
              </Alert>
            )}
            <TextField
              label="Hostname"
              value={registerForm.hostname}
              onChange={(e) => setRegisterForm({ ...registerForm, hostname: e.target.value })}
              fullWidth
            />
            <TextField
              label="IP address"
              value={registerForm.ip_address}
              onChange={(e) => setRegisterForm({ ...registerForm, ip_address: e.target.value })}
              fullWidth
            />
            <TextField
              label="Tier"
              type="number"
              value={registerForm.tier}
              onChange={(e) => setRegisterForm({ ...registerForm, tier: Number(e.target.value) })}
              helperText="Tier 0/1 = production/Tier cao"
              fullWidth
            />
            <TextField
              label="SSH user"
              value={registerForm.ssh_user}
              onChange={(e) => setRegisterForm({ ...registerForm, ssh_user: e.target.value })}
              helperText="Dùng cho scan/ssh-check (remediate/restore luôn dùng root) — phải nằm trong ALLOWED_SSH_USERS phía server"
              fullWidth
            />
            <TextField
              label="SSH port"
              type="number"
              value={registerForm.ssh_port}
              onChange={(e) => setRegisterForm({ ...registerForm, ssh_port: Number(e.target.value) || 0 })}
              inputProps={{ min: 1, max: 65535 }}
              error={registerForm.ssh_port < 1 || registerForm.ssh_port > 65535}
              helperText="Mặc định 22 — chỉ đổi nếu host đã dùng cổng khác từ trước khi vào hệ thống này"
              fullWidth
            />
            {registerMethod === "ssh" && (
              <TextField
                label="SSH password (tuỳ chọn)"
                type="password"
                value={registerForm.ssh_password}
                onChange={(e) => setRegisterForm({ ...registerForm, ssh_password: e.target.value })}
                helperText="Lưu THAM KHẢO, mã hoá — chưa dùng cho scan/remediate nào (vẫn dùng SSH cert)"
                fullWidth
              />
            )}
            <FormControl fullWidth>
              <InputLabel id="register-exposure-label">Mức độ tiếp xúc Internet</InputLabel>
              <Select
                labelId="register-exposure-label"
                label="Mức độ tiếp xúc Internet"
                value={registerForm.exposure}
                onChange={(e) =>
                  setRegisterForm({ ...registerForm, exposure: e.target.value as ExposureLevel })
                }
              >
                {EXPOSURE_LEVELS.map((level) => (
                  <MenuItem key={level} value={level}>
                    {exposureLabel[level]}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setRegisterOpen(false);
              setRegisterMethod("ssh");
            }}
          >
            Huỷ
          </Button>
          <Button
            variant="contained"
            onClick={handleRegister}
            disabled={
              !registerForm.hostname ||
              !registerForm.ip_address ||
              registerForm.ssh_port < 1 ||
              registerForm.ssh_port > 65535
            }
          >
            Đăng ký
          </Button>
        </DialogActions>
      </Dialog>

      {/* Sửa host đã đăng ký */}
      <Dialog open={editHost !== null} onClose={() => setEditHost(null)} fullWidth maxWidth="sm">
        <DialogTitle>Sửa host — {editHost?.hostname}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="IP address"
              value={editForm.ip_address}
              onChange={(e) => setEditForm({ ...editForm, ip_address: e.target.value })}
              helperText="Đổi IP sẽ tự động reset ca_migration_status về not_started"
              fullWidth
            />
            <TextField
              label="OS family (tuỳ chọn)"
              value={editForm.os_family}
              onChange={(e) => setEditForm({ ...editForm, os_family: e.target.value })}
              helperText="Agent tự báo cáo nếu có cài — chỉ cần điền tay cho máy thuần agentless. Bắt buộc phải có trước khi remediate."
              fullWidth
            />
            <TextField
              label="OS version"
              value={editForm.os_version}
              onChange={(e) => setEditForm({ ...editForm, os_version: e.target.value })}
              fullWidth
            />
            <TextField
              label="Tier"
              type="number"
              value={editForm.tier}
              onChange={(e) => setEditForm({ ...editForm, tier: Number(e.target.value) })}
              helperText="Chỉ admin sửa được — backend trả 403 nếu không đủ quyền"
              fullWidth
            />
            <TextField
              label="SSH user"
              value={editForm.ssh_user}
              onChange={(e) => setEditForm({ ...editForm, ssh_user: e.target.value })}
              helperText="Dùng cho scan/ssh-check — phải nằm trong ALLOWED_SSH_USERS phía server"
              fullWidth
            />
            <TextField
              label="SSH port"
              type="number"
              value={editForm.ssh_port}
              onChange={(e) => setEditForm({ ...editForm, ssh_port: Number(e.target.value) || 0 })}
              inputProps={{ min: 1, max: 65535 }}
              error={editForm.ssh_port < 1 || editForm.ssh_port > 65535}
              helperText="Chỉ KHAI LẠI — không tự đổi gì trên host thật. Đổi cổng an toàn (có xác minh kết nối) dùng 'Đổi cổng SSH' ở menu Actions."
              fullWidth
            />
            <TextField
              label="SSH password mới (để trống = giữ nguyên)"
              type="password"
              value={editForm.ssh_password}
              onChange={(e) => setEditForm({ ...editForm, ssh_password: e.target.value })}
              disabled={editForm.clearSshPassword}
              helperText={
                editHost?.has_ssh_password
                  ? "Đã có password lưu sẵn — chỉ nhập nếu muốn ghi đè"
                  : "Chưa cấu hình password cho host này"
              }
              fullWidth
            />
            {editHost?.has_ssh_password && (
              <FormControlLabel
                control={
                  <Checkbox
                    checked={editForm.clearSshPassword}
                    onChange={(e) =>
                      setEditForm({ ...editForm, clearSshPassword: e.target.checked, ssh_password: "" })
                    }
                  />
                }
                label="Xoá password đã lưu"
              />
            )}
            {editHost?.has_static_ssh_key && (
              <>
                <Alert severity="info">
                  Host này đang dùng 1 SSH key tĩnh đã lưu cho mọi job SSH (xem "Thiết lập trust" ở
                  menu Actions) — không xem lại được key này qua đâu, chỉ xoá được.
                </Alert>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={editForm.clearStaticSshKey}
                      onChange={(e) => setEditForm({ ...editForm, clearStaticSshKey: e.target.checked })}
                    />
                  }
                  label="Xoá SSH key tĩnh đã lưu (job SSH sau này sẽ cần cert CA — phải đã bootstrap-ca-trust từ trước)"
                />
              </>
            )}
            <FormControl fullWidth>
              <InputLabel id="edit-exposure-label">Mức độ tiếp xúc Internet</InputLabel>
              <Select
                labelId="edit-exposure-label"
                label="Mức độ tiếp xúc Internet"
                value={editForm.exposure}
                onChange={(e) => setEditForm({ ...editForm, exposure: e.target.value as ExposureLevel })}
              >
                {EXPOSURE_LEVELS.map((level) => (
                  <MenuItem key={level} value={level}>
                    {exposureLabel[level]}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditHost(null)}>Huỷ</Button>
          <Button
            variant="contained"
            onClick={handleSaveEdit}
            disabled={editSaving || editForm.ssh_port < 1 || editForm.ssh_port > 65535}
          >
            {editSaving ? <CircularProgress size={16} /> : "Lưu"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Đổi cổng SSH thật — có tự xác minh kết nối trước khi coi thành công,
          xem app/jobs.py:trigger_ssh_port_change. KHÔNG có bước "xem trước"
          riêng vì cơ chế tự xác minh chính là cửa an toàn (nếu cổng mới
          không kết nối được, host vẫn nghe cả cổng cũ, không mất kết nối). */}
      <Dialog
        open={portChangeHost !== null}
        onClose={() => setPortChangeHost(null)}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>Đổi cổng SSH — {portChangeHost?.hostname}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Alert severity="warning">
              Hệ thống sẽ tự cấu hình host nghe CẢ 2 cổng (cũ + mới), tự kiểm tra kết nối được
              cổng mới TRƯỚC KHI gỡ cổng cũ — nếu không kết nối được, cổng cũ vẫn giữ nguyên,
              không mất kết nối. Vẫn nên cẩn trọng với host Tier 0/1.
            </Alert>
            <Typography variant="body2" color="text.secondary">
              Cổng hiện tại: <strong>{portChangeHost?.ssh_port}</strong>
            </Typography>
            <TextField
              label="Cổng mới"
              type="number"
              value={newSshPort}
              onChange={(e) => setNewSshPort(Number(e.target.value) || 0)}
              inputProps={{ min: 1, max: 65535 }}
              error={newSshPort < 1 || newSshPort > 65535}
              fullWidth
            />
            {changingPort && (
              <Stack direction="row" spacing={1} alignItems="center">
                <CircularProgress size={20} />
                <Typography variant="body2">
                  Đang đổi cổng (cấu hình 2 cổng, xác minh, gỡ cổng cũ)...
                </Typography>
              </Stack>
            )}
            {portChangeResult && (
              <Stack spacing={1}>
                <Stack direction="row" spacing={1} alignItems="center">
                  <Typography>Job #{portChangeResult.id}</Typography>
                  <Chip label={portChangeResult.status} color={progressColor(portChangeResult.status)} size="small" />
                </Stack>
                {portChangeResult.status !== "succeeded" && (
                  <Typography variant="body2" color="text.secondary">
                    Xem chi tiết log (dòng PORT_CHANGE_STATUS) ở job #{portChangeResult.id} tại
                    trang Jobs.
                  </Typography>
                )}
              </Stack>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPortChangeHost(null)}>Đóng</Button>
          <Button
            variant="contained"
            onClick={handleChangeSshPort}
            disabled={
              changingPort ||
              !portChangeHost ||
              newSshPort === portChangeHost?.ssh_port ||
              newSshPort < 1 ||
              newSshPort > 65535
            }
          >
            {changingPort ? <CircularProgress size={16} /> : "Đổi cổng"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Tiến độ % THẬT cho "Test SSH"/"Cài Agent" — dùng chung 1 Dialog cho
          cả 2 (chỉ 2 job_type có script in marker ##PROGRESS##, xem
          app/jobs.py:_PROGRESS_SUPPORTED_JOB_TYPES). Không có nút "Đóng" khi
          còn "running" — tự đóng khi useEffect polling phía trên phát hiện
          job terminal, đúng lúc bắn Snackbar kết quả cuối, xem
          handleTestSsh/handleInstallAgent + useEffect poll ở trên. */}
      <Dialog open={progressJob !== null} maxWidth="sm" fullWidth>
        <DialogTitle>
          {progressJob?.kind === "agent-install" ? "Cài Agent" : "Test SSH"} — {progressJob?.hostname}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <LinearProgress
              variant={jobProgress ? "determinate" : "indeterminate"}
              value={jobProgress?.pct ?? 0}
            />
            <Typography variant="body2" color="text.secondary">
              {jobProgress?.stage ?? "starting"}
            </Typography>
          </Stack>
        </DialogContent>
      </Dialog>

      {/* OS/kernel/phần cứng thu thập lúc "Test SSH" — xem
          apps/execution-env/ssh-check.sh + app/models.py:Host.system_info.
          Hiển thị nguyên các khoá có mặt (máy thiếu lệnh/file nào thì khoá
          đó vắng), KHÔNG bịa giá trị mặc định cho khoá thiếu. */}
      <Dialog
        open={systemInfoHost !== null}
        onClose={() => setSystemInfoHost(null)}
        fullWidth
        maxWidth="md"
      >
        <DialogTitle>Thông tin máy — {systemInfoHost?.hostname}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            {/* Gauge % tài nguyên — do Agent tự đo, KHÁC nguồn/cadence với
                phần system_info (SSH) bên dưới, xem comment
                app/models.py:Host.metrics. Tự hiện "chưa có" riêng, không
                phụ thuộc phần system_info có dữ liệu hay không. */}
            <Stack spacing={1}>
              <Typography variant="caption" color="text.secondary">
                Số liệu tài nguyên do Agent tự đo, làm mới mỗi ~3 phút — CHỈ có với host đã cài Agent.
                {systemInfoHost?.metrics_updated_at ? (
                  <>
                    {" "}Cập nhật lúc{" "}
                    <strong>{new Date(systemInfoHost.metrics_updated_at).toLocaleString()}</strong>{" "}
                    ({formatRelativeTime(systemInfoHost.metrics_updated_at)}).
                  </>
                ) : (
                  " Chưa có dữ liệu (cần cài Agent và đợi lần báo cáo đầu, ~3 phút sau khi Agent khởi động)."
                )}
              </Typography>
              <Stack direction="row" spacing={3} justifyContent="center">
                <ResourceGauge label="CPU" pct={(systemInfoHost?.metrics.cpu_pct as number) ?? null} />
                <ResourceGauge label="RAM" pct={(systemInfoHost?.metrics.ram_pct as number) ?? null} />
                <ResourceGauge label="Disk" pct={(systemInfoHost?.metrics.disk_pct as number) ?? null} />
                <ResourceGauge
                  label="Network"
                  pct={(systemInfoHost?.metrics.net_pct as number) ?? null}
                  sublabel={systemInfoHost?.metrics.net_iface as string | undefined}
                />
              </Stack>
              {systemInfoHost?.metrics.executor_reachable === false && (
                <Alert severity="error">
                  Executor không phản hồi trên host này — remediate qua Agent (fix lỗi) sẽ lỗi cho
                  tới khi khởi động lại <code>hardening-executor.service</code>. Scan/giám sát qua
                  Agent không bị ảnh hưởng (Reporter và Executor là 2 tiến trình độc lập).
                </Alert>
              )}
            </Stack>
            <Divider />
            <Alert severity="info">
              Do chính máy đích tự khai lúc "Test SSH" chạy thành công — dùng để tra cứu nhanh,
              KHÔNG phải bằng chứng tuân thủ (kết luận tuân thủ vẫn lấy từ job Quét).
              {systemInfoHost?.system_info_updated_at && (
                <>
                  {" "}Thu thập lúc{" "}
                  <strong>
                    {new Date(systemInfoHost.system_info_updated_at).toLocaleString()}
                  </strong>{" "}
                  ({formatRelativeTime(systemInfoHost.system_info_updated_at)}).
                </>
              )}
            </Alert>
            <Table size="small">
              <TableBody>
                {SYSTEM_INFO_ROWS.map(({ key, label, format }) => {
                  const raw = systemInfoHost?.system_info[key];
                  if (!raw) return null;
                  return (
                    <TableRow key={key}>
                      <TableCell sx={{ width: 180, color: "text.secondary" }}>{label}</TableCell>
                      <TableCell>{format ? format(raw) : raw}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSystemInfoHost(null)}>Đóng</Button>
        </DialogActions>
      </Dialog>

      {/* Xem lại SSH credential đã lưu — tách riêng khỏi dialog Sửa, chỉ
          fetch khi bấm rõ ràng (admin-only phía backend, tự audit mỗi lần). */}
      <Dialog
        open={viewCredentialHost !== null}
        onClose={() => {
          setViewCredentialHost(null);
          setViewCredentialResult(null);
        }}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>SSH credential — {viewCredentialHost?.hostname}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            {viewingCredential && (
              <Stack direction="row" spacing={1} alignItems="center">
                <CircularProgress size={20} />
                <Typography variant="body2">Đang lấy credential...</Typography>
              </Stack>
            )}
            {viewCredentialResult && (
              <>
                <Alert severity="info">Mỗi lần xem đều được ghi lại vào audit log.</Alert>
                <TextField label="SSH user" value={viewCredentialResult.ssh_user} InputProps={{ readOnly: true }} fullWidth />
                {viewCredentialResult.ssh_password !== null ? (
                  <TextField
                    label="SSH password"
                    value={viewCredentialResult.ssh_password}
                    InputProps={{ readOnly: true }}
                    fullWidth
                  />
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    Chưa cấu hình password cho host này.
                  </Typography>
                )}
              </>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setViewCredentialHost(null);
              setViewCredentialResult(null);
            }}
          >
            Đóng
          </Button>
        </DialogActions>
      </Dialog>

      {/* Xoá host thật (hard-delete, admin-only) — xoá TOÀN BỘ dữ liệu liên
          quan (kể cả lịch sử job/remediation request), xem app/hosts.py. */}
      <Dialog open={deleteHostTarget !== null} onClose={() => setDeleteHostTarget(null)} fullWidth maxWidth="sm">
        <DialogTitle>Xoá host — {deleteHostTarget?.hostname}</DialogTitle>
        <DialogContent>
          <Alert severity="error">
            Xoá THẬT, KHÔNG thể hoàn tác — mất luôn toàn bộ lịch sử job/remediation của host này,
            không chỉ riêng thông tin đăng ký. Hệ thống sẽ cố gắng gỡ Agent trên máy thật qua SSH
            trước khi xoá (nếu máy có cài và còn kết nối được) — nếu máy không còn online, bước gỡ
            Agent bị bỏ qua nhưng record trên console vẫn bị xoá. Muốn GIỮ lại lịch sử, dùng
            "Tạm ngưng quản lý" (không xoá gì) thay vào đó.
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteHostTarget(null)}>Huỷ</Button>
          <Button variant="contained" color="error" onClick={handleDeleteHost} disabled={deleting}>
            {deleting ? <CircularProgress size={16} /> : "Xác nhận xoá"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Thiết lập trust cho host còn "not_started" bằng credential CŨ — dùng
          ĐÚNG 1 LẦN, KHÔNG lưu lại (credential CŨ này — key TĨNH MỚI sinh ra
          ở nhánh "static_key" thì CÓ lưu lại, xem cảnh báo trong dialog).
          Chọn 1 trong 2 cơ chế loại trừ nhau — xem app/jobs.py:
          trigger_ca_bootstrap / trigger_static_ssh_key_bootstrap. */}
      <Dialog open={bootstrapHost !== null} onClose={resetBootstrapForm} fullWidth maxWidth="sm">
        <DialogTitle>Thiết lập trust — {bootstrapHost?.hostname}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <FormLabel>Cơ chế</FormLabel>
            <RadioGroup
              value={bootstrapForm.mechanism}
              onChange={(e) =>
                setBootstrapForm({ ...bootstrapForm, mechanism: e.target.value as "ca_cert" | "static_key" })
              }
            >
              <FormControlLabel
                value="ca_cert"
                control={<Radio />}
                label="CA cert ngắn hạn (khuyến nghị) — không lưu secret nào, mỗi job tự mint cert mới"
              />
              <FormControlLabel
                value="static_key"
                control={<Radio />}
                label="SSH key tĩnh — tạo 1 key, LƯU LẠI trên console, dùng cho mọi job SSH sau này"
              />
            </RadioGroup>
            {bootstrapForm.mechanism === "ca_cert" ? (
              <Alert severity="warning">
                Credential dưới đây chỉ dùng ĐÚNG 1 LẦN để tự động bước 1 Zero-to-CA Migration (đẩy
                public key CA + bật TrustedUserCAKeys + reload sshd) — KHÔNG được lưu lại ở bất kỳ
                đâu (không DB, không log). Yêu cầu: user đăng nhập là <code>root</code>, hoặc có sudo{" "}
                <strong>không cần mật khẩu</strong>. Sau bước này, credential cũ <strong>vẫn còn hoạt
                động</strong> — tự verify cert mới rồi thu hồi credential cũ thủ công (xem{" "}
                <code>ansible/README.md</code> bước 2), console không tự làm bước đó.
              </Alert>
            ) : (
              <Alert severity="error">
                Đánh đổi bảo mật CÓ CHỦ ĐÍCH: sẽ tạo 1 SSH keypair mới, cài public key lên host, và{" "}
                <strong>LƯU LẠI private key (mã hoá) trên console mãi mãi</strong> — không có bước
                "revoke" như credential cũ. Nếu console bị chiếm, key này lộ ra cho mọi host đã dùng
                cơ chế này. Credential CŨ nhập dưới đây vẫn chỉ dùng đúng 1 lần, không lưu lại —
                KHÔNG đổi cấu hình sshd trên host đích (không TrustedUserCAKeys). Yêu cầu: user đăng
                nhập là <code>root</code>, hoặc có sudo <strong>không cần mật khẩu</strong>.
              </Alert>
            )}
            <TextField
              label="Legacy SSH user"
              value={bootstrapForm.legacy_ssh_user}
              onChange={(e) => setBootstrapForm({ ...bootstrapForm, legacy_ssh_user: e.target.value })}
              fullWidth
            />
            <FormLabel>Xác thực bằng</FormLabel>
            <RadioGroup
              row
              value={bootstrapForm.authMethod}
              onChange={(e) =>
                setBootstrapForm({ ...bootstrapForm, authMethod: e.target.value as "password" | "key" })
              }
            >
              <FormControlLabel value="password" control={<Radio />} label="Password" />
              <FormControlLabel value="key" control={<Radio />} label="Private key" />
            </RadioGroup>
            {bootstrapForm.authMethod === "password" ? (
              <TextField
                label="Legacy SSH password"
                type="password"
                value={bootstrapForm.legacy_ssh_password}
                onChange={(e) =>
                  setBootstrapForm({ ...bootstrapForm, legacy_ssh_password: e.target.value })
                }
                fullWidth
              />
            ) : (
              <TextField
                label="Legacy SSH private key (nội dung file, vd id_rsa)"
                value={bootstrapForm.legacy_ssh_private_key}
                onChange={(e) =>
                  setBootstrapForm({ ...bootstrapForm, legacy_ssh_private_key: e.target.value })
                }
                multiline
                minRows={4}
                fullWidth
              />
            )}
            {bootstrapping && (
              <Stack direction="row" spacing={1} alignItems="center">
                <CircularProgress size={20} />
                <Typography variant="body2">Đang kết nối bằng credential cũ...</Typography>
              </Stack>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={resetBootstrapForm}>Huỷ</Button>
          <Button
            variant="contained"
            onClick={handleBootstrapCaTrust}
            disabled={
              bootstrapping ||
              !bootstrapForm.legacy_ssh_user ||
              (bootstrapForm.authMethod === "password"
                ? !bootstrapForm.legacy_ssh_password
                : !bootstrapForm.legacy_ssh_private_key)
            }
          >
            Chạy bootstrap
          </Button>
        </DialogActions>
      </Dialog>

      {/* Trigger scan */}
      <Dialog open={scanHost !== null} onClose={() => { setScanHost(null); setJobResult(null); }} fullWidth maxWidth="md">
        <DialogTitle>Trigger scan — {scanHost?.hostname}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Select value={scapProfileKey} onChange={(e) => setScapProfileKey(e.target.value)}>
              {SCAP_PROFILE_KEYS.map((k) => (
                <MenuItem key={k} value={k}>
                  {k}
                </MenuItem>
              ))}
            </Select>
            <Typography variant="caption" color="text.secondary">
              Dùng ssh_user đã cấu hình cho host này ("{scanHost?.ssh_user}") — sửa qua nút "Sửa" ở
              bảng nếu cần đổi.
            </Typography>
            {scanning && (
              <Stack direction="row" spacing={1} alignItems="center">
                <CircularProgress size={20} />
                <Typography variant="body2">
                  Đang scan thật (mint SSH cert, spawn container, oscap-ssh) — có thể mất 30-90s...
                </Typography>
              </Stack>
            )}
            {jobResult && (
              <Stack spacing={1}>
                <Stack direction="row" spacing={1} alignItems="center">
                  <Typography>Job #{jobResult.id}</Typography>
                  <Chip
                    label={jobResult.status}
                    color={progressColor(jobResult.status)}
                    size="small"
                  />
                </Stack>
                {findings.length > 0 ? (
                  <FindingsTable findings={findings} />
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    Không có finding pass/fail nào (có thể do content SCAP không khớp phiên bản OS —
                    xem README mục ghi chú vận hành).
                  </Typography>
                )}
              </Stack>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => { setScanHost(null); setJobResult(null); }}>Đóng</Button>
          <Button variant="contained" onClick={handleTriggerScan} disabled={scanning}>
            Chạy scan
          </Button>
        </DialogActions>
      </Dialog>

      {/* Tạo enrollment token cho Agent tự phát triển (mục 4.3) */}
      <Dialog
        open={enrollHost !== null}
        onClose={() => {
          setEnrollHost(null);
          setEnrollResult(null);
        }}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>Bootstrap token cho agent — {enrollHost?.hostname}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            {enrolling && (
              <Stack direction="row" spacing={1} alignItems="center">
                <CircularProgress size={20} />
                <Typography variant="body2">Đang tạo token qua step-ca...</Typography>
              </Stack>
            )}
            {!enrolling && !enrollResult && enrollHost && (
              <Stack spacing={1} alignItems="flex-start">
                <Typography variant="body2" color="text.secondary">
                  Chưa tạo được token — thử lại?
                </Typography>
                <Button variant="outlined" onClick={() => handleCreateEnrollmentToken(enrollHost)}>
                  Thử lại
                </Button>
              </Stack>
            )}
            {enrollResult && (
              <>
                <Alert severity="warning">
                  Token chỉ hiển thị ĐÚNG 1 LẦN — sao chép và đặt vào file <code>enroll-token</code>{" "}
                  trên máy đích (cùng <code>ca-root.crt</code>) trước khi hết hạn. Xem{" "}
                  <code>apps/agent/README.md</code> để biết các bước tiếp theo.
                </Alert>
                <TextField
                  label="Bootstrap token"
                  value={enrollResult.token}
                  multiline
                  fullWidth
                  InputProps={{ readOnly: true }}
                />
                <Typography variant="body2" color="text.secondary">
                  Hết hạn lúc: {new Date(enrollResult.expires_at).toLocaleString()}
                </Typography>
                <Button
                  variant="outlined"
                  onClick={() => {
                    // writeText() có thể reject (context không secure, quyền
                    // clipboard bị chặn...) — im lặng bỏ qua sẽ khiến operator
                    // tưởng đã copy được 1 token dùng-1-lần không thể lấy lại,
                    // nên phải báo rõ thành công/thất bại qua Snackbar chung.
                    navigator.clipboard.writeText(enrollResult.token).then(
                      () => showSuccess("Đã sao chép token vào clipboard"),
                      () => showError("Không sao chép được — hãy tự chọn và copy thủ công từ ô bên trên")
                    );
                  }}
                >
                  Sao chép token
                </Button>
              </>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setEnrollHost(null);
              setEnrollResult(null);
            }}
          >
            Đóng
          </Button>
        </DialogActions>
      </Dialog>

      {/* Sinh script cài Agent gộp sẵn (provision.sh + 2 systemd unit + token +
          ca-root.crt) — operator tự dán vào phiên SSH của chính họ tới máy
          đích, Orchestrator KHÔNG tự SSH/chạy hộ. Vẫn cần binary agent/executor
          đã scp sẵn lên máy đích trước (script tự kiểm tra + báo lỗi rõ). */}
      <Dialog
        open={installScriptHost !== null}
        onClose={() => {
          setInstallScriptHost(null);
          setInstallScriptResult(null);
        }}
        fullWidth
        maxWidth="md"
      >
        <DialogTitle>Script cài Agent — {installScriptHost?.hostname}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            {generatingInstallScript && (
              <Stack direction="row" spacing={1} alignItems="center">
                <CircularProgress size={20} />
                <Typography variant="body2">Đang sinh script (tạo bootstrap token qua step-ca)...</Typography>
              </Stack>
            )}
            {!generatingInstallScript && !installScriptResult && installScriptHost && (
              <Stack spacing={1} alignItems="flex-start">
                <Typography variant="body2" color="text.secondary">
                  Chưa sinh được script — thử lại?
                </Typography>
                <Button
                  variant="outlined"
                  onClick={() => handleGenerateInstallScript(installScriptHost)}
                >
                  Thử lại
                </Button>
              </Stack>
            )}
            {installScriptResult && (
              <>
                <Alert severity="warning">
                  Script chứa bootstrap token DÙNG 1 LẦN, hết hạn lúc{" "}
                  {new Date(installScriptResult.expires_at).toLocaleString()} — chỉ hiển thị ĐÚNG 1
                  LẦN. Dán vào phiên SSH của <strong>chính bạn</strong> tới máy đích rồi chạy bằng
                  root (KHÔNG phải Orchestrator tự chạy hộ — xem lý do trong{" "}
                  <code>apps/agent/README.md</code>). Cần binary <code>agent</code>/
                  <code>executor</code> đã build sẵn tại <code>/opt/hardening-agent/</code> trên
                  máy đích TRƯỚC — script tự kiểm tra và báo lỗi rõ nếu thiếu.
                </Alert>
                <TextField
                  value={installScriptResult.script}
                  multiline
                  fullWidth
                  minRows={10}
                  maxRows={20}
                  InputProps={{
                    readOnly: true,
                    sx: { fontFamily: "monospace", fontSize: "0.75rem" },
                  }}
                />
                <Button
                  variant="outlined"
                  onClick={() => {
                    navigator.clipboard.writeText(installScriptResult.script).then(
                      () => showSuccess("Đã sao chép script vào clipboard"),
                      () => showError("Không sao chép được — hãy tự chọn và copy thủ công từ ô bên trên")
                    );
                  }}
                >
                  Sao chép script
                </Button>
              </>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button
            onClick={() => {
              setInstallScriptHost(null);
              setInstallScriptResult(null);
            }}
          >
            Đóng
          </Button>
        </DialogActions>
      </Dialog>

    </Stack>
  );
}
