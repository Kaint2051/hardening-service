import { useEffect, useRef, useState } from "react";
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
import IconButton from "@mui/material/IconButton";
import Dialog from "@mui/material/Dialog";
import DialogTitle from "@mui/material/DialogTitle";
import DialogContent from "@mui/material/DialogContent";
import DialogActions from "@mui/material/DialogActions";
import TextField from "@mui/material/TextField";
import Snackbar from "@mui/material/Snackbar";
import Alert from "@mui/material/Alert";
import CircularProgress from "@mui/material/CircularProgress";
import Tooltip from "@mui/material/Tooltip";
import Checkbox from "@mui/material/Checkbox";
import FormControlLabel from "@mui/material/FormControlLabel";
import FormLabel from "@mui/material/FormLabel";
import Radio from "@mui/material/Radio";
import RadioGroup from "@mui/material/RadioGroup";
import { api, ApiError } from "../api/client";
import { CA_MIGRATION_STATUSES, SCAP_PROFILE_KEYS } from "../api/types";
import type {
  AgentEnrollmentTokenOut,
  AgentInstallScriptOut,
  CaMigrationStatus,
  HostOut,
  HostSshCredentialOut,
  JobOut,
} from "../api/types";

const statusColor: Record<CaMigrationStatus, "default" | "warning" | "success"> = {
  not_started: "default",
  trust_deployed: "warning",
  migrated: "success",
};

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
  const [hosts, setHosts] = useState<HostOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [snack, setSnack] = useState<{ severity: "success" | "error"; message: string } | null>(null);
  // Mặc định ẩn host đã decommission (khớp include_decommissioned=false mặc
  // định phía backend) — bật lên khi cần tra cứu/khôi phục.
  const [includeDecommissioned, setIncludeDecommissioned] = useState(false);

  const [registerOpen, setRegisterOpen] = useState(false);
  const [registerForm, setRegisterForm] = useState({
    hostname: "",
    ip_address: "",
    os_family: "",
    os_version: "",
    tier: 2,
    ssh_user: "root",
    ssh_password: "",
  });

  // Sửa host đã đăng ký (ip_address/os_family/os_version/tier/ssh_user) —
  // xem app/hosts.py:update_host. `tier` chỉ admin sửa được, form KHÔNG tự
  // ẩn field theo role (RBAC 100% phía backend, cùng quy ước toàn app).
  // ssh_password: ô để trống + KHÔNG tick "xoá" = giữ nguyên (không gửi field
  // này lên server); tick "xoá" = gửi "" (server xoá); có nhập chữ = ghi đè.
  // Không bao giờ điền sẵn giá trị cũ vào ô này (chỉ xem qua "Xem SSH
  // credential" riêng, xem viewCredentialHost bên dưới).
  const [editHost, setEditHost] = useState<HostOut | null>(null);
  const [editForm, setEditForm] = useState({
    ip_address: "", os_family: "", os_version: "", tier: 2, ssh_user: "root",
    ssh_password: "", clearSshPassword: false,
  });
  const [editSaving, setEditSaving] = useState(false);

  // Xem lại SSH credential đã lưu (admin-only phía backend, tự audit mỗi
  // lần gọi) — tách riêng khỏi dialog Sửa, chỉ fetch khi bấm rõ ràng.
  const [viewCredentialHost, setViewCredentialHost] = useState<HostOut | null>(null);
  const [viewingCredential, setViewingCredential] = useState(false);
  const [viewCredentialResult, setViewCredentialResult] = useState<HostSshCredentialOut | null>(null);

  // Xoá host thật (hard-delete, admin-only) — CHỈ thành công nếu host chưa
  // từng chạy job (409 nếu đã có lịch sử, xem app/hosts.py:delete_host).
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
  // nhất khi nó resolve.
  const enrollRequestIdRef = useRef(0);

  // "Test SSH" — chỉ khả thi cho host đã trust_deployed/migrated (xem
  // app/jobs.py:trigger_ssh_check). Kết quả báo qua Snackbar, không cần
  // dialog riêng (không có input nào phải cấu hình trước, khác Trigger scan).
  const [testingSshHostname, setTestingSshHostname] = useState<string | null>(null);
  const testSshRequestIdRef = useRef(0);

  // Remote-deploy Agent tự động — cùng lớp race-condition đã gặp ở
  // testSshRequestIdRef ngay trên (bấm liên tiếp cho 2 host khác nhau).
  const [installingAgentHostname, setInstallingAgentHostname] = useState<string | null>(null);
  const installAgentRequestIdRef = useRef(0);

  // Menu "..." gộp toàn bộ action của 1 dòng host — thay cho việc xếp thẳng
  // hàng 9 nút riêng biệt trong cột Actions (quá dài/rối khi nhiều host).
  const [actionMenu, setActionMenu] = useState<{ anchorEl: HTMLElement; host: HostOut } | null>(null);

  // Sinh script cài Agent gộp sẵn — cùng lớp race-condition đã gặp ở
  // enrollRequestIdRef phía trên (bấm liên tiếp cho 2 host khác nhau).
  const [installScriptHost, setInstallScriptHost] = useState<HostOut | null>(null);
  const [generatingInstallScript, setGeneratingInstallScript] = useState(false);
  const [installScriptResult, setInstallScriptResult] = useState<AgentInstallScriptOut | null>(null);
  const installScriptRequestIdRef = useRef(0);

  // Bootstrap CA trust bằng credential CŨ — dùng ĐÚNG 1 LẦN, xem
  // app/jobs.py:trigger_ca_bootstrap. Chỉ khả thi khi ca_migration_status
  // còn "not_started". Form tự xoá password/private key khỏi state ngay sau
  // khi request xong (thành công lẫn lỗi) — không giữ lại trong React state
  // lâu hơn mức cần thiết.
  const [bootstrapHost, setBootstrapHost] = useState<HostOut | null>(null);
  const [bootstrapForm, setBootstrapForm] = useState({
    legacy_ssh_user: "root",
    authMethod: "password" as "password" | "key",
    legacy_ssh_password: "",
    legacy_ssh_private_key: "",
  });
  const [bootstrapping, setBootstrapping] = useState(false);

  const loadHosts = () => {
    setLoading(true);
    api
      .listHosts(undefined, includeDecommissioned)
      .then(setHosts)
      .catch((err) => setSnack({ severity: "error", message: String(err) }))
      .finally(() => setLoading(false));
  };

  useEffect(loadHosts, [includeDecommissioned]);

  const handleRegister = async () => {
    try {
      await api.registerHost({
        ...registerForm,
        os_version: registerForm.os_version || undefined,
        ssh_password: registerForm.ssh_password || undefined,
      });
      setRegisterOpen(false);
      setRegisterForm({
        hostname: "", ip_address: "", os_family: "", os_version: "", tier: 2,
        ssh_user: "root", ssh_password: "",
      });
      setSnack({ severity: "success", message: "Đã đăng ký host" });
      loadHosts();
    } catch (err) {
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    }
  };

  const openEditHost = (host: HostOut) => {
    setEditHost(host);
    setEditForm({
      ip_address: host.ip_address,
      os_family: host.os_family,
      os_version: host.os_version ?? "",
      tier: host.tier,
      ssh_user: host.ssh_user,
      ssh_password: "",
      clearSshPassword: false,
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
        os_family: editForm.os_family,
        os_version: editForm.os_version || undefined,
        tier: editForm.tier,
        ssh_user: editForm.ssh_user,
        ssh_password,
      });
      setSnack({ severity: "success", message: `Đã cập nhật ${editHost.hostname}` });
      setEditHost(null);
      loadHosts();
    } catch (err) {
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    } finally {
      // Xoá password khỏi state ngay dù thành công hay lỗi — không giữ lại
      // lâu hơn mức cần thiết trong bộ nhớ trình duyệt.
      setEditForm((f) => ({ ...f, ssh_password: "", clearSshPassword: false }));
      setEditSaving(false);
    }
  };

  const handleMigrationStatusChange = async (host: HostOut, status: CaMigrationStatus) => {
    try {
      await api.updateHostMigrationStatus(host.hostname, status);
      setSnack({ severity: "success", message: `Đã cập nhật ${host.hostname} -> ${status}` });
      loadHosts();
    } catch (err) {
      setSnack({
        severity: "error",
        message: err instanceof ApiError ? err.message : String(err),
      });
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
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    } finally {
      setScanning(false);
    }
  };

  const handleCreateEnrollmentToken = async (host: HostOut) => {
    const requestId = ++enrollRequestIdRef.current;
    setEnrollHost(host);
    setEnrollResult(null);
    setEnrolling(true);
    try {
      const result = await api.createAgentEnrollmentToken(host.hostname);
      // 1 request mới hơn (click host khác) đã bắt đầu trong lúc chờ — bỏ
      // kết quả cũ, không ghi đè dialog đang mở cho host khác.
      if (enrollRequestIdRef.current !== requestId) return;
      setEnrollResult(result);
    } catch (err) {
      if (enrollRequestIdRef.current !== requestId) return;
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
      // KHÔNG đóng dialog (khác các handler khác trong app luôn giữ dialog
      // mở khi lỗi để retry tại chỗ) — chỉ dừng spinner, còn lại nút "Thử
      // lại" bên dưới xử lý.
    } finally {
      if (enrollRequestIdRef.current === requestId) {
        setEnrolling(false);
      }
    }
  };

  const handleTestSsh = async (host: HostOut) => {
    const requestId = ++testSshRequestIdRef.current;
    setTestingSshHostname(host.hostname);
    try {
      const job = await api.testSshReachability(host.hostname);
      if (testSshRequestIdRef.current !== requestId) return;
      if (job.status === "succeeded") {
        const uname = (job.result_summary?.ssh_check_uname as string | undefined) ?? "";
        setSnack({ severity: "success", message: `SSH tới ${host.hostname} OK — ${uname}` });
      } else {
        setSnack({
          severity: "error",
          message: `SSH tới ${host.hostname} thất bại — xem chi tiết ở job #${job.id} (trang Jobs)`,
        });
      }
    } catch (err) {
      if (testSshRequestIdRef.current !== requestId) return;
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    } finally {
      if (testSshRequestIdRef.current === requestId) setTestingSshHostname(null);
    }
  };

  const handleInstallAgent = async (host: HostOut) => {
    const requestId = ++installAgentRequestIdRef.current;
    setInstallingAgentHostname(host.hostname);
    try {
      const job = await api.installAgent(host.hostname);
      if (installAgentRequestIdRef.current !== requestId) return;
      if (job.status === "succeeded") {
        setSnack({ severity: "success", message: `Đã cài Agent lên ${host.hostname} (job #${job.id})` });
      } else {
        setSnack({
          severity: "error",
          message: `Cài Agent lên ${host.hostname} thất bại — xem chi tiết ở job #${job.id} (trang Jobs)`,
        });
      }
    } catch (err) {
      if (installAgentRequestIdRef.current !== requestId) return;
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    } finally {
      if (installAgentRequestIdRef.current === requestId) setInstallingAgentHostname(null);
    }
  };

  const handleToggleDecommission = async (host: HostOut, decommissioned: boolean) => {
    try {
      await api.updateHostDecommission(host.hostname, decommissioned);
      setSnack({
        severity: "success",
        message: decommissioned
          ? `Đã decommission ${host.hostname} — lịch sử job/audit vẫn giữ nguyên`
          : `Đã recommission ${host.hostname}`,
      });
      loadHosts();
    } catch (err) {
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
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
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
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
      setSnack({ severity: "success", message: `Đã xoá ${deleteHostTarget.hostname}` });
      setDeleteHostTarget(null);
      loadHosts();
    } catch (err) {
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    } finally {
      setDeleting(false);
    }
  };

  const handleGenerateInstallScript = async (host: HostOut) => {
    const requestId = ++installScriptRequestIdRef.current;
    setInstallScriptHost(host);
    setInstallScriptResult(null);
    setGeneratingInstallScript(true);
    try {
      const result = await api.createAgentInstallScript(host.hostname);
      if (installScriptRequestIdRef.current !== requestId) return;
      setInstallScriptResult(result);
    } catch (err) {
      if (installScriptRequestIdRef.current !== requestId) return;
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    } finally {
      if (installScriptRequestIdRef.current === requestId) setGeneratingInstallScript(false);
    }
  };

  const resetBootstrapForm = () => {
    setBootstrapHost(null);
    setBootstrapForm({
      legacy_ssh_user: "root",
      authMethod: "password",
      legacy_ssh_password: "",
      legacy_ssh_private_key: "",
    });
  };

  const handleBootstrapCaTrust = async () => {
    if (!bootstrapHost) return;
    setBootstrapping(true);
    try {
      const job = await api.bootstrapCaTrust(bootstrapHost.hostname, {
        legacy_ssh_user: bootstrapForm.legacy_ssh_user,
        ...(bootstrapForm.authMethod === "password"
          ? { legacy_ssh_password: bootstrapForm.legacy_ssh_password }
          : { legacy_ssh_private_key: bootstrapForm.legacy_ssh_private_key }),
      });
      if (job.status === "succeeded") {
        setSnack({
          severity: "success",
          message: `Đã bật CA trust cho ${bootstrapHost.hostname} (job #${job.id}) — ca_migration_status = trust_deployed. Nhớ tự verify + thu hồi credential cũ (ansible/README.md bước 2).`,
        });
      } else {
        setSnack({
          severity: "error",
          message: `Bootstrap CA trust thất bại cho ${bootstrapHost.hostname} — xem job #${job.id} (trang Jobs)`,
        });
      }
      resetBootstrapForm();
      loadHosts();
    } catch (err) {
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    } finally {
      // Xoá credential khỏi state NGAY dù thành công hay lỗi — không giữ
      // lại trong bộ nhớ trình duyệt lâu hơn mức cần thiết.
      setBootstrapForm((f) => ({ ...f, legacy_ssh_password: "", legacy_ssh_private_key: "" }));
      setBootstrapping(false);
    }
  };

  const findings = (jobResult?.result_summary?.findings as
    | { rule_id: string; title: string; result: string; severity: string }[]
    | undefined) ?? [];

  return (
    <Stack spacing={2}>
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Typography variant="h5">Hosts</Typography>
        <Stack direction="row" spacing={1} alignItems="center">
          <FormControlLabel
            control={
              <Checkbox
                size="small"
                checked={includeDecommissioned}
                onChange={(e) => setIncludeDecommissioned(e.target.checked)}
              />
            }
            label="Hiện cả host đã decommission"
          />
          <Button variant="outlined" onClick={loadHosts}>
            Tải lại
          </Button>
          <Button variant="contained" onClick={() => setRegisterOpen(true)}>
            Đăng ký host
          </Button>
        </Stack>
      </Stack>

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
                <TableCell>Agent</TableCell>
                <TableCell>Added by</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {hosts.map((h) => {
                const isDecommissioned = h.decommissioned_at !== null;
                return (
                  <TableRow key={h.hostname} sx={isDecommissioned ? { opacity: 0.6 } : undefined}>
                    <TableCell>
                      <Stack direction="row" spacing={1} alignItems="center">
                        {h.hostname}
                        {isDecommissioned && <Chip label="Decommissioned" size="small" color="default" />}
                      </Stack>
                    </TableCell>
                    <TableCell>{h.ip_address}</TableCell>
                    <TableCell>
                      {h.os_family}
                      {h.os_version ? ` ${h.os_version}` : ""}
                    </TableCell>
                    <TableCell>
                      <Chip label={`Tier ${h.tier}`} size="small" />
                    </TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={0.5} alignItems="center">
                        {h.ssh_user}
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
                          <Chip label={value} size="small" color={statusColor[value as CaMigrationStatus]} />
                        )}
                      >
                        {CA_MIGRATION_STATUSES.map((s) => (
                          <MenuItem key={s} value={s}>
                            {s}
                          </MenuItem>
                        ))}
                      </Select>
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
                  <TableCell colSpan={9} align="center">
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
              ? "Host đã decommission — recommission trước khi thao tác"
              : "";
            const sshTooltip = isDecommissioned
              ? decommissionedTooltip
              : h.ca_migration_status === "not_started"
              ? "Cần trust_deployed/migrated trước — chạy Zero-to-CA Migration playbook"
              : "";
            const closeMenu = () => setActionMenu(null);
            return [
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
                    Bootstrap CA trust
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
                key="enroll-token"
                disabled={isDecommissioned}
                onClick={() => {
                  handleCreateEnrollmentToken(h);
                  closeMenu();
                }}
              >
                Tạo enrollment token
              </MenuItem>,
              <Tooltip key="agent-install" title={sshTooltip}>
                <span>
                  <MenuItem
                    disabled={
                      h.ca_migration_status === "not_started" ||
                      isDecommissioned ||
                      installingAgentHostname === h.hostname
                    }
                    onClick={() => {
                      handleInstallAgent(h);
                      closeMenu();
                    }}
                  >
                    Cài Agent
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
              <MenuItem
                key="decommission"
                onClick={() => {
                  handleToggleDecommission(h, !isDecommissioned);
                  closeMenu();
                }}
              >
                {isDecommissioned ? "Recommission" : "Decommission"}
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
            ];
          })()}
      </Menu>

      {/* Đăng ký host */}
      <Dialog open={registerOpen} onClose={() => setRegisterOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Đăng ký host</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
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
              label="OS family"
              value={registerForm.os_family}
              onChange={(e) => setRegisterForm({ ...registerForm, os_family: e.target.value })}
              fullWidth
            />
            <TextField
              label="OS version (tuỳ chọn)"
              value={registerForm.os_version}
              onChange={(e) => setRegisterForm({ ...registerForm, os_version: e.target.value })}
              fullWidth
            />
            <TextField
              label="Tier"
              type="number"
              value={registerForm.tier}
              onChange={(e) => setRegisterForm({ ...registerForm, tier: Number(e.target.value) })}
              helperText="Tier 0/1 = production/Tier cao (bắt buộc four-eyes khi xác nhận migrated)"
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
              label="SSH password (tuỳ chọn)"
              type="password"
              value={registerForm.ssh_password}
              onChange={(e) => setRegisterForm({ ...registerForm, ssh_password: e.target.value })}
              helperText="Lưu THAM KHẢO, mã hoá — chưa dùng cho scan/remediate nào (vẫn dùng SSH cert)"
              fullWidth
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRegisterOpen(false)}>Huỷ</Button>
          <Button
            variant="contained"
            onClick={handleRegister}
            disabled={!registerForm.hostname || !registerForm.ip_address || !registerForm.os_family}
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
              label="OS family"
              value={editForm.os_family}
              onChange={(e) => setEditForm({ ...editForm, os_family: e.target.value })}
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
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditHost(null)}>Huỷ</Button>
          <Button variant="contained" onClick={handleSaveEdit} disabled={editSaving}>
            {editSaving ? <CircularProgress size={16} /> : "Lưu"}
          </Button>
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

      {/* Xoá host thật (hard-delete, admin-only) — chỉ thành công nếu host
          chưa từng chạy job (409 nếu đã có lịch sử, xem app/hosts.py). */}
      <Dialog open={deleteHostTarget !== null} onClose={() => setDeleteHostTarget(null)} fullWidth maxWidth="sm">
        <DialogTitle>Xoá host — {deleteHostTarget?.hostname}</DialogTitle>
        <DialogContent>
          <Alert severity="error">
            Xoá THẬT, KHÔNG thể hoàn tác. Chỉ thành công nếu host này chưa từng chạy job nào —
            nếu đã có lịch sử job, dùng "Decommission" thay vào đó để giữ nguyên lịch sử audit/job.
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteHostTarget(null)}>Huỷ</Button>
          <Button variant="contained" color="error" onClick={handleDeleteHost} disabled={deleting}>
            {deleting ? <CircularProgress size={16} /> : "Xác nhận xoá"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Bootstrap CA trust bằng credential CŨ — dùng ĐÚNG 1 LẦN, KHÔNG lưu
          lại (xem app/jobs.py:trigger_ca_bootstrap). Chỉ tự động hoá bước 1
          Zero-to-CA Migration — bước thu hồi credential cũ vẫn thủ công. */}
      <Dialog open={bootstrapHost !== null} onClose={resetBootstrapForm} fullWidth maxWidth="sm">
        <DialogTitle>Bootstrap CA trust — {bootstrapHost?.hostname}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Alert severity="warning">
              Credential dưới đây chỉ dùng ĐÚNG 1 LẦN để tự động bước 1 Zero-to-CA Migration (đẩy
              public key CA + bật TrustedUserCAKeys + reload sshd) — KHÔNG được lưu lại ở bất kỳ
              đâu (không DB, không log). Yêu cầu: user đăng nhập là <code>root</code>, hoặc có sudo{" "}
              <strong>không cần mật khẩu</strong>. Sau bước này, credential cũ <strong>vẫn còn hoạt
              động</strong> — tự verify cert mới rồi thu hồi credential cũ thủ công (xem{" "}
              <code>ansible/README.md</code> bước 2), console không tự làm bước đó.
            </Alert>
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
                    color={jobResult.status === "succeeded" ? "success" : "error"}
                    size="small"
                  />
                </Stack>
                {findings.length > 0 ? (
                  <TableContainer component={Paper}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Rule</TableCell>
                          <TableCell>Kết quả</TableCell>
                          <TableCell>Mức độ</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {findings.map((f) => (
                          <TableRow key={f.rule_id}>
                            <TableCell>{f.title}</TableCell>
                            <TableCell>
                              <Chip
                                label={f.result}
                                size="small"
                                color={f.result === "pass" ? "success" : "error"}
                              />
                            </TableCell>
                            <TableCell>{f.severity}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
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
                      () => setSnack({ severity: "success", message: "Đã sao chép token vào clipboard" }),
                      () =>
                        setSnack({
                          severity: "error",
                          message: "Không sao chép được — hãy tự chọn và copy thủ công từ ô bên trên",
                        })
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
                      () => setSnack({ severity: "success", message: "Đã sao chép script vào clipboard" }),
                      () =>
                        setSnack({
                          severity: "error",
                          message: "Không sao chép được — hãy tự chọn và copy thủ công từ ô bên trên",
                        })
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

      <Snackbar open={snack !== null} autoHideDuration={5000} onClose={() => setSnack(null)}>
        {snack ? <Alert severity={snack.severity}>{snack.message}</Alert> : undefined}
      </Snackbar>
    </Stack>
  );
}
