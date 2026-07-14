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
import Dialog from "@mui/material/Dialog";
import DialogTitle from "@mui/material/DialogTitle";
import DialogContent from "@mui/material/DialogContent";
import DialogActions from "@mui/material/DialogActions";
import TextField from "@mui/material/TextField";
import Snackbar from "@mui/material/Snackbar";
import Alert from "@mui/material/Alert";
import CircularProgress from "@mui/material/CircularProgress";
import { api, ApiError } from "../api/client";
import { CA_MIGRATION_STATUSES, SCAP_PROFILE_KEYS } from "../api/types";
import type { AgentEnrollmentTokenOut, CaMigrationStatus, HostOut, JobOut } from "../api/types";

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

  const [registerOpen, setRegisterOpen] = useState(false);
  const [registerForm, setRegisterForm] = useState({
    hostname: "",
    ip_address: "",
    os_family: "",
    os_version: "",
    tier: 2,
  });

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

  const loadHosts = () => {
    setLoading(true);
    api
      .listHosts()
      .then(setHosts)
      .catch((err) => setSnack({ severity: "error", message: String(err) }))
      .finally(() => setLoading(false));
  };

  useEffect(loadHosts, []);

  const handleRegister = async () => {
    try {
      await api.registerHost({
        ...registerForm,
        os_version: registerForm.os_version || undefined,
      });
      setRegisterOpen(false);
      setRegisterForm({ hostname: "", ip_address: "", os_family: "", os_version: "", tier: 2 });
      setSnack({ severity: "success", message: "Đã đăng ký host" });
      loadHosts();
    } catch (err) {
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
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
      // ssh_user cố định "root" — backend chỉ allowlist đúng giá trị này
      // (xem app/jobs.py ALLOWED_SSH_USERS), không có lý do để expose ô nhập
      // tự do sẽ luôn thất bại 422.
      const job = await api.triggerScan(scanHost.hostname, scapProfileKey, "root");
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

  const findings = (jobResult?.result_summary?.findings as
    | { rule_id: string; title: string; result: string; severity: string }[]
    | undefined) ?? [];

  return (
    <Stack spacing={2}>
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Typography variant="h5">Hosts</Typography>
        <Stack direction="row" spacing={1}>
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
                <TableCell>CA Migration Status</TableCell>
                <TableCell>Agent</TableCell>
                <TableCell>Added by</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {hosts.map((h) => (
                <TableRow key={h.hostname}>
                  <TableCell>{h.hostname}</TableCell>
                  <TableCell>{h.ip_address}</TableCell>
                  <TableCell>
                    {h.os_family}
                    {h.os_version ? ` ${h.os_version}` : ""}
                  </TableCell>
                  <TableCell>
                    <Chip label={`Tier ${h.tier}`} size="small" />
                  </TableCell>
                  <TableCell>
                    <Select
                      size="small"
                      value={h.ca_migration_status}
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
                    <Stack direction="row" spacing={1} justifyContent="flex-end">
                      <Button size="small" onClick={() => setScanHost(h)}>
                        Trigger scan
                      </Button>
                      <Button size="small" onClick={() => handleCreateEnrollmentToken(h)}>
                        Tạo enrollment token
                      </Button>
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
              {hosts.length === 0 && (
                <TableRow>
                  <TableCell colSpan={8} align="center">
                    Chưa có host nào.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

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
              ssh_user cố định "root" (backend chỉ cho phép giá trị này).
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

      <Snackbar open={snack !== null} autoHideDuration={5000} onClose={() => setSnack(null)}>
        {snack ? <Alert severity={snack.severity}>{snack.message}</Alert> : undefined}
      </Snackbar>
    </Stack>
  );
}
