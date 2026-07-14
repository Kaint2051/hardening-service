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
import TextField from "@mui/material/TextField";
import Dialog from "@mui/material/Dialog";
import DialogTitle from "@mui/material/DialogTitle";
import DialogContent from "@mui/material/DialogContent";
import DialogActions from "@mui/material/DialogActions";
import Snackbar from "@mui/material/Snackbar";
import Alert from "@mui/material/Alert";
import CircularProgress from "@mui/material/CircularProgress";
import { api, ApiError } from "../api/client";
import { JOB_STATUSES, JOB_TYPES } from "../api/types";
import type { JobListItemOut, JobOut } from "../api/types";

const PAGE_SIZE = 20;

const statusColor: Record<string, "default" | "warning" | "success" | "error"> = {
  pending: "default",
  running: "warning",
  succeeded: "success",
  failed: "error",
};

// Findings (xem app/jobs.py _parse_scan_summary) chỉ có ý nghĩa cho job_type
// "scan"/"agent-scan" — remediate-*/restore không có mảng này trong
// result_summary, dialog chi tiết tự rơi về hiển thị JSON thô cho các loại đó.
type Finding = { rule_id: string; title: string; result: string; severity: string };

export default function JobsPage() {
  const [jobs, setJobs] = useState<JobListItemOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [snack, setSnack] = useState<{ severity: "success" | "error"; message: string } | null>(null);

  const [hostnameFilter, setHostnameFilter] = useState("");
  const [hostnameInput, setHostnameInput] = useState("");
  const [jobTypeFilter, setJobTypeFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [offset, setOffset] = useState(0);

  // GET /jobs (list) CỐ Ý không trả result_summary (có thể chứa backup base64
  // tới 2 MiB/job — xem app/schemas.py:JobListOut), nên dialog chi tiết phải
  // tự gọi riêng api.getJob(id) khi mở, KHÔNG dùng lại thẳng item trong bảng.
  // detailJobId điều khiển việc dialog có mở hay không (biết ngay lúc bấm);
  // detailJob chỉ có giá trị sau khi fetch xong.
  const [detailJobId, setDetailJobId] = useState<number | null>(null);
  const [detailJob, setDetailJob] = useState<JobOut | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const detailRequestIdRef = useRef(0);

  // Đổi filter/trang liên tiếp trước khi request trước hoàn tất có thể khiến
  // response CŨ (vd hostname "web-01" chậm hơn) ghi đè lên response MỚI hơn
  // (vd "web-02" nhanh hơn, tới trước) — cùng lớp bug đã gặp và sửa ở
  // HostsPage.tsx (enrollRequestIdRef), áp dụng lại đúng kỹ thuật đó: chỉ
  // "commit" kết quả nếu vẫn là request mới nhất khi nó resolve.
  const requestIdRef = useRef(0);

  const loadJobs = () => {
    const requestId = ++requestIdRef.current;
    setLoading(true);
    api
      .listJobs({
        hostname: hostnameFilter || undefined,
        job_type: jobTypeFilter || undefined,
        status: statusFilter || undefined,
        limit: PAGE_SIZE,
        offset,
      })
      .then((result) => {
        if (requestIdRef.current !== requestId) return;
        setJobs(result);
      })
      .catch((err) => {
        if (requestIdRef.current !== requestId) return;
        setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
      })
      .finally(() => {
        if (requestIdRef.current === requestId) setLoading(false);
      });
  };

  useEffect(loadJobs, [hostnameFilter, jobTypeFilter, statusFilter, offset]);

  // Đổi filter (khác trang) luôn quay về offset=0 — offset cũ của 1 tập kết
  // quả khác có thể vượt quá số job khớp filter mới, hiện trang rỗng gây
  // hiểu nhầm "hết job" dù chỉ là lệch trang.
  const applyHostnameFilter = () => {
    setOffset(0);
    setHostnameFilter(hostnameInput.trim());
  };

  const openJobDetail = (jobId: number) => {
    const requestId = ++detailRequestIdRef.current;
    setDetailJobId(jobId);
    setDetailJob(null);
    setDetailLoading(true);
    api
      .getJob(jobId)
      .then((result) => {
        if (detailRequestIdRef.current !== requestId) return;
        setDetailJob(result);
      })
      .catch((err) => {
        if (detailRequestIdRef.current !== requestId) return;
        setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
        setDetailJobId(null);
      })
      .finally(() => {
        if (detailRequestIdRef.current === requestId) setDetailLoading(false);
      });
  };

  const closeJobDetail = () => {
    // Bump ref để bất kỳ request nào đang bay lúc đóng dialog cũng bị bỏ qua
    // khi resolve — tránh setDetailJob() âm thầm chạy nền sau khi đóng.
    ++detailRequestIdRef.current;
    setDetailJobId(null);
    setDetailJob(null);
  };

  const findings = (detailJob?.result_summary?.findings as Finding[] | undefined) ?? [];

  return (
    <Stack spacing={2}>
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Typography variant="h5">Jobs</Typography>
        <Button variant="outlined" onClick={loadJobs}>
          Tải lại
        </Button>
      </Stack>

      <Stack direction="row" spacing={2} alignItems="center">
        <TextField
          label="Hostname"
          size="small"
          value={hostnameInput}
          onChange={(e) => setHostnameInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && applyHostnameFilter()}
        />
        <Button size="small" variant="outlined" onClick={applyHostnameFilter}>
          Lọc
        </Button>
        <Select
          size="small"
          displayEmpty
          value={jobTypeFilter}
          onChange={(e) => {
            setOffset(0);
            setJobTypeFilter(e.target.value);
          }}
        >
          <MenuItem value="">Tất cả job type</MenuItem>
          {JOB_TYPES.map((t) => (
            <MenuItem key={t} value={t}>
              {t}
            </MenuItem>
          ))}
        </Select>
        <Select
          size="small"
          displayEmpty
          value={statusFilter}
          onChange={(e) => {
            setOffset(0);
            setStatusFilter(e.target.value);
          }}
        >
          <MenuItem value="">Tất cả status</MenuItem>
          {JOB_STATUSES.map((s) => (
            <MenuItem key={s} value={s}>
              {s}
            </MenuItem>
          ))}
        </Select>
      </Stack>

      {loading ? (
        <CircularProgress />
      ) : (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>ID</TableCell>
                <TableCell>Hostname</TableCell>
                <TableCell>Job type</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Triggered by</TableCell>
                <TableCell>Tạo lúc</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {jobs.map((j) => (
                <TableRow key={j.id}>
                  <TableCell>{j.id}</TableCell>
                  <TableCell>{j.hostname}</TableCell>
                  <TableCell>{j.job_type}</TableCell>
                  <TableCell>
                    <Chip label={j.status} size="small" color={statusColor[j.status] ?? "default"} />
                  </TableCell>
                  <TableCell>{j.triggered_by}</TableCell>
                  <TableCell>{new Date(j.created_at).toLocaleString("vi-VN")}</TableCell>
                  <TableCell align="right">
                    <Button size="small" onClick={() => openJobDetail(j.id)}>
                      Xem chi tiết
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {jobs.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    Không có job nào khớp bộ lọc hiện tại.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <Stack direction="row" spacing={1} justifyContent="center" alignItems="center">
        <Button size="small" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
          Trang trước
        </Button>
        <Typography variant="body2" color="text.secondary">
          {offset + 1}-{offset + jobs.length}
        </Typography>
        {/* jobs.length < PAGE_SIZE nghĩa là đã tới trang cuối — không cần
            COUNT(*) riêng phía backend chỉ để biết tổng số trang. */}
        <Button size="small" disabled={jobs.length < PAGE_SIZE} onClick={() => setOffset(offset + PAGE_SIZE)}>
          Trang sau
        </Button>
      </Stack>

      <Dialog open={detailJobId !== null} onClose={closeJobDetail} fullWidth maxWidth="md">
        <DialogTitle>Job #{detailJobId}</DialogTitle>
        <DialogContent>
          {detailLoading && (
            <Stack direction="row" spacing={1} alignItems="center" sx={{ my: 2 }}>
              <CircularProgress size={20} />
              <Typography variant="body2">Đang tải chi tiết job...</Typography>
            </Stack>
          )}
          {detailJob && (
            <Stack spacing={2} sx={{ mt: 1 }}>
              <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                <Chip label={detailJob.hostname} size="small" />
                <Chip label={detailJob.job_type} size="small" />
                <Chip
                  label={detailJob.status}
                  size="small"
                  color={statusColor[detailJob.status] ?? "default"}
                />
                {detailJob.control_id && <Chip label={`control: ${detailJob.control_id}`} size="small" />}
              </Stack>
              <Typography variant="body2" color="text.secondary">
                Triggered by {detailJob.triggered_by} lúc{" "}
                {new Date(detailJob.created_at).toLocaleString("vi-VN")}
                {detailJob.finished_at &&
                  ` — kết thúc ${new Date(detailJob.finished_at).toLocaleString("vi-VN")}`}
              </Typography>
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
                <Typography
                  component="pre"
                  variant="body2"
                  sx={{
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-all",
                    bgcolor: "action.hover",
                    p: 1.5,
                    borderRadius: 1,
                    maxHeight: 400,
                    overflow: "auto",
                  }}
                >
                  {detailJob.result_summary
                    ? JSON.stringify(detailJob.result_summary, null, 2)
                    : "(chưa có result_summary)"}
                </Typography>
              )}
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={closeJobDetail}>Đóng</Button>
        </DialogActions>
      </Dialog>

      <Snackbar open={snack !== null} autoHideDuration={5000} onClose={() => setSnack(null)}>
        {snack ? <Alert severity={snack.severity}>{snack.message}</Alert> : undefined}
      </Snackbar>
    </Stack>
  );
}
