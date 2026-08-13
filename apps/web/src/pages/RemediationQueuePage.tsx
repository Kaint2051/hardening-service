import { useEffect, useState } from "react";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";
import Button from "@mui/material/Button";
import Chip from "@mui/material/Chip";
import Table from "@mui/material/Table";
import TableHead from "@mui/material/TableHead";
import TableBody from "@mui/material/TableBody";
import TableRow from "@mui/material/TableRow";
import TableCell from "@mui/material/TableCell";
import Paper from "@mui/material/Paper";
import TableContainer from "@mui/material/TableContainer";
import Dialog from "@mui/material/Dialog";
import DialogTitle from "@mui/material/DialogTitle";
import DialogContent from "@mui/material/DialogContent";
import DialogActions from "@mui/material/DialogActions";
import TextField from "@mui/material/TextField";
import CircularProgress from "@mui/material/CircularProgress";
import { api, ApiError } from "../api/client";
import type { RemediationRequestOut, RemediationRequestStatus } from "../api/types";
import DiffView from "../components/DiffView";
import PageHeader from "../components/PageHeader";
import { useSnackbar } from "../hooks/useSnackbar";
import { useLatestRequest } from "../hooks/useLatestRequest";
import { errMessage } from "../lib/errors";
import { remediationColor } from "../lib/statusColors";

// "Chờ duyệt" — hàng đợi duyệt remediate-apply thật, xem
// app/remediation_requests.py. "Đang chờ tôi duyệt" chỉ hiện được nếu
// backend cho phép (role approver/admin — 403 thì tự ẩn, KHÔNG tự kiểm tra
// role phía frontend trước, để backend luôn là nguồn sự thật duy nhất về
// RBAC, cùng quy ước toàn app này).
const statusLabel: Record<RemediationRequestStatus, string> = {
  pending: "Đang chờ duyệt",
  approved: "Đã duyệt",
  rejected: "Đã từ chối",
  failed: "Lỗi khi duyệt",
};

// connection_method=null nghĩa là "tự động" — chọn tay lúc gửi duyệt
// (ComplianceWizardPage), giữ nguyên tới lúc approve, xem app/schemas.py:
// RemediationSubmitRequest.
function connectionMethodLabel(m: RemediationRequestOut["connection_method"]): string {
  if (m === "ssh") return "SSH";
  if (m === "agent") return "Agent";
  return "Tự động";
}

export default function RemediationQueuePage() {
  const { showSuccess, showError } = useSnackbar();
  const [pending, setPending] = useState<RemediationRequestOut[]>([]);
  const [canSeeFullQueue, setCanSeeFullQueue] = useState(true);
  const [mine, setMine] = useState<RemediationRequestOut[]>([]);
  const [loading, setLoading] = useState(true);

  const [detailRequest, setDetailRequest] = useState<RemediationRequestOut | null>(null);
  const [detailDiff, setDetailDiff] = useState<string | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [deciding, setDeciding] = useState(false);
  const [rejectReason, setRejectReason] = useState("");
  const [showRejectForm, setShowRejectForm] = useState(false);
  // Mở nhanh 2 yêu cầu liên tiếp: getJob của yêu cầu A có thể resolve SAU khi
  // đã mở dialog cho yêu cầu B, ghi đè detailDiff của B bằng diff của A trong
  // khi metadata vẫn là B — approver xem nhầm diff. Guard bằng useLatestRequest.
  const beginDetail = useLatestRequest();

  const load = () => {
    setLoading(true);
    Promise.all([
      api
        .listRemediationRequests({ statusFilter: "pending" })
        .then((result) => {
          setPending(result);
          setCanSeeFullQueue(true);
        })
        .catch((err) => {
          if (err instanceof ApiError && err.status === 403) {
            setCanSeeFullQueue(false);
            setPending([]);
          } else {
            throw err;
          }
        }),
      api.listRemediationRequests({ mineOnly: true }).then(setMine),
    ])
      .catch((err) => showError(errMessage(err)))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const openDetail = async (req: RemediationRequestOut) => {
    const isStale = beginDetail();
    setDetailRequest(req);
    setDetailDiff(null);
    setShowRejectForm(false);
    setRejectReason("");
    setDetailLoading(true);
    try {
      const job = await api.getJob(req.dry_run_job_id);
      if (isStale()) return;
      setDetailDiff((job.result_summary?.diff_output as string | undefined) ?? null);
    } catch (err) {
      if (isStale()) return;
      showError(errMessage(err));
    } finally {
      if (!isStale()) setDetailLoading(false);
    }
  };

  const closeDetail = () => {
    // Bump guard: getJob đang bay lúc đóng dialog sẽ bị bỏ khi resolve.
    beginDetail();
    setDetailRequest(null);
    setDetailDiff(null);
    setShowRejectForm(false);
  };

  const handleApprove = async () => {
    if (!detailRequest) return;
    setDeciding(true);
    try {
      const updated = await api.approveRemediationRequest(detailRequest.id);
      showSuccess(`Đã duyệt — job áp dụng #${updated.apply_job_id} đã chạy (${updated.status}).`);
      closeDetail();
      load();
    } catch (err) {
      showError(errMessage(err));
    } finally {
      setDeciding(false);
    }
  };

  const handleReject = async () => {
    if (!detailRequest) return;
    setDeciding(true);
    try {
      await api.rejectRemediationRequest(detailRequest.id, rejectReason || undefined);
      showSuccess("Đã từ chối yêu cầu.");
      closeDetail();
      load();
    } catch (err) {
      showError(errMessage(err));
    } finally {
      setDeciding(false);
    }
  };

  return (
    <Stack spacing={3}>
      <PageHeader
        title="Chờ duyệt"
        actions={
          <Button variant="outlined" onClick={load}>
            Tải lại
          </Button>
        }
      />

      {loading ? (
        <CircularProgress />
      ) : (
        <Stack spacing={4}>
          {canSeeFullQueue && (
            <Stack spacing={1}>
              <Typography variant="subtitle1">Đang chờ tôi duyệt ({pending.length})</Typography>
              <TableContainer component={Paper}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Máy chủ</TableCell>
                      <TableCell>Control</TableCell>
                      <TableCell>Kênh kết nối</TableCell>
                      <TableCell>Người gửi</TableCell>
                      <TableCell>Gửi lúc</TableCell>
                      <TableCell align="right">Hành động</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {pending.map((r) => (
                      <TableRow key={r.id}>
                        <TableCell>{r.hostname}</TableCell>
                        <TableCell>{r.control_id}</TableCell>
                        <TableCell>{connectionMethodLabel(r.connection_method)}</TableCell>
                        <TableCell>{r.requested_by}</TableCell>
                        <TableCell>{new Date(r.requested_at).toLocaleString("vi-VN")}</TableCell>
                        <TableCell align="right">
                          <Button size="small" onClick={() => openDetail(r)}>
                            Xem & duyệt
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                    {pending.length === 0 && (
                      <TableRow>
                        <TableCell colSpan={6} align="center">
                          Không có yêu cầu nào đang chờ.
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
            </Stack>
          )}

          <Stack spacing={1}>
            <Typography variant="subtitle1">Yêu cầu của tôi</Typography>
            <TableContainer component={Paper}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Máy chủ</TableCell>
                    <TableCell>Control</TableCell>
                    <TableCell>Kênh kết nối</TableCell>
                    <TableCell>Trạng thái</TableCell>
                    <TableCell>Người duyệt</TableCell>
                    <TableCell>Ghi chú</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {mine.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell>{r.hostname}</TableCell>
                      <TableCell>{r.control_id}</TableCell>
                      <TableCell>{connectionMethodLabel(r.connection_method)}</TableCell>
                      <TableCell>
                        <Chip label={statusLabel[r.status]} size="small" color={remediationColor[r.status]} />
                      </TableCell>
                      <TableCell>{r.decided_by ?? "—"}</TableCell>
                      <TableCell>{r.decision_note ?? "—"}</TableCell>
                    </TableRow>
                  ))}
                  {mine.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} align="center">
                        Bạn chưa gửi yêu cầu nào.
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </Stack>
        </Stack>
      )}

      <Dialog open={detailRequest !== null} onClose={closeDetail} fullWidth maxWidth="md">
        <DialogTitle>
          Yêu cầu #{detailRequest?.id} — {detailRequest?.hostname}
        </DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Typography variant="body2">
              Control: <strong>{detailRequest?.control_id}</strong> — gửi bởi {detailRequest?.requested_by}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Kênh kết nối: {connectionMethodLabel(detailRequest?.connection_method ?? null)}
            </Typography>
            {detailLoading ? (
              <CircularProgress size={24} />
            ) : detailDiff ? (
              <DiffView diffText={detailDiff} />
            ) : (
              <Typography variant="body2" color="text.secondary">
                Không có thay đổi nào khác so với hiện tại.
              </Typography>
            )}
            {showRejectForm && (
              <TextField
                label="Lý do từ chối (tuỳ chọn)"
                value={rejectReason}
                onChange={(e) => setRejectReason(e.target.value)}
                multiline
                minRows={2}
                fullWidth
              />
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeDetail} disabled={deciding}>
            Đóng
          </Button>
          {!showRejectForm ? (
            <Button color="error" onClick={() => setShowRejectForm(true)} disabled={deciding}>
              Từ chối
            </Button>
          ) : (
            <Button color="error" onClick={handleReject} disabled={deciding}>
              {deciding ? <CircularProgress size={16} /> : "Xác nhận từ chối"}
            </Button>
          )}
          <Button variant="contained" onClick={handleApprove} disabled={deciding || showRejectForm}>
            {deciding ? <CircularProgress size={16} /> : "Duyệt"}
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
