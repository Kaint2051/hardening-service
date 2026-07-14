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
import Dialog from "@mui/material/Dialog";
import DialogTitle from "@mui/material/DialogTitle";
import DialogContent from "@mui/material/DialogContent";
import DialogActions from "@mui/material/DialogActions";
import TextField from "@mui/material/TextField";
import Snackbar from "@mui/material/Snackbar";
import Alert from "@mui/material/Alert";
import CircularProgress from "@mui/material/CircularProgress";
import Divider from "@mui/material/Divider";
import { api, ApiError } from "../api/client";
import { MATURITY_LEVELS } from "../api/types";
import type {
  CanaryRolloutDetailOut,
  ControlDetailOut,
  ControlOut,
  ControlVersionOut,
  Maturity,
} from "../api/types";

const maturityColor: Record<Maturity, "default" | "warning" | "success"> = {
  draft: "default",
  reviewed: "warning",
  production: "success",
};

function nextMaturity(current: Maturity): Maturity | null {
  const idx = MATURITY_LEVELS.indexOf(current);
  return idx >= 0 && idx < MATURITY_LEVELS.length - 1 ? MATURITY_LEVELS[idx + 1] : null;
}

// Dùng chung cho status chip của cả canary rollout (running/completed/aborted)
// lẫn job dry-run/apply từng host (pending/running/succeeded/failed) — 2 tập
// giá trị không trùng chữ nhưng ý nghĩa "đang chạy/xong tốt/lỗi" giống nhau.
function statusChipColor(status: string): "default" | "warning" | "success" | "error" | "info" {
  if (status === "succeeded" || status === "completed") return "success";
  if (status === "failed" || status === "aborted") return "error";
  if (status === "running") return "info";
  return "default";
}

function describeEvent(v: ControlVersionOut): string {
  const detail = v.detail ?? {};
  switch (v.event_type) {
    case "created":
      return `${v.actor} tạo control (category: ${detail.category ?? "?"})`;
    case "maturity_changed":
      return detail.reason === "content_changed_after_production"
        ? `${v.actor} thêm nội dung mới -> tự động đưa production về draft`
        : `${v.actor} chuyển maturity ${v.from_maturity} -> ${v.to_maturity}`;
    case "standard_mapping_added":
      return `${v.actor} thêm standard mapping ${detail.standard ?? ""} ${detail.standard_version ?? ""} — ${detail.section_id ?? ""}`;
    case "remediation_variant_added":
      return `${v.actor} thêm remediation variant ${detail.os_family ?? ""} ${detail.os_version ?? ""} — ${detail.remediation_ref ?? ""}`;
    default:
      return `${v.actor}: ${v.event_type}`;
  }
}

export default function ControlsPage() {
  const [controls, setControls] = useState<ControlOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [snack, setSnack] = useState<{ severity: "success" | "error"; message: string } | null>(null);

  const [createOpen, setCreateOpen] = useState(false);
  const [createForm, setCreateForm] = useState({ title: "", description: "", category: "" });

  const [detail, setDetail] = useState<ControlDetailOut | null>(null);
  const [history, setHistory] = useState<ControlVersionOut[]>([]);
  const [mappingForm, setMappingForm] = useState({ standard: "", standard_version: "", section_id: "" });
  const [variantForm, setVariantForm] = useState({
    os_family: "",
    os_version: "",
    check_method: "",
    remediation_ref: "",
  });

  // Canary rollout: control đang mở dialog xác nhận/tiến độ (null = đóng),
  // và tiến độ rollout đang theo dõi (null trước khi bấm "Xác nhận").
  const [canaryDialogControl, setCanaryDialogControl] = useState<ControlOut | null>(null);
  const [canaryStarting, setCanaryStarting] = useState(false);
  const [canaryRollout, setCanaryRollout] = useState<CanaryRolloutDetailOut | null>(null);

  const loadControls = () => {
    setLoading(true);
    api
      .listControls()
      .then(setControls)
      .catch((err) => setSnack({ severity: "error", message: String(err) }))
      .finally(() => setLoading(false));
  };

  useEffect(loadControls, []);

  const handleCreate = async () => {
    try {
      await api.createControl(createForm);
      setCreateOpen(false);
      setCreateForm({ title: "", description: "", category: "" });
      setSnack({ severity: "success", message: "Đã tạo control" });
      loadControls();
    } catch (err) {
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    }
  };

  const handlePromote = async (control: ControlOut) => {
    const next = nextMaturity(control.maturity);
    if (!next) return;
    try {
      await api.updateControlMaturity(control.id, next);
      setSnack({ severity: "success", message: `Đã chuyển ${control.id} -> ${next}` });
      loadControls();
    } catch (err) {
      // 403 four-eyes (không được tự duyệt control của chính mình) là kết quả
      // mong đợi, không phải lỗi hệ thống — vẫn hiển thị cho người dùng biết.
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    }
  };

  const handleRiskGroupToggle = async (control: ControlOut) => {
    const next = control.risk_group === "A" ? "B" : "A";
    try {
      await api.updateControlRiskGroup(control.id, next);
      setSnack({ severity: "success", message: `Đã chuyển ${control.id} sang risk_group ${next}` });
      loadControls();
    } catch (err) {
      // 403 four-eyes hoặc 422 (gán "A" khi chưa production) đều là kết quả
      // mong đợi từ backend, không phải lỗi hệ thống — vẫn hiển thị cho
      // người dùng biết (giống handlePromote ở trên).
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    }
  };

  const closeCanaryDialog = () => {
    setCanaryDialogControl(null);
    setCanaryRollout(null);
  };

  const handleStartCanary = async () => {
    if (!canaryDialogControl) return;
    setCanaryStarting(true);
    try {
      const started = await api.startCanaryRollout(canaryDialogControl.id);
      // Endpoint start trả CanaryRolloutOut (không có mảng "hosts") — gọi lại
      // GET ngay để có bản đầy đủ (CanaryRolloutDetailOut) cho bảng tiến độ,
      // trước khi polling định kỳ tiếp quản.
      const fullDetail = await api.getCanaryRollout(started.id);
      setCanaryRollout(fullDetail);
    } catch (err) {
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    } finally {
      setCanaryStarting(false);
    }
  };

  const handleCancelCanary = async () => {
    if (!canaryRollout) return;
    try {
      await api.cancelCanaryRollout(canaryRollout.id);
      // PATCH .../cancel chỉ đặt cờ cancel_requested — rollout vẫn "running"
      // cho tới khi background task kiểm tra cờ ở đầu vòng lặp host kế tiếp,
      // nên KHÔNG ghi đè canaryRollout bằng response này (sẽ mất mảng hosts
      // vì CanaryRolloutOut không có field đó) — cứ để polling bên dưới bắt
      // trạng thái "aborted" ở lần refresh tiếp theo.
      setSnack({
        severity: "success",
        message: "Đã gửi yêu cầu huỷ — canary rollout sẽ dừng sau khi xử lý xong host hiện tại",
      });
    } catch (err) {
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    }
  };

  // Poll tiến độ mỗi ~3s trong khi rollout còn "running" — tự dừng khi
  // completed/aborted hoặc khi dialog đóng (canaryRollout về null).
  useEffect(() => {
    if (!canaryRollout || canaryRollout.status !== "running") return;
    const rolloutId = canaryRollout.id;
    const intervalId = window.setInterval(() => {
      api
        .getCanaryRollout(rolloutId)
        .then(setCanaryRollout)
        .catch((err) =>
          setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) })
        );
    }, 3000);
    return () => window.clearInterval(intervalId);
  }, [canaryRollout?.id, canaryRollout?.status]);

  const openDetail = async (controlId: string) => {
    try {
      const [d, h] = await Promise.all([api.getControl(controlId), api.getControlHistory(controlId)]);
      setDetail(d);
      setHistory(h);
    } catch (err) {
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    }
  };

  const handleAddMapping = async () => {
    if (!detail) return;
    try {
      await api.addStandardMapping(detail.id, mappingForm);
      setMappingForm({ standard: "", standard_version: "", section_id: "" });
      setSnack({ severity: "success", message: "Đã thêm standard mapping" });
      openDetail(detail.id);
    } catch (err) {
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    }
  };

  const handleAddVariant = async () => {
    if (!detail) return;
    try {
      await api.addRemediationVariant(detail.id, {
        ...variantForm,
        os_version: variantForm.os_version || undefined,
      });
      setVariantForm({ os_family: "", os_version: "", check_method: "", remediation_ref: "" });
      setSnack({ severity: "success", message: "Đã thêm remediation variant" });
      openDetail(detail.id);
    } catch (err) {
      setSnack({ severity: "error", message: err instanceof ApiError ? err.message : String(err) });
    }
  };

  return (
    <Stack spacing={2}>
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Typography variant="h5">Controls</Typography>
        <Stack direction="row" spacing={1}>
          <Button variant="outlined" onClick={loadControls}>
            Tải lại
          </Button>
          <Button variant="contained" onClick={() => setCreateOpen(true)}>
            Tạo control
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
                <TableCell>ID</TableCell>
                <TableCell>Title</TableCell>
                <TableCell>Category</TableCell>
                <TableCell>Maturity</TableCell>
                <TableCell>Risk Group</TableCell>
                <TableCell>Created by</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {controls.map((c) => {
                const next = nextMaturity(c.maturity);
                const isProduction = c.maturity === "production";
                return (
                  <TableRow key={c.id} hover sx={{ cursor: "pointer" }}>
                    <TableCell onClick={() => openDetail(c.id)}>{c.id}</TableCell>
                    <TableCell onClick={() => openDetail(c.id)}>{c.title}</TableCell>
                    <TableCell onClick={() => openDetail(c.id)}>{c.category}</TableCell>
                    <TableCell>
                      <Chip label={c.maturity} size="small" color={maturityColor[c.maturity]} />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={c.risk_group}
                        size="small"
                        color={c.risk_group === "A" ? "success" : "default"}
                      />
                    </TableCell>
                    <TableCell>{c.created_by}</TableCell>
                    <TableCell align="right">
                      <Stack direction="row" spacing={1} justifyContent="flex-end">
                        <Button size="small" disabled={!next} onClick={() => handlePromote(c)}>
                          {next ? `Duyệt -> ${next}` : "Đã production"}
                        </Button>
                        <Button
                          size="small"
                          disabled={!isProduction}
                          onClick={() => handleRiskGroupToggle(c)}
                        >
                          {c.risk_group === "A" ? "Chuyển về Nhóm B" : "Chuyển Nhóm A"}
                        </Button>
                        <Button
                          size="small"
                          disabled={!(isProduction && c.risk_group === "A")}
                          onClick={() => setCanaryDialogControl(c)}
                        >
                          Bắt đầu canary rollout
                        </Button>
                      </Stack>
                    </TableCell>
                  </TableRow>
                );
              })}
              {controls.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} align="center">
                    Chưa có control nào.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Tạo control */}
      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Tạo control</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="Title"
              value={createForm.title}
              onChange={(e) => setCreateForm({ ...createForm, title: e.target.value })}
              fullWidth
            />
            <TextField
              label="Category"
              value={createForm.category}
              onChange={(e) => setCreateForm({ ...createForm, category: e.target.value })}
              fullWidth
            />
            <TextField
              label="Description"
              value={createForm.description}
              onChange={(e) => setCreateForm({ ...createForm, description: e.target.value })}
              multiline
              minRows={2}
              fullWidth
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>Huỷ</Button>
          <Button
            variant="contained"
            onClick={handleCreate}
            disabled={!createForm.title || !createForm.category}
          >
            Tạo
          </Button>
        </DialogActions>
      </Dialog>

      {/* Chi tiết control */}
      <Dialog open={detail !== null} onClose={() => setDetail(null)} fullWidth maxWidth="md">
        <DialogTitle>{detail?.id}</DialogTitle>
        <DialogContent>
          {detail && (
            <Stack spacing={3} sx={{ mt: 1 }}>
              <Typography variant="body2" color="text.secondary">
                {detail.description || "(không có mô tả)"}
              </Typography>

              <Stack spacing={1}>
                <Typography variant="subtitle1">Standard mappings</Typography>
                {detail.standard_mappings.map((m) => (
                  <Typography key={m.id} variant="body2">
                    {m.standard} {m.standard_version} — {m.section_id}
                  </Typography>
                ))}
                {detail.standard_mappings.length === 0 && (
                  <Typography variant="body2" color="text.secondary">
                    Chưa có mapping nào.
                  </Typography>
                )}
                <Stack direction="row" spacing={1}>
                  <TextField
                    size="small"
                    label="Standard (vd CIS)"
                    value={mappingForm.standard}
                    onChange={(e) => setMappingForm({ ...mappingForm, standard: e.target.value })}
                  />
                  <TextField
                    size="small"
                    label="Version"
                    value={mappingForm.standard_version}
                    onChange={(e) =>
                      setMappingForm({ ...mappingForm, standard_version: e.target.value })
                    }
                  />
                  <TextField
                    size="small"
                    label="Section ID"
                    value={mappingForm.section_id}
                    onChange={(e) => setMappingForm({ ...mappingForm, section_id: e.target.value })}
                  />
                  <Button
                    onClick={handleAddMapping}
                    disabled={!mappingForm.standard || !mappingForm.standard_version || !mappingForm.section_id}
                  >
                    Thêm
                  </Button>
                </Stack>
              </Stack>

              <Divider />

              <Stack spacing={1}>
                <Typography variant="subtitle1">Remediation variants</Typography>
                {detail.remediation_variants.map((v) => (
                  <Typography key={v.id} variant="body2">
                    {v.os_family} {v.os_version ?? ""} — {v.check_method} — {v.remediation_ref}
                  </Typography>
                ))}
                {detail.remediation_variants.length === 0 && (
                  <Typography variant="body2" color="text.secondary">
                    Chưa có remediation variant nào.
                  </Typography>
                )}
                <Stack direction="row" spacing={1} flexWrap="wrap">
                  <TextField
                    size="small"
                    label="OS family"
                    value={variantForm.os_family}
                    onChange={(e) => setVariantForm({ ...variantForm, os_family: e.target.value })}
                  />
                  <TextField
                    size="small"
                    label="OS version"
                    value={variantForm.os_version}
                    onChange={(e) => setVariantForm({ ...variantForm, os_version: e.target.value })}
                  />
                  <TextField
                    size="small"
                    label="Check method"
                    value={variantForm.check_method}
                    onChange={(e) => setVariantForm({ ...variantForm, check_method: e.target.value })}
                  />
                  <TextField
                    size="small"
                    label="Remediation ref"
                    value={variantForm.remediation_ref}
                    onChange={(e) =>
                      setVariantForm({ ...variantForm, remediation_ref: e.target.value })
                    }
                  />
                  <Button
                    onClick={handleAddVariant}
                    disabled={
                      !variantForm.os_family || !variantForm.check_method || !variantForm.remediation_ref
                    }
                  >
                    Thêm
                  </Button>
                </Stack>
              </Stack>

              <Divider />

              <Stack spacing={1}>
                <Typography variant="subtitle1">Lịch sử thay đổi</Typography>
                {history.map((h) => (
                  <Typography key={h.id} variant="body2">
                    <Typography component="span" variant="caption" color="text.secondary">
                      {new Date(h.created_at).toLocaleString("vi-VN")}
                    </Typography>{" "}
                    — {describeEvent(h)}
                  </Typography>
                ))}
                {history.length === 0 && (
                  <Typography variant="body2" color="text.secondary">
                    Chưa có lịch sử.
                  </Typography>
                )}
              </Stack>
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetail(null)}>Đóng</Button>
        </DialogActions>
      </Dialog>

      {/* Canary rollout */}
      <Dialog open={canaryDialogControl !== null} onClose={closeCanaryDialog} fullWidth maxWidth="md">
        <DialogTitle>Canary rollout — {canaryDialogControl?.id}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            {!canaryRollout && !canaryStarting && (
              <Typography variant="body2">
                Rollout sẽ tự động dry-run rồi apply NGAY lần lượt trên từng host Tier 2 đang có
                remediation variant phù hợp với control này, và dừng ngay khi có 1 host lỗi. Xác
                nhận bắt đầu?
              </Typography>
            )}
            {canaryStarting && (
              <Stack direction="row" spacing={1} alignItems="center">
                <CircularProgress size={20} />
                <Typography variant="body2">Đang khởi tạo canary rollout...</Typography>
              </Stack>
            )}
            {canaryRollout && (
              <Stack spacing={2}>
                <Stack direction="row" spacing={1} alignItems="center">
                  <Typography>Rollout #{canaryRollout.id}</Typography>
                  <Chip
                    label={canaryRollout.status}
                    size="small"
                    color={statusChipColor(canaryRollout.status)}
                  />
                  <Typography variant="body2" color="text.secondary">
                    {canaryRollout.eligible_host_count} host đủ điều kiện
                  </Typography>
                </Stack>
                {canaryRollout.status === "aborted" && (
                  <Alert severity="error">
                    Dừng tại host {canaryRollout.aborted_hostname ?? "?"} — lý do:{" "}
                    {canaryRollout.abort_reason ?? "?"}
                  </Alert>
                )}
                {canaryRollout.hosts.length > 0 ? (
                  <TableContainer component={Paper}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Hostname</TableCell>
                          <TableCell>Dry-run job</TableCell>
                          <TableCell>Apply job</TableCell>
                          <TableCell>Trạng thái</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {canaryRollout.hosts.map((h) => (
                          <TableRow key={h.hostname}>
                            <TableCell>{h.hostname}</TableCell>
                            <TableCell>{h.dry_run_job_id ?? "-"}</TableCell>
                            <TableCell>{h.apply_job_id ?? "-"}</TableCell>
                            <TableCell>
                              <Chip label={h.status} size="small" color={statusChipColor(h.status)} />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    Chưa có host nào được xử lý.
                  </Typography>
                )}
              </Stack>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={closeCanaryDialog}>Đóng</Button>
          {canaryRollout && canaryRollout.status === "running" && (
            <Button color="error" onClick={handleCancelCanary}>
              Huỷ
            </Button>
          )}
          {!canaryRollout && (
            <Button variant="contained" onClick={handleStartCanary} disabled={canaryStarting}>
              Xác nhận
            </Button>
          )}
        </DialogActions>
      </Dialog>

      <Snackbar open={snack !== null} autoHideDuration={5000} onClose={() => setSnack(null)}>
        {snack ? <Alert severity={snack.severity}>{snack.message}</Alert> : undefined}
      </Snackbar>
    </Stack>
  );
}
