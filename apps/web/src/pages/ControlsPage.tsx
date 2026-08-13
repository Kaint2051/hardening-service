import { useEffect, useMemo, useState } from "react";
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
import Alert from "@mui/material/Alert";
import CircularProgress from "@mui/material/CircularProgress";
import Divider from "@mui/material/Divider";
import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import Checkbox from "@mui/material/Checkbox";
import Select from "@mui/material/Select";
import MenuItem from "@mui/material/MenuItem";
import FormControl from "@mui/material/FormControl";
import InputLabel from "@mui/material/InputLabel";
import { api } from "../api/client";
import { MATURITY_LEVELS } from "../api/types";
import type {
  CanaryRolloutDetailOut,
  ControlDetailOut,
  ControlOut,
  ControlTemplateOut,
  ControlTemplateRuleOut,
  ControlVersionOut,
  Maturity,
} from "../api/types";
import PageHeader from "../components/PageHeader";
import { useSnackbar } from "../hooks/useSnackbar";
import { errMessage } from "../lib/errors";
// progressColor thay statusChipColor cũ (logic giống hệt: chip trạng thái
// canary rollout + job dry-run/apply từng host).
import { maturityColor, progressColor } from "../lib/statusColors";

function nextMaturity(current: Maturity): Maturity | null {
  const idx = MATURITY_LEVELS.indexOf(current);
  return idx >= 0 && idx < MATURITY_LEVELS.length - 1 ? MATURITY_LEVELS[idx + 1] : null;
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
  const { showSuccess, showError } = useSnackbar();
  const [controls, setControls] = useState<ControlOut[]>([]);
  const [loading, setLoading] = useState(true);

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

  // Tab "Template" — duyệt + chọn rule từ nội dung chuẩn chính thức để tạo
  // Control mới, xem app/control_templates.py.
  const [tab, setTab] = useState(0);
  const [templates, setTemplates] = useState<ControlTemplateOut[]>([]);
  const [selectedTemplateId, setSelectedTemplateId] = useState("");
  const [templateRules, setTemplateRules] = useState<ControlTemplateRuleOut[]>([]);
  const [rulesLoading, setRulesLoading] = useState(false);
  const [ruleFilter, setRuleFilter] = useState("");
  const [selectedRuleIds, setSelectedRuleIds] = useState<Set<string>>(new Set());
  const [previewPlaybook, setPreviewPlaybook] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [templateCreateForm, setTemplateCreateForm] = useState({ title: "", category: "", description: "" });
  const [creatingFromTemplate, setCreatingFromTemplate] = useState(false);
  const [templateCreateResult, setTemplateCreateResult] = useState<{
    control_id: string;
    standard_mappings_added: number;
  } | null>(null);

  useEffect(() => {
    if (tab !== 1 || templates.length > 0) return;
    api
      .listControlTemplates()
      .then(setTemplates)
      .catch((err) => showError(errMessage(err)));
  }, [tab, templates.length]);

  useEffect(() => {
    setSelectedRuleIds(new Set());
    setPreviewPlaybook(null);
    setTemplateCreateResult(null);
    setRuleFilter("");
    if (!selectedTemplateId) {
      setTemplateRules([]);
      return;
    }
    setRulesLoading(true);
    api
      .listTemplateRules(selectedTemplateId)
      .then(setTemplateRules)
      .catch((err) => showError(errMessage(err)))
      .finally(() => setRulesLoading(false));
  }, [selectedTemplateId]);

  const filteredTemplateRules = useMemo(() => {
    const needle = ruleFilter.trim().toLowerCase();
    if (!needle) return templateRules;
    return templateRules.filter(
      (r) => r.rule_id.toLowerCase().includes(needle) || r.title.toLowerCase().includes(needle)
    );
  }, [templateRules, ruleFilter]);

  const toggleRuleSelection = (ruleId: string) => {
    setSelectedRuleIds((prev) => {
      const next = new Set(prev);
      if (next.has(ruleId)) next.delete(ruleId);
      else next.add(ruleId);
      return next;
    });
    // Chọn lại rule thì bản xem trước cũ không còn đúng nữa — bắt xem lại.
    setPreviewPlaybook(null);
    setTemplateCreateResult(null);
  };

  const handlePreviewTemplate = async () => {
    if (!selectedTemplateId || selectedRuleIds.size === 0) return;
    setPreviewLoading(true);
    try {
      const result = await api.previewTemplatePlaybook(selectedTemplateId, Array.from(selectedRuleIds));
      setPreviewPlaybook(result.playbook_yaml);
    } catch (err) {
      showError(errMessage(err));
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleCreateFromTemplate = async () => {
    if (!selectedTemplateId || previewPlaybook === null) return;
    setCreatingFromTemplate(true);
    try {
      const result = await api.createControlFromTemplate(selectedTemplateId, {
        title: templateCreateForm.title,
        category: templateCreateForm.category,
        description: templateCreateForm.description,
        rule_ids: Array.from(selectedRuleIds),
        playbook_yaml: previewPlaybook,
      });
      setTemplateCreateResult(result);
      showSuccess(`Đã tạo Control ${result.control_id} (${result.standard_mappings_added} standard mapping)`);
    } catch (err) {
      showError(errMessage(err));
    } finally {
      setCreatingFromTemplate(false);
    }
  };

  const loadControls = () => {
    setLoading(true);
    api
      .listControls()
      .then(setControls)
      .catch((err) => showError(errMessage(err)))
      .finally(() => setLoading(false));
  };

  useEffect(loadControls, []);

  const handleCreate = async () => {
    try {
      await api.createControl(createForm);
      setCreateOpen(false);
      setCreateForm({ title: "", description: "", category: "" });
      showSuccess("Đã tạo control");
      loadControls();
    } catch (err) {
      showError(errMessage(err));
    }
  };

  const handlePromote = async (control: ControlOut) => {
    const next = nextMaturity(control.maturity);
    if (!next) return;
    try {
      await api.updateControlMaturity(control.id, next);
      showSuccess(`Đã chuyển ${control.id} -> ${next}`);
      loadControls();
    } catch (err) {
      showError(errMessage(err));
    }
  };

  const handleRiskGroupToggle = async (control: ControlOut) => {
    const next = control.risk_group === "A" ? "B" : "A";
    try {
      await api.updateControlRiskGroup(control.id, next);
      showSuccess(`Đã chuyển ${control.id} sang risk_group ${next}`);
      loadControls();
    } catch (err) {
      // 422 (gán "A" khi chưa production) là kết quả mong đợi từ backend,
      // không phải lỗi hệ thống — vẫn hiển thị cho người dùng biết.
      showError(errMessage(err));
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
      showError(errMessage(err));
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
      showSuccess("Đã gửi yêu cầu huỷ — canary rollout sẽ dừng sau khi xử lý xong host hiện tại");
    } catch (err) {
      showError(errMessage(err));
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
          showError(errMessage(err))
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
      showError(errMessage(err));
    }
  };

  const handleAddMapping = async () => {
    if (!detail) return;
    try {
      await api.addStandardMapping(detail.id, mappingForm);
      setMappingForm({ standard: "", standard_version: "", section_id: "" });
      showSuccess("Đã thêm standard mapping");
      openDetail(detail.id);
    } catch (err) {
      showError(errMessage(err));
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
      showSuccess("Đã thêm remediation variant");
      openDetail(detail.id);
    } catch (err) {
      showError(errMessage(err));
    }
  };

  return (
    <Stack spacing={2}>
      <Typography variant="body2" color="text.secondary">
        Khu vực biên soạn/duyệt nội dung chuẩn (dành cho rule-editor/approver) — để quét máy chủ và
        sửa lỗi hằng ngày, dùng trang "Kiểm tra & Khắc phục".
      </Typography>
      <Tabs value={tab} onChange={(_, v) => setTab(v)}>
        <Tab label="Controls" />
        <Tab label="Template" />
      </Tabs>

      {tab === 0 && (
    <Stack spacing={2}>
      <PageHeader
        title="Controls"
        actions={
          <>
            <Button variant="outlined" onClick={loadControls}>
              Tải lại
            </Button>
            <Button variant="contained" onClick={() => setCreateOpen(true)}>
              Tạo control
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
    </Stack>
      )}

      {tab === 1 && (
        <Stack spacing={2}>
          <Typography variant="body2" color="text.secondary">
            Chọn rule từ nội dung chuẩn chính thức (ComplianceAsCode/CIS — cùng nguồn dùng cho tính
            năng "Quét") để tạo Control mới. Bước ký nội dung qua 3 vai trò vẫn phải làm thủ công sau
            khi tạo — xem đọc kỹ playbook trước khi chọn (1 vài rule như "Disable SSH Root Login" có
            thể tự khoá SSH nếu áp mặc định).
          </Typography>

          <FormControl size="small" sx={{ maxWidth: 480 }}>
            <InputLabel>Template</InputLabel>
            <Select
              value={selectedTemplateId}
              label="Template"
              onChange={(e) => setSelectedTemplateId(e.target.value)}
            >
              {templates.map((t) => (
                <MenuItem key={t.id} value={t.id}>
                  {t.title} ({t.rule_count} rule)
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {selectedTemplateId && (
            <>
              <TextField
                size="small"
                label="Tìm rule (theo tên hoặc mã)"
                value={ruleFilter}
                onChange={(e) => setRuleFilter(e.target.value)}
                fullWidth
              />

              {rulesLoading ? (
                <CircularProgress size={24} />
              ) : (
                <TableContainer component={Paper} sx={{ maxHeight: 420 }}>
                  <Table size="small" stickyHeader>
                    <TableHead>
                      <TableRow>
                        <TableCell padding="checkbox" />
                        <TableCell>Rule ID</TableCell>
                        <TableCell>Tiêu đề</TableCell>
                        <TableCell>Mức độ</TableCell>
                        <TableCell>Chuẩn tham chiếu</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {filteredTemplateRules.map((r) => (
                        <TableRow
                          key={r.rule_id}
                          hover
                          onClick={() => toggleRuleSelection(r.rule_id)}
                          sx={{ cursor: "pointer" }}
                        >
                          <TableCell padding="checkbox">
                            <Checkbox
                              size="small"
                              checked={selectedRuleIds.has(r.rule_id)}
                              onClick={(e) => e.stopPropagation()}
                              onChange={() => toggleRuleSelection(r.rule_id)}
                            />
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" fontFamily="monospace">
                              {r.rule_id}
                            </Typography>
                          </TableCell>
                          <TableCell>{r.title}</TableCell>
                          <TableCell>
                            {r.severity && <Chip label={r.severity} size="small" />}
                          </TableCell>
                          <TableCell>
                            <Typography variant="caption" color="text.secondary">
                              {r.compliance_refs.slice(0, 3).join(", ")}
                              {r.compliance_refs.length > 3 ? " ..." : ""}
                            </Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                      {filteredTemplateRules.length === 0 && (
                        <TableRow>
                          <TableCell colSpan={5} align="center">
                            Không có rule khớp.
                          </TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}

              <Stack direction="row" spacing={2} alignItems="center">
                <Typography variant="body2">{selectedRuleIds.size} rule đã chọn</Typography>
                <Button
                  variant="outlined"
                  disabled={selectedRuleIds.size === 0 || previewLoading}
                  onClick={handlePreviewTemplate}
                >
                  {previewLoading ? <CircularProgress size={16} /> : "Xem trước playbook"}
                </Button>
              </Stack>

              {previewPlaybook !== null && (
                <Stack spacing={2}>
                  <Typography variant="subtitle1">
                    Playbook ghép sẵn — có thể sửa tay trước khi tạo Control
                  </Typography>
                  <TextField
                    value={previewPlaybook}
                    onChange={(e) => setPreviewPlaybook(e.target.value)}
                    multiline
                    fullWidth
                    minRows={12}
                    maxRows={24}
                    InputProps={{ sx: { fontFamily: "monospace", fontSize: 12 } }}
                  />
                  <Stack direction="row" spacing={2} flexWrap="wrap">
                    <TextField
                      size="small"
                      label="Title Control mới"
                      value={templateCreateForm.title}
                      onChange={(e) => setTemplateCreateForm({ ...templateCreateForm, title: e.target.value })}
                    />
                    <TextField
                      size="small"
                      label="Category"
                      value={templateCreateForm.category}
                      onChange={(e) => setTemplateCreateForm({ ...templateCreateForm, category: e.target.value })}
                    />
                  </Stack>
                  <TextField
                    size="small"
                    label="Description (tuỳ chọn)"
                    value={templateCreateForm.description}
                    onChange={(e) => setTemplateCreateForm({ ...templateCreateForm, description: e.target.value })}
                    multiline
                    minRows={2}
                  />
                  <Button
                    variant="contained"
                    disabled={!templateCreateForm.title || !templateCreateForm.category || creatingFromTemplate}
                    onClick={handleCreateFromTemplate}
                    sx={{ alignSelf: "flex-start" }}
                  >
                    {creatingFromTemplate ? <CircularProgress size={16} /> : "Tạo Control"}
                  </Button>
                </Stack>
              )}

              {templateCreateResult && (
                <Alert severity="success">
                  Đã tạo Control <strong>{templateCreateResult.control_id}</strong> (
                  {templateCreateResult.standard_mappings_added} standard mapping tự động) — trạng
                  thái <strong>draft</strong>, CHƯA có RemediationVariant. Bước tiếp theo (thủ công):
                  lưu nội dung playbook ở trên thành file, đưa qua{" "}
                  <code>scripts/content-signing/pull.sh → review.sh → sign.sh</code>, rồi mở lại
                  Control này để thêm RemediationVariant trỏ tới bundle đã ký.
                </Alert>
              )}
            </>
          )}
        </Stack>
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
                <Typography variant="subtitle1">Biến có thể override theo host</Typography>
                {Object.keys(detail.overridable_variables).length > 0 ? (
                  Object.entries(detail.overridable_variables).map(([name, defaultValue]) => (
                    <Typography key={name} variant="body2">
                      <Typography component="span" fontFamily="monospace">
                        {name}
                      </Typography>{" "}
                      — mặc định: {defaultValue}
                    </Typography>
                  ))
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    Control này không có biến nào override riêng theo host được (chỉ Control tạo từ
                    tab "Template" mới có).
                  </Typography>
                )}
                {Object.keys(detail.overridable_variables).length > 0 && (
                  <Typography variant="caption" color="text.secondary">
                    Đặt giá trị riêng cho từng host qua menu "⋮" ở trang Hosts → "Override biến
                    Ansible".
                  </Typography>
                )}
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
                    color={progressColor(canaryRollout.status)}
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
                              <Chip label={h.status} size="small" color={progressColor(h.status)} />
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
    </Stack>
  );
}
