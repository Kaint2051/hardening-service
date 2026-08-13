import { useEffect, useState } from "react";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";
import Button from "@mui/material/Button";
import Chip from "@mui/material/Chip";
import Select from "@mui/material/Select";
import MenuItem from "@mui/material/MenuItem";
import FormControl from "@mui/material/FormControl";
import FormHelperText from "@mui/material/FormHelperText";
import InputLabel from "@mui/material/InputLabel";
import Checkbox from "@mui/material/Checkbox";
import FormControlLabel from "@mui/material/FormControlLabel";
import Alert from "@mui/material/Alert";
import CircularProgress from "@mui/material/CircularProgress";
import Stepper from "@mui/material/Stepper";
import Step from "@mui/material/Step";
import StepLabel from "@mui/material/StepLabel";
import Table from "@mui/material/Table";
import TableHead from "@mui/material/TableHead";
import TableBody from "@mui/material/TableBody";
import TableRow from "@mui/material/TableRow";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import Accordion from "@mui/material/Accordion";
import AccordionSummary from "@mui/material/AccordionSummary";
import AccordionDetails from "@mui/material/AccordionDetails";
import { api } from "../api/client";
import { CONNECTION_METHODS, SCAP_PROFILE_KEYS } from "../api/types";
import type { ConnectionMethod, ControlLookupItem, Finding, HostOut, JobOut, RemediationRequestOut } from "../api/types";
import DiffView from "../components/DiffView";
import PageHeader from "../components/PageHeader";
import { useSnackbar } from "../hooks/useSnackbar";
import { useLatestRequest } from "../hooks/useLatestRequest";
import { errMessage } from "../lib/errors";
import { passFailColor } from "../lib/statusColors";
import { agentIneligibleReason } from "../lib/connection";
import { groupFindings } from "../lib/findingCategory";

// "Kiểm tra & Khắc phục" — 4 bước tuần tự đúng ngôn ngữ người vận hành đã
// dùng: kiểm tra -> xem kết quả -> chọn lỗi cần sửa -> gửi duyệt. Tái dùng
// 100% API scan/dry-run/override biến/submit-for-approval đã có, KHÔNG có
// đường "áp dụng" trực tiếp ở đây — mọi lần áp dụng thật đều phải qua hàng
// đợi chờ duyệt (trang "Chờ duyệt"), xem app/remediation_requests.py.
const STEPS = ["Chọn máy chủ & chuẩn", "Xem kết quả", "Chọn lỗi cần sửa", "Gửi duyệt"];

// Agent (Reporter) tự quét theo chu kỳ cố định (AGENT_SCAN_INTERVAL, mặc
// định 1 giờ) — KHÔNG có cách yêu cầu Agent quét ngay theo yêu cầu, nên ưu
// tiên hiển thị kết quả agent-scan gần nhất đã có sẵn (kèm thời điểm) thay
// vì chờ, và luôn để nguyên lựa chọn quét mới qua SSH bên cạnh — dùng
// GET /jobs có sẵn (list_jobs cho mọi role đã đăng nhập), không cần API mới.
function formatRelativeVi(iso: string): string {
  const minutes = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (minutes < 1) return "vừa xong";
  if (minutes < 60) return `${minutes} phút trước`;
  return `${Math.round(minutes / 60)} giờ trước`;
}

// "" = tự động (mặc định — ưu tiên Agent nếu host đủ điều kiện, không thì
// SSH, xem app/jobs.py:_agent_ineligible_reason). Chọn tay áp dụng cho CẢ
// dry-run (xem trước) lẫn apply thật (sau khi được duyệt) — chọn 1 lần,
// dùng lại y hệt lúc gửi duyệt, KHÔNG chọn lại ở bước sau.
const CONNECTION_METHOD_LABELS: Record<ConnectionMethod, string> = {
  ssh: "SSH (agentless)",
  agent: "Agent (Active Response)",
};

export default function ComplianceWizardPage() {
  const { showSuccess, showError } = useSnackbar();
  const [activeStep, setActiveStep] = useState(0);
  // Race-guard dùng chung: đổi host trong lúc 1 request đang bay không được
  // đè kết quả của host mới bằng dữ liệu host cũ. Host Select cũng bị disable
  // khi đang quét (xem Bước 0) để chặn mismatch ngay từ đầu.
  const beginAgentScan = useLatestRequest();
  const beginScan = useLatestRequest();

  // Bước 0
  const [hosts, setHosts] = useState<HostOut[]>([]);
  // Kill-switch Active Response toàn cục — cần để disable đúng option "Agent"
  // ở dropdown Kênh kết nối thay vì để người dùng chọn rồi nhận 422 từ
  // backend (xem lib/connection.ts, app/main.py:runtime_config).
  const [globalActiveResponse, setGlobalActiveResponse] = useState<boolean | undefined>(undefined);
  const [selectedHostname, setSelectedHostname] = useState("");
  const [scapProfileKey, setScapProfileKey] = useState<string>(SCAP_PROFILE_KEYS[0]);
  const [scanning, setScanning] = useState(false);
  const [scanJob, setScanJob] = useState<JobOut | null>(null);
  const [agentScanJob, setAgentScanJob] = useState<JobOut | null>(null);
  const [checkingAgentScan, setCheckingAgentScan] = useState(false);

  // Bước 1
  const [lookupLoading, setLookupLoading] = useState(false);
  const [lookupByRuleId, setLookupByRuleId] = useState<Record<string, ControlLookupItem>>({});
  const [showPassed, setShowPassed] = useState(false);

  // Bước 2
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [selectedControlId, setSelectedControlId] = useState<string | null>(null);
  const [selectedControlTitle, setSelectedControlTitle] = useState<string | null>(null);
  // "" = tự động — dùng CHUNG cho cả dry-run (Bước 2) lẫn gửi duyệt (Bước 3),
  // xem CONNECTION_METHOD_LABELS ở trên.
  const [connectionMethod, setConnectionMethod] = useState<ConnectionMethod | "">("");
  const [dryRunning, setDryRunning] = useState(false);
  const [dryRunJob, setDryRunJob] = useState<JobOut | null>(null);

  // Bước 3
  const [submitting, setSubmitting] = useState(false);
  const [submitResult, setSubmitResult] = useState<RemediationRequestOut | null>(null);

  useEffect(() => {
    api
      .listHosts()
      .then(setHosts)
      .catch((err) => showError(errMessage(err)));
    // Lỗi ở đây KHÔNG chặn cả wizard — bỏ qua im lặng, agentIneligibleReason
    // tự rơi về chế độ chỉ xét cấu hình host (backend vẫn chặn bằng 422).
    api
      .getRuntimeConfig()
      .then((cfg) => setGlobalActiveResponse(cfg.active_response_enabled))
      .catch(() => undefined);
  }, []);

  const selectedHost = hosts.find((h) => h.hostname === selectedHostname) ?? null;

  useEffect(() => {
    setAgentScanJob(null);
    if (!selectedHost?.agent_enrolled_at) return;
    const isStale = beginAgentScan();
    setCheckingAgentScan(true);
    api
      .listJobs({ hostname: selectedHost.hostname, job_type: "agent-scan", status: "succeeded", limit: 1, offset: 0 })
      .then((jobs) => (jobs.length > 0 ? api.getJob(jobs[0].id) : null))
      .then((job) => {
        if (isStale()) return;
        setAgentScanJob(job);
      })
      .catch(() => {
        if (!isStale()) setAgentScanJob(null);
      })
      .finally(() => {
        if (!isStale()) setCheckingAgentScan(false);
      });
  }, [selectedHost?.hostname, selectedHost?.agent_enrolled_at]);

  const resetAll = () => {
    setActiveStep(0);
    setScanJob(null);
    setLookupByRuleId({});
    setSelectedFinding(null);
    setSelectedControlId(null);
    setSelectedControlTitle(null);
    setConnectionMethod("");
    setDryRunJob(null);
    setSubmitResult(null);
  };

  // Dùng chung cho cả 2 nguồn kết quả (scan SSH mới vừa chạy xong, hoặc
  // agent-scan có sẵn từ trước) — job truyền vào PHẢI đã "succeeded".
  // isStale: bỏ qua nếu host đã đổi giữa chừng (chỉ liên quan đường scan SSH
  // chạy nền lâu; agent-scan có sẵn thì resolve tức thì).
  const applyScanResult = async (job: JobOut, isStale?: () => boolean) => {
    if (isStale?.()) return;
    setScanJob(job);
    setActiveStep(1);
    const findings = (job.result_summary?.findings as Finding[] | undefined) ?? [];
    const failedRuleIds = findings.filter((f) => f.result === "fail").map((f) => f.rule_id);
    // Chưa xác định OS (host mới đăng ký, chưa cài Agent lẫn chưa ai điền
    // tay — xem app/schemas.py:HostCreate) -> không tra được, giữ nguyên
    // findings đã quét (scan KHÔNG cần biết os_family) chỉ bỏ qua gợi ý sửa
    // qua giao diện cho tới khi biết OS, xem cảnh báo hiển thị ở bước render.
    if (failedRuleIds.length > 0 && selectedHost?.os_family) {
      setLookupLoading(true);
      try {
        const results = await api.lookupControlsByRule(
          failedRuleIds,
          selectedHost.os_family,
          selectedHost.os_version ?? undefined
        );
        if (isStale?.()) return;
        const byId: Record<string, ControlLookupItem> = {};
        for (const r of results) byId[r.rule_id] = r;
        setLookupByRuleId(byId);
      } finally {
        if (!isStale?.()) setLookupLoading(false);
      }
    }
  };

  const handleStartScan = async () => {
    if (!selectedHostname) return;
    const isStale = beginScan();
    setScanning(true);
    try {
      const job = await api.triggerScan(selectedHostname, scapProfileKey);
      if (isStale()) return;
      if (job.status !== "succeeded") {
        setScanJob(job);
        showError(`Kiểm tra thất bại cho ${selectedHostname} — xem chi tiết job #${job.id} ở trang Jobs`);
        return;
      }
      await applyScanResult(job, isStale);
    } catch (err) {
      if (!isStale()) showError(errMessage(err));
    } finally {
      if (!isStale()) setScanning(false);
    }
  };

  const handleUseAgentScan = async () => {
    if (!agentScanJob) return;
    await applyScanResult(agentScanJob);
  };

  const findings = (scanJob?.result_summary?.findings as Finding[] | undefined) ?? [];
  const failedFindings = findings.filter((f) => f.result === "fail");
  const passedFindings = findings.filter((f) => f.result !== "fail");
  const visibleFindings = showPassed ? findings : failedFindings;
  const visibleGroups = groupFindings(visibleFindings);

  const handleSelectFindingToFix = (finding: Finding) => {
    const lookup = lookupByRuleId[finding.rule_id];
    if (!lookup?.fixable || !lookup.control_id) return;
    setSelectedFinding(finding);
    setSelectedControlId(lookup.control_id);
    setSelectedControlTitle(lookup.control_title ?? lookup.control_id);
    setConnectionMethod("");
    setDryRunJob(null);
    setActiveStep(2);
  };

  const handlePreviewChange = async () => {
    if (!selectedHostname || !selectedControlId) return;
    setDryRunning(true);
    setDryRunJob(null);
    try {
      const job = await api.triggerRemediateDryRun(
        selectedHostname, selectedControlId, connectionMethod || undefined
      );
      setDryRunJob(job);
      if (job.status === "succeeded") {
        setActiveStep(3);
      } else {
        showError(`Xem trước thất bại — xem chi tiết job #${job.id} ở trang Jobs`);
      }
    } catch (err) {
      showError(errMessage(err));
    } finally {
      setDryRunning(false);
    }
  };

  const handleSubmitForApproval = async () => {
    if (!selectedHostname || !selectedControlId || !dryRunJob) return;
    setSubmitting(true);
    try {
      const result = await api.submitForApproval(
        selectedHostname, selectedControlId, dryRunJob.id, connectionMethod || undefined
      );
      setSubmitResult(result);
      showSuccess(`Đã gửi duyệt (mã yêu cầu #${result.id}) — chờ 1 người khác duyệt ở trang "Chờ duyệt".`);
    } catch (err) {
      showError(errMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  const diffOutput = dryRunJob?.result_summary?.diff_output as string | undefined;

  return (
    <Stack spacing={3}>
      <PageHeader title="Kiểm tra & Khắc phục" />
      <Stepper activeStep={activeStep}>
        {STEPS.map((label) => (
          <Step key={label}>
            <StepLabel>{label}</StepLabel>
          </Step>
        ))}
      </Stepper>

      {/* Bước 0 — Chọn máy chủ & chuẩn kiểm tra */}
      {activeStep === 0 && (
        <Stack spacing={2} sx={{ maxWidth: 480 }}>
          <Typography variant="body2" color="text.secondary">
            Hệ thống sẽ so sánh cấu hình máy chủ với chuẩn quốc tế (CIS) và liệt kê các điểm chưa
            đạt.
          </Typography>
          <FormControl size="small" fullWidth disabled={scanning}>
            <InputLabel>Máy chủ</InputLabel>
            <Select label="Máy chủ" value={selectedHostname} onChange={(e) => setSelectedHostname(e.target.value)}>
              {hosts.map((h) => (
                <MenuItem key={h.hostname} value={h.hostname}>
                  {h.hostname} {h.os_family ? `(${h.os_family} ${h.os_version ?? ""})` : "(chưa xác định OS)"}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControl size="small" fullWidth disabled={scanning}>
            <InputLabel>Chuẩn kiểm tra</InputLabel>
            <Select label="Chuẩn kiểm tra" value={scapProfileKey} onChange={(e) => setScapProfileKey(e.target.value)}>
              {SCAP_PROFILE_KEYS.map((k) => (
                <MenuItem key={k} value={k}>
                  {k}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          {checkingAgentScan && (
            <Stack direction="row" spacing={1} alignItems="center">
              <CircularProgress size={16} />
              <Typography variant="body2" color="text.secondary">
                Đang kiểm tra Agent trên máy này...
              </Typography>
            </Stack>
          )}
          {agentScanJob && !scanning && (
            <Alert
              severity="info"
              action={
                <Button color="inherit" size="small" onClick={handleUseAgentScan}>
                  Dùng kết quả này
                </Button>
              }
            >
              Máy này có Agent đang chạy — đã có kết quả quét từ{" "}
              {formatRelativeVi(agentScanJob.finished_at ?? agentScanJob.created_at)}.
            </Alert>
          )}
          {scanning && (
            <Stack direction="row" spacing={1} alignItems="center">
              <CircularProgress size={20} />
              <Typography variant="body2">Đang kiểm tra (có thể mất 30-90s)...</Typography>
            </Stack>
          )}
          <Button
            variant={agentScanJob ? "outlined" : "contained"}
            onClick={handleStartScan}
            disabled={!selectedHostname || scanning}
            sx={{ alignSelf: "flex-start" }}
          >
            {agentScanJob ? "Quét mới qua SSH" : "Bắt đầu kiểm tra"}
          </Button>
        </Stack>
      )}

      {/* Bước 1 — Xem kết quả */}
      {activeStep === 1 && (
        <Stack spacing={2}>
          <Stack direction="row" spacing={2} alignItems="center">
            <Typography variant="body1">
              <strong>{failedFindings.length}</strong> lỗi cần sửa / <strong>{passedFindings.length}</strong>{" "}
              mục đã đạt trên <strong>{selectedHostname}</strong>
            </Typography>
            <FormControlLabel
              control={<Checkbox checked={showPassed} onChange={(e) => setShowPassed(e.target.checked)} />}
              label="Hiện cả mục đã đạt"
            />
          </Stack>
          {!selectedHost?.os_family && (
            <Alert severity="info">
              Host này chưa xác định OS (os_family) — kết quả quét vẫn đầy đủ, nhưng chưa tra được
              gợi ý sửa qua giao diện cho tới khi Agent tự báo cáo hoặc điền tay ở trang Hosts.
            </Alert>
          )}
          {lookupLoading ? (
            <CircularProgress size={24} />
          ) : visibleGroups.length === 0 ? (
            <Typography variant="body2" color="text.secondary">
              Không có mục nào.
            </Typography>
          ) : (
            // Gộp theo chủ đề (lib/findingCategory.ts) — bảng phẳng 180+ dòng
            // không xử lý được. Nhóm nhiều lỗi nhất nằm trên cùng; nhóm đã
            // sạch lỗi tự thu gọn để không chiếm chỗ.
            visibleGroups.map((group) => (
              <Accordion
                key={group.key}
                defaultExpanded={group.failCount > 0}
                disableGutters
                slotProps={{ transition: { unmountOnExit: true } }}
              >
                <AccordionSummary expandIcon={<span>▾</span>}>
                  <Stack direction="row" spacing={1.5} alignItems="center" sx={{ flexGrow: 1 }}>
                    <Typography sx={{ fontWeight: 500 }}>{group.label}</Typography>
                    {group.failCount > 0 && (
                      <Chip label={`${group.failCount} lỗi`} size="small" color="error" />
                    )}
                    {group.passCount > 0 && (
                      <Chip
                        label={`${group.passCount} đạt`}
                        size="small"
                        color="success"
                        variant="outlined"
                      />
                    )}
                  </Stack>
                </AccordionSummary>
                <AccordionDetails sx={{ p: 0 }}>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Mục kiểm tra</TableCell>
                          <TableCell>Kết quả</TableCell>
                          <TableCell>Mức độ</TableCell>
                          <TableCell>Có thể sửa qua giao diện</TableCell>
                          <TableCell align="right">Hành động</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {group.findings.map((f) => {
                          const lookup = lookupByRuleId[f.rule_id];
                          return (
                            <TableRow key={f.rule_id}>
                              <TableCell>{f.title}</TableCell>
                              <TableCell>
                                <Chip
                                  label={f.result === "pass" ? "Đạt" : "Chưa đạt"}
                                  size="small"
                                  color={passFailColor(f.result)}
                                />
                              </TableCell>
                              <TableCell>{f.severity}</TableCell>
                              <TableCell>
                                {f.result !== "fail" ? (
                                  "—"
                                ) : lookup?.fixable ? (
                                  <Chip label="Có" size="small" color="success" variant="outlined" />
                                ) : (
                                  <Typography variant="caption" color="text.secondary">
                                    Chưa có bản vá — báo quản trị nội dung
                                  </Typography>
                                )}
                              </TableCell>
                              <TableCell align="right">
                                {f.result === "fail" && lookup?.fixable && (
                                  <Button size="small" onClick={() => handleSelectFindingToFix(f)}>
                                    Sửa lỗi này
                                  </Button>
                                )}
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </AccordionDetails>
              </Accordion>
            ))
          )}
          <Button onClick={resetAll} sx={{ alignSelf: "flex-start" }}>
            Kiểm tra máy chủ khác
          </Button>
        </Stack>
      )}

      {/* Bước 2 — Chọn lỗi cần sửa */}
      {activeStep === 2 && selectedFinding && (
        <Stack spacing={2} sx={{ maxWidth: 560 }}>
          <Typography variant="subtitle1">{selectedFinding.title}</Typography>
          <Typography variant="body2" color="text.secondary">
            Bản vá: {selectedControlTitle}
          </Typography>
          <FormControl size="small" fullWidth disabled={dryRunning}>
            <InputLabel>Kênh kết nối</InputLabel>
            <Select
              label="Kênh kết nối"
              value={connectionMethod}
              onChange={(e) => setConnectionMethod(e.target.value as ConnectionMethod | "")}
            >
              <MenuItem value="">Tự động (mặc định)</MenuItem>
              {CONNECTION_METHODS.map((m) => {
                const reason =
                  m === "agent" ? agentIneligibleReason(selectedHost, globalActiveResponse) : null;
                return (
                  <MenuItem key={m} value={m} disabled={reason !== null}>
                    {CONNECTION_METHOD_LABELS[m]}
                    {reason ? ` — ${reason}` : ""}
                  </MenuItem>
                );
              })}
            </Select>
            <FormHelperText>
              Áp dụng cho cả bước xem trước này lẫn lần áp dụng thật sau khi được duyệt.
            </FormHelperText>
          </FormControl>
          {dryRunning && (
            <Stack direction="row" spacing={1} alignItems="center">
              <CircularProgress size={20} />
              <Typography variant="body2">Đang xem trước thay đổi...</Typography>
            </Stack>
          )}
          <Stack direction="row" spacing={2}>
            <Button onClick={() => setActiveStep(1)}>Quay lại</Button>
            <Button variant="contained" onClick={handlePreviewChange} disabled={dryRunning}>
              Xem trước thay đổi
            </Button>
          </Stack>
        </Stack>
      )}

      {/* Bước 3 — Gửi duyệt */}
      {activeStep === 3 && dryRunJob && (
        <Stack spacing={2}>
          <Typography variant="subtitle1">Các thay đổi sẽ được áp dụng cho {selectedHostname}</Typography>
          <Typography variant="body2" color="text.secondary">
            Kênh kết nối: {connectionMethod ? CONNECTION_METHOD_LABELS[connectionMethod] : "Tự động (mặc định)"}
          </Typography>
          {diffOutput ? (
            <DiffView diffText={diffOutput} />
          ) : (
            <Typography variant="body2" color="text.secondary">
              Không có thay đổi nào khác so với hiện tại (đã đạt chuẩn).
            </Typography>
          )}
          {!submitResult ? (
            <Stack direction="row" spacing={2}>
              <Button onClick={() => setActiveStep(2)} disabled={submitting}>
                Quay lại
              </Button>
              <Button
                variant="contained"
                onClick={handleSubmitForApproval}
                disabled={submitting}
                startIcon={submitting ? <CircularProgress size={16} /> : undefined}
              >
                Gửi duyệt
              </Button>
            </Stack>
          ) : (
            <Stack spacing={2}>
              <Alert severity="success">
                Đã gửi yêu cầu #{submitResult.id} — chờ 1 người khác (vai trò duyệt) xem lại và bấm
                "Duyệt" ở trang "Chờ duyệt" trước khi áp dụng thật. Bạn có thể xem trạng thái yêu cầu
                này ở mục "Yêu cầu của tôi" trên cùng trang đó.
              </Alert>
              <Button variant="outlined" onClick={resetAll} sx={{ alignSelf: "flex-start" }}>
                Kiểm tra tiếp máy chủ khác
              </Button>
            </Stack>
          )}
        </Stack>
      )}

    </Stack>
  );
}
