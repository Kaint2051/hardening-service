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
import CircularProgress from "@mui/material/CircularProgress";
import { api } from "../api/client";
import type { HostRiskOverviewItem } from "../api/types";
import PageHeader from "../components/PageHeader";
import { useSnackbar } from "../hooks/useSnackbar";
import { errMessage } from "../lib/errors";
import { attentionColor, attentionLabel, caMigrationColor, exposureColor, exposureLabel } from "../lib/statusColors";

// "Cần chú ý" — tổng hợp Tier × điểm compliance có trọng số theo severity ×
// exposure (local/proxied/direct) × ca_migration_status thành 1 mức ưu tiên
// duy nhất, xem app/risk.py. KHÔNG thay thế trang Hosts (đó là nơi SỬA thông
// tin host) — trang này chỉ ĐỌC, để trả lời đúng 1 câu hỏi: "nên xem máy nào
// trước?".
export default function RiskOverviewPage() {
  const { showError } = useSnackbar();
  const [items, setItems] = useState<HostRiskOverviewItem[]>([]);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    api
      .getRiskOverview()
      .then(setItems)
      .catch((err) => showError(errMessage(err)))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const highCount = items.filter((it) => it.attention_level === "high").length;

  return (
    <Stack spacing={3}>
      <PageHeader
        title="Cần chú ý"
        actions={
          <Button variant="outlined" onClick={load}>
            Tải lại
          </Button>
        }
      />
      <Typography variant="body2" color="text.secondary">
        Gộp mức độ quan trọng (Tier), điểm compliance lần quét gần nhất (tính nặng hơn cho lỗi
        severity cao), mức độ tiếp xúc Internet (local/qua proxy/trực tiếp), và máy còn dùng SSH
        key/password tĩnh hay đã chuyển sang chứng chỉ — thành 1 mức ưu tiên duy nhất. Không thay
        cho trang Hosts, chỉ giúp biết nên xem máy nào trước.
      </Typography>

      {loading ? (
        <CircularProgress />
      ) : (
        <Stack spacing={2}>
          {highCount > 0 && (
            <Typography variant="subtitle1" color="error.main">
              {highCount} máy cần chú ý ngay
            </Typography>
          )}
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Mức ưu tiên</TableCell>
                  <TableCell>Hostname</TableCell>
                  <TableCell>Tier</TableCell>
                  <TableCell>Tiếp xúc Internet</TableCell>
                  <TableCell>SSH cert</TableCell>
                  <TableCell>Điểm compliance</TableCell>
                  <TableCell>Lần quét gần nhất</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {items.map((it) => (
                  <TableRow key={it.hostname}>
                    <TableCell>
                      <Chip
                        label={attentionLabel[it.attention_level]}
                        size="small"
                        color={attentionColor[it.attention_level]}
                      />
                    </TableCell>
                    <TableCell>{it.hostname}</TableCell>
                    <TableCell>
                      <Chip label={`Tier ${it.tier}`} size="small" />
                    </TableCell>
                    <TableCell>
                      <Chip label={exposureLabel[it.exposure]} size="small" color={exposureColor[it.exposure]} />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={it.ca_migration_status}
                        size="small"
                        color={caMigrationColor[it.ca_migration_status]}
                      />
                    </TableCell>
                    <TableCell>
                      {it.compliance_score === null ? "Chưa quét" : `${it.compliance_score}/100`}
                    </TableCell>
                    <TableCell>
                      {it.latest_scan_at ? new Date(it.latest_scan_at).toLocaleString("vi-VN") : "—"}
                    </TableCell>
                  </TableRow>
                ))}
                {items.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={7} align="center">
                      Chưa có host nào.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </Stack>
      )}
    </Stack>
  );
}
