import Table from "@mui/material/Table";
import TableHead from "@mui/material/TableHead";
import TableBody from "@mui/material/TableBody";
import TableRow from "@mui/material/TableRow";
import TableCell from "@mui/material/TableCell";
import TableContainer from "@mui/material/TableContainer";
import Accordion from "@mui/material/Accordion";
import AccordionSummary from "@mui/material/AccordionSummary";
import AccordionDetails from "@mui/material/AccordionDetails";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";
import Chip from "@mui/material/Chip";
import type { Finding } from "../api/types";
import { groupFindings } from "../lib/findingCategory";
import { passFailColor } from "../lib/statusColors";

// Bảng findings dùng chung (rule / kết quả pass-fail / mức độ) — dùng ở
// JobsPage.tsx (dialog chi tiết job scan) và HostsPage.tsx (dialog "Trigger
// scan"). ComplianceWizardPage.tsx CỐ Ý dùng bảng riêng vì cần thêm 2 cột
// "Có thể sửa"/"Hành động" gắn state trang, không gộp vào đây — nhưng CẢ HAI
// dùng chung groupFindings() để cách phân nhóm không lệch giữa 2 chỗ.
//
// Gộp theo chủ đề thay vì 1 bảng phẳng: 1 lần quét CIS thật trả ~180 rule,
// cuộn hết bảng đó để tìm mục cần xử lý là không khả thi.
export default function FindingsTable({ findings }: { findings: Finding[] }) {
  const groups = groupFindings(findings);

  if (groups.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary">
        Không có mục nào.
      </Typography>
    );
  }

  return (
    <>
      {groups.map((group) => (
        <Accordion
          key={group.key}
          defaultExpanded={group.failCount > 0}
          disableGutters
          slotProps={{ transition: { unmountOnExit: true } }}
        >
          <AccordionSummary expandIcon={<span>▾</span>}>
            <Stack direction="row" spacing={1.5} alignItems="center">
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
                  </TableRow>
                </TableHead>
                <TableBody>
                  {group.findings.map((f) => (
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
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>
      ))}
    </>
  );
}
