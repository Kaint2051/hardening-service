import Box from "@mui/material/Box";

// Hiện diff dạng unified-diff (app/jobs.py result_summary.diff_output) có tô
// màu dòng thêm/bớt — thay cho khối <pre>{JSON.stringify(...)}</pre> thô
// trước đây (JobsPage.tsx), dùng chung với ComplianceWizardPage.tsx (Bước 4
// "Gửi duyệt" — xem trước thay đổi trước khi gửi) và RemediationQueuePage.tsx
// (approver xem lại diff trước khi Duyệt).
export default function DiffView({ diffText }: { diffText: string }) {
  const lines = diffText.split("\n");
  return (
    <Box
      component="pre"
      sx={{
        m: 0,
        whiteSpace: "pre-wrap",
        wordBreak: "break-all",
        bgcolor: "action.hover",
        p: 1.5,
        borderRadius: 1,
        maxHeight: 400,
        overflow: "auto",
        fontFamily: "monospace",
        fontSize: "0.8rem",
      }}
    >
      {lines.map((line, i) => (
        <Box
          key={i}
          component="div"
          sx={{
            color: line.startsWith("+")
              ? "success.main"
              : line.startsWith("-")
              ? "error.main"
              : "text.primary",
          }}
        >
          {line || " "}
        </Box>
      ))}
    </Box>
  );
}
