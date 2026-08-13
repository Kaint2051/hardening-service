import type { ReactNode } from "react";
import Stack from "@mui/material/Stack";
import Typography from "@mui/material/Typography";

// Tiêu đề trang thống nhất — thay khối lặp <Stack row space-between><h5/>
// {actions}</Stack> ở đầu mỗi trang. `actions` là cụm nút bên phải (Tải lại,
// Đăng ký host, checkbox lọc...); để trống nếu trang không có hành động cấp
// trang.
export default function PageHeader({ title, actions }: { title: string; actions?: ReactNode }) {
  return (
    <Stack
      direction="row"
      justifyContent="space-between"
      alignItems="center"
      spacing={2}
      sx={{ mb: 1, flexWrap: "wrap", gap: 1 }}
    >
      <Typography variant="h5">{title}</Typography>
      {actions ? (
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
          {actions}
        </Stack>
      ) : null}
    </Stack>
  );
}
