import { createTheme } from "@mui/material/styles";

// Theme dùng chung toàn app — trước đây KHÔNG có (main.tsx chỉ có <CssBaseline/>,
// mọi trang thừa hưởng mặc định MUI). Chủ ý giới hạn phạm vi để không đổi hành
// vi/layout: chỉ chỉnh palette/typography/shape + vài default props an toàn.
//
// CỐ TÌNH KHÔNG làm:
//  - size="small" toàn cục cho TextField/Table/Select: sẽ co field trong các
//    dialog (đăng ký/sửa host, bootstrap CA) đang dùng cỡ mặc định -> lệch
//    layout. Chip thì an toàn vì mọi chip trong app vốn đã size="small".
//  - MuiPaper variant="outlined" toàn cục: Dialog/Menu render bề mặt qua Paper,
//    ép outlined sẽ làm phẳng (mất đổ bóng) mọi modal -> để nguyên mặc định.
const theme = createTheme({
  palette: {
    primary: { main: "#1565c0" },
    secondary: { main: "#00897b" },
    background: { default: "#f4f6f8" },
  },
  shape: { borderRadius: 8 },
  typography: {
    fontFamily: [
      "Roboto",
      '"Segoe UI"',
      "system-ui",
      '"Helvetica Neue"',
      "Arial",
      // dự phòng glyph có dấu tiếng Việt nếu font trên thiếu
      '"Noto Sans"',
      "sans-serif",
    ].join(","),
    h5: { fontWeight: 600 },
    h6: { fontWeight: 600 },
    subtitle1: { fontWeight: 600 },
  },
  components: {
    MuiChip: { defaultProps: { size: "small" } },
    MuiAppBar: { defaultProps: { elevation: 1 } },
    // textTransform: none -> nút không viết HOA toàn bộ (mặc định MUI), dễ đọc
    // tiếng Việt có dấu hơn; disableElevation cho phẳng nhất quán. Bề rộng nút
    // gần như không đổi nên không ảnh hưởng layout.
    MuiButton: {
      defaultProps: { disableElevation: true },
      styleOverrides: { root: { textTransform: "none" } },
    },
  },
});

export default theme;
