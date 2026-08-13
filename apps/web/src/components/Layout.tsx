import { useEffect, useState } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import AppBar from "@mui/material/AppBar";
import Toolbar from "@mui/material/Toolbar";
import Typography from "@mui/material/Typography";
import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import Chip from "@mui/material/Chip";
import Stack from "@mui/material/Stack";
import Button from "@mui/material/Button";
import Container from "@mui/material/Container";
import Alert from "@mui/material/Alert";
import keycloak from "../auth/keycloak";
import { api } from "../api/client";

// RBAC tuỳ biến (app/permissions.py, app/roles.py) — permission KHÔNG còn
// cố định theo 6 vai trò cũ, admin tự tạo vai trò + tự chọn quyền qua tab
// Cài đặt. Gate hiển thị tab dựa trên PERMISSION (GET /me/permissions), không
// còn so tên role — KHÔNG dùng để CHẶN, RBAC thật 100% ở backend (mọi
// endpoint tự kiểm tra permission riêng qua require_permission), đây chỉ là
// gợi ý hiển thị để operator/viewer không thấy khu vực không dành cho công
// việc hằng ngày của họ, cùng chủ trương xuyên suốt app này.
const _CONTENT_ADMIN_PERMISSIONS = ["controls.edit", "controls.promote"];
// Tab "Chờ duyệt" cần cho CẢ operator (gửi yêu cầu, xem "Yêu cầu của tôi" —
// xem RemediationQueuePage.tsx) lẫn approver (duyệt hàng đợi) —
// ComplianceWizardPage.tsx sau khi "Gửi duyệt" luôn hướng operator quay lại
// đúng trang này, nên KHÔNG được ẩn tab với riêng permission submit.
const _REMEDIATION_QUEUE_PERMISSIONS = ["remediation_requests.submit", "remediation_requests.approve"];
// Tab "Cài đặt" (quản lý người dùng + vai trò/quyền, xem app/users.py,
// app/roles.py) — cần 1 trong 2 permission quản trị, khác các tab khác vốn
// mở cho nhiều permission "view" cùng lúc.
const _SETTINGS_PERMISSIONS = ["users.manage", "rbac.manage"];

function hasAnyPermission(permissions: string[], required: string[]): boolean {
  return permissions.some((p) => required.includes(p));
}

export default function Layout() {
  const location = useLocation();
  const [user, setUser] = useState<{ username: string; roles: string[] } | null>(null);
  const [meError, setMeError] = useState<string | null>(null);
  const [permissions, setPermissions] = useState<string[]>([]);

  useEffect(() => {
    api
      .me()
      .then(setUser)
      .catch((err) => setMeError(String(err)));
    api
      .getMyPermissions()
      .then((res) => setPermissions(res.permissions))
      .catch(() => undefined);
  }, []);

  const activeTab = location.pathname.startsWith("/controls")
    ? "/controls"
    : location.pathname.startsWith("/jobs")
      ? "/jobs"
      : location.pathname.startsWith("/remediation-queue")
        ? "/remediation-queue"
        : location.pathname.startsWith("/risk-overview")
          ? "/risk-overview"
          : location.pathname.startsWith("/hosts")
            ? "/hosts"
            : location.pathname.startsWith("/settings")
              ? "/settings"
              : "/compliance";

  const showContentAdmin = hasAnyPermission(permissions, _CONTENT_ADMIN_PERMISSIONS);
  const showApprovalQueue = hasAnyPermission(permissions, _REMEDIATION_QUEUE_PERMISSIONS);
  const showSettings = hasAnyPermission(permissions, _SETTINGS_PERMISSIONS);

  return (
    <>
      <AppBar position="static">
        <Toolbar sx={{ gap: 2 }}>
          <Typography variant="h6" sx={{ flexGrow: 0 }}>
            Hardening Console
          </Typography>
          <Tabs
            value={activeTab}
            textColor="inherit"
            indicatorColor="secondary"
            variant="scrollable"
            scrollButtons="auto"
            allowScrollButtonsMobile
            sx={{ flexGrow: 1, minWidth: 0 }}
          >
            <Tab label="Kiểm tra & Khắc phục" value="/compliance" component={Link} to="/compliance" />
            <Tab label="Cần chú ý" value="/risk-overview" component={Link} to="/risk-overview" />
            {showApprovalQueue && (
              <Tab label="Chờ duyệt" value="/remediation-queue" component={Link} to="/remediation-queue" />
            )}
            <Tab label="Hosts" value="/hosts" component={Link} to="/hosts" />
            {showContentAdmin && (
              <Tab label="Quản trị nội dung chuẩn" value="/controls" component={Link} to="/controls" />
            )}
            <Tab label="Jobs" value="/jobs" component={Link} to="/jobs" />
            {showSettings && (
              <Tab label="Cài đặt" value="/settings" component={Link} to="/settings" />
            )}
          </Tabs>
          {user && (
            <Stack direction="row" spacing={1} alignItems="center">
              <Typography variant="body2">{user.username}</Typography>
              {/* user.roles giờ tới từ user_role_assignments (DB app, xem
                  GET /me + app/auth.py:get_current_user) — KHÔNG còn đọc JWT
                  claim realm_access.roles nữa, nên không còn lẫn role nội bộ
                  Keycloak (default-roles-<realm>/offline_access/
                  uma_authorization) như trước, không cần lọc lại. */}
              {user.roles.map((r) => (
                <Chip key={r} label={r} size="small" color="secondary" />
              ))}
            </Stack>
          )}
          <Button color="inherit" onClick={() => keycloak.logout()}>
            Đăng xuất
          </Button>
        </Toolbar>
      </AppBar>
      {/* maxWidth={false} thay vì "lg" (1200px cố định) — các bảng dữ liệu
          (Hosts/Jobs/Controls) có nhiều cột (chip, dropdown, text nhiều
          dòng) rộng hơn 1200px, nên trước đây bảng vẫn phải tự cuộn ngang
          BÊN TRONG khung 1200px dù màn hình còn thừa rất nhiều khoảng trống
          hai bên — px thay cho maxWidth để vẫn có lề, không full-bleed sát
          mép trình duyệt. */}
      <Container maxWidth={false} sx={{ mt: 3, mb: 6, px: { xs: 2, sm: 3 } }}>
        {meError && <Alert severity="error">Không lấy được thông tin người dùng: {meError}</Alert>}
        <Outlet />
      </Container>
    </>
  );
}
