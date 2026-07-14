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

export default function Layout() {
  const location = useLocation();
  const [user, setUser] = useState<{ username: string; roles: string[] } | null>(null);
  const [meError, setMeError] = useState<string | null>(null);

  useEffect(() => {
    api
      .me()
      .then(setUser)
      .catch((err) => setMeError(String(err)));
  }, []);

  const activeTab = location.pathname.startsWith("/controls")
    ? "/controls"
    : location.pathname.startsWith("/jobs")
      ? "/jobs"
      : "/hosts";

  return (
    <>
      <AppBar position="static">
        <Toolbar sx={{ gap: 2 }}>
          <Typography variant="h6" sx={{ flexGrow: 0 }}>
            Hardening Console
          </Typography>
          <Tabs value={activeTab} textColor="inherit" indicatorColor="secondary" sx={{ flexGrow: 1 }}>
            <Tab label="Hosts" value="/hosts" component={Link} to="/hosts" />
            <Tab label="Controls" value="/controls" component={Link} to="/controls" />
            <Tab label="Jobs" value="/jobs" component={Link} to="/jobs" />
          </Tabs>
          {user && (
            <Stack direction="row" spacing={1} alignItems="center">
              <Typography variant="body2">{user.username}</Typography>
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
      <Container maxWidth="lg" sx={{ mt: 3, mb: 6 }}>
        {meError && <Alert severity="error">Không lấy được thông tin người dùng: {meError}</Alert>}
        <Outlet />
      </Container>
    </>
  );
}
