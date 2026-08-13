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
import Chip from "@mui/material/Chip";
import Select from "@mui/material/Select";
import MenuItem from "@mui/material/MenuItem";
import Checkbox from "@mui/material/Checkbox";
import ListItemText from "@mui/material/ListItemText";
import CircularProgress from "@mui/material/CircularProgress";
import Alert from "@mui/material/Alert";
import Button from "@mui/material/Button";
import Dialog from "@mui/material/Dialog";
import DialogTitle from "@mui/material/DialogTitle";
import DialogContent from "@mui/material/DialogContent";
import DialogActions from "@mui/material/DialogActions";
import TextField from "@mui/material/TextField";
import FormGroup from "@mui/material/FormGroup";
import FormControlLabel from "@mui/material/FormControlLabel";
import { api } from "../api/client";
import type { PermissionOut, RoleOut, UserOut } from "../api/types";
import PageHeader from "../components/PageHeader";
import { useSnackbar } from "../hooks/useSnackbar";
import { errMessage } from "../lib/errors";

// Gợi ý hiển thị (KHÔNG phải enforcement thật — backend tự tính lại và chặn
// 422 qua app/rbac.py:check_caller_keeps_permission): tính quyền hợp lệ nếu
// user giữ ĐÚNG tập `roleNames` này, dùng để disable checkbox role sẽ làm
// chính người đang sửa (isSelf) mất quyền users.manage.
function grantedPermissions(allRoles: RoleOut[], roleNames: string[]): Set<string> {
  const granted = new Set<string>();
  for (const name of roleNames) {
    const role = allRoles.find((r) => r.name === name);
    role?.permissions.forEach((p) => granted.add(p));
  }
  return granted;
}

export default function SettingsPage() {
  const { showSuccess, showError } = useSnackbar();
  const [users, setUsers] = useState<UserOut[]>([]);
  const [usersLoading, setUsersLoading] = useState(true);
  const [myUsername, setMyUsername] = useState<string | null>(null);

  const [roles, setRoles] = useState<RoleOut[]>([]);
  const [rolesLoading, setRolesLoading] = useState(true);
  const [permissionsList, setPermissionsList] = useState<PermissionOut[]>([]);

  const loadUsers = () => {
    setUsersLoading(true);
    api
      .listUsers()
      .then(setUsers)
      .catch((err) => showError(errMessage(err)))
      .finally(() => setUsersLoading(false));
  };

  const loadRoles = () => {
    setRolesLoading(true);
    api
      .listRoles()
      .then(setRoles)
      .catch((err) => showError(errMessage(err)))
      .finally(() => setRolesLoading(false));
  };

  useEffect(loadUsers, []);
  useEffect(loadRoles, []);
  useEffect(() => {
    api.listPermissions().then(setPermissionsList).catch(() => undefined);
  }, []);
  useEffect(() => {
    api.me().then((me) => setMyUsername(me.username)).catch(() => undefined);
  }, []);

  const permissionGroups = useMemo(() => {
    const groups = new Map<string, PermissionOut[]>();
    for (const p of permissionsList) {
      const prefix = p.permission.split(".")[0];
      if (!groups.has(prefix)) groups.set(prefix, []);
      groups.get(prefix)!.push(p);
    }
    return groups;
  }, [permissionsList]);

  const handleRolesChange = async (target: UserOut, newRoles: string[]) => {
    try {
      await api.updateUserRoles(target.id, newRoles);
      showSuccess(`Đã cập nhật vai trò cho ${target.username}`);
      loadUsers();
    } catch (err) {
      showError(errMessage(err));
    }
  };

  // --- Tạo vai trò mới ---
  const [createRoleOpen, setCreateRoleOpen] = useState(false);
  const [newRoleName, setNewRoleName] = useState("");
  const [newRoleDescription, setNewRoleDescription] = useState("");
  const [creatingRole, setCreatingRole] = useState(false);

  const handleCreateRole = async () => {
    setCreatingRole(true);
    try {
      await api.createRole(newRoleName.trim(), newRoleDescription.trim() || undefined);
      showSuccess(`Đã tạo vai trò "${newRoleName.trim()}"`);
      setCreateRoleOpen(false);
      setNewRoleName("");
      setNewRoleDescription("");
      loadRoles();
    } catch (err) {
      showError(errMessage(err));
    } finally {
      setCreatingRole(false);
    }
  };

  // --- Sửa ma trận quyền của 1 vai trò ---
  const [editRoleTarget, setEditRoleTarget] = useState<RoleOut | null>(null);
  const [editSelectedPermissions, setEditSelectedPermissions] = useState<string[]>([]);
  const [savingPermissions, setSavingPermissions] = useState(false);

  const openEditPermissions = (role: RoleOut) => {
    setEditRoleTarget(role);
    setEditSelectedPermissions(role.permissions);
  };

  const togglePermission = (permission: string) => {
    setEditSelectedPermissions((prev) =>
      prev.includes(permission) ? prev.filter((p) => p !== permission) : [...prev, permission]
    );
  };

  const handleSavePermissions = async () => {
    if (!editRoleTarget) return;
    setSavingPermissions(true);
    try {
      await api.updateRolePermissions(editRoleTarget.name, editSelectedPermissions);
      showSuccess(`Đã cập nhật quyền cho vai trò "${editRoleTarget.name}"`);
      setEditRoleTarget(null);
      loadRoles();
    } catch (err) {
      showError(errMessage(err));
    } finally {
      setSavingPermissions(false);
    }
  };

  // --- Xoá vai trò tuỳ biến ---
  const [deleteRoleTarget, setDeleteRoleTarget] = useState<RoleOut | null>(null);
  const [deletingRole, setDeletingRole] = useState(false);

  const handleDeleteRole = async () => {
    if (!deleteRoleTarget) return;
    setDeletingRole(true);
    try {
      await api.deleteRole(deleteRoleTarget.name);
      showSuccess(`Đã xoá vai trò "${deleteRoleTarget.name}"`);
      setDeleteRoleTarget(null);
      loadRoles();
    } catch (err) {
      showError(errMessage(err));
    } finally {
      setDeletingRole(false);
    }
  };

  return (
    <Stack spacing={4}>
      <PageHeader title="Cài đặt hệ thống" />

      <Stack spacing={2}>
        <Typography variant="subtitle1">Quản lý người dùng</Typography>
        <Typography variant="body2" color="text.secondary">
          Danh sách user thật lấy từ Keycloak — chỉ xem + đổi vai trò tại đây.
          Tạo user mới/đặt lại mật khẩu/xoá user vẫn làm qua Keycloak admin
          console như trước.
        </Typography>
        {usersLoading ? (
          <CircularProgress />
        ) : (
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Username</TableCell>
                  <TableCell>Email</TableCell>
                  <TableCell>Trạng thái</TableCell>
                  <TableCell>Vai trò</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {users.map((u) => {
                  const isSelf = myUsername !== null && u.username === myUsername;
                  return (
                    <TableRow key={u.id}>
                      <TableCell>{u.username}</TableCell>
                      <TableCell>{u.email ?? "—"}</TableCell>
                      <TableCell>
                        <Chip
                          label={u.enabled ? "Đang hoạt động" : "Đã khoá"}
                          size="small"
                          color={u.enabled ? "success" : "default"}
                        />
                      </TableCell>
                      <TableCell>
                        <Select
                          multiple
                          size="small"
                          value={u.roles}
                          onChange={(e) => handleRolesChange(u, e.target.value as string[])}
                          renderValue={(selected) => (
                            <Stack direction="row" spacing={0.5} flexWrap="wrap">
                              {(selected as string[]).map((r) => (
                                <Chip key={r} label={r} size="small" />
                              ))}
                            </Stack>
                          )}
                          sx={{ minWidth: 260 }}
                        >
                          {roles.map((r) => {
                            // Tự-khoá-quyền: nếu bỏ chọn role này khỏi CHÍNH
                            // MÌNH sẽ làm mất quyền users.manage, disable checkbox
                            // — chỉ là gợi ý hiển thị, backend tự chặn 422 thật.
                            const wouldLoseUsersManage =
                              isSelf &&
                              u.roles.includes(r.name) &&
                              !grantedPermissions(
                                roles,
                                u.roles.filter((x) => x !== r.name)
                              ).has("users.manage");
                            return (
                              <MenuItem key={r.name} value={r.name} disabled={wouldLoseUsersManage}>
                                <Checkbox checked={u.roles.includes(r.name)} size="small" />
                                <ListItemText primary={r.name} secondary={r.description ?? undefined} />
                              </MenuItem>
                            );
                          })}
                        </Select>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        )}
        {!usersLoading && users.length === 0 && (
          <Alert severity="info">Không lấy được danh sách user (hoặc chưa có user nào).</Alert>
        )}
      </Stack>

      <Stack spacing={2}>
        <Stack direction="row" justifyContent="space-between" alignItems="center">
          <Typography variant="subtitle1">Quản lý vai trò &amp; quyền</Typography>
          <Button variant="contained" size="small" onClick={() => setCreateRoleOpen(true)}>
            Tạo vai trò mới
          </Button>
        </Stack>
        <Typography variant="body2" color="text.secondary">
          6 vai trò gốc (đánh dấu "Có sẵn") không xoá được — vai trò tuỳ biến
          có thể tạo mới/xoá tự do. Sửa quyền của bất kỳ vai trò nào (kể cả
          gốc) đều áp dụng ngay lần gọi API kế tiếp của user giữ vai trò đó,
          không cần đăng nhập lại.
        </Typography>
        {rolesLoading ? (
          <CircularProgress />
        ) : (
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Vai trò</TableCell>
                  <TableCell>Loại</TableCell>
                  <TableCell>Mô tả</TableCell>
                  <TableCell>Số quyền</TableCell>
                  <TableCell align="right">Hành động</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {roles.map((r) => (
                  <TableRow key={r.name}>
                    <TableCell>{r.name}</TableCell>
                    <TableCell>
                      <Chip
                        label={r.is_builtin ? "Có sẵn" : "Tuỳ biến"}
                        size="small"
                        color={r.is_builtin ? "default" : "info"}
                      />
                    </TableCell>
                    <TableCell>{r.description ?? "—"}</TableCell>
                    <TableCell>{r.permissions.length}</TableCell>
                    <TableCell align="right">
                      <Stack direction="row" spacing={1} justifyContent="flex-end">
                        <Button size="small" onClick={() => openEditPermissions(r)}>
                          Sửa quyền
                        </Button>
                        <Button
                          size="small"
                          color="error"
                          onClick={() => setDeleteRoleTarget(r)}
                          disabled={r.is_builtin}
                          title={r.is_builtin ? "Không thể xoá vai trò có sẵn" : "Xoá vai trò"}
                        >
                          Xoá
                        </Button>
                      </Stack>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Stack>

      {/* Tạo vai trò mới — permission gán rỗng lúc tạo, sửa ngay sau qua "Sửa quyền". */}
      <Dialog open={createRoleOpen} onClose={() => setCreateRoleOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Tạo vai trò mới</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              label="Tên vai trò"
              value={newRoleName}
              onChange={(e) => setNewRoleName(e.target.value)}
              autoFocus
              fullWidth
            />
            <TextField
              label="Mô tả (tuỳ chọn)"
              value={newRoleDescription}
              onChange={(e) => setNewRoleDescription(e.target.value)}
              fullWidth
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateRoleOpen(false)}>Huỷ</Button>
          <Button variant="contained" onClick={handleCreateRole} disabled={creatingRole || !newRoleName.trim()}>
            {creatingRole ? <CircularProgress size={16} /> : "Tạo"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Sửa ma trận quyền — group theo tiền tố resource (hosts./jobs./...) cho gọn. */}
      <Dialog open={editRoleTarget !== null} onClose={() => setEditRoleTarget(null)} fullWidth maxWidth="md">
        <DialogTitle>Sửa quyền — {editRoleTarget?.name}</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 1 }}>
            {editRoleTarget?.name === "admin" && (
              <Alert severity="warning">
                Vai trò "admin" luôn phải giữ quyền "rbac.manage" — bỏ chọn sẽ
                bị chặn (422), không có cách nào tự sửa lại RBAC nếu thiếu.
              </Alert>
            )}
            {Array.from(permissionGroups.entries()).map(([prefix, perms]) => (
              <Stack key={prefix} spacing={0.5}>
                <Typography variant="subtitle2">{prefix}</Typography>
                <FormGroup>
                  {perms.map((p) => (
                    <FormControlLabel
                      key={p.permission}
                      control={
                        <Checkbox
                          size="small"
                          checked={editSelectedPermissions.includes(p.permission)}
                          onChange={() => togglePermission(p.permission)}
                        />
                      }
                      label={`${p.permission} — ${p.description}`}
                    />
                  ))}
                </FormGroup>
              </Stack>
            ))}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditRoleTarget(null)}>Huỷ</Button>
          <Button variant="contained" onClick={handleSavePermissions} disabled={savingPermissions}>
            {savingPermissions ? <CircularProgress size={16} /> : "Lưu"}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Xoá vai trò tuỳ biến — chặn 422 phía backend nếu còn user nào đang gán. */}
      <Dialog open={deleteRoleTarget !== null} onClose={() => setDeleteRoleTarget(null)} fullWidth maxWidth="sm">
        <DialogTitle>Xoá vai trò — {deleteRoleTarget?.name}</DialogTitle>
        <DialogContent>
          <Alert severity="error">
            Xoá THẬT, không thể hoàn tác. Nếu còn user nào đang gán vai trò
            này, backend sẽ từ chối — bỏ gán khỏi mọi user trước khi xoá.
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteRoleTarget(null)}>Huỷ</Button>
          <Button variant="contained" color="error" onClick={handleDeleteRole} disabled={deletingRole}>
            {deletingRole ? <CircularProgress size={16} /> : "Xác nhận xoá"}
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
