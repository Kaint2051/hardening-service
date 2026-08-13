import { createContext, useContext, useMemo, useState } from "react";
import type { ReactNode } from "react";
import Snackbar from "@mui/material/Snackbar";
import Alert from "@mui/material/Alert";

// Toast dùng chung toàn app — thay 5 bản `const [snack,setSnack]` + 5 khối
// <Snackbar> giống hệt nhau rải rác trong từng trang. 1 slot toàn cục (giống
// hệt hành vi cũ của mỗi trang: gọi liên tiếp thì cái sau đè cái trước), nên
// không đổi trải nghiệm, chỉ bỏ trùng lặp.
type SnackbarApi = {
  showSuccess: (message: string) => void;
  showError: (message: string) => void;
};

const SnackbarContext = createContext<SnackbarApi | null>(null);

export function SnackbarProvider({ children }: { children: ReactNode }) {
  const [snack, setSnack] = useState<{ severity: "success" | "error"; message: string } | null>(null);
  const value = useMemo<SnackbarApi>(
    () => ({
      showSuccess: (message) => setSnack({ severity: "success", message }),
      showError: (message) => setSnack({ severity: "error", message }),
    }),
    []
  );
  return (
    <SnackbarContext.Provider value={value}>
      {children}
      <Snackbar open={snack !== null} autoHideDuration={5000} onClose={() => setSnack(null)}>
        {snack ? (
          <Alert severity={snack.severity} onClose={() => setSnack(null)} variant="filled">
            {snack.message}
          </Alert>
        ) : undefined}
      </Snackbar>
    </SnackbarContext.Provider>
  );
}

export function useSnackbar(): SnackbarApi {
  const ctx = useContext(SnackbarContext);
  if (!ctx) throw new Error("useSnackbar phải nằm trong <SnackbarProvider> (xem main.tsx)");
  return ctx;
}
