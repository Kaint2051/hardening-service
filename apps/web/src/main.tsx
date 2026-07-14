import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import CssBaseline from "@mui/material/CssBaseline";
import keycloak from "./auth/keycloak";
import App from "./App";

const rootEl = document.getElementById("root")!;

// onLoad: "login-required" -> khung sườn này KHÔNG có trang public nào, mọi
// truy cập đều bắt đăng nhập qua Keycloak trước (Authorization Code + PKCE).
//
// checkLoginIframe: false — mặc định keycloak-js là true, tự chèn 1 iframe
// ẩn trỏ sang origin Keycloak (khác port -> khác origin, bị coi là
// third-party) để phát hiện đăng xuất ở tab khác. Cơ chế này cần trình duyệt
// cho phép truy cập storage/cookie third-party trong iframe đó — trình
// duyệt chặn third-party mặc định (Brave Shields, Safari ITP, và dần là mọi
// trình duyệt) làm bước check này treo vĩnh viễn, khiến init() không bao giờ
// resolve và app không bao giờ redirect sang trang login (phát hiện qua báo
// cáo thật từ người dùng: trang trắng, chỉ có 1 iframe ẩn trỏ tới
// "3p-cookies/step1.html", root div rỗng). Tắt hẳn cơ chế này — không mất gì
// về bảo mật vì mỗi lần gọi API vẫn tự verify/refresh token riêng
// (api/client.ts:updateToken trước mỗi request), chỉ mất khả năng tự phát
// hiện đăng xuất ở TAB KHÁC trong cùng trình duyệt (không phải yêu cầu của
// khung sườn này).
keycloak
  .init({ onLoad: "login-required", pkceMethod: "S256", checkLoginIframe: false })
  .then((authenticated) => {
    if (!authenticated) {
      keycloak.login();
      return;
    }
    createRoot(rootEl).render(
      <StrictMode>
        <CssBaseline />
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </StrictMode>
    );
  })
  .catch((err) => {
    rootEl.innerHTML = `<p style="font-family: sans-serif; padding: 2rem; color: #b00020;">Không khởi tạo được đăng nhập Keycloak: ${String(
      err
    )}</p>`;
  });
