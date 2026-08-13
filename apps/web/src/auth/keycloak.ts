import Keycloak from "keycloak-js";

// Client public "web" (Authorization Code + PKCE, không có client secret —
// đúng chuẩn cho SPA chạy hoàn toàn phía trình duyệt). Xem
// infra/keycloak/realm-export.json và app/config.py (keycloak_client_ids)
// phía Orchestrator để hiểu vì sao có 2 client riêng (web vs orchestrator).
// Mục "thống nhất 1 port" — url KHÔNG còn bake cứng IP:port riêng lúc build
// (trước đây VITE_KEYCLOAK_URL, phải khớp đúng PUBLIC_HOST mỗi lần đổi IP
// truy cập). nginx (apps/web/nginx.conf) giờ reverse-proxy "/realms/*",
// "/resources/*" sang Keycloak, SAME-ORIGIN với SPA -> dùng thẳng origin
// hiện tại của trình duyệt, đúng mọi cách truy cập (IP LAN, localhost, ...).
const keycloak = new Keycloak({
  url: window.location.origin,
  realm: import.meta.env.VITE_KEYCLOAK_REALM,
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID,
});

export default keycloak;
