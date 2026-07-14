import Keycloak from "keycloak-js";

// Client public "web" (Authorization Code + PKCE, không có client secret —
// đúng chuẩn cho SPA chạy hoàn toàn phía trình duyệt). Xem
// infra/keycloak/realm-export.json và app/config.py (keycloak_client_ids)
// phía Orchestrator để hiểu vì sao có 2 client riêng (web vs orchestrator).
const keycloak = new Keycloak({
  url: import.meta.env.VITE_KEYCLOAK_URL,
  realm: import.meta.env.VITE_KEYCLOAK_REALM,
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID,
});

export default keycloak;
