FROM node:20-alpine AS build
WORKDIR /app

COPY package.json ./
RUN npm install

COPY . .

# Bake vào bundle JS lúc build (Vite inline biến VITE_* tại build-time, không
# đọc được env lúc container chạy). Mục "thống nhất 1 port" — KHÔNG còn
# VITE_API_BASE_URL/VITE_KEYCLOAK_URL (client.ts/keycloak.ts giờ dùng
# same-origin qua nginx reverse-proxy, xem nginx.conf) — chỉ 2 biến này
# không phụ thuộc IP/hostname truy cập, giữ nguyên.
ARG VITE_KEYCLOAK_REALM
ARG VITE_KEYCLOAK_CLIENT_ID
ENV VITE_KEYCLOAK_REALM=$VITE_KEYCLOAK_REALM \
    VITE_KEYCLOAK_CLIENT_ID=$VITE_KEYCLOAK_CLIENT_ID
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Mục "Dựng TLS thật" — Alpine có apk (khác Keycloak/RHEL-UBI-micro, xem
# infra/keycloak/README.md) nên cài thẳng curl+jq cho fetch-cert.sh, gọn/
# chắc hơn hẳn so với tự viết HTTP client bằng /dev/tcp + sed. bash: image
# gốc chỉ có /bin/sh (busybox ash), script dùng "#!/usr/bin/env bash".
RUN apk add --no-cache curl jq bash
COPY --chmod=755 fetch-cert.sh /fetch-cert.sh
COPY --chmod=755 entrypoint-wrapper.sh /entrypoint-wrapper.sh

EXPOSE 443
ENTRYPOINT ["/entrypoint-wrapper.sh"]
