FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
COPY main_test.go ./
RUN CGO_ENABLED=0 go build -o /agent-manager .

FROM alpine:3.19
RUN apk add --no-cache wget
COPY --from=build /agent-manager /usr/local/bin/agent-manager

EXPOSE 8443
HEALTHCHECK --interval=10s --timeout=5s --retries=15 \
    CMD wget --no-check-certificate -qO- https://localhost:8443/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/agent-manager"]
