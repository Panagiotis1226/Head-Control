# Head-Control — single static binary on distroless.
# Stage 1 builds the frontend; stage 2 cross-compiles the Go binary with the
# frontend embedded (BUILDPLATFORM everywhere = no QEMU during compilation);
# stage 3 is distroless/static with a nonroot user.

FROM --platform=$BUILDPLATFORM node:22-alpine AS frontend
WORKDIR /app
RUN corepack enable
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm build

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /app/dist/ internal/webui/dist/
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath \
      -ldflags="-s -w -X main.version=$VERSION -X github.com/panagiotis1226/claude-head/internal/server.Version=$VERSION" \
      -o /head-control ./cmd/head-control
# Seed for /data in the final image: distroless has no shell, so the
# directory must be COPY'd in with the right ownership. Without this, fresh
# named/anonymous volumes initialize root-owned and the nonroot process
# cannot create its SQLite database.
RUN mkdir -p /data-seed

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=backend /head-control /head-control
COPY --from=backend --chown=nonroot:nonroot /data-seed /data
VOLUME /data
EXPOSE 8000
USER nonroot
ENTRYPOINT ["/head-control"]
