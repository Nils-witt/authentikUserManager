# syntax=docker/dockerfile:1

# The frontend output is platform-independent, so build it once on the build host.
FROM --platform=$BUILDPLATFORM node:24-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY frontend/ ./
# vite.config writes to ../internal/web/dist.
RUN npm run build

# Cross-compile on the build host instead of emulating the target platform.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS backend
ARG TARGETOS TARGETARCH
# Shown in the UI footer; .git is not in the build context, so pass them in.
ARG COMMIT="" TAG=""
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY --from=frontend /src/internal/web/dist internal/web/dist
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath \
      -ldflags="-s -w -X authentikManager/internal/buildinfo.commit=${COMMIT} -X authentikManager/internal/buildinfo.tag=${TAG}" \
      -o /out/authentik-manager ./cmd/authentik-manager

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=backend /out/authentik-manager /authentik-manager
# The binary defaults to 127.0.0.1, which is unreachable from outside the container.
ENV LISTEN_ADDR=:8080
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/authentik-manager"]
